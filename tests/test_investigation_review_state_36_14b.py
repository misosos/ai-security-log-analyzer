from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from threading import Barrier

import pytest
from hypothesis import given, strategies as st

from app.investigation_review_state_36_14b import (
    ReviewCaseIdentity,
    ReviewResetCommand,
    ReviewState,
    ReviewStateError,
    ReviewStateStore,
    ReviewStateSnapshot,
    ReviewTransitionCommand,
)


ANALYSIS = "a_0123456789abcdef0123456789abcdef"
CASE = "c_0123456789abcdef01234567"


def identity(analysis: str = ANALYSIS, case: str = CASE) -> ReviewCaseIdentity:
    return ReviewCaseIdentity(1, analysis, case)


def test_identity_is_closed_frozen_and_has_a_safe_projection() -> None:
    value = identity()
    assert value.to_mapping() == {
        "schema_version": 1,
        "analysis_ref": ANALYSIS,
        "case_ref": CASE,
    }
    with pytest.raises(ReviewStateError) as exc:
        ReviewCaseIdentity.from_mapping({**value.to_mapping(), "note": "CANARY"})
    assert exc.value.code == "INVALID_INPUT"
    assert "CANARY" not in str(exc.value)
    with pytest.raises((AttributeError, TypeError)):
        value.case_ref = CASE  # type: ignore[misc]
    assert not hasattr(value, "__dict__")

    class ExtendedIdentity(ReviewCaseIdentity):
        __slots__ = ("extra",)

    extended = ExtendedIdentity(1, ANALYSIS, CASE)
    with pytest.raises(ReviewStateError):
        ReviewStateStore().register_analysis(ANALYSIS, [CASE])
        ReviewTransitionCommand(extended, ReviewState.IN_REVIEW, 0)


@pytest.mark.parametrize(
    "schema,analysis,case",
    [
        (True, ANALYSIS, CASE),
        (2, ANALYSIS, CASE),
        (1, " " + ANALYSIS, CASE),
        (1, ANALYSIS + " ", CASE),
        (1, "a_../etc/passwd", CASE),
        (1, ANALYSIS, "c_../etc/passwd"),
        (1, ANALYSIS, CASE + "\n"),
        (1, "a_" + "f" * 100, CASE),
    ],
)
def test_identity_rejects_noncanonical_or_unsafe_identifiers(schema, analysis, case) -> None:
    with pytest.raises(ReviewStateError):
        ReviewCaseIdentity(schema, analysis, case)


def test_enum_and_revision_are_strict() -> None:
    for value in ("safe", "resolved", "Reviewed", " reviewed", "false_positive"):
        with pytest.raises((ReviewStateError, ValueError)):
            ReviewState(value)
    for value in (True, -1, "0", 2**53):
        with pytest.raises(ReviewStateError):
            ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, value)


def test_store_register_transition_reset_and_clear() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    initial = store.get(identity())
    assert initial == ReviewStateSnapshot(identity(), ReviewState.UNREVIEWED, 0)
    changed = store.transition(
        ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0)
    )
    assert changed.review_state is ReviewState.IN_REVIEW
    assert changed.revision == 1
    reset = store.reset(ReviewResetCommand(identity(), 1))
    assert reset.review_state is ReviewState.UNREVIEWED
    assert reset.revision == 2
    with pytest.raises(ReviewStateError) as exc:
        store.get(identity(analysis="a_ffffffffffffffffffffffffffffffff"))
    assert exc.value.code == "UNKNOWN_ANALYSIS"
    store.clear_analysis(ANALYSIS)
    with pytest.raises(ReviewStateError) as exc:
        store.get(identity())
    assert exc.value.code == "UNKNOWN_ANALYSIS"


def test_case_scope_and_analysis_replacement_are_isolated() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    store.transition(ReviewTransitionCommand(identity(), ReviewState.DEFERRED, 0))
    next_analysis = "a_ffffffffffffffffffffffffffffffff"
    store.register_analysis(next_analysis, [CASE])
    assert store.get(identity(next_analysis)).review_state is ReviewState.UNREVIEWED
    with pytest.raises(ReviewStateError):
        store.get(identity())
    with pytest.raises(ReviewStateError) as exc:
        store.get(identity(next_analysis, "c_ffffffffffffffffffffffff"))
    assert exc.value.code == "UNKNOWN_CASE"


def test_invalid_transition_and_stale_revision_preserve_snapshot() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    before = store.get(identity())
    with pytest.raises(ReviewStateError) as exc:
        store.transition(ReviewTransitionCommand(identity(), ReviewState.UNREVIEWED, 0))
    assert exc.value.code == "INVALID_TRANSITION"
    assert store.get(identity()) == before
    store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0))
    with pytest.raises(ReviewStateError) as exc:
        store.transition(ReviewTransitionCommand(identity(), ReviewState.DEFERRED, 0))
    assert exc.value.code == "STALE_REVISION"
    assert store.get(identity()).revision == 1


def test_reset_is_the_only_way_back_to_unreviewed_and_noop_is_rejected() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    with pytest.raises(ReviewStateError):
        store.transition(ReviewTransitionCommand(identity(), ReviewState.UNREVIEWED, 0))
    store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0))
    with pytest.raises(ReviewStateError):
        store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 1))
    assert store.get(identity()).revision == 1


def test_input_collection_is_copied_and_capacity_failure_preserves_active_state() -> None:
    store = ReviewStateStore()
    refs = [CASE]
    store.register_analysis(ANALYSIS, refs)
    refs.clear()
    assert store.get(identity()).review_state is ReviewState.UNREVIEWED
    with pytest.raises(ReviewStateError) as exc:
        store.register_analysis("a_ffffffffffffffffffffffffffffffff", [
            f"c_{index:024x}" for index in range(129)
        ])
    assert exc.value.code == "CAPACITY_EXCEEDED"
    assert store.get(identity()).revision == 0


def test_concurrent_same_revision_commands_have_one_winner() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    barrier = Barrier(2)

    def update(state: ReviewState):
        barrier.wait(timeout=2)
        return store.transition(ReviewTransitionCommand(identity(), state, 0))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(update, ReviewState.IN_REVIEW), pool.submit(update, ReviewState.DEFERRED)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=3))
            except ReviewStateError as exc:
                outcomes.append(exc.code)
    assert sum(isinstance(outcome, ReviewStateSnapshot) for outcome in outcomes) == 1
    assert outcomes.count("STALE_REVISION") == 1
    assert store.get(identity()).revision == 1


def test_concurrent_updates_to_distinct_cases_do_not_interfere() -> None:
    other_case = "c_ffffffffffffffffffffffff"
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE, other_case])
    barrier = Barrier(2)

    def update(case_ref: str):
        barrier.wait(timeout=2)
        return store.transition(
            ReviewTransitionCommand(identity(case=case_ref), ReviewState.IN_REVIEW, 0)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(update, case_ref) for case_ref in (CASE, other_case)]
        snapshots = [future.result(timeout=3) for future in results]
    assert {snapshot.identity.case_ref for snapshot in snapshots} == {CASE, other_case}
    assert all(snapshot.revision == 1 for snapshot in snapshots)


def test_snapshot_projection_contains_no_arbitrary_fields() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    snapshot = store.get(identity())
    assert set(snapshot.to_mapping()) == {
        "schema_version", "analysis_ref", "case_ref", "review_state", "revision"
    }
    assert not hasattr(snapshot, "__dict__")
    assert ReviewStateSnapshot.from_mapping(snapshot.to_mapping()) == snapshot


def test_commands_have_closed_mapping_validators() -> None:
    transition = ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 4)
    reset = ReviewResetCommand(identity(), 4)
    assert ReviewTransitionCommand.from_mapping(transition.to_mapping()) == transition
    assert ReviewResetCommand.from_mapping(reset.to_mapping()) == reset
    invalid = transition.to_mapping()
    invalid["unknown"] = "CANARY"
    with pytest.raises(ReviewStateError) as exc:
        ReviewTransitionCommand.from_mapping(invalid)
    assert "CANARY" not in str(exc.value)


@given(st.text())
def test_arbitrary_strings_never_expand_the_closed_enum(value: str) -> None:
    if value not in {state.value for state in ReviewState}:
        with pytest.raises(ValueError):
            ReviewState(value)


@given(st.sampled_from(list(ReviewState)), st.sampled_from(list(ReviewState)))
def test_only_documented_transition_edges_mutate(current_state, target_state) -> None:
    allowed = {
        (ReviewState.UNREVIEWED, ReviewState.IN_REVIEW),
        (ReviewState.UNREVIEWED, ReviewState.REVIEWED),
        (ReviewState.UNREVIEWED, ReviewState.DEFERRED),
        (ReviewState.IN_REVIEW, ReviewState.REVIEWED),
        (ReviewState.IN_REVIEW, ReviewState.DEFERRED),
        (ReviewState.REVIEWED, ReviewState.IN_REVIEW),
        (ReviewState.REVIEWED, ReviewState.DEFERRED),
        (ReviewState.DEFERRED, ReviewState.IN_REVIEW),
        (ReviewState.DEFERRED, ReviewState.REVIEWED),
    }
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    revision = 0
    if current_state is not ReviewState.UNREVIEWED:
        store.transition(ReviewTransitionCommand(identity(), current_state, revision))
        revision += 1
    before = store.get(identity())
    command = ReviewTransitionCommand(identity(), target_state, revision)
    if (current_state, target_state) in allowed:
        result = store.transition(command)
        assert result.review_state is target_state
        assert result.revision == revision + 1
    else:
        with pytest.raises(ReviewStateError):
            store.transition(command)
        assert store.get(identity()) == before


def test_replacement_same_analysis_ref_is_not_an_implicit_reset() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0))
    with pytest.raises(ReviewStateError) as exc:
        store.register_analysis(ANALYSIS, [CASE])
    assert exc.value.code == "ANALYSIS_ALREADY_ACTIVE"
    assert store.get(identity()).review_state is ReviewState.IN_REVIEW


def test_clear_racing_transition_is_linearizable_and_leaves_no_partial_state() -> None:
    for _ in range(20):
        store = ReviewStateStore()
        store.register_analysis(ANALYSIS, [CASE])
        barrier = Barrier(2)

        def transition():
            barrier.wait(timeout=2)
            try:
                return store.transition(
                    ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0)
                )
            except ReviewStateError as exc:
                return exc.code

        def clear():
            barrier.wait(timeout=2)
            try:
                store.clear_analysis(ANALYSIS)
                return "CLEARED"
            except ReviewStateError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(transition)
            second = pool.submit(clear)
            transition_result = first.result(timeout=3)
            clear_result = second.result(timeout=3)
        assert clear_result == "CLEARED"
        assert isinstance(transition_result, ReviewStateSnapshot) or transition_result == "UNKNOWN_ANALYSIS"
        with pytest.raises(ReviewStateError) as exc:
            store.get(identity())
        assert exc.value.code == "UNKNOWN_ANALYSIS"


def test_store_rejects_unbounded_or_non_reference_case_inputs() -> None:
    store = ReviewStateStore()
    with pytest.raises(ReviewStateError) as exc:
        store.register_analysis(ANALYSIS, iter([CASE]))
    assert exc.value.code == "INVALID_INPUT"
    with pytest.raises(ReviewStateError):
        store.register_analysis(ANALYSIS, [CASE, CASE])
    with pytest.raises(ReviewStateError):
        store.register_analysis(ANALYSIS, [object()])


def test_clear_all_and_closed_store_have_fixed_errors() -> None:
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    store.clear_all()
    with pytest.raises(ReviewStateError) as exc:
        store.get(identity())
    assert exc.value.code == "UNKNOWN_ANALYSIS"
    store.close()
    with pytest.raises(ReviewStateError) as exc:
        store.register_analysis(ANALYSIS, [CASE])
    assert exc.value.code == "STORE_CLOSED"


def test_fixed_errors_and_repr_do_not_echo_identifier_canaries() -> None:
    canary = "a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    error = ReviewStateError("UNKNOWN_ANALYSIS")
    assert canary not in str(error)
    assert canary not in repr(error)
    assert canary not in repr(ReviewCaseIdentity(1, canary, CASE))
    assert canary not in repr(ReviewStateStore())


def test_workflow_changes_do_not_mutate_canonical_analysis_projection() -> None:
    projection = {
        "detection": [{"kind": "synthetic_detection", "count": 1}],
        "relation": [{"kind": "synthetic_relation"}],
        "risk": {"band": "medium", "score": 20},
        "case": {"title": "Synthetic case", "case_ref": CASE},
        "checklist": {"status": "not_requested"},
        "report": {"schema_version": 1, "case_count": 1},
    }
    before = sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).digest()
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0))
    store.transition(ReviewTransitionCommand(identity(), ReviewState.REVIEWED, 1))
    store.reset(ReviewResetCommand(identity(), 2))
    after = sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).digest()
    assert after == before


def test_api_route_and_openapi_contract_is_unchanged_by_memory_core_use() -> None:
    from app.api import create_app

    before = create_app().openapi()
    store = ReviewStateStore()
    store.register_analysis(ANALYSIS, [CASE])
    store.transition(ReviewTransitionCommand(identity(), ReviewState.IN_REVIEW, 0))
    after = create_app().openapi()
    assert set(after["paths"]) == set(before["paths"])
    assert after["components"]["schemas"] == before["components"]["schemas"]
