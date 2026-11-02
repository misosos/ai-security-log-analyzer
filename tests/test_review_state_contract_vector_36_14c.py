from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.investigation_review_state_36_14b import (
    MAX_CASES_PER_ANALYSIS,
    ReviewCaseIdentity,
    ReviewResetCommand,
    ReviewState,
    ReviewStateError,
    ReviewStateStore,
    ReviewTransitionCommand,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "tests/fixtures/investigation_review_state_v1_contract.json"


@pytest.fixture(scope="module")
def vector() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_contract_vector_is_closed_synthetic_and_contains_expected_contract(vector: dict) -> None:
    assert set(vector) == {
        "schema_version", "synthetic_refs", "review_states", "allowed_transitions", "same_state_transition",
        "reset", "revision", "unknown_reference_errors", "generation_isolation",
        "max_cases_per_analysis", "error_categories", "state_fields",
    }
    assert vector["schema_version"] == 1
    assert vector["synthetic_refs"] == {
        "analysis_ref": "a_0123456789abcdef0123456789abcdef",
        "case_ref": "c_0123456789abcdef01234567",
        "next_analysis_ref": "a_abcdef0123456789abcdef0123456789",
        "unknown_case_ref": "c_ffffffffffffffffffffffff",
    }
    assert vector["review_states"] == [state.value for state in ReviewState]
    assert vector["max_cases_per_analysis"] == MAX_CASES_PER_ANALYSIS == 128
    assert vector["same_state_transition"] == "reject"
    assert vector["reset"] == {"target_state": "unreviewed", "requires_explicit_command": True}
    assert vector["revision"] == {
        "initial": 0, "successful_change_increment": 1, "stale_expected_revision": "reject"
    }
    assert vector["unknown_reference_errors"] == {
        "analysis": "UNKNOWN_ANALYSIS", "case": "UNKNOWN_CASE"
    }
    assert vector["generation_isolation"] == "new_generation_starts_unreviewed"
    assert vector["state_fields"] == [
        "schema_version", "analysis_ref", "case_ref", "review_state", "revision"
    ]
    assert set(vector["error_categories"]) == {
        "INVALID_INPUT", "INVALID_IDENTIFIER", "UNSUPPORTED_SCHEMA", "UNKNOWN_ANALYSIS",
        "UNKNOWN_CASE", "INVALID_TRANSITION", "STALE_REVISION", "CAPACITY_EXCEEDED",
        "STORE_CLOSED", "ANALYSIS_ALREADY_ACTIVE", "REVISION_LIMIT_REACHED",
    }
    assert set(vector["error_categories"]) == set(ReviewStateError._MESSAGES)
    serialized = json.dumps(vector, sort_keys=True)
    for forbidden in (
        "raw_log", "account", "username", "src_ip", "dst_ip", "hostname", "path",
        "timestamp", "title", "risk", "note", "fingerprint",
    ):
        assert forbidden not in serialized


def test_python_reference_implementation_matches_transition_vector(vector: dict) -> None:
    analysis = vector["synthetic_refs"]["analysis_ref"]
    case = vector["synthetic_refs"]["case_ref"]
    allowed = {tuple(edge) for edge in vector["allowed_transitions"]}
    for current in vector["review_states"]:
        for target in vector["review_states"]:
            store = ReviewStateStore()
            store.register_analysis(analysis, [case])
            identity = ReviewCaseIdentity(1, analysis, case)
            revision = 0
            if current != "unreviewed":
                store.transition(ReviewTransitionCommand(identity, ReviewState(current), revision))
                revision += 1
            command = ReviewTransitionCommand(identity, ReviewState(target), revision)
            if (current, target) in allowed:
                result = store.transition(command)
                assert result.review_state.value == target
                assert result.revision == revision + 1
            else:
                with pytest.raises(ReviewStateError) as exc:
                    store.transition(command)
                assert exc.value.code == "INVALID_TRANSITION"
                assert store.get(identity).review_state.value == current
                assert store.get(identity).revision == revision


def test_python_reference_implementation_matches_reset_cas_capacity_and_generation_vector(vector: dict) -> None:
    analysis = vector["synthetic_refs"]["analysis_ref"]
    next_analysis = vector["synthetic_refs"]["next_analysis_ref"]
    case = vector["synthetic_refs"]["case_ref"]
    identity = ReviewCaseIdentity(1, analysis, case)
    store = ReviewStateStore()
    store.register_analysis(analysis, [case])
    state = store.transition(ReviewTransitionCommand(identity, ReviewState.IN_REVIEW, 0))
    assert state.revision == vector["revision"]["initial"] + vector["revision"]["successful_change_increment"]
    with pytest.raises(ReviewStateError) as exc:
        store.transition(ReviewTransitionCommand(identity, ReviewState.DEFERRED, 0))
    assert exc.value.code == "STALE_REVISION"
    reset = store.reset(ReviewResetCommand(identity, 1))
    assert reset.review_state.value == vector["reset"]["target_state"]
    with pytest.raises(ReviewStateError) as exc:
        store.get(ReviewCaseIdentity(1, analysis, vector["synthetic_refs"]["unknown_case_ref"]))
    assert exc.value.code == vector["unknown_reference_errors"]["case"]
    store.register_analysis(next_analysis, [case])
    assert store.get(ReviewCaseIdentity(1, next_analysis, case)).review_state is ReviewState.UNREVIEWED
    with pytest.raises(ReviewStateError) as exc:
        store.get(identity)
    assert exc.value.code == vector["unknown_reference_errors"]["analysis"]
    with pytest.raises(ReviewStateError) as exc:
        store.register_analysis("a_11111111111111111111111111111111", [f"c_{i:024x}" for i in range(129)])
    assert exc.value.code == "CAPACITY_EXCEEDED"


def test_contract_document_exists_and_defines_client_memory_boundary() -> None:
    document = ROOT / "docs/investigation_review_workflow_state_integration_decision_36_14c.md"
    text = document.read_text(encoding="utf-8")
    for required in (
        "NO_API", "NO_SQLITE", "NO_WEB_STORAGE", "document-memory",
        "analysis_ref", "case_ref", "checklist", "rollback", "NOT_TESTED",
    ):
        assert required.casefold() in text.casefold()


def test_frontend_does_not_import_python_reference_or_contract_fixture() -> None:
    forbidden = ("investigation_review_state_v1_contract", "investigation_review_state_36_14b")
    frontend = ROOT / "frontend"
    for path in frontend.rglob("*"):
        if path.is_file() and path.suffix in {".js", ".css", ".html"}:
            text = path.read_text(encoding="utf-8")
            assert all(token not in text for token in forbidden)
