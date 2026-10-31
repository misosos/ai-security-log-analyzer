"""Security boundary tests for the isolated Spray prototype (not Production)."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.evaluation.spray_trusted_context_prototype import (
    PrototypeSprayRunOwner,
    PrototypeValidationError,
    build_prototype_window,
    correlate_c1,
    correlate_c2,
    issue_detection_evidence,
    validate_detection_evidence,
    validate_window,
)
from app.models.schemas import AuthenticationContext, NormalizedEvent


IP = "192.0.2.77"
BASE = datetime(2026, 10, 31, tzinfo=timezone.utc)


def event(second, user="spray_a", *, ip=IP, kind="login_failed", source="application"):
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=second), event_type=kind, source=source,
        user=user, src_ip=ip, dst_ip=None, application="synthetic-auth",
        protocol=None, user_agent=None, raw=f"synthetic {second} {user} {ip} {kind}",
        authentication=AuthenticationContext(
            outcome="failure" if kind == "login_failed" else "success"
        ) if kind in {"login_failed", "user_login"} else None,
    )


def qualifying(*, success_at=20, success_user="spray_a"):
    events = [event(0), event(5, "spray_b"), event(10, "spray_c"), event(15)]
    if success_at is not None:
        events.append(event(success_at, success_user, kind="user_login"))
    return events


def make_context(events):
    owner = PrototypeSprayRunOwner()
    owner.register_events(events)
    return owner, build_prototype_window(owner, IP)


def test_owner_binds_exact_events_once_and_rejects_copies_and_other_runs():
    events = qualifying()
    owner, context = make_context(events)
    assert validate_window(owner, context) is None
    with pytest.raises(PrototypeValidationError, match="owner_already_bound"):
        owner.register_events(events)
    clone = replace(events[0])
    other = PrototypeSprayRunOwner()
    other.register_events([clone])
    with pytest.raises(PrototypeValidationError, match="wrong_run"):
        build_prototype_window(other, IP, events=events)


def test_window_context_repackaging_wrong_type_and_brute_context_are_rejected():
    events = qualifying()
    owner, context = make_context(events)
    from app.evaluation.spray_trusted_context_prototype import PrototypeSprayWindowContext

    repacked = PrototypeSprayWindowContext._untrusted_copy(context)
    with pytest.raises(PrototypeValidationError, match="unissued_context"):
        validate_window(owner, repacked)
    with pytest.raises(PrototypeValidationError, match="invalid_context"):
        validate_window(owner, object())


@pytest.mark.parametrize("mutation", [
    lambda e: setattr(e, "timestamp", BASE + timedelta(seconds=99)),
    lambda e: setattr(e, "src_ip", "192.0.2.88"),
    lambda e: setattr(e, "user", "spray_other"),
    lambda e: setattr(e, "event_type", "user_login"),
    lambda e: setattr(e.authentication, "outcome", "success"),
])
def test_post_registration_event_mutation_fails_closed(mutation):
    events = qualifying()
    owner, context = make_context(events)
    mutation(events[0])
    with pytest.raises(PrototypeValidationError, match="event_mutated"):
        validate_window(owner, context)


def test_window_exact_membership_counts_utc_and_evidence_are_bound():
    events = [event(0), event(20, "spray_b"), event(40, "spray_c"), event(60)]
    owner, context = make_context(events)
    assert context.start_utc == BASE
    assert context.end_utc == BASE + timedelta(seconds=60)
    assert context.failure_count == 4
    assert context.known_target_count == 3
    evidence = issue_detection_evidence(owner, context)
    assert validate_detection_evidence(owner, context, evidence) is None
    forged = replace(evidence, failure_count=5)
    with pytest.raises(PrototypeValidationError, match="unissued_evidence"):
        validate_detection_evidence(owner, context, forged)
    with pytest.raises(PrototypeValidationError, match="unissued_evidence"):
        validate_detection_evidence(owner, context, replace(evidence))


def test_window_boundaries_missing_user_sources_and_late_noise():
    at_limit = [event(0), event(20, "spray_b"), event(40, "spray_c"), event(60, None)]
    owner, context = make_context(at_limit)
    assert context.failure_count == 4 and context.missing_user_count == 1
    assert context.end_utc == BASE + timedelta(seconds=60)

    mixed = [event(0, source="application"), event(5, "spray_b", source="ssh"),
             event(10, "spray_c"), event(15, "spray_d"), event(90, "spray_z")]
    owner3 = PrototypeSprayRunOwner()
    owner3.register_events(mixed)
    context3 = build_prototype_window(owner3, IP)
    assert context3 is not None and context3.end_utc == BASE + timedelta(seconds=15)
    assert context3.sources == ("application", "ssh")


def test_window_plus_one_microsecond_is_rejected_and_exactly_sixty_is_inclusive():
    exact = [event(0), event(20, "spray_b"), event(40, "spray_c"), event(60)]
    owner = PrototypeSprayRunOwner()
    owner.register_events(exact)
    context = build_prototype_window(owner, IP)
    assert context is not None and context.end_utc - context.start_utc == timedelta(seconds=60)

    over = [event(0), event(20, "spray_b"), event(40, "spray_c"), event(60)]
    over[-1].timestamp += timedelta(microseconds=1)
    owner_over = PrototypeSprayRunOwner()
    owner_over.register_events(over)
    assert build_prototype_window(owner_over, IP) is None


def test_equal_value_distinct_membership_is_rejected_as_ambiguous_without_dedup():
    events = [event(0), event(5, "spray_b"), event(10, "spray_c"), event(15), event(15)]
    owner = PrototypeSprayRunOwner()
    owner.register_events(events)
    with pytest.raises(PrototypeValidationError, match="ambiguous_selection"):
        build_prototype_window(owner, IP)


def test_member_bound_c1_blocks_late_noise_endpoint_and_c2_uses_end_anchor():
    events = qualifying(success_at=None)
    events.extend([event(12, kind="user_login", user="spray_a"),
                   event(90, kind="login_failed", user="spray_a"),
                   event(95, kind="user_login", user="spray_a")])
    owner, context = make_context(events)
    assert context.end_utc == BASE + timedelta(seconds=15)
    c1 = correlate_c1(owner, context, events)
    c2 = correlate_c2(owner, context, events)
    assert c1.correlated is True
    assert c1.failure_event is events[0]
    assert c1.success_event is events[4]
    assert c2.correlated is False  # Success is beyond end + 60 seconds.


def test_correlation_requires_known_same_account_strict_order_and_unique_endpoint():
    for events in (
        qualifying(success_at=20, success_user="spray_other"),
        [*qualifying(success_at=None), event(20, "spray_a", ip="192.0.2.99", kind="user_login")],
        [event(-1, "spray_a", kind="user_login"), *qualifying(success_at=None)],
        [event(0, "spray_a", kind="user_login"), *qualifying(success_at=None)],
    ):
        owner, context = make_context(events)
        assert correlate_c1(owner, context, events).correlated is False

    ambiguous = [*qualifying(success_at=None), event(20, "spray_a", kind="user_login"),
                 event(20, "spray_a", kind="user_login")]
    owner, context = make_context(ambiguous)
    assert correlate_c1(owner, context, ambiguous).correlated is False


def test_cross_run_success_and_context_field_mutation_are_rejected():
    events = qualifying()
    owner, context = make_context(events)
    other = PrototypeSprayRunOwner()
    other_success = event(21, "spray_a", kind="user_login")
    other.register_events([other_success])
    with pytest.raises(PrototypeValidationError, match="wrong_run"):
        correlate_c1(owner, context, [*events, other_success])
    object.__setattr__(context, "failure_count", context.failure_count + 1)
    with pytest.raises(PrototypeValidationError, match="context_mutated"):
        validate_window(owner, context)


def test_evidence_cannot_be_rebound_to_another_run_context():
    events_a = qualifying(success_at=None)
    owner_a, context_a = make_context(events_a)
    evidence_a = issue_detection_evidence(owner_a, context_a)
    events_b = qualifying(success_at=None)
    owner_b, context_b = make_context(events_b)
    with pytest.raises(PrototypeValidationError, match="unissued_evidence"):
        validate_detection_evidence(owner_b, context_b, evidence_a)


def test_owner_registration_is_bounded_and_snapshot_is_exact():
    owner = PrototypeSprayRunOwner()
    consumed = 0

    def too_many_events():
        nonlocal consumed
        for index in range(10_000):
            consumed += 1
            yield event(index % 60)

    with pytest.raises(PrototypeValidationError, match="invalid_event_set"):
        owner.register_events(too_many_events())
    assert consumed == 513

    oversized = event(0)
    oversized.raw = "x" * 8193
    with pytest.raises(PrototypeValidationError, match="event_too_large"):
        PrototypeSprayRunOwner().register_events([oversized])


def test_stable_redacted_repr_and_production_pipeline_does_not_import_prototype():
    events = qualifying()
    owner, context = make_context(events)
    assert "spray_a" not in repr(owner) + repr(context)
    assert events[0].raw not in repr(owner) + repr(context)
    from pathlib import Path

    pipeline = Path("app/analyzer/pipeline.py").read_text()
    assert "spray_trusted_context_prototype" not in pipeline


def test_prototype_cli_is_deterministic_and_redacted():
    from app.evaluation.spray_trusted_context_prototype import run_prototype_checks

    first = run_prototype_checks()
    second = run_prototype_checks()
    assert first == second
    rendered = repr(first)
    assert "spray_a" not in rendered and "192.0.2.77" not in rendered
    assert first["production_changed"] is False


def test_owner_rejects_subset_and_duplicate_event_reference():
    events = qualifying()
    owner = PrototypeSprayRunOwner()
    owner.register_events(events)
    with pytest.raises(PrototypeValidationError, match="event_set_mismatch"):
        build_prototype_window(owner, IP, events=events[:-1])

    duplicate_owner = PrototypeSprayRunOwner()
    with pytest.raises(PrototypeValidationError, match="duplicate_event_reference"):
        duplicate_owner.register_events([events[0], events[0]])


def test_selection_is_order_independent_and_preserves_actual_references():
    events = qualifying(success_at=None)
    late = event(90, "spray_z")
    events.append(late)
    first_owner = PrototypeSprayRunOwner()
    first_owner.register_events(events)
    first = build_prototype_window(first_owner, IP)
    second_owner = PrototypeSprayRunOwner()
    second_owner.register_events(list(reversed(events)))
    second = build_prototype_window(second_owner, IP)
    assert first is not None and second is not None
    assert {id(item) for item in first.members} == {id(item) for item in second.members}
    assert late not in first.members


def test_offset_timestamps_are_normalized_to_utc_for_membership():
    events = qualifying(success_at=None)
    events[0].timestamp = datetime(2026, 10, 31, 9, tzinfo=timezone(timedelta(hours=9)))
    owner = PrototypeSprayRunOwner()
    owner.register_events(events)
    context = build_prototype_window(owner, IP)
    assert context is not None
    assert context.start_utc.tzinfo is timezone.utc
    assert context.start_utc == BASE


@pytest.mark.parametrize("field,value", [
    ("subject_ip", "192.0.2.88"),
    ("known_target_count", 4),
    ("missing_user_count", 1),
    ("start_utc", BASE + timedelta(seconds=1)),
    ("end_utc", BASE + timedelta(seconds=16)),
    ("sources", ("ssh",)),
    ("policy_id", "unapproved-policy"),
])
def test_context_mutations_are_detected(field, value):
    owner, context = make_context(qualifying(success_at=None))
    object.__setattr__(context, field, value)
    with pytest.raises(PrototypeValidationError, match="context_mutated"):
        validate_window(owner, context)


def test_correlation_rejects_cross_run_success_and_out_of_window_pair():
    events = qualifying(success_at=None)
    late_failure = event(90, "spray_a")
    late_success = event(95, "spray_a", kind="user_login")
    events.extend([late_failure, late_success])
    owner, context = make_context(events)
    pair = correlate_c1(owner, context, events)
    assert not pair.correlated

    foreign_owner = PrototypeSprayRunOwner()
    foreign_success = event(20, "spray_a", kind="user_login")
    foreign_owner.register_events([foreign_success])
    with pytest.raises(PrototypeValidationError, match="wrong_run"):
        correlate_c1(owner, context, [*events, foreign_success])


def test_c2_requires_success_after_window_end_and_rejects_missing_member_account():
    events = qualifying(success_at=30)
    owner, context = make_context(events)
    assert correlate_c2(owner, context, events).correlated

    missing = [event(0), event(5, "spray_b"), event(10, "spray_c"), event(15, None),
               event(30, "spray_a", kind="user_login")]
    missing_owner, missing_context = make_context(missing)
    assert not correlate_c2(missing_owner, missing_context, missing).correlated


def test_mixed_sources_are_reported_but_not_treated_as_actor_identity():
    events = [event(0, source="application"), event(5, "spray_b", source="ssh"),
              event(10, "spray_c", source="application"), event(15, "spray_a", source="ssh"),
              event(20, "spray_a", source="application", kind="user_login")]
    owner, context = make_context(events)
    assert context.sources == ("application", "ssh")
    assert correlate_c1(owner, context, events).correlated


def test_brute_context_cannot_be_used_as_spray_context():
    from app.detector.brute_force import BruteWindowContext

    owner, context = make_context(qualifying(success_at=None))
    brute = BruteWindowContext(IP, "spray_a", BASE, BASE, 5, (),)
    with pytest.raises(PrototypeValidationError, match="invalid_context"):
        validate_window(owner, brute)


def test_prototype_is_not_imported_by_production_consumer_modules():
    from pathlib import Path

    for path in (
        Path("app/analyzer/pipeline.py"), Path("app/correlation/attack_chain.py"),
        Path("app/analyzer/risk.py"), Path("app/analyzer/incident_case_adapter.py"),
        Path("app/analyzer/report_projection.py"),
    ):
        assert "spray_trusted_context_prototype" not in path.read_text()
