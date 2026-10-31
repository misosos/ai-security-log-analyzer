"""Independent, evaluation-only Spray consumer-boundary regression corpus."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import shutil
import socket

import pytest

from app.evaluation.spray_consumer_boundary import (
    CORPUS_ROOT,
    BoundaryValidationError,
    SprayWindowContext,
    EvaluationRun,
    build_selected_window,
    correlate_conservative,
    correlate_member_bound,
    evaluate,
    load_scenarios,
    render_text,
    validate_spray_window,
)
from app.models.schemas import NormalizedEvent


IP = "192.0.2.44"
BASE = datetime(2026, 10, 31, tzinfo=timezone.utc)


def event(second, *, user="spray_a", ip=IP, kind="login_failed", source="application"):
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=second),
        event_type=kind,
        source=source,
        user=user,
        src_ip=ip,
        dst_ip=None,
        application="synthetic-auth",
        protocol=None,
        user_agent=None,
        raw=f"synthetic {second} {user} {ip} {kind}",
    )


def qualifying_events(*, success_at=22, success_user="spray_a"):
    return [
        event(0, user="spray_a"),
        event(5, user="spray_b"),
        event(10, user="spray_c"),
        event(15, user="spray_a"),
        event(success_at, kind="user_login", user=success_user),
    ]


def test_new_corpus_has_independent_closed_labels_and_sufficient_scenarios():
    scenarios = load_scenarios()
    result = evaluate()

    assert len(scenarios) >= 28
    assert result["data_scope"] == "synthetic-only"
    assert result["scenario_count"] == len(scenarios)
    assert set(result["label_counts"]) == {
        "behavioral_pattern", "operational_context", "parser_status",
        "correlation_eligibility",
    }
    assert result["parser_summary"]["parsed"] > 0
    assert all("raw" not in row and "user" not in row for row in result["scenario_results"])


def test_duplicate_delivery_oracle_is_separate_from_runtime_observation():
    result = evaluate()
    rows = {row["scenario_id"]: row for row in result["scenario_results"]}
    replay = rows["replay_three_attempts_four_rows"]
    genuine = rows["genuine_four_attempts_identical_rows"]

    assert replay["behavioral_pattern"] == "PATTERN_ABSENT"
    assert replay["observed_failure_rows"] == 4
    assert replay["underlying_attempt_count"] == 3
    assert replay["production_detection"] is True
    assert replay["oracle_dedup_counterfactual"] is False
    assert genuine["observed_failure_rows"] == 4
    assert genuine["underlying_attempt_count"] == 4
    assert genuine["behavioral_pattern"] == "PATTERN_ABSENT"
    assert genuine["production_detection"] is False  # Four identical known-account rows still have one target.
    assert genuine["oracle_dedup_counterfactual"] is False


def test_pattern_and_known_benign_context_are_independent_axes():
    result = evaluate()
    row = next(
        row for row in result["scenario_results"]
        if row["scenario_id"] == "approved_batch_same_pattern"
    )
    assert row["behavioral_pattern"] == "PATTERN_PRESENT"
    assert row["operational_context"] == "KNOWN_BENIGN"
    assert row["production_detection"] is True
    assert row["operational_false_alert_candidate"] is True


def test_current_production_detection_and_actual_correlation_are_reported_separately():
    result = evaluate()
    row = next(
        row for row in result["scenario_results"]
        if row["scenario_id"] == "window_outside_late_failure_success"
    )
    assert row["production_detection"] is False
    assert row["production_correlation"] is False
    assert row["production_gate_open_correlation"]["failure_offset_seconds"] == 90
    assert row["production_gate_open_correlation"]["success_offset_seconds"] == 95
    assert row["member_bound_correlation"]["failure_offset_seconds"] != 90


def test_member_bound_success_is_scoped_to_actual_window_members():
    events = qualifying_events()
    owner = EvaluationRun()
    context = build_selected_window(events, IP, owner)
    result = correlate_member_bound(context, events, owner)

    assert result.correlated is True
    assert result.failure_event is events[3]
    assert result.success_event is events[4]
    assert result.failure_event in context.member_events


def test_member_bound_rejects_cross_account_cross_ip_and_pre_failure_success():
    for events in (
        qualifying_events(success_user="spray_elsewhere"),
        [*qualifying_events()[:4], event(22, user="spray_a", ip="192.0.2.99", kind="user_login")],
        [event(-1, user="spray_a", kind="user_login"), *qualifying_events()[:4]],
    ):
        owner = EvaluationRun()
        context = build_selected_window(events, IP, owner)
        assert correlate_member_bound(context, events, owner).correlated is False


@pytest.mark.parametrize("case", ["wrong_ip", "success_member", "wrong_count", "wrong_targets", "bad_timestamp", "duplicate_reference", "empty"])
def test_window_validator_rejects_invalid_membership(case):
    events = qualifying_events()
    owner = EvaluationRun()
    context = build_selected_window(events, IP, owner)
    if case == "wrong_ip":
        context = replace(context, member_events=(event(0, ip="192.0.2.99"), *context.member_events[1:]))
    elif case == "success_member":
        context = replace(context, member_events=(*context.member_events[:-1], events[4]))
    elif case == "wrong_count":
        context = replace(context, failure_count=context.failure_count + 1)
    elif case == "wrong_targets":
        context = replace(context, known_target_count=context.known_target_count + 1)
    elif case == "bad_timestamp":
        context = replace(context, end_utc=context.end_utc + timedelta(seconds=1))
    elif case == "duplicate_reference":
        context = replace(context, member_events=(*context.member_events, context.member_events[0]))
    elif case == "empty":
        context = replace(context, member_events=())
    with pytest.raises(BoundaryValidationError):
        validate_spray_window(context, events, owner)


def test_window_validator_rejects_wrong_run_and_equal_value_repackaging():
    events_a = qualifying_events()
    run_a, run_b = EvaluationRun(), EvaluationRun()
    context_a = build_selected_window(events_a, IP, run_a)
    cloned_equal_values = [replace(item) for item in events_a]

    with pytest.raises(BoundaryValidationError):
        validate_spray_window(context_a, cloned_equal_values, run_a)
    with pytest.raises(BoundaryValidationError):
        validate_spray_window(context_a, events_a, run_b)
    repacked = SprayWindowContext(
        owner=run_b,
        subject_ip=context_a.subject_ip,
        start_utc=context_a.start_utc,
        end_utc=context_a.end_utc,
        failure_count=context_a.failure_count,
        known_target_count=context_a.known_target_count,
        missing_user_count=context_a.missing_user_count,
        policy_id=context_a.policy_id,
        member_events=context_a.member_events,
    )
    with pytest.raises(BoundaryValidationError):
        validate_spray_window(repacked, events_a, run_a)
    with pytest.raises(BoundaryValidationError):
        validate_spray_window(replace(context_a, start_utc=context_a.start_utc), events_a, run_a)


def test_member_bound_and_conservative_candidates_separate_success_time_rules():
    in_window = qualifying_events(success_at=12)
    owner = EvaluationRun()
    context = build_selected_window(in_window, IP, owner)
    assert correlate_member_bound(context, in_window, owner).correlated is True
    assert correlate_conservative(context, in_window, owner).correlated is False

    after_end = qualifying_events(success_at=22)
    owner_after = EvaluationRun()
    context_after = build_selected_window(after_end, IP, owner_after)
    conservative = correlate_conservative(context_after, after_end, owner_after)
    assert conservative.correlated is True


def test_conservative_candidate_fails_closed_for_equal_delta_and_duplicate_pair():
    tied = [
        event(0, user="spray_a"), event(0, user="spray_b"), event(0, user="spray_c"),
        event(0, user="spray_a"), event(0, user="spray_a"),
        event(20, user="spray_a", kind="user_login"),
        event(20, user="spray_a", kind="user_login"),
    ]
    owner = EvaluationRun()
    context = build_selected_window(tied, IP, owner)
    assert correlate_conservative(context, tied, owner).reason == "ambiguous_pair"

    duplicate = [event(0, user="spray_a"), event(0, user="spray_a"), event(0, user="spray_b"),
                 event(0, user="spray_c"), event(22, user="spray_a", kind="user_login")]
    duplicate_owner = EvaluationRun()
    duplicate_context = build_selected_window(duplicate, IP, duplicate_owner)
    assert correlate_conservative(duplicate_context, duplicate, duplicate_owner).reason in {
        "ambiguous_member", "ambiguous_pair",
    }


def test_same_timestamp_has_no_strictly_ordered_correlation():
    events = [event(0, user="spray_b"), event(5, user="spray_c"), event(10, user="spray_d"),
              event(15, user="spray_a"), event(15, user="spray_a", kind="user_login")]
    owner = EvaluationRun()
    context = build_selected_window(events, IP, owner)
    assert correlate_member_bound(context, events, owner).correlated is False
    assert correlate_conservative(context, events, owner).correlated is False


def test_brute_context_is_not_accepted_as_spray_context():
    from app.evaluation.brute_window_consumer_contract import BruteWindowContext

    events = qualifying_events()
    owner = EvaluationRun()
    context = build_selected_window(events, IP, owner)
    brute = BruteWindowContext(IP, "spray_a", context.start_utc, context.end_utc, 4,
                               context.member_events)
    with pytest.raises(BoundaryValidationError):
        validate_spray_window(brute, events, owner)


def test_evaluation_is_deterministic_and_does_not_open_network_connections(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    first = evaluate()
    second = evaluate()
    assert first["scenario_results"] == second["scenario_results"]
    assert render_text(first) == render_text(second)
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second, sort_keys=True, separators=(",", ":")
    )


def test_prefix_results_change_only_with_observed_prefix_and_do_not_claim_live_parity():
    result = evaluate()
    row = next(
        row for row in result["scenario_results"]
        if row["scenario_id"] == "late_noise_changes_full_input_result"
    )
    assert row["prefix_detection_sequence"] == [False, True, False]
    assert result["live_runtime_integrated"] is False
    assert result["static_live_claim"] == "same-prefix-simulation-only"


def test_manifest_rejects_duplicate_key_and_fixture_symlink_and_path_traversal(tmp_path):
    scenarios = load_scenarios()
    assert scenarios
    manifest = CORPUS_ROOT / "manifest.json"
    raw = manifest.read_text(encoding="utf-8")
    assert '"schema_version":1' in raw.replace(" ", "")

    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS_ROOT, copy_root)
    copied_manifest = copy_root / "manifest.json"
    copied_manifest.write_text(
        '{"schema_version":1,"schema_version":1,"data_scope":"synthetic-only","scenarios":[]}',
        encoding="utf-8",
    )
    from app.evaluation.spray_consumer_boundary import load_scenarios as load_from
    with pytest.raises(BoundaryValidationError):
        load_from(copied_manifest)

    scenario = scenarios[0]
    outside = tmp_path / "outside.log"
    outside.write_text("synthetic", encoding="utf-8")
    copied_scenarios = list(scenarios)
    bad = dict(copied_scenarios[0])
    bad["fixture"] = "../outside.log"
    value = {"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [bad]}
    copied_manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BoundaryValidationError):
        load_from(copied_manifest)
