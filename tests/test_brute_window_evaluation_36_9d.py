from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

from app.evaluation.brute_window_policy import evaluate_candidate_policies
from app.evaluation.brute_window_policy import select_window
from app.evaluation.brute_window_evaluation import (
    BruteWindowEvaluationError,
    load_manifest,
    evaluate_corpus,
    score_confusion,
)


BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)
SUBJECT = "198.51.100.21"


def failures(seconds, *, ip=SUBJECT, user="synthetic_user_a"):
    return [
        SimpleNamespace(
            timestamp=BASE + timedelta(seconds=second),
            src_ip=ip,
            user=user,
            event_type="login_failed",
        )
        for second in seconds
    ]


def test_late_noise_reproduces_whole_span_miss_but_candidates_find_burst():
    from app.detector.brute_force import detect_brute_force, summarize_ip_failures

    events = failures([0, 5, 10, 15, 20, 70])
    features = summarize_ip_failures(events)[SUBJECT]
    current = detect_brute_force(features, events)
    candidates = evaluate_candidate_policies(events, SUBJECT)

    assert features["failure_count"] == 6
    assert features["unique_target_count"] == 1
    assert features["window_seconds"] == 70
    assert current.is_detected is False
    assert candidates["sliding_global"].detected is True
    assert candidates["sliding_window"].detected is True
    assert candidates["per_account"].detected is True
    assert candidates["sliding_window"].window.failure_count == 5
    assert candidates["sliding_window"].full_failure_count == 6
    assert candidates["sliding_window"].window.average_interval == 5
    assert candidates["sliding_window"].window.interval_variability == 0


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [([0, 15, 30, 45, 60], True), ([0, 15, 30, 45, 61], False)],
)
def test_candidate_window_boundary_is_inclusive_and_exact(seconds, expected):
    result = evaluate_candidate_policies(failures(seconds), SUBJECT)
    assert result["sliding_window"].detected is expected


def test_microsecond_over_sixty_seconds_is_outside_window():
    events = failures([0, 15, 30, 45, 60])
    events[-1].timestamp += timedelta(microseconds=1)
    result = evaluate_candidate_policies(events, SUBJECT)
    assert result["sliding_window"].detected is False


def test_four_failures_do_not_meet_threshold():
    result = evaluate_candidate_policies(failures([0, 5, 10, 15]), SUBJECT)
    assert all(not item.detected for item in result.values())


def test_input_order_does_not_change_selected_evidence():
    events = failures([0, 5, 10, 15, 20, 70])
    forward = evaluate_candidate_policies(events, SUBJECT)["sliding_window"]
    reverse = evaluate_candidate_policies(list(reversed(events)), SUBJECT)["sliding_window"]
    assert forward == reverse


def test_tied_timestamps_count_all_records_without_deduplication():
    result = evaluate_candidate_policies(failures([0, 0, 0, 0, 0, 0]), SUBJECT)
    chosen = result["sliding_window"]
    assert chosen.detected is True
    assert chosen.window.failure_count == 6
    assert chosen.window.window_seconds == 0


def test_equal_strength_windows_for_two_accounts_do_not_pick_username_lexically():
    events = failures([0, 5, 10, 15, 20], user="synthetic_user_a")
    events += failures([0, 5, 10, 15, 20], user="synthetic_user_b")
    result = evaluate_candidate_policies(events, SUBJECT)["per_account"]
    assert result.detected is False
    assert result.candidate_present is True
    assert result.window is None
    assert result.selection == "ambiguous_tie"
    assert result.exclusion == "window_selection_ambiguous"


def test_selection_strategies_are_explicit_and_deterministic():
    candidates = evaluate_candidate_policies(failures([0, 5, 10, 15, 20, 30, 31, 32, 33, 34]), SUBJECT)["sliding_window"]
    assert candidates.selection == "fastest_threshold"
    assert candidates.window.start_time == BASE.isoformat().replace("+00:00", "Z")
    selected_shortest = select_window(
        [
            evaluate_candidate_policies(failures([0, 5, 10, 15, 20]), SUBJECT)["sliding_window"].window,
            evaluate_candidate_policies(failures([30, 31, 32, 33, 34]), SUBJECT)["sliding_window"].window,
        ],
        "shortest",
    )
    assert selected_shortest.start_time.endswith("00:00:30Z")


def test_candidate_variants_expose_global_window_and_per_account_semantics():
    events = failures([0, 5, 10, 15, 20], user="synthetic_user_a")
    events += failures([10], user="synthetic_user_b")
    result = evaluate_candidate_policies(events, SUBJECT)
    assert result["sliding_global"].detected is False
    assert result["sliding_window"].detected is False
    assert result["per_account"].detected is True


def test_late_different_account_separates_global_from_window_local_policy():
    events = failures([0, 5, 10, 15, 20], user="synthetic_user_a")
    events += failures([70], user="synthetic_user_b")
    result = evaluate_candidate_policies(events, SUBJECT)
    assert result["sliding_global"].detected is False
    assert result["sliding_window"].detected is True
    assert result["per_account"].detected is True


def test_ip_subjects_are_isolated():
    events = failures([0, 5, 10], ip="198.51.100.21")
    events += failures([15, 20], ip="203.0.113.21")
    result = evaluate_candidate_policies(events, "198.51.100.21")
    assert all(not item.detected for item in result.values())


def test_missing_account_is_not_invented_and_candidate_variants_are_explicit():
    events = failures([0, 5, 10, 15], user="synthetic_user_a")
    events += failures([20], user=None)
    result = evaluate_candidate_policies(events, SUBJECT)
    assert result["sliding_global"].detected is True
    assert result["sliding_window"].detected is True
    assert result["per_account"].detected is False


def test_missing_event_can_drop_below_threshold():
    result = evaluate_candidate_policies(failures([0, 5, 10, 20]), SUBJECT)
    assert all(not item.detected for item in result.values())


def test_same_observed_row_duplicates_are_not_automatically_deduplicated():
    repeated = failures([0, 0, 0, 0, 0])
    result = evaluate_candidate_policies(repeated, SUBJECT)
    assert result["sliding_window"].detected is True
    assert result["sliding_window"].window.failure_count == 5


def test_candidate_rejects_naive_or_mixed_awareness_timestamps_safely():
    events = failures([0, 5, 10, 15, 20])
    events[0].timestamp = events[0].timestamp.replace(tzinfo=None)
    result = evaluate_candidate_policies(events, SUBJECT)
    assert all(not item.detected for item in result.values())


def test_equal_instants_with_different_offsets_compare_as_the_same_utc_window():
    events = failures([0, 5, 10, 15, 20])
    base = evaluate_candidate_policies(events, SUBJECT)["sliding_window"]
    shifted = [
        SimpleNamespace(timestamp=event.timestamp.astimezone(timezone(timedelta(hours=9))),
                        src_ip=event.src_ip, user=event.user, event_type=event.event_type)
        for event in events
    ]
    assert evaluate_candidate_policies(shifted, SUBJECT)["sliding_window"] == base


def test_confusion_metrics_and_zero_denominators():
    scored = score_confusion([(True, True), (True, False), (False, True), (False, False)])
    assert (scored.tp, scored.fp, scored.fn, scored.tn) == (1, 1, 1, 1)
    assert scored.precision == "0.500000"
    assert scored.recall == "0.500000"
    assert scored.f1 == "0.500000"
    empty = score_confusion([])
    assert empty.precision == empty.recall == empty.f1 == "not_applicable"


def test_manifest_evaluation_is_deterministic_and_sanitized():
    first = evaluate_corpus()
    second = evaluate_corpus()
    assert first == second
    assert "raw" not in str(first).lower()
    assert "synthetic_user" not in str(first)
    assert "198.51.100." not in str(first)
    assert first["scenario_count"] == 24
    assert first["behavioral_label_counts"] == {
        "PATTERN_ABSENT": 5, "PATTERN_PRESENT": 18, "PATTERN_UNDETERMINED": 1,
    }
    assert first["operational_context_counts"] == {
        "AMBIGUOUS": 7, "KNOWN_BENIGN": 2, "SIMULATED_ATTACK": 14, "UNVERIFIED": 1,
    }
    assert first["metrics"]["current_whole_span"]["fn"] == 9
    assert first["metrics"]["candidate_window_account"]["fn"] == 2
    assert first["metrics"]["candidate_ip_account"]["fn"] == 1
    assert len(first["operational_false_alert_candidates"]["candidate_window_account"]) == 2


def test_cli_json_is_stable_and_does_not_echo_fixture_data(capsys):
    from app.evaluation.brute_window_cli import main

    assert main(["--format", "json"]) == 0
    first = capsys.readouterr().out
    assert main(["--format", "json"]) == 0
    second = capsys.readouterr().out
    assert first == second
    assert "synthetic_user" not in first
    assert "198.51.100." not in first
    assert "sample_logs" not in first


def test_supported_application_fixture_reproduces_current_fn_without_parser_loss():
    from pathlib import Path
    from app.evaluation.brute_window_evaluation import load_manifest, _parse_scenario
    from app.evaluation.brute_window_policy import evaluate_whole_span

    scenario = next(item for item in load_manifest() if item["id"] == "bf_late_noise_70s")
    events = _parse_scenario(scenario, Path("sample_logs/brute_window_evaluation"))
    assert len(events) == 6
    assert {event.src_ip for event in events} == {SUBJECT}
    assert {event.user for event in events} == {"synthetic_user_a"}
    assert evaluate_whole_span(events, SUBJECT).detected is False
    assert evaluate_candidate_policies(events, SUBJECT)["sliding_window"].window.failure_count == 5


def test_original_36_9c_late_noise_fixture_reproduces_whole_span_miss():
    from pathlib import Path
    from app.analyzer.pipeline import load_normalized_logs
    from app.detector.brute_force import detect_brute_force, summarize_ip_failures
    from app.main import analyze

    path = Path("sample_logs/detector_accuracy/bf_burst_with_late_noise.log")
    events = load_normalized_logs([{"source": "application", "path": str(path)}])
    assert len(events) == 6
    assert {event.event_type for event in events} == {"login_failed"}
    assert {event.src_ip for event in events} == {"198.51.100.23"}
    assert {event.user for event in events} == {"synthetic_user_c"}
    failures_by_ip = summarize_ip_failures(events)
    features = failures_by_ip["198.51.100.23"]
    assert (events[4].timestamp - events[0].timestamp).total_seconds() == 20
    assert features["failure_count"] == 6
    assert features["window_seconds"] == 70
    assert features["within_window"] is False
    assert detect_brute_force(features, events).is_detected is False
    # 과거 whole-span 계산은 위에서 직접 재현했고, Production은 Candidate C를 적용한다.
    assert analyze([{"source": "application", "path": str(path)}])["results"]["198.51.100.23"]["detections"]["brute_force"].is_detected is True


def test_production_password_spray_detection_is_unchanged_for_spray_scenario():
    from app.main import analyze
    from pathlib import Path

    path = Path("sample_logs/brute_window_evaluation/bf_spray_boundary.log")
    result = analyze([{"source": "application", "path": str(path)}])["results"][SUBJECT]
    assert result["detections"]["brute_force"].is_detected is False
    assert result["detections"]["password_spray"].is_detected is True


def test_historical_whole_span_correlation_requires_private_window_context():
    from pathlib import Path
    from app.correlation.attack_chain import correlate_brute_force_to_success
    from app.evaluation.brute_window_evaluation import load_manifest, _parse_scenario
    from app.models.schemas import DetectionResult

    scenario = next(item for item in load_manifest() if item["id"] == "bf_late_noise_then_success")
    events = _parse_scenario(scenario, Path("sample_logs/brute_window_evaluation"))
    candidate = evaluate_candidate_policies(events, SUBJECT)["sliding_window"].window
    correlation = correlate_brute_force_to_success(
        events, DetectionResult(is_detected=True, detection_type="brute_force", evidence=[])
    )
    assert candidate.end_time.endswith("00:00:20Z")
    assert correlation["is_correlated"] is False


def test_manifest_rejects_path_traversal(tmp_path):
    scenario = {
        "id": "scenario_one", "source": "application", "fixture": "../outside.log",
        "subject": SUBJECT, "expected_event_count": 1, "expected_failure_count": 1,
        "timestamp_contract": "parser_aware_localized_then_candidate_utc",
        "behavioral_pattern": "PATTERN_ABSENT", "operational_context": "UNVERIFIED",
        "label_basis": "사전 지정된 합성 패턴 라벨.", "context_basis": "운영 맥락은 확인하지 않음.",
        "current_policy_expectation": False,
        "candidate_policy_expectation": {"global_single_account": False, "window_single_account": False, "per_account": False},
        "ambiguity": [], "expected_exclusion": False, "evidence_selection_expectation": None,
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [scenario]}),
        encoding="utf-8",
    )
    with pytest.raises(BruteWindowEvaluationError):
        load_manifest(manifest_path)


def test_manifest_rejects_duplicate_scenario_ids_and_unknown_labels(tmp_path):
    from app.evaluation.brute_window_evaluation import load_manifest

    scenario = {
        "id": "scenario_one", "source": "application", "fixture": "one.log",
        "subject": SUBJECT, "expected_event_count": 1, "expected_failure_count": 1,
        "timestamp_contract": "parser_aware_localized_then_candidate_utc",
        "behavioral_pattern": "PATTERN_ABSENT", "operational_context": "UNVERIFIED",
        "label_basis": "독립 합성 패턴 정의.", "context_basis": "운영 맥락을 미확정으로 둠.",
        "current_policy_expectation": False,
        "candidate_policy_expectation": {"global_single_account": False, "window_single_account": False, "per_account": False},
        "ambiguity": [], "expected_exclusion": False, "evidence_selection_expectation": None,
    }
    (tmp_path / "one.log").write_text("synthetic\n", encoding="utf-8")
    duplicate = dict(scenario, fixture="two.log")
    (tmp_path / "two.log").write_text("synthetic\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [scenario, duplicate]}), encoding="utf-8")
    with pytest.raises(BruteWindowEvaluationError):
        load_manifest(manifest)

    scenario["id"] = "scenario_two"
    scenario["fixture"] = "one.log"
    scenario["behavioral_pattern"] = "ATTACK"
    manifest.write_text(json.dumps({"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [scenario]}), encoding="utf-8")
    with pytest.raises(BruteWindowEvaluationError):
        load_manifest(manifest)


def test_parser_contract_mismatch_is_not_scored_as_detector_failure(monkeypatch, tmp_path):
    from app.evaluation import brute_window_evaluation as evaluation

    manifest = tmp_path / "manifest.json"
    fixture = tmp_path / "scenario.log"
    fixture.write_text("synthetic\n", encoding="utf-8")
    manifest.write_text(
        '{"schema_version":1,"data_scope":"synthetic-only","scenarios":[]}',
        encoding="utf-8",
    )
    event = SimpleNamespace(event_type="login_failed", src_ip=SUBJECT, timestamp=BASE)
    monkeypatch.setattr(evaluation, "load_normalized_logs", lambda _sources: [event])
    scenario = {
        "source": "application", "fixture": "scenario.log", "expected_event_count": 2,
        "expected_failure_count": 2,
    }
    with pytest.raises(BruteWindowEvaluationError) as error:
        evaluation._parse_scenario(scenario, tmp_path)
    assert error.value.code == "parser_contract_mismatch"


def test_ambiguous_behavioral_label_is_excluded_instead_of_counted_as_tn():
    from app.evaluation.brute_window_evaluation import evaluate_corpus

    summary = evaluate_corpus()
    for metric in summary["metrics"].values():
        assert metric["excluded_undetermined"] == 1
        assert metric["negative_support"] == 5
        assert metric["tn"] + metric["fp"] == 5


def test_alternate_window_selection_is_reported_without_raw_account_data():
    from app.evaluation.brute_window_evaluation import evaluate_corpus

    scenario = next(item for item in evaluate_corpus()["scenario_results"] if item["scenario_id"] == "bf_late_noise_61_after_60")
    selection = scenario["policies"]["candidate_window_account"]["selection_comparison"]
    assert selection["fastest_threshold"]["end_time"].endswith("00:01:00Z")
    assert selection["shortest"]["end_time"].endswith("00:01:01Z")
    assert "target_account" not in scenario["policies"]["candidate_window_account"]["window"]
