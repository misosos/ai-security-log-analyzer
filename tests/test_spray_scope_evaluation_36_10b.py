from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import socket

import pytest

from app.evaluation.spray_scope_evaluation import (
    CORPUS_ROOT,
    SprayScopeEvaluationError,
    _scenario_sources,
    evaluate,
    load_scenarios,
    render_text,
)
from app.evaluation.spray_scope_policy import (
    evaluate_known_account_window,
    evaluate_sliding_ip_window,
)
from app.models.schemas import AuthenticationContext, NormalizedEvent
from app.main import analyze


SUBJECT = "192.0.2.44"
BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)


def _failure(second: int, user: str | None, *, timestamp: datetime | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or BASE + timedelta(seconds=second),
        event_type="login_failed",
        source="application",
        user=user,
        src_ip=SUBJECT,
        dst_ip=None,
        application="synthetic-auth",
        protocol=None,
        user_agent=None,
        raw=f"synthetic event {second}",
        authentication=AuthenticationContext(outcome="failure"),
    )


def test_corpus_is_closed_synthetic_and_has_independent_label_axes():
    scenarios = load_scenarios()
    result = evaluate()

    assert len(scenarios) == 36
    assert result["data_scope"] == "synthetic-only"
    assert result["label_counts"]["behavioral_pattern"] == {
        "PATTERN_ABSENT": 12,
        "PATTERN_PRESENT": 20,
        "PATTERN_UNDETERMINED": 4,
    }
    assert result["label_counts"]["operational_context"]["KNOWN_BENIGN"] == 5
    assert result["label_counts"]["parser_status"] == {
        "IGNORED": 1,
        "PARTIAL": 5,
        "REJECTED": 1,
        "VERIFIED": 29,
    }
    assert all("raw" not in record for record in result["parser_summary"]["scenario_observations"])


def test_policy_metrics_and_operational_candidates_are_separate():
    result = evaluate()
    by_name = {item["policy"]: item for item in result["metrics"]}

    assert (by_name["current_whole_span"]["tp"], by_name["current_whole_span"]["fp"],
            by_name["current_whole_span"]["fn"], by_name["current_whole_span"]["tn"]) == (15, 1, 4, 10)
    assert (by_name["sliding_ip_window"]["tp"], by_name["sliding_ip_window"]["fp"],
            by_name["sliding_ip_window"]["fn"], by_name["sliding_ip_window"]["tn"]) == (17, 1, 2, 10)
    assert (by_name["known_account_window"]["tp"], by_name["known_account_window"]["fp"],
            by_name["known_account_window"]["fn"], by_name["known_account_window"]["tn"]) == (16, 1, 3, 10)
    candidates = ["duplicate_delivery_three_attempts", "known_benign_batch", "shared_nat_multiple_users"]
    assert by_name["current_whole_span"]["operational_false_alert_candidate_scenarios"] == [
        "duplicate_delivery_three_attempts", "known_benign_batch", "shared_nat_multiple_users",
    ]
    duplicate = next(row for row in result["scenario_results"] if row["scenario_id"] == candidates[0])
    assert duplicate["behavioral_pattern"] == "PATTERN_ABSENT"
    benign = next(row for row in result["scenario_results"] if row["scenario_id"] == "known_benign_batch")
    assert benign["behavioral_pattern"] == "PATTERN_PRESENT"
    assert benign["detected_by_policy"]["current_whole_span"] is True


def test_late_noise_and_missing_account_tradeoffs_are_recorded():
    result = evaluate()
    rows = {item["scenario_id"]: item for item in result["scenario_results"]}

    for scenario_id in ("late_noise_other_account", "late_noise_same_account"):
        row = rows[scenario_id]
        assert row["detected_by_policy"] == {
            "current_whole_span": False,
            "sliding_ip_window": True,
            "known_account_window": True,
        }
        subject = next(iter(row["production_features_by_subject"]))
        window = row["candidate_windows_by_subject"]["sliding_ip_window"][subject]
        assert window["failure_count"] == 4
        assert window["known_target_count"] == 3
    assert rows["late_noise_other_account"]["production_features_by_subject"]["192.0.2.10"]["known_target_count"] == 4
    assert rows["late_noise_same_account"]["production_features_by_subject"]["192.0.2.10"]["known_target_count"] == 3

    assert rows["one_missing_username"]["detected_by_policy"] == {
        "current_whole_span": True,
        "sliding_ip_window": True,
        "known_account_window": False,
    }
    assert rows["distributed_two_ips"]["detected_by_policy"] == {
        "current_whole_span": False,
        "sliding_ip_window": False,
        "known_account_window": False,
    }


def test_window_includes_exact_sixty_seconds_and_rejects_one_microsecond_more():
    included = [_failure(sec, f"spray_user_{index}") for index, sec in enumerate((0, 20, 40, 60))]
    decision = evaluate_sliding_ip_window(included, (SUBJECT,))[SUBJECT]
    assert decision.detected
    assert decision.window is not None
    assert decision.window.failure_count == 4
    assert decision.window.start_time == "2026-10-30T00:00:00Z"
    assert decision.window.end_time == "2026-10-30T00:01:00Z"

    outside = list(included)
    outside[-1] = _failure(60, "spray_user_3", timestamp=BASE + timedelta(seconds=60, microseconds=1))
    assert not evaluate_sliding_ip_window(outside, (SUBJECT,))[SUBJECT].detected


def test_candidate_normalizes_offset_equivalent_instants_and_ignores_input_order():
    events = [
        _failure(0, "spray_user_a", timestamp=datetime.fromisoformat("2026-10-30T09:00:00+09:00")),
        _failure(10, "spray_user_b", timestamp=datetime.fromisoformat("2026-10-30T00:00:10+00:00")),
        _failure(20, "spray_user_c", timestamp=datetime.fromisoformat("2026-10-30T02:00:20+02:00")),
        _failure(30, "spray_user_d", timestamp=datetime.fromisoformat("2026-10-30T00:00:30+00:00")),
    ]
    forward = evaluate_sliding_ip_window(events, (SUBJECT,))[SUBJECT]
    reverse = evaluate_sliding_ip_window(list(reversed(events)), (SUBJECT,))[SUBJECT]
    assert forward == reverse
    assert forward.window is not None
    assert forward.window.start_time == "2026-10-30T00:00:00Z"
    assert forward.window.end_time == "2026-10-30T00:00:30Z"


def test_known_account_candidate_excludes_missing_account_failures():
    events = [
        _failure(0, "spray_user_a"),
        _failure(5, None),
        _failure(10, "spray_user_b"),
        _failure(15, "spray_user_c"),
    ]
    assert evaluate_sliding_ip_window(events, (SUBJECT,))[SUBJECT].detected
    assert not evaluate_known_account_window(events, (SUBJECT,))[SUBJECT].detected


def test_duplicate_delivery_is_not_deduplicated_and_can_cross_threshold():
    result = evaluate()
    row = next(item for item in result["scenario_results"]
               if item["scenario_id"] == "duplicate_delivery_three_attempts")
    subject = next(iter(row["production_features_by_subject"]))
    assert row["production_features_by_subject"][subject]["failure_count"] == 4
    assert row["detected_by_policy"]["current_whole_span"] is True
    assert row["behavioral_pattern"] == "PATTERN_ABSENT"


def test_brute_and_spray_overlap_keeps_distinct_production_evidence():
    scenario = next(item for item in load_scenarios() if item["id"] == "brute_and_spray_overlap")
    result = analyze(_scenario_sources(scenario, CORPUS_ROOT))
    entry = result["results"][scenario["subjects"][0]]
    detections = entry["detections"]
    assert detections["brute_force"].is_detected is True
    assert detections["password_spray"].is_detected is True
    brute_failure_evidence = next(
        item for item in detections["brute_force"].evidence
        if item.type == "multiple_login_failures" and item.source == "brute_force_detector"
    )
    spray_failure_evidence = next(
        item for item in detections["password_spray"].evidence
        if item.type == "multiple_login_failures" and item.source == "password_spray_detector"
    )
    assert brute_failure_evidence.value == 5
    assert spray_failure_evidence.value == 7
    assert brute_failure_evidence.time_range != spray_failure_evidence.time_range


def test_parser_rejection_and_undetermined_labels_use_separate_exclusions():
    result = evaluate()
    rows = {item["scenario_id"]: item for item in result["scenario_results"]}
    assert rows["unsupported_inline_timezone_offset"]["metric_disposition"] == "EXCLUDED_PARSER"
    assert rows["all_missing_usernames"]["metric_disposition"] == "EXCLUDED_UNDETERMINED"
    assert rows["all_missing_usernames"]["detected_by_policy"]["current_whole_span"] is False


def test_text_and_json_metrics_match_and_semantic_output_is_deterministic():
    first = evaluate()
    second = evaluate()
    assert first["metrics"] == second["metrics"]
    assert first["scenario_results"] == second["scenario_results"]
    assert first["policy_differences"] == second["policy_differences"]
    rendered = render_text(first)
    assert "current_whole_span 15 1 4 10" in rendered
    assert "unsupported_inline_timezone_offset: EXCLUDED_PARSER" in rendered
    assert "all_missing_usernames: EXCLUDED_UNDETERMINED" in rendered
    assert "production_mutation: none" in rendered


def test_evaluation_does_not_open_network_connections(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    result = evaluate()
    assert result["data_scope"] == "synthetic-only"


def _copy_corpus(tmp_path: Path) -> Path:
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS_ROOT, target)
    return target / "manifest.json"


def test_manifest_rejects_duplicate_json_key(tmp_path):
    manifest = _copy_corpus(tmp_path)
    manifest.write_text('{"schema_version":1,"schema_version":1,"data_scope":"synthetic-only","scenarios":[]}', encoding="utf-8")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)


def test_manifest_rejects_path_traversal_and_duplicate_id(tmp_path):
    manifest = _copy_corpus(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["scenarios"][0]["inputs"][0]["fixture"] = "../outside.log"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)

    value = json.loads((CORPUS_ROOT / "manifest.json").read_text(encoding="utf-8"))
    value["scenarios"][1]["id"] = value["scenarios"][0]["id"]
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)


def test_manifest_rejects_duplicate_fixture_reference(tmp_path):
    manifest = _copy_corpus(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["scenarios"][1]["inputs"][0]["fixture"] = value["scenarios"][0]["inputs"][0]["fixture"]
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)


def test_manifest_rejects_fixture_symlink_and_oversized_fixture(tmp_path):
    manifest = _copy_corpus(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    fixture = value["scenarios"][0]["inputs"][0]["fixture"]
    path = manifest.parent / fixture
    contents = path.read_bytes()
    path.unlink()
    path.symlink_to(CORPUS_ROOT / fixture)
    with pytest.raises(SprayScopeEvaluationError, match="fixture_unavailable"):
        load_scenarios(manifest)

    path.unlink()
    path.write_bytes(contents + b" " * 9000)
    with pytest.raises(SprayScopeEvaluationError, match="fixture_unavailable"):
        load_scenarios(manifest)


def test_manifest_rejects_invalid_utf8_and_nonstandard_json_constant(tmp_path):
    manifest = _copy_corpus(tmp_path)
    manifest.write_bytes(b"\xff")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)
    manifest.write_text('{"schema_version":NaN,"data_scope":"synthetic-only","scenarios":[]}', encoding="utf-8")
    with pytest.raises(SprayScopeEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)
