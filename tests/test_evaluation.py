"""Evaluation labels are hand-reviewed, not analyzer-generated snapshots."""

from dataclasses import replace
from datetime import timedelta
from copy import deepcopy
import json
import os
import subprocess
import sys

import pytest

from app.evaluation.corpus import SCENARIOS, ExpectedDetection, utc
from app.evaluation.runner import Confusion, EvaluationError, evaluate, ratio


def _cli(*args: str, tz: str = "UTC") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["TZ"] = tz
    return subprocess.run(
        [sys.executable, "-m", "app.evaluation", *args],
        check=False, capture_output=True, text=True, env=env,
    )


def test_hand_calculated_confusion_and_ratios():
    count = Confusion()
    for expected, actual in ((True, True), (True, True), (True, False),
                             (False, True), (False, False), (False, False)):
        count = count.add(expected, actual)
    assert count == Confusion(tp=2, fp=1, fn=1, tn=2)
    assert ratio(2, 3) == "0.666667"
    assert ratio(4, 6) == "0.666667"  # F1 = 2TP/(2TP+FP+FN)
    assert ratio(0, 0) == "not_applicable"


def test_fixed_corpus_baseline_and_layers():
    result = evaluate()
    assert result.corpus_kind == "synthetic_boundary_corpus"
    assert (result.scenario_count, result.passed_scenarios, result.failed_scenarios) == (21, 21, 0)
    assert (result.parser_summary.input_lines, result.parser_summary.parsed) == (75, 75)
    assert [(m.detection_type, m.tp, m.fp, m.fn, m.tn, m.support) for m in result.detection_metrics] == [
        ("brute_force", 6, 0, 0, 15, 6),
        ("password_spraying_like", 2, 0, 0, 19, 2),
        ("path_traversal", 2, 0, 0, 19, 2),
    ]
    assert [(m.relation_type, m.tp, m.fp, m.fn) for m in result.correlation_metrics] == [
        ("failed_to_successful_login", 3, 0, 0),
        ("brute_force_to_successful_login", 1, 0, 0),
        ("password_spray_to_successful_login", 1, 0, 0),
    ]
    assert result.risk_summary.matched_scenarios == 21
    assert result.case_summary.matched_scenarios == 21


def test_cli_stability_filter_and_bounded_error():
    one = _cli("--format", "json")
    two = _cli("--format", "json", tz="Pacific/Honolulu")
    assert one.returncode == two.returncode == 0
    assert one.stdout == two.stdout
    parsed = json.loads(one.stdout)
    assert parsed["scenario_count"] == 21
    assert not parsed["invariant_failures"]
    filtered = _cli("--format", "json", "--scenario", "brute_success")
    assert filtered.returncode == 0
    assert json.loads(filtered.stdout)["scenario_count"] == 1
    invalid = _cli("--scenario", "PRIVATE-CANARY")
    assert invalid.returncode == 2
    assert invalid.stderr.strip() == "unknown_scenario"
    assert "PRIVATE-CANARY" not in invalid.stderr


def test_invalid_labels_fail_closed():
    with pytest.raises(EvaluationError, match="invalid_label"):
        evaluate((SCENARIOS[0], SCENARIOS[0]))
    bad_type = replace(SCENARIOS[0], detections=(ExpectedDetection("unknown", "192.0.2.10"),))
    with pytest.raises(EvaluationError, match="invalid_label"):
        evaluate((bad_type,))
    bad_time = replace(SCENARIOS[0].parser, first_timestamp=utc(0).replace(tzinfo=None))
    with pytest.raises(EvaluationError, match="invalid_label"):
        evaluate((replace(SCENARIOS[0], parser=bad_time),))
    wrong = replace(SCENARIOS[0], fixture="../private.log")
    with pytest.raises(EvaluationError, match="invalid_label"):
        evaluate((wrong,))
    malformed_detection = replace(
        SCENARIOS[2], detections=(replace(SCENARIOS[2].detections[0], start=utc(0).replace(tzinfo=None)),)
    )
    with pytest.raises(EvaluationError, match="invalid_label"):
        evaluate((malformed_detection,))
    assert "PRIVATE-CANARY" not in repr(EvaluationError("PRIVATE-CANARY"))


def test_label_mismatch_is_failure_not_metric_zero():
    wrong = replace(SCENARIOS[0], risks=(replace(SCENARIOS[0].risks[0], level="HIGH"),))
    result = evaluate((wrong,))
    assert result.failed_scenarios == 1
    assert result.invariant_failures == ("login_only:risk",)


def test_microsecond_contract_on_normalized_events():
    from app.detector.brute_force import is_within_window
    from app.correlation.attack_chain import correlate_authentication_transition
    from app.models.schemas import NormalizedEvent

    def event(kind, at):
        return NormalizedEvent(timestamp=at, event_type=kind, source="application",
                               user="synthetic_a", src_ip="192.0.2.10", dst_ip=None,
                               application=None, protocol=None, user_agent=None, raw="")

    start = utc(0)
    boundary = start + timedelta(seconds=60)
    over = boundary + timedelta(microseconds=1)
    assert is_within_window([event("login_failed", start), event("login_failed", boundary)], 60)
    assert not is_within_window([event("login_failed", start), event("login_failed", over)], 60)
    assert correlate_authentication_transition([event("login_failed", start), event("user_login", boundary)])["is_correlated"]
    assert not correlate_authentication_transition([event("login_failed", start), event("user_login", over)])["is_correlated"]


def test_private_fixture_content_not_in_public_output():
    text = _cli("--format", "json").stdout + _cli("--format", "text").stdout
    for canary in ("user=synthetic_a", "user=synthetic_b", "user=synthetic_c", "path=%252e", ".log", "sample_logs/"):
        assert canary not in text


def test_permutation_and_numeric_ip_review_order():
    from app.analyzer.pipeline import load_normalized_logs
    from app.main import _analyze_normalized_logs
    from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
    from app.evaluation.corpus import FIXTURE_ROOT

    logs = load_normalized_logs([{"source": "application", "path": str(FIXTURE_ROOT / "brute_success.log")}])
    first = project_investigation_cases_from_analysis(_analyze_normalized_logs(logs))
    reversed_result = project_investigation_cases_from_analysis(_analyze_normalized_logs(list(reversed(logs))))
    assert first == reversed_result
    ipv6 = deepcopy(logs)
    for event in ipv6:
        event.src_ip = "2001:db8::10"
    both = project_investigation_cases_from_analysis(_analyze_normalized_logs(ipv6 + logs))
    assert [case.row.subject_ip for case in both.cases] == ["192.0.2.10", "2001:db8::10"]


def test_path_patterns_status_and_duplicate_event_contract():
    from app.detector.web_attack import detect_path_traversal
    from app.analyzer.pipeline import load_normalized_logs
    from app.main import _analyze_normalized_logs
    from app.evaluation.corpus import FIXTURE_ROOT

    for value in ("/../manual", "/%2e%2e%2fmanual", "/%252e%252e%252fmanual", "..\\manual"):
        assert detect_path_traversal(value, status_code=200).is_detected
        assert detect_path_traversal(value, status_code=404).is_detected
    assert not detect_path_traversal("/version..txt", query="view=manual", status_code=200).is_detected
    logs = load_normalized_logs([{"source": "application", "path": str(FIXTURE_ROOT / "brute_below.log")}])
    result = _analyze_normalized_logs(logs + [deepcopy(logs[0])])
    subject = result["results"]["192.0.2.10"]
    assert subject["features"]["failure_count"] == 5
    assert subject["detections"]["brute_force"].is_detected


def test_offline_runner_does_not_use_network(monkeypatch):
    import socket

    def blocked(*_args, **_kwargs):
        raise AssertionError("network access forbidden")

    monkeypatch.setattr(socket, "create_connection", blocked)
    assert evaluate((SCENARIOS[0],)).passed_scenarios == 1


def test_cross_subject_same_account_does_not_create_per_subject_relation():
    from app.main import _analyze_normalized_logs
    from app.models.schemas import NormalizedEvent

    def event(kind, subject, at):
        return NormalizedEvent(
            timestamp=at, event_type=kind, source="application", user="synthetic_a",
            src_ip=subject, dst_ip=None, application=None, protocol=None,
            user_agent=None, raw="",
        )

    analysis = _analyze_normalized_logs([
        event("login_failed", "192.0.2.10", utc(0)),
        event("user_login", "2001:db8::10", utc(20)),
    ])
    assert set(analysis["results"]) == {"192.0.2.10", "2001:db8::10"}
    assert all(
        not subject["correlation"]["authentication"]["is_correlated"]
        for subject in analysis["results"].values()
    )


def test_parser_bad_timestamp_and_http_5xx_are_bounded_observations():
    from app.parser.auth_log import parse_auth_log
    from app.detector.web_attack import detect_path_traversal
    from app.parser.time_utils import normalize_to_utc

    with pytest.raises(ValueError):
        parse_auth_log("invalid-date 09:00:00 INFO login_failed user=synthetic_a ip=192.0.2.10", "Asia/Seoul")
    with pytest.raises(ValueError):
        normalize_to_utc(utc(0).replace(tzinfo=None))
    observation = detect_path_traversal("/../manual", status_code=503)
    assert observation.is_detected
    assert any(item.type == "http_status_code" and item.value == 503 for item in observation.evidence)


def test_spray_account_membership_not_promoted_to_case():
    from app.evaluation.corpus import FIXTURE_ROOT
    from app.main import analyze
    from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis

    result = analyze([{"source": "application", "path": str(FIXTURE_ROOT / "spray_success.log")}])
    projection = project_investigation_cases_from_analysis(result)
    assert [case.rule_code for case in projection.cases] == ["CASE-AUTH-TRANSITION-01"]
    assert {item.display_type for item in projection.independent_observations} == {
        "Password Spraying-like", "Password Spraying-like → Successful Login"
    }
