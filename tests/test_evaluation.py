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
    assert (result.scenario_count, result.passed_scenarios, result.failed_scenarios) == (43, 43, 0)
    assert (result.parser_summary.input_lines, result.parser_summary.parsed) == (134, 129)
    assert (result.parser_summary.ignored, result.parser_summary.failed) == (2, 3)
    assert (result.parser_summary.unexpected_parse_count, result.parser_summary.unexpected_rejection_count) == (0, 0)
    assert (result.ssh_scenario_count, result.excluded_ambiguous_scenarios) == (13, 1)
    assert result.excluded_reasons == ("automation_ambiguous:authorization_context_unavailable",)
    assert [(m.detection_type, m.tp, m.fp, m.fn, m.tn, m.support) for m in result.detection_metrics] == [
        ("brute_force", 11, 0, 0, 22, 11),
        ("password_spraying_like", 2, 0, 0, 31, 2),
        ("path_traversal", 2, 0, 0, 31, 2),
    ]
    assert [(m.relation_type, m.tp, m.fp, m.fn) for m in result.correlation_metrics] == [
        ("failed_to_successful_login", 6, 0, 0),
        ("brute_force_to_successful_login", 3, 0, 0),
        ("password_spray_to_successful_login", 1, 0, 0),
    ]
    assert (result.risk_summary.matched_scenarios, result.risk_summary.applicable_scenarios) == (34, 34)
    assert (result.case_summary.matched_scenarios, result.case_summary.applicable_scenarios) == (34, 34)
    assert [item.id for item in SCENARIOS[:21]] == [
        "login_only", "brute_below", "brute_exact", "brute_over_window",
        "brute_success", "brute_other_account", "brute_success_late",
        "spray_exact", "spray_success", "spray_below_accounts",
        "spray_over_window", "auth_transition", "auth_transition_late",
        "traversal", "normal_web", "brute_above", "low_failures",
        "spray_below_failures", "success_before", "traversal_raw",
        "traversal_false_like",
    ]


def test_cli_stability_filter_and_bounded_error():
    one = _cli("--format", "json")
    two = _cli("--format", "json", tz="Pacific/Honolulu")
    assert one.returncode == two.returncode == 0
    assert one.stdout == two.stdout
    parsed = json.loads(one.stdout)
    assert parsed["scenario_count"] == 43
    assert not parsed["invariant_failures"]
    filtered = _cli("--format", "json", "--scenario", "brute_success")
    assert filtered.returncode == 0
    assert json.loads(filtered.stdout)["scenario_count"] == 1
    invalid = _cli("--scenario", "PRIVATE-CANARY")
    assert invalid.returncode == 2
    assert invalid.stderr.strip() == "unknown_scenario"
    assert "PRIVATE-CANARY" not in invalid.stderr


def test_text_and_json_metrics_report_the_same_counts():
    text_result = _cli("--format", "text")
    json_result = _cli("--format", "json")
    assert text_result.returncode == json_result.returncode == 0
    lines = text_result.stdout.splitlines()
    summary = json.loads(json_result.stdout)
    assert lines[0] == "synthetic_boundary_corpus: 43/43 scenarios passed"
    for metric in summary["detection_metrics"]:
        line = next(line for line in lines if line.startswith(f"detection {metric['detection_type']}:"))
        for key, label in (("tp", "TP"), ("fp", "FP"), ("fn", "FN"),
                           ("tn", "TN"), ("support", "support")):
            assert f"{label}={metric[key]}" in line
    for metric in summary["correlation_metrics"]:
        line = next(line for line in lines if line.startswith(f"correlation {metric['relation_type']}:"))
        for key, label in (("tp", "TP"), ("fp", "FP"), ("fn", "FN")):
            assert f"{label}={metric[key]}" in line
    parser = summary["parser_summary"]
    assert (f"parser: {parser['parsed']}/{parser['input_lines']} parsed; "
            f"ignored={parser['ignored']}; rejected={parser['failed']}") in text_result.stdout


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
    for canary in ("user=synthetic_a", "user=synthetic_b", "user=synthetic_c", "not-an-ip", "path=%252e", ".log", "sample_logs/"):
        assert canary not in text


def test_parser_only_and_ambiguous_are_not_confusion_labels():
    ids = {item.id: item for item in SCENARIOS}
    parser_only = evaluate((ids["ssh_unsupported"], ids["ssh_malformed"], ids["access_ignored"]))
    assert (parser_only.parser_summary.parsed, parser_only.parser_summary.ignored,
            parser_only.parser_summary.failed) == (1, 1, 1)
    assert parser_only.risk_summary.applicable_scenarios == 0
    assert all(metric.precision == "not_applicable" for metric in parser_only.detection_metrics)
    ambiguous = evaluate((ids["automation_ambiguous"],))
    assert ambiguous.passed_scenarios == 1
    assert ambiguous.excluded_ambiguous_scenarios == 1
    assert all(metric.tp == metric.fp == metric.fn == metric.tn == 0 for metric in ambiguous.detection_metrics)
    assert ambiguous.risk_summary.applicable_scenarios == 1


def test_parser_unexpected_parse_and_rejection_count_by_line():
    ids = {item.id: item for item in SCENARIOS}
    ignored_label = replace(
        ids["ssh_login_only"], label_scope="parser_only", risks=(),
        parser=replace(
            ids["ssh_login_only"].parser, parsed=0, ignored=1,
            event_types=(), first_timestamp=None, last_timestamp=None,
            account_present=(), http_methods=(), http_statuses=(),
            line_dispositions=("ignored",),
        ),
    )
    unexpected_parse = evaluate((ignored_label,))
    assert unexpected_parse.failed_scenarios == 1
    assert unexpected_parse.parser_summary.unexpected_parse_count == 1
    parsed_label = replace(
        ids["access_ignored"],
        parser=replace(
            ids["access_ignored"].parser, parsed=1, ignored=0,
            event_types=("http_request",), first_timestamp=utc(0),
            last_timestamp=utc(0), account_present=(False,),
            http_methods=("GET",), http_statuses=(200,),
            line_dispositions=("parsed",),
        ),
    )
    unexpected_rejection = evaluate((parsed_label,))
    assert unexpected_rejection.failed_scenarios == 1
    assert unexpected_rejection.parser_summary.unexpected_rejection_count == 1


def test_ssh_multi_success_pipeline_permutations_preserve_endpoint_and_timeline():
    from app.analyzer.pipeline import load_normalized_logs
    from app.main import _analyze_normalized_logs
    from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
    from app.evaluation.corpus import FIXTURE_ROOT

    logs = load_normalized_logs([{"source": "ssh", "path": str(FIXTURE_ROOT / "ssh_multi_success.log")}])
    assert len(logs) == 7
    snapshots = []
    for arrangement in (logs, list(reversed(logs)), logs[:5] + [logs[6], logs[5]]):
        result = _analyze_normalized_logs(arrangement)
        subject = result["results"]["192.0.2.10"]
        relation = subject["correlation"]["authentication"]
        case = project_investigation_cases_from_analysis(result).cases[0]
        snapshots.append((
            relation["failure_timestamp"], relation["success_timestamp"],
            relation["time_delta_seconds"], subject["risk_level"],
            case.rule_code, case.row.observation_count,
            case.row.supporting_relation_count, case.timeline_entries,
        ))
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert snapshots[0][1] == utc(50)


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
