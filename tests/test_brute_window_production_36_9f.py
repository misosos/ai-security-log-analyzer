"""Brute sliding-window Production 계약과 전체 분석 경로 회귀."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import detect_attacks, load_normalized_logs
from app.api import create_app
from app.detector.brute_force import (
    brute_evidence_matches_context,
    select_brute_window_contexts,
    summarize_ip_failures,
)
from app.correlation.attack_chain import correlate_brute_force_to_success
from app.evaluation.brute_window_evaluation import (
    _parse_scenario,
    load_manifest,
)
from app.evaluation.brute_window_policy import evaluate_candidate_policies
from app.detector.password_spray import detect_password_spray
from app.main import analyze_with_source_role_snapshot
from app.models.schemas import DetectionResult, NormalizedEvent


ROOT = Path(__file__).resolve().parents[1]
BURST = ROOT / "sample_logs/detector_accuracy/bf_burst_with_late_noise.log"
LATE_SUCCESS = ROOT / "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log"
SUBJECT = "198.51.100.21"
ACCOUNT = "synthetic_user_a"


def _run(path=LATE_SUCCESS):
    return analyze_with_source_role_snapshot((
        {"source": "application", "path": str(path)},
    ))


def _failure(timestamp, *, user=ACCOUNT, ip=SUBJECT):
    return NormalizedEvent(
        timestamp=timestamp,
        event_type="login_failed",
        source="application",
        user=user,
        src_ip=ip,
        dst_ip=None,
        application="synthetic-auth",
        protocol=None,
        user_agent=None,
        raw="synthetic",
    )


def test_late_noise_brute_window_is_detected_without_changing_full_ip_features():
    events = load_normalized_logs([{"source": "application", "path": str(BURST)}])
    results = detect_attacks(events)
    result = results["198.51.100.23"]
    assert result["detections"]["brute_force"].is_detected is True
    assert result["features"]["failure_count"] == 6
    assert result["features"]["window_seconds"] == 70
    assert result["features"]["within_window"] is False
    evidence = result["detections"]["brute_force"].evidence
    assert next(item.value for item in evidence if item.type == "multiple_login_failures") == 5
    assert next(item.value for item in evidence if item.type == "failures_within_short_window") == 20


def test_private_context_reaches_real_case_adapter_and_selected_window_correlation():
    run = _run()
    analysis = run.analysis
    result = analysis["results"][SUBJECT]
    assert result["detections"]["brute_force"].is_detected is True
    context = run.brute_window_contexts[SUBJECT]
    assert context.failure_count == 5
    assert len(context.member_events) == 5
    assert result["features"]["failure_count"] == 6
    assert result["features"]["window_seconds"] == 70
    relation = result["correlation"]["brute_force_to_success"]
    assert relation["is_correlated"] is True
    assert relation["failure_timestamp"] == context.end_utc
    assert relation["time_delta_seconds"] == 60
    projection = project_investigation_cases_from_analysis(run)
    assert projection.summary.case_count >= 1


def test_production_selector_matches_candidate_c_for_all_24_scenarios():
    root = ROOT / "sample_logs/brute_window_evaluation"
    manifest = load_manifest()
    assert len(manifest) == 24
    for scenario in manifest:
        events = _parse_scenario(scenario, root)
        candidate = evaluate_candidate_policies(events, scenario["subject"])["per_account"]
        production = select_brute_window_contexts(events).get(scenario["subject"])
        assert (production is not None) is candidate.detected, scenario["id"]
        if production is not None:
            assert production.failure_count == candidate.window.failure_count, scenario["id"]
            assert production.start_utc.isoformat().replace("+00:00", "Z") == candidate.window.start_time, scenario["id"]
            assert production.end_utc.isoformat().replace("+00:00", "Z") == candidate.window.end_time, scenario["id"]
            assert production.target_account == candidate.window.target_account, scenario["id"]


def test_sliding_evidence_without_private_context_remains_rejected():
    run = _run()
    analysis = run.analysis
    result = analysis["results"][SUBJECT]
    result["detections"]["brute_force"] = DetectionResult(
        True, "brute_force", [
            type(result["detections"]["brute_force"].evidence[0])(
                "multiple_login_failures", 5, "brute_force_detector",
                time_range=(run.brute_window_contexts[SUBJECT].start_utc,
                            run.brute_window_contexts[SUBJECT].end_utc),
            ),
            type(result["detections"]["brute_force"].evidence[1])(
                "single_target_user", 1, "brute_force_detector",
            ),
            type(result["detections"]["brute_force"].evidence[2])(
                "failures_within_short_window", 20, "brute_force_detector",
            ),
        ],
    )
    from app.analyzer.incident_case_adapter import IncidentCaseAdapterError

    with pytest.raises(IncidentCaseAdapterError):
        project_investigation_cases_from_analysis(analysis)


def test_context_is_bound_to_actual_event_membership_and_evidence():
    first = _run()
    context = first.brute_window_contexts[SUBJECT]
    detection = first.analysis["results"][SUBJECT]["detections"]["brute_force"]
    assert brute_evidence_matches_context(detection, context, subject_ip=SUBJECT)
    second_events = load_normalized_logs([{"source": "application", "path": str(LATE_SUCCESS)}])
    assert correlate_brute_force_to_success(
        second_events,
        detection,
        window_context=context,
        run_owner=first.run_owner,
    )["is_correlated"] is False
    changed = DetectionResult(
        True,
        "brute_force",
        [replace(item, value=6) if item.type == "multiple_login_failures" else item
         for item in detection.evidence],
    )
    assert brute_evidence_matches_context(changed, context, subject_ip=SUBJECT) is False


def test_production_selector_includes_exact_60_seconds_and_excludes_one_microsecond_over():
    base = datetime(2026, 10, 30, tzinfo=timezone.utc)

    def event(second, user=ACCOUNT, ip=SUBJECT):
        return NormalizedEvent(
            timestamp=base + timedelta(seconds=second),
            event_type="login_failed",
            source="application",
            user=user,
            src_ip=ip,
            dst_ip=None,
            application="synthetic-auth",
            protocol=None,
            user_agent=None,
            raw="synthetic",
        )

    exact = [event(second) for second in (0, 15, 30, 45, 60)]
    assert select_brute_window_contexts(exact)[SUBJECT].failure_count == 5
    duplicate = [*exact[:-1], event(60), event(60)]
    # Event identity is unavailable; equal-time rows are retained, not deduplicated.
    assert select_brute_window_contexts(duplicate)[SUBJECT].failure_count == 6
    over = [event(second) for second in (0, 15, 30, 45, 60)]
    over[-1].timestamp += timedelta(microseconds=1)
    assert SUBJECT not in select_brute_window_contexts(over)


def test_naive_timestamps_and_cross_account_ties_fail_closed_in_production():
    base = datetime(2026, 10, 30)
    naive = [_failure(base + timedelta(seconds=second)) for second in (0, 5, 10, 15, 20)]
    assert SUBJECT not in select_brute_window_contexts(naive)
    assert detect_attacks(naive)[SUBJECT]["detections"]["brute_force"].is_detected is False

    tied = load_normalized_logs([{
        "source": "application",
        "path": str(ROOT / "sample_logs/brute_window_evaluation/bf_two_account_tied_windows.log"),
    }])
    result = detect_attacks(tied)[SUBJECT]["detections"]["brute_force"]
    assert result.is_detected is False
    assert result.evidence == []


def test_password_spray_shared_whole_span_contract_is_unchanged():
    events = load_normalized_logs([{"source": "application", "path": str(LATE_SUCCESS)}])
    features = summarize_ip_failures(events)[SUBJECT]
    failures = [event for event in events if event.event_type == "login_failed"]
    result = detect_password_spray(features, failures)
    assert features["failure_count"] == 6
    assert features["unique_target_count"] == 1
    assert features["window_seconds"] == 70
    assert features["within_window"] is False
    assert result.is_detected is False
    assert result.evidence == []


def test_text_api_late_noise_and_success_reach_case_and_report_without_private_data():
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    response = client.post("/api/v1/investigations/text", json={
        "schema_version": 1,
        "source": "application",
        "log_text": LATE_SUCCESS.read_text(encoding="utf-8"),
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["result"]["case_summary"]["case_count"] >= 1
    assert "synthetic_user_a" not in response.text
    assert "INFO login_failed user=" not in response.text
    assert str(LATE_SUCCESS) not in response.text


def test_three_file_api_late_noise_analysis_keeps_closed_public_contract():
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as name:
        paths = [Path(name) / label for label in ("app.log", "ssh.log", "access.log")]
        paths[0].write_bytes(LATE_SUCCESS.read_bytes())
        paths[1].write_bytes((ROOT / "sample_logs/ssh_auth.log").read_bytes())
        paths[2].write_bytes((ROOT / "sample_logs/web_shell.log").read_bytes())
        client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                            client=("127.0.0.1", 50000))
        response = client.post("/api/v1/investigations", files=[
            (field, (path.name, path.read_bytes(), "text/plain"))
            for field, path in zip(
                ("application_file", "ssh_file", "access_file"), paths, strict=True,
            )
        ])
    assert response.status_code == 200, response.text
    assert response.json()["case_summary"]["case_count"] >= 1
    assert "synthetic_user_a" not in response.text
