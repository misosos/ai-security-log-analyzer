"""Read-only characterization of current Spray consumers.

Candidate Window assertions here are simulations at existing consumer
boundaries; they do not connect the evaluation candidate to production.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.analyzer.pipeline import (
    assess_risk_with_metadata,
    correlate_attacks,
    detect_attacks,
)
from app.analyzer.report_projection import (
    PasswordSprayingLikeEvidenceProjection,
    build_investigation_report_projection,
)
from app.correlation.attack_chain import correlate_password_spray_to_success
from app.evaluation.spray_scope_policy import evaluate_sliding_ip_window
from app.models.schemas import DetectionResult, Evidence, NormalizedEvent


BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)
IP = "198.51.100.77"


def event(second, kind="login_failed", user="user-a"):
    return NormalizedEvent(
        timestamp=BASE + timedelta(seconds=second),
        event_type=kind,
        source="application",
        user=user,
        src_ip=IP,
        dst_ip=None,
        application="synthetic-auth",
        protocol=None,
        user_agent=None,
        raw=f"synthetic-{second}-{kind}-{user}",
    )


def late_noise_events():
    return [
        event(0, user="user-a"),
        event(5, user="user-b"),
        event(10, user="user-c"),
        event(15, user="user-d"),
        event(90, user="user-a"),
        event(95, "user_login", "user-a"),
    ]


def candidate_detection():
    return DetectionResult(
        True,
        "password_spraying_like",
        [
            Evidence(
                "multiple_login_failures", 4, "password_spray_detector",
                time_range=(BASE, BASE + timedelta(seconds=15)),
            ),
            Evidence("multiple_target_users", 4, "password_spray_detector"),
            Evidence("failures_within_short_window", 15.0, "password_spray_detector"),
        ],
    )


def test_current_pipeline_keeps_spray_features_and_evidence_whole_span():
    events = late_noise_events()
    results = detect_attacks(events)
    result = results[IP]

    assert result["features"]["failure_count"] == 5
    assert result["features"]["unique_target_count"] == 4
    assert result["features"]["window_seconds"] == 90
    assert result["features"]["within_window"] is False
    assert result["detections"]["password_spray"].is_detected is False
    assert evaluate_sliding_ip_window(events, (IP,))[IP].detected is True


def test_current_spray_correlation_can_choose_failure_outside_candidate_window():
    events = late_noise_events()
    # Deliberately inject only a candidate DetectionResult at the consumer
    # boundary to characterize current pairing. This is not pipeline wiring.
    relation = correlate_password_spray_to_success(events, candidate_detection())

    assert relation["is_correlated"] is True
    assert relation["user"] == "user-a"
    assert relation["failure_timestamp"] == BASE + timedelta(seconds=90)
    assert relation["success_timestamp"] == BASE + timedelta(seconds=95)
    assert relation["time_delta_seconds"] == 5
    assert relation["failure_timestamp"] > BASE + timedelta(seconds=15)


def test_current_risk_uses_whole_span_predicate_for_candidate_spray():
    events = late_noise_events()
    results = detect_attacks(events)
    results[IP]["detections"]["password_spray"] = candidate_detection()
    analysis = correlate_attacks(events, results)
    analysis = assess_risk_with_metadata(analysis, {})

    likelihood = analysis["results"][IP]["risk_factors"]["likelihood"]
    # The current correlation above uses the 90s failure, so the existing
    # Spray+Success branch fires. Whole-IP feature signals remain 5/4/90.
    assert likelihood["level"] == "HIGH"
    assert analysis["results"][IP]["risk_factors"]["likelihood"]["failure_count"] == 5
    assert analysis["results"][IP]["risk_factors"]["likelihood"]["target_scope"] == 4
    assert analysis["results"][IP]["risk_factors"]["likelihood"]["time_window"] == 90
    assert analysis["results"][IP]["correlation"]["password_spray_to_success"]["failure_timestamp"] == BASE + timedelta(seconds=90)


def test_case_adapter_rejects_candidate_window_against_whole_span_features():
    events = late_noise_events()
    analysis = correlate_attacks(events, detect_attacks(events))
    analysis["results"][IP]["detections"]["password_spray"] = candidate_detection()
    analysis = assess_risk_with_metadata(analysis, {})

    with pytest.raises(IncidentCaseAdapterError) as caught:
        project_investigation_cases_from_analysis(analysis)
    assert caught.value.code == "invalid_detection_contract"


def test_report_projection_keeps_scalar_spray_evidence_only():
    events = late_noise_events()
    analysis = correlate_attacks(events, detect_attacks(events))
    analysis["results"][IP]["detections"]["password_spray"] = candidate_detection()
    analysis = assess_risk_with_metadata(analysis, {})
    projection = build_investigation_report_projection(analysis)
    spray = next(
        detection
        for subject in projection.subjects
        for detection in subject.detections
        if detection.detection_type == "password_spraying_like"
    )

    assert spray.evidence == PasswordSprayingLikeEvidenceProjection(4, 4, 15.0)
    assert set(PasswordSprayingLikeEvidenceProjection.__dataclass_fields__) == {
        "failed_attempt_count",
        "target_account_count",
        "time_window_seconds",
    }
