"""Candidate C와 기존 consumer의 격리된 계약 검증."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.analyzer.pipeline import (
    assess_risk_with_metadata,
    correlate_attacks,
    detect_attacks,
    load_normalized_logs,
)
from app.analyzer.legacy_api_projection import project_legacy_analysis_response
from app.analyzer.html_report import render_investigation_report_html
from app.analyzer.report_projection import build_investigation_report_projection
from app.correlation.attack_chain import correlate_brute_force_to_success
from app.detector.brute_force import summarize_ip_failures
from app.detector.password_spray import detect_password_spray
from app.evaluation.brute_window_policy import evaluate_candidate_policies
from app.models.schemas import DetectionResult, NormalizedEvent

from app.evaluation.brute_window_consumer_contract import (
    BruteWindowContext,
    build_brute_window_context,
    build_window_detection,
    correlate_window_end_to_success,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log"
SUBJECT = "198.51.100.21"
ACCOUNT = "synthetic_user_a"
BASE = datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)


def _fixture_events():
    return load_normalized_logs([{"source": "application", "path": str(FIXTURE)}])


def _context(events=None):
    events = _fixture_events() if events is None else events
    decision = evaluate_candidate_policies(events, SUBJECT)["per_account"]
    return build_brute_window_context(events, SUBJECT, decision)


def _event(second, kind="login_failed", *, user=ACCOUNT, ip=SUBJECT, source="application"):
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
        raw=f"synthetic event {second}",
    )


def _analysis_with_candidate(events, context):
    results = detect_attacks(events)
    results[SUBJECT]["detections"]["brute_force"] = build_window_detection(context)
    analysis = correlate_attacks(events, results)
    analysis = assess_risk_with_metadata(analysis, {})
    return analysis


def _analysis_with_window_correlation(events, context):
    results = detect_attacks(events)
    results[SUBJECT]["detections"]["brute_force"] = build_window_detection(context)
    analysis = correlate_attacks(events, results)
    analysis["results"][SUBJECT]["correlation"]["brute_force_to_success"] = (
        correlate_window_end_to_success(context, events)
    )
    return assess_risk_with_metadata(analysis, {})


def test_candidate_window_context_preserves_full_ip_features_and_exact_membership():
    events = _fixture_events()
    full = summarize_ip_failures(events)[SUBJECT]
    context = _context(events)

    assert full["failure_count"] == 6
    assert full["window_seconds"] == 70
    assert full["within_window"] is False
    assert context.failure_count == 5
    assert context.start_utc == BASE
    assert context.end_utc == BASE + timedelta(seconds=20)
    assert len(context.member_events) == 5
    assert all(item.src_ip == SUBJECT and item.user == ACCOUNT for item in context.member_events)
    assert repr(context).find(ACCOUNT) == -1


def test_context_uses_only_selected_ip_and_account_membership():
    events = [
        *[_event(second) for second in (0, 5, 10, 15, 20)],
        _event(70, user="synthetic_user_other"),
        _event(10, ip="192.0.2.10"),
    ]
    decision = evaluate_candidate_policies(events, SUBJECT)["per_account"]
    context = build_brute_window_context(events, SUBJECT, decision)
    assert context.target_account == ACCOUNT
    assert context.failure_count == 5
    assert all(item.user == ACCOUNT and item.src_ip == SUBJECT for item in context.member_events)


def test_candidate_context_is_supported_for_both_application_and_ssh_inputs():
    for source, fixture in (
        ("application", ROOT / "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log"),
        ("ssh", ROOT / "sample_logs/brute_window_evaluation/bf_ssh_positive.log"),
    ):
        events = load_normalized_logs([{"source": source, "path": str(fixture)}])
        decision = evaluate_candidate_policies(events, SUBJECT)["per_account"]
        context = build_brute_window_context(events, SUBJECT, decision)
        assert context.failure_count == 5
        assert len(context.member_events) == 5
        assert all(item.source == source for item in context.member_events)


def test_tied_accounts_and_missing_user_do_not_create_window_context():
    tied = load_normalized_logs([{
        "source": "application",
        "path": str(ROOT / "sample_logs/brute_window_evaluation/bf_two_account_tied_windows.log"),
    }])
    tied_decision = evaluate_candidate_policies(tied, SUBJECT)["per_account"]
    assert tied_decision.candidate_present is True
    assert tied_decision.detected is False
    with pytest.raises(ValueError, match="invalid_window_context"):
        build_brute_window_context(tied, SUBJECT, tied_decision)

    missing = load_normalized_logs([{
        "source": "application",
        "path": str(ROOT / "sample_logs/brute_window_evaluation/bf_missing_account.log"),
    }])
    missing_decision = evaluate_candidate_policies(missing, SUBJECT)["per_account"]
    assert missing_decision.detected is False
    with pytest.raises(ValueError, match="invalid_window_context"):
        build_brute_window_context(missing, SUBJECT, missing_decision)


def test_actual_case_adapter_rejects_window_evidence_against_full_ip_features():
    events = _fixture_events()
    context = _context(events)
    analysis = _analysis_with_candidate(events, context)
    features = analysis["results"][SUBJECT]["features"]
    assert (features["failure_count"], features["window_seconds"]) == (6, 70)

    # 현재 adapter가 전체 feature와 선택 window evidence를 같은 범위로
    # 요구하는 계약 충돌을 실제 공개 adapter 경계에서 재현한다.
    with pytest.raises(IncidentCaseAdapterError) as error:
        project_investigation_cases_from_analysis(analysis)
    assert error.value.code == "invalid_detection_contract"
    assert (features["failure_count"], features["window_seconds"]) == (6, 70)


def test_brute_correlation_without_window_context_fails_closed():
    events = _fixture_events()
    result = correlate_brute_force_to_success(
        events,
        DetectionResult(True, "brute_force", []),
    )

    assert result["is_correlated"] is False


def test_shadow_correlation_uses_window_endpoint_not_late_failure():
    events = _fixture_events()
    context = _context(events)
    result = correlate_window_end_to_success(context, events)

    assert result["is_correlated"] is True
    assert result["failure_timestamp"] == context.end_utc
    assert result["success_timestamp"] == BASE + timedelta(seconds=80)
    assert result["time_delta_seconds"] == 60
    assert result["user"] == ACCOUNT
    assert "70초" not in " ".join(result["rationale"])


@pytest.mark.parametrize(
    ("success_second", "expected"),
    [(21, True), (80, True), (81, False), (20, False)],
)
def test_window_endpoint_success_order_and_inclusive_sixty_second_limit(success_second, expected):
    context = _context()
    events = list(context.member_events) + [_event(success_second, "user_login")]
    result = correlate_window_end_to_success(context, events)
    assert result["is_correlated"] is expected
    if expected:
        assert result["failure_timestamp"] == context.end_utc
        assert result["time_delta_seconds"] == success_second - 20


def test_shadow_correlation_requires_same_ip_and_known_account():
    context = _context()
    events = [
        _event(21, "user_login", ip="192.0.2.99"),
        _event(21, "user_login", user="synthetic_user_other"),
        _event(21, "user_login", user=None),
    ]
    assert correlate_window_end_to_success(context, events)["is_correlated"] is False


def test_shadow_correlation_is_order_independent_and_fails_closed_on_tied_successes():
    context = _context()
    unique = _event(21, "user_login")
    first = correlate_window_end_to_success(context, [unique])
    reversed_result = correlate_window_end_to_success(context, [unique, *reversed(context.member_events)])
    assert first == reversed_result

    tied = [_event(21, "user_login", source="application"), _event(21, "user_login", source="ssh")]
    assert correlate_window_end_to_success(context, tied)["is_correlated"] is False


def test_window_correlation_requires_validated_context_and_pattern_completion():
    context = _context()
    during_window = [_event(10, "user_login")]
    endpoint_policy = correlate_window_end_to_success(context, during_window)
    member_closest_policy = correlate_brute_force_to_success(
        [*context.member_events, *during_window],
        DetectionResult(True, "brute_force", []),
    )
    assert endpoint_policy["is_correlated"] is False
    assert member_closest_policy["is_correlated"] is False


def test_exact_duplicate_success_is_ambiguous_without_ingestion_identity():
    context = _context()
    duplicate = _event(21, "user_login")
    assert correlate_window_end_to_success(context, [duplicate, replace(duplicate)])["is_correlated"] is False


def test_shadow_contract_rejects_membership_count_or_endpoint_mismatch():
    events = _fixture_events()
    context = _context(events)
    full_decision = evaluate_candidate_policies(events, SUBJECT)["per_account"]
    with pytest.raises(ValueError, match="invalid_window_context"):
        build_brute_window_context(events[:-3], SUBJECT, full_decision)

    wrong_endpoint = replace(context, end_utc=context.end_utc + timedelta(seconds=1))
    with pytest.raises(ValueError, match="invalid_window_context"):
        build_window_detection(wrong_endpoint)


def test_candidate_risk_uses_overall_statistics_without_rewriting_them():
    events = _fixture_events()
    context = _context(events)
    analysis = _analysis_with_candidate(events, context)
    result = analysis["results"][SUBJECT]

    assert result["features"]["failure_count"] == 6
    assert result["features"]["window_seconds"] == 70
    assert result["risk_factors"]["likelihood"]["failure_count"] == 6
    assert result["risk_factors"]["likelihood"]["time_window"] == 70
    assert result["risk_factors"]["likelihood"]["signals"]["detection"]["level"] != "LOW"
    rationale = "".join(result["risk_factors"]["likelihood"]["signals"]["temporal"]["rationale"])
    assert "70.0초" in rationale


def test_risk_separates_candidate_window_rationale_from_full_ip_signal_values():
    events = _fixture_events()
    context = _context(events)
    current = _analysis_with_candidate(events, context)["results"][SUBJECT]
    corrected = _analysis_with_window_correlation(events, context)["results"][SUBJECT]

    assert current["correlation"]["brute_force_to_success"]["failure_timestamp"] == BASE + timedelta(seconds=20)
    assert corrected["correlation"]["brute_force_to_success"]["failure_timestamp"] == BASE + timedelta(seconds=20)
    assert corrected["correlation"]["brute_force_to_success"]["time_delta_seconds"] == 60
    assert corrected["risk_factors"]["likelihood"]["failure_count"] == 6
    assert corrected["risk_factors"]["likelihood"]["time_window"] == 70
    assert corrected["risk_factors"]["likelihood"]["signals"]["volume"]["rationale"] == "IP 전체에서 인증 실패가 6회 관찰됨"
    assert "선택된 반복 실패 창에서 인증 실패 5회" in " ".join(corrected["risk_factors"]["likelihood"]["rationale"])
    assert "선택된 반복 실패 창의 길이는 20.0초" in " ".join(corrected["risk_factors"]["likelihood"]["rationale"])
    assert "70.0초" in corrected["risk_factors"]["likelihood"]["signals"]["temporal"]["rationale"]


def test_candidate_public_legacy_projection_does_not_expose_account_canary():
    events = _fixture_events()
    context = _context(events)
    analysis = _analysis_with_candidate(events, context)
    public = project_legacy_analysis_response(analysis, total_sources=1)
    serialized = public.model_dump_json()
    assert ACCOUNT not in serialized
    assert "multiple_login_failures" not in serialized


def test_report_projection_preserves_window_evidence_and_redacts_account():
    events = _fixture_events()
    context = _context(events)
    analysis = _analysis_with_candidate(events, context)
    projection = build_investigation_report_projection(analysis)
    subject = projection.subjects[0]
    brute = next(item for item in subject.detections if item.detection_type == "brute_force")
    assert brute.evidence.failed_attempt_count == 5
    assert brute.evidence.target_account_count == 1
    assert brute.evidence.time_window_seconds == 20
    html = render_investigation_report_html(projection)
    assert ACCOUNT not in html


@pytest.mark.parametrize(
    ("seconds", "users", "expected"),
    [
        ([0, 10, 20, 60], ["synthetic_user_a", "synthetic_user_b", "synthetic_user_c", "synthetic_user_a"], True),
        ([0, 10, 20, 61], ["synthetic_user_a", "synthetic_user_b", "synthetic_user_c", "synthetic_user_a"], False),
        ([0, 10, 20, 30], ["synthetic_user_a", "synthetic_user_b", "synthetic_user_c", "synthetic_user_a"], True),
    ],
)
def test_password_spray_whole_ip_contract_stays_separate(seconds, users, expected):
    events = [_event(second, user=user) for second, user in zip(seconds, users)]
    features = summarize_ip_failures(events)[SUBJECT]
    before = dict(features)
    result = detect_password_spray(features, events)
    assert result.is_detected is expected
    assert features == before
    assert features["failure_count"] == 4
    assert features["unique_target_count"] == 3


def test_password_spray_late_noise_mixed_ip_missing_user_and_duplicates_are_whole_span():
    mixed_accounts = [
        _event(0, user="synthetic_user_a"),
        _event(5, user="synthetic_user_b"),
        _event(10, user="synthetic_user_c"),
        _event(15, user="synthetic_user_a"),
        _event(70, user="synthetic_user_a"),
    ]
    features = summarize_ip_failures(mixed_accounts)[SUBJECT]
    assert features["failure_count"] == 5
    assert features["unique_target_count"] == 3
    assert features["window_seconds"] == 70
    assert detect_password_spray(features, mixed_accounts).is_detected is False

    split_ips = [_event(second, user=user, ip=ip) for second, user, ip in [
        (0, "synthetic_user_a", SUBJECT),
        (5, "synthetic_user_b", SUBJECT),
        (10, "synthetic_user_c", "192.0.2.7"),
        (15, "synthetic_user_a", SUBJECT),
    ]]
    split_features = summarize_ip_failures(split_ips)[SUBJECT]
    assert split_features["failure_count"] == 3
    assert detect_password_spray(split_features, [event for event in split_ips if event.src_ip == SUBJECT]).is_detected is False

    with_missing = [
        _event(0, user="synthetic_user_a"),
        _event(5, user="synthetic_user_b"),
        _event(10, user="synthetic_user_c"),
        _event(15, user=None),
    ]
    missing_features = summarize_ip_failures(with_missing)[SUBJECT]
    assert missing_features["failure_count"] == 4
    assert missing_features["unique_target_count"] == 3
    assert detect_password_spray(missing_features, with_missing).is_detected is True

    duplicates = [
        _event(0, user="synthetic_user_a"),
        _event(5, user="synthetic_user_b"),
        _event(10, user="synthetic_user_c"),
        _event(10, user="synthetic_user_c"),
    ]
    duplicate_features = summarize_ip_failures(duplicates)[SUBJECT]
    assert duplicate_features["failure_count"] == 4
    assert detect_password_spray(duplicate_features, duplicates).is_detected is True


def test_late_noise_candidate_detection_coexists_with_unchanged_spray():
    events = _fixture_events()
    results = detect_attacks(events)
    brute = results[SUBJECT]["detections"]["brute_force"]
    assert brute.is_detected is True
    assert next(item.value for item in brute.evidence if item.type == "multiple_login_failures") == 5
    assert next(item.value for item in brute.evidence if item.type == "failures_within_short_window") == 20
    assert results[SUBJECT]["detections"]["password_spray"].is_detected is False
    assert results[SUBJECT]["features"]["failure_count"] == 6
    assert results[SUBJECT]["features"]["window_seconds"] == 70
