import builtins
import copy
from dataclasses import FrozenInstanceError, fields, is_dataclass
import json
import math
import os
import random
import socket
import time

import pytest

from app.analyzer.llm import build_llm_input
from app.analyzer.report import print_analysis_result
from app.analyzer.report_projection import (
    AssessmentDimensionProjection,
    BruteForceEvidenceProjection,
    CorrelationDisplayItem,
    DetectionDisplayItem,
    FixedNextStepItem,
    InterpretationLimitationItem,
    InvestigationReportProjection,
    InvestigationReportProjectionError,
    InvestigationSubjectRow,
    LinuxAuditAggregateProjection,
    PasswordSprayingLikeEvidenceProjection,
    PathTraversalEvidenceProjection,
    ReportSummaryProjection,
    RiskAssessmentProjection,
    build_investigation_report_projection,
)
from app.api import build_analysis_response
from app.analyzer.legacy_api_projection import LegacyAnalysisProjectionError
from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
)
from app.models.schemas import DetectionResult, Evidence


PRIVATE = "PRIVATE-CANARY-account-query-token-path-digest"


def empty_detection():
    return DetectionResult(False, None, [])


def brute_force_detection(*, window=16.0):
    return DetectionResult(
        True,
        "brute_force",
        [
            Evidence(
                "multiple_login_failures",
                5,
                "brute_force_detector",
            ),
            Evidence("single_target_user", 1, "brute_force_detector"),
            Evidence(
                "failures_within_short_window",
                window,
                "brute_force_detector",
            ),
        ],
    )


def password_spraying_detection(*, window=6):
    return DetectionResult(
        True,
        "password_spraying_like",
        [
            Evidence(
                "multiple_login_failures",
                4,
                "password_spray_detector",
            ),
            Evidence(
                "multiple_target_users",
                4,
                "password_spray_detector",
            ),
            Evidence(
                "failures_within_short_window",
                window,
                "password_spray_detector",
            ),
        ],
    )


def path_traversal_detection(*, query=PRIVATE):
    return DetectionResult(
        True,
        "path_traversal",
        [
            Evidence(
                "url_decoded_path",
                "/download",
                "path_traversal_detector",
            ),
            Evidence("path_pattern", "../", "path_traversal_detector"),
            Evidence(
                "url_decoded_query",
                query,
                "path_traversal_detector",
            ),
            Evidence("http_method", "GET", "path_traversal_detector"),
            Evidence("http_status_code", 200, "path_traversal_detector"),
            Evidence("http_response_size", 2048, "path_traversal_detector"),
        ],
    )


def no_correlation():
    return {"is_correlated": False, "type": None, "user": None, "rationale": []}


def supported_correlation(correlation_type, account, delta=2.5):
    return {
        "is_correlated": True,
        "type": correlation_type,
        "user": account,
        "failure_timestamp": PRIVATE,
        "success_timestamp": PRIVATE,
        "time_delta_seconds": delta,
        "rationale": [PRIVATE],
    }


def risk_factors(*, likelihood="LOW", impact="LOW", confidence="LOW"):
    return {
        "likelihood": {
            "level": likelihood,
            "rationale": [
                "공격으로 판단할 만큼 강한 인증 이상 징후가 확인되지 않음"
            ],
            "signals": {"private": PRIVATE},
            "failure_count": 0,
            "target_scope": 0,
            "time_window": 0,
        },
        "impact": {
            "level": impact,
            "rationale": ["영향도를 높일 수 있는 대상 중요도 정보가 확인되지 않음"],
            "basis": {"private": PRIVATE},
            "privileged_account_targeted": False,
            "authentication_success": False,
        },
        "confidence": {
            "level": confidence,
            "rationale": ["판단을 뒷받침할 충분한 공격 증거가 확인되지 않음"],
        },
        "evidence": [{"raw": PRIVATE}],
        "account_context": {PRIVATE: {"credential": PRIVATE}},
    }


def subject_result(
    *,
    risk="LOW",
    likelihood="LOW",
    impact="LOW",
    confidence="LOW",
    brute=None,
    spray=None,
    path=None,
    authentication=None,
    brute_to_success=None,
    post_authentication=None,
    spray_to_success=None,
):
    return {
        "features": {"raw_log": PRIVATE, "source_path": PRIVATE},
        "detections": {
            "brute_force": brute or empty_detection(),
            "password_spray": spray or empty_detection(),
            "path_traversal": path or empty_detection(),
        },
        "correlation": {
            "authentication": authentication or no_correlation(),
            "post_authentication": post_authentication or no_correlation(),
            "brute_force_to_success": brute_to_success or no_correlation(),
            "password_spray_to_success": spray_to_success or no_correlation(),
        },
        "risk_factors": risk_factors(
            likelihood=likelihood,
            impact=impact,
            confidence=confidence,
        ),
        "risk_level": risk,
    }


def analysis(results=None):
    return {
        "results": {} if results is None else results,
        "global_correlation": {
            "raw": PRIVATE,
            "source_instance": PRIVATE,
            "event_id": PRIVATE,
        },
    }


def scalar_tree(value):
    if is_dataclass(value):
        return {
            field.name: scalar_tree(getattr(value, field.name))
            for field in fields(value)
        }
    if type(value) is tuple:
        return [scalar_tree(item) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise AssertionError("projection contains a non-scalar contract value")


def test_projection_dataclasses_are_frozen_and_have_exact_field_allowlists():
    expected = {
        ReportSummaryProjection: (
            "analyzed_subject_count",
            "high_risk_subject_count",
            "medium_risk_subject_count",
            "low_risk_subject_count",
            "supported_detection_observation_count",
            "supported_correlation_observation_count",
            "linux_audit_process_observation_count",
            "shared_memory_review_observation_count",
            "session_process_co_observation_count",
        ),
        BruteForceEvidenceProjection: (
            "failed_attempt_count",
            "target_account_count",
            "time_window_seconds",
        ),
        PasswordSprayingLikeEvidenceProjection: (
            "failed_attempt_count",
            "target_account_count",
            "time_window_seconds",
        ),
        PathTraversalEvidenceProjection: (
            "matched_pattern",
            "http_method",
            "response_status",
            "response_size_bytes",
        ),
        DetectionDisplayItem: ("detection_type", "display_name", "evidence"),
        CorrelationDisplayItem: (
            "correlation_type",
            "display_name",
            "account_alias",
            "time_delta_seconds",
        ),
        AssessmentDimensionProjection: ("level", "rationale"),
        RiskAssessmentProjection: (
            "risk_level",
            "likelihood",
            "impact",
            "confidence",
        ),
        InterpretationLimitationItem: ("limitation_id", "text"),
        FixedNextStepItem: ("next_step_id", "text"),
        LinuxAuditAggregateProjection: (
            "process_observation_count",
            "process_outcome_success_count",
            "process_outcome_failure_count",
            "process_outcome_unknown_count",
            "process_argv_complete_count",
            "process_argv_incomplete_count",
            "process_path_complete_count",
            "process_path_incomplete_count",
            "shared_memory_review_observation_count",
            "session_process_co_observation_count",
            "session_process_observation_count",
            "session_process_outcome_success_count",
            "session_process_outcome_failure_count",
            "session_process_outcome_unknown_count",
            "session_shared_memory_observation_count",
            "sessions_with_shared_memory_observation_count",
        ),
        InvestigationSubjectRow: (
            "review_order",
            "subject_ip",
            "primary_detection_display_name",
            "notable_correlation_display_name",
            "review_reason",
            "detections",
            "correlations",
            "risk_assessment",
            "unsupported_detection_observed",
            "unsupported_correlation_observed",
            "limitations",
            "next_steps",
        ),
        InvestigationReportProjection: (
            "schema_version",
            "classification",
            "summary",
            "subjects",
            "linux_audit",
        ),
    }
    for model, names in expected.items():
        assert tuple(field.name for field in fields(model)) == names
        assert model.__dataclass_params__.frozen is True

    projection = build_investigation_report_projection(analysis())
    with pytest.raises(FrozenInstanceError):
        projection.schema_version = "changed"


def test_empty_analysis_has_explicit_zero_counts_and_no_linux_audit_section():
    projection = build_investigation_report_projection(analysis())

    assert projection == InvestigationReportProjection(
        schema_version="1",
        classification="Sensitive — Security Investigation Data",
        summary=ReportSummaryProjection(0, 0, 0, 0, 0, 0, None, None, None),
        subjects=(),
        linux_audit=None,
    )


def test_supported_detection_mappings_typed_values_units_and_query_exclusion():
    projection = build_investigation_report_projection(analysis({
        "192.0.2.3": subject_result(path=path_traversal_detection()),
        "192.0.2.2": subject_result(spray=password_spraying_detection()),
        "192.0.2.1": subject_result(brute=brute_force_detection(window=0.0)),
    }))
    by_ip = {subject.subject_ip: subject for subject in projection.subjects}

    brute = by_ip["192.0.2.1"].detections[0]
    assert (brute.detection_type, brute.display_name) == (
        "brute_force",
        "Brute Force",
    )
    assert brute.evidence == BruteForceEvidenceProjection(5, 1, 0.0)

    spray = by_ip["192.0.2.2"].detections[0]
    assert (spray.detection_type, spray.display_name) == (
        "password_spraying_like",
        "Password Spraying-like",
    )
    assert spray.evidence == PasswordSprayingLikeEvidenceProjection(4, 4, 6)

    traversal = by_ip["192.0.2.3"].detections[0]
    assert (traversal.detection_type, traversal.display_name) == (
        "path_traversal",
        "Path Traversal",
    )
    assert traversal.evidence == PathTraversalEvidenceProjection(
        matched_pattern="../",
        http_method="GET",
        response_status=200,
        response_size_bytes=2048,
    )
    assert "query" not in {field.name for field in fields(traversal.evidence)}
    assert PRIVATE not in repr(projection)


def test_evidence_is_resolved_by_type_and_input_permutations_are_equal():
    first = analysis({
        "192.0.2.1": subject_result(brute=brute_force_detection()),
        "192.0.2.2": subject_result(path=path_traversal_detection()),
    })
    second = copy.deepcopy(first)
    second["results"] = dict(reversed(tuple(second["results"].items())))
    for result in second["results"].values():
        result["detections"] = dict(reversed(tuple(result["detections"].items())))
        result["correlation"] = dict(reversed(tuple(result["correlation"].items())))
        for detection in result["detections"].values():
            detection.evidence.reverse()

    assert build_investigation_report_projection(first) == (
        build_investigation_report_projection(second)
    )


def test_supported_correlations_use_global_deterministic_account_aliases():
    projection = build_investigation_report_projection(analysis({
        "192.0.2.3": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", "가"
            ),
        ),
        "192.0.2.2": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", "é"
            ),
        ),
        "192.0.2.1": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", "z"
            ),
            brute_to_success=supported_correlation(
                "brute_force_to_successful_login", "z", 0
            ),
        ),
    }))
    by_ip = {subject.subject_ip: subject for subject in projection.subjects}

    assert [item.account_alias for item in by_ip["192.0.2.1"].correlations] == [
        "Account 1",
        "Account 1",
    ]
    assert by_ip["192.0.2.2"].correlations[0].account_alias == "Account 2"
    assert by_ip["192.0.2.3"].correlations[0].account_alias == "Account 3"
    assert {
        item.display_name
        for subject in projection.subjects
        for item in subject.correlations
    } == {
        "Failed Login → Successful Login",
        "Brute Force → Successful Login",
    }


def test_account_aliases_are_independent_of_subject_and_dictionary_order():
    first = analysis({
        "192.0.2.2": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", "é"
            ),
        ),
        "192.0.2.1": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", "z"
            ),
        ),
    })
    second = copy.deepcopy(first)
    second["results"] = dict(reversed(tuple(second["results"].items())))
    for result in second["results"].values():
        result["correlation"] = dict(
            reversed(tuple(result["correlation"].items()))
        )

    assert build_investigation_report_projection(first) == (
        build_investigation_report_projection(second)
    )


def test_review_order_uses_risk_correlation_confidence_detection_and_numeric_ip():
    projection = build_investigation_report_projection(analysis({
        "2001:db8::1": subject_result(risk="LOW"),
        "192.0.2.20": subject_result(risk="LOW"),
        "192.0.2.3": subject_result(
            risk="HIGH",
            confidence="HIGH",
            brute=brute_force_detection(),
        ),
        "192.0.2.2": subject_result(
            risk="HIGH",
            confidence="LOW",
            authentication=supported_correlation(
                "failed_to_successful_login", "analyst"
            ),
        ),
        "192.0.2.10": subject_result(
            risk="HIGH",
            confidence="MEDIUM",
            path=path_traversal_detection(query="excluded"),
        ),
        "192.0.2.1": subject_result(
            risk="HIGH",
            confidence="MEDIUM",
            brute=brute_force_detection(),
        ),
    }))

    assert [subject.subject_ip for subject in projection.subjects] == [
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.1",
        "192.0.2.10",
        "192.0.2.20",
        "2001:db8::1",
    ]
    assert [subject.review_order for subject in projection.subjects] == list(
        range(1, 7)
    )


def test_summary_counts_partition_subjects_and_count_supported_observations():
    projection = build_investigation_report_projection(analysis({
        "192.0.2.1": subject_result(
            risk="HIGH",
            brute=brute_force_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", "account"
            ),
        ),
        "192.0.2.2": subject_result(
            risk="MEDIUM", spray=password_spraying_detection()
        ),
        "192.0.2.3": subject_result(risk="LOW"),
    }))
    summary = projection.summary

    assert (
        summary.analyzed_subject_count,
        summary.high_risk_subject_count,
        summary.medium_risk_subject_count,
        summary.low_risk_subject_count,
        summary.supported_detection_observation_count,
        summary.supported_correlation_observation_count,
    ) == (3, 1, 1, 1, 2, 1)
    assert summary.analyzed_subject_count == (
        summary.high_risk_subject_count
        + summary.medium_risk_subject_count
        + summary.low_risk_subject_count
    )


def test_fixed_limitations_and_next_steps_are_stable_and_deduplicated():
    projection = build_investigation_report_projection(analysis({
        "192.0.2.1": subject_result(
            brute=brute_force_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", "account"
            ),
            brute_to_success=supported_correlation(
                "brute_force_to_successful_login", "account"
            ),
        ),
    }))
    subject = projection.subjects[0]

    assert [item.limitation_id for item in subject.limitations] == [
        "detection_not_compromise",
        "correlation_not_causation",
        "successful_login_not_account_compromise",
    ]
    assert [item.next_step_id for item in subject.next_steps] == [
        "review_authentication_failures",
        "review_login_transition",
        "review_brute_force_login_transition",
    ]
    assert len({item.next_step_id for item in subject.next_steps}) == 3
    assert PRIVATE not in repr(subject.next_steps)


def test_fixed_limitation_and_next_step_allowlists_use_approved_korean_text():
    projection = build_investigation_report_projection(analysis({
        "192.0.2.1": subject_result(
            brute=brute_force_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", "account"
            ),
            brute_to_success=supported_correlation(
                "brute_force_to_successful_login", "account"
            ),
        ),
        "192.0.2.2": subject_result(
            spray=password_spraying_detection(),
        ),
        "192.0.2.3": subject_result(
            path=path_traversal_detection(),
        ),
    }))
    limitation_texts = {
        item.limitation_id: item.text
        for subject in projection.subjects
        for item in subject.limitations
    }
    next_step_texts = {
        item.next_step_id: item.text
        for subject in projection.subjects
        for item in subject.next_steps
    }

    assert limitation_texts == {
        "detection_not_compromise": "탐지는 침해 확인을 의미하지 않습니다.",
        "spraying_like_not_credential_reuse": (
            "Password Spraying-like 관찰만으로 동일한 인증정보가 "
            "재사용되었다고 판단할 수 없습니다."
        ),
        "path_traversal_not_file_disclosure": (
            "HTTP 응답과 경로 탐색 패턴만으로 파일 접근 또는 데이터 "
            "노출이 이루어졌다고 판단할 수 없습니다."
        ),
        "correlation_not_causation": (
            "상관관계는 인과관계나 침해의 증거를 의미하지 않습니다."
        ),
        "successful_login_not_account_compromise": (
            "로그인 성공만으로 계정 침해가 발생했다고 판단할 수 없습니다."
        ),
    }
    assert next_step_texts == {
        "review_authentication_failures": (
            "관찰된 시간대의 인증 실패 기록을 검토하고, 해당 활동이 "
            "승인된 출발지 또는 프로세스와 일치하는지 확인하십시오."
        ),
        "review_cross_account_authentication": (
            "관련 계정 별칭의 IdP 인증 기록을 검토하고, 예상된 관리자 "
            "또는 자동화 활동인지 확인하십시오."
        ),
        "review_traversal_response_context": (
            "관찰된 요청에 대한 애플리케이션, 리버스 프록시 및 파일 "
            "접근 텔레메트리를 검토하고, 응답 내용이나 파일 접근이 "
            "기록되었는지 확인하십시오."
        ),
        "review_login_transition": (
            "상관된 로그인에 대한 IdP, MFA, 장치 및 세션 기록을 "
            "검토하고, 예상된 로그인인지 확인하십시오."
        ),
        "review_brute_force_login_transition": (
            "Brute Force 관찰과 상관된 로그인 전후의 인증, MFA, 장치 "
            "및 세션 기록을 검토하십시오."
        ),
    }
    assert PRIVATE not in repr(projection)


def test_unsupported_types_are_omitted_without_invented_guidance():
    result = subject_result()
    result["detections"]["brute_force"] = DetectionResult(
        True, "future_private_detection", [PRIVATE]
    )
    result["correlation"]["authentication"] = {
        "is_correlated": True,
        "type": "future_private_correlation",
        "user": PRIVATE,
        "time_delta_seconds": PRIVATE,
    }

    subject = build_investigation_report_projection(
        analysis({"192.0.2.1": result})
    ).subjects[0]

    assert subject.detections == ()
    assert subject.correlations == ()
    assert subject.unsupported_detection_observed is True
    assert subject.unsupported_correlation_observed is True
    assert subject.next_steps == ()
    assert subject.limitations == ()
    assert PRIVATE not in repr(subject)


@pytest.mark.parametrize("invalid", [True, -1, math.nan, math.inf, -math.inf])
def test_invalid_authentication_time_windows_fail_closed(invalid):
    detection = brute_force_detection(window=invalid)
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "192.0.2.1": subject_result(brute=detection),
        }))


@pytest.mark.parametrize("invalid", [True, -1, math.nan, math.inf, -math.inf])
def test_invalid_correlation_deltas_fail_closed(invalid):
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "192.0.2.1": subject_result(
                authentication=supported_correlation(
                    "failed_to_successful_login", "account", invalid
                ),
            ),
        }))


@pytest.mark.parametrize("invalid", [True, -1])
def test_invalid_path_status_and_size_fail_closed(invalid):
    detection = path_traversal_detection(query="excluded")
    detection.evidence[-1].value = invalid
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "192.0.2.1": subject_result(path=detection),
        }))


def test_malformed_cardinality_type_rationale_ip_and_account_are_bounded():
    malformed_inputs = []

    missing_evidence = brute_force_detection()
    missing_evidence.evidence.pop()
    malformed_inputs.append(analysis({
        "192.0.2.1": subject_result(brute=missing_evidence),
    }))

    wrong_type = brute_force_detection()
    wrong_type.evidence[0].value = True
    malformed_inputs.append(analysis({
        "192.0.2.1": subject_result(brute=wrong_type),
    }))

    unexpected_evidence = brute_force_detection()
    unexpected_evidence.evidence[0].type = "private_unexpected_evidence"
    malformed_inputs.append(analysis({
        "192.0.2.1": subject_result(brute=unexpected_evidence),
    }))

    unknown_rationale = subject_result()
    unknown_rationale["risk_factors"]["impact"]["rationale"] = [PRIVATE]
    malformed_inputs.append(analysis({"192.0.2.1": unknown_rationale}))
    malformed_inputs.append(analysis({PRIVATE: subject_result()}))
    malformed_inputs.append(analysis({
        "192.0.2.1": subject_result(
            authentication=supported_correlation(
                "failed_to_successful_login", f"account\n{PRIVATE}"
            ),
        ),
    }))

    for malformed in malformed_inputs:
        with pytest.raises(InvestigationReportProjectionError) as caught:
            build_investigation_report_projection(malformed)
        assert str(caught.value) == "Investigation report projection failed."
        assert PRIVATE not in str(caught.value)
        assert PRIVATE not in repr(caught.value)


def test_linux_audit_projection_copies_counts_only_and_validates_invariants():
    process = {
        "observation_count": 3,
        "outcome_counts": {"success": 1, "failure": 1, "unknown": 1},
        "argv_completeness_counts": {"complete": 2, "incomplete": 1},
        "path_completeness_counts": {"complete": 1, "incomplete": 2},
    }
    shared = SharedMemoryExecutionReviewSummary(1)
    session = SessionProcessReviewSummary(1, 2, 1, 1, 0, 1, 1)

    projection = build_investigation_report_projection(
        analysis(),
        process_execution_aggregate=process,
        process_detection_summary=shared,
        session_process_review_summary=session,
    )

    assert projection.summary == ReportSummaryProjection(
        0, 0, 0, 0, 0, 0, 3, 1, 1
    )
    assert projection.linux_audit == LinuxAuditAggregateProjection(
        3, 1, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1, 0, 1, 1
    )
    assert all(
        type(getattr(projection.linux_audit, field.name)) is int
        for field in fields(projection.linux_audit)
    )

    invalid = copy.deepcopy(process)
    invalid["outcome_counts"]["success"] = 2
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(
            analysis(), process_execution_aggregate=invalid
        )


def test_private_canaries_are_absent_from_projection_repr_and_json_safe_tree():
    source = analysis({
        "192.0.2.1": subject_result(
            path=path_traversal_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", PRIVATE
            ),
        ),
    })
    projection = build_investigation_report_projection(source)
    json_safe = json.dumps(
        scalar_tree(projection), ensure_ascii=False, sort_keys=True
    )

    assert PRIVATE not in repr(projection)
    assert PRIVATE not in json_safe
    assert "Account 1" in json_safe
    for prohibited_name in (
        "query",
        "raw_log",
        "credential",
        "token",
        "cookie",
        "authorization",
        "argv",
        "proctitle",
        "executable",
        "cwd",
        "pid",
        "uid",
        "source_instance",
        "event_id",
        "filename",
        "digest",
        "traceback",
        "global_correlation",
    ):
        assert prohibited_name not in json_safe.casefold()


def test_builder_is_pure_deterministic_and_does_not_mutate_inputs(monkeypatch):
    source = analysis({
        "192.0.2.1": subject_result(
            brute=brute_force_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", "account"
            ),
        ),
    })
    original = copy.deepcopy(source)

    def forbidden(*args, **kwargs):
        raise AssertionError("projection attempted an external read")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(time, "time", forbidden)
    monkeypatch.setattr(random, "random", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    first = build_investigation_report_projection(source)
    second = build_investigation_report_projection(source)

    assert first == second
    assert source == original


def test_report_projection_does_not_mutate_cli_or_invalid_public_inputs(capsys):
    source = analysis({
        "192.0.2.1": subject_result(
            brute=brute_force_detection(),
            authentication=supported_correlation(
                "failed_to_successful_login", "account"
            ),
        ),
    })
    ip_result = source["results"]["192.0.2.1"]

    print_analysis_result(source)
    cli_before = capsys.readouterr().out
    with pytest.raises(LegacyAnalysisProjectionError):
        build_analysis_response(source, total_sources=1)
    with pytest.raises(LegacyAnalysisProjectionError):
        build_llm_input("192.0.2.1", ip_result)

    build_investigation_report_projection(source)

    print_analysis_result(source)
    cli_after = capsys.readouterr().out
    with pytest.raises(LegacyAnalysisProjectionError):
        build_analysis_response(source, total_sources=1)
    with pytest.raises(LegacyAnalysisProjectionError):
        build_llm_input("192.0.2.1", ip_result)

    assert cli_after == cli_before


def test_canonical_ip_collision_and_non_exact_top_level_contract_fail_closed():
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "2001:db8::1": subject_result(),
            "2001:0db8:0:0:0:0:0:1": subject_result(),
        }))

    malformed = analysis()
    malformed["extra"] = PRIVATE
    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(malformed)

    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "fe80::1%private-interface": subject_result(),
        }))


def test_malformed_negative_correlation_fails_closed():
    result = subject_result()
    result["correlation"]["authentication"]["type"] = (
        "failed_to_successful_login"
    )

    with pytest.raises(InvestigationReportProjectionError):
        build_investigation_report_projection(analysis({
            "192.0.2.1": result,
        }))
