"""Deprecated API's explicit, privacy-safe projection of trusted analysis."""

from datetime import datetime, timezone
from math import isfinite

from app.analyzer.report_projection import (
    BruteForceEvidenceProjection,
    InvestigationReportProjectionError,
    PasswordSprayingLikeEvidenceProjection,
    PathTraversalEvidenceProjection,
    build_investigation_report_projection,
)
from app.models.schemas import (
    AnalysisResponse,
    AnalysisResultResponse,
    AnalysisSummary,
    LegacyDetectionProjection,
    LegacyGlobalCorrelationProjection,
    LegacyRelationProjection,
    LegacyRiskProjection,
)


_ACCOUNT_NOTICE = "원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다."
_RELATION_LIMITATION = "상관관계는 인과관계나 침해의 증거가 아닙니다."
_RISK_LIMITATION = "기존 분석의 위험도이며 침해 확률이나 확정된 사고를 뜻하지 않습니다."
_GLOBAL_LIMITATION = "전체 로그 관계의 건수만 표시하며 개별 대상의 위험도에 자동 적용하지 않습니다."
_RELATION_TYPES = {
    "authentication": "failed_to_successful_login",
    "post_authentication": "successful_login_to_file_access",
    "brute_force_to_success": "brute_force_to_successful_login",
    "password_spray_to_success": "password_spray_to_successful_login",
}
_GLOBAL_TYPES = {
    "multi_ip_authentication": "multi_ip_authentication_failure",
    "distributed_authentication_to_success": "distributed_authentication_failures_to_successful_login",
    "linux_audit_session_lifecycle": "linux_audit_session_lifecycle",
    "linux_audit_login_start_co_observation": "linux_audit_login_start_co_observation",
}
_DETECTION_SLOTS = ("brute_force", "password_spray", "path_traversal")


class LegacyAnalysisProjectionError(ValueError):
    def __init__(self) -> None:
        self.code = "legacy_projection_failed"
        super().__init__("Legacy analysis projection failed.")


def _fail() -> None:
    raise LegacyAnalysisProjectionError() from None


def _utc(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        _fail()
    return value


def _delta(value: object) -> int | float:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and isfinite(value) and value >= 0:
        return value
    _fail()


def _relations(raw: object) -> tuple[LegacyRelationProjection, ...]:
    if type(raw) is not dict or set(raw) != set(_RELATION_TYPES):
        _fail()
    projected = []
    for slot, relation_type in _RELATION_TYPES.items():
        relation = raw[slot]
        if type(relation) is not dict or type(relation.get("is_correlated")) is not bool:
            _fail()
        if not relation["is_correlated"]:
            if relation.get("type") is not None or relation.get("user") is not None:
                _fail()
            continue
        if relation.get("type") != relation_type or type(relation.get("user")) is not str or not relation["user"]:
            _fail()
        if slot == "post_authentication":
            start = _utc(relation.get("success_timestamp"))
            end = _utc(relation.get("file_access_timestamp"))
        else:
            start = _utc(relation.get("failure_timestamp"))
            end = _utc(relation.get("success_timestamp"))
        delta = _delta(relation.get("time_delta_seconds"))
        if not start < end or (end - start).total_seconds() != delta or delta > 60:
            _fail()
        projected.append(LegacyRelationProjection(
            relation_type=relation_type,
            start_timestamp_utc=start,
            end_timestamp_utc=end,
            time_delta_seconds=delta,
            account_reference_available=False,
            account_notice=_ACCOUNT_NOTICE,
            limitation=_RELATION_LIMITATION,
        ))
    return tuple(projected)


def _detections(row) -> dict[str, LegacyDetectionProjection]:
    projected = {
        slot: LegacyDetectionProjection(is_detected=False, detection_type=None)
        for slot in _DETECTION_SLOTS
    }
    for detection in row.detections:
        evidence = detection.evidence
        if type(evidence) is BruteForceEvidenceProjection:
            slot = "brute_force"
            values = dict(
                failed_attempt_count=evidence.failed_attempt_count,
                target_account_count=evidence.target_account_count,
                time_window_seconds=evidence.time_window_seconds,
            )
        elif type(evidence) is PasswordSprayingLikeEvidenceProjection:
            slot = "password_spray"
            values = dict(
                failed_attempt_count=evidence.failed_attempt_count,
                target_account_count=evidence.target_account_count,
                time_window_seconds=evidence.time_window_seconds,
            )
        elif type(evidence) is PathTraversalEvidenceProjection:
            slot = "path_traversal"
            values = dict(
                matched_pattern=evidence.matched_pattern,
                http_method=evidence.http_method,
                response_status=evidence.response_status,
                response_size_bytes=evidence.response_size_bytes,
            )
        else:
            _fail()
        if projected[slot].is_detected:
            _fail()
        projected[slot] = LegacyDetectionProjection(
            is_detected=True, detection_type=detection.detection_type, **values,
        )
    return projected


def _global_counts(raw: object) -> LegacyGlobalCorrelationProjection:
    if type(raw) is not dict or set(raw) != set(_GLOBAL_TYPES):
        _fail()
    counts = {}
    for slot, expected_type in _GLOBAL_TYPES.items():
        records = raw[slot]
        if type(records) is not list or any(
            type(record) is not dict
            or record.get("is_correlated") is not True
            or record.get("type") != expected_type
            for record in records
        ):
            _fail()
        counts[f"{slot}_count"] = len(records)
    return LegacyGlobalCorrelationProjection(**counts, limitation=_GLOBAL_LIMITATION)


def project_legacy_analysis_response(raw: object, total_sources: int) -> AnalysisResponse:
    if (type(raw) is not dict or set(raw) != {"results", "global_correlation"}
            or type(raw["results"]) is not dict
            or type(total_sources) is not int or total_sources < 0):
        _fail()
    try:
        report = build_investigation_report_projection(raw)
    except InvestigationReportProjectionError:
        _fail()
    results = []
    for row in report.subjects:
        if row.subject_ip not in raw["results"]:
            _fail()
        subject = raw["results"][row.subject_ip]
        if type(subject) is not dict or "correlation" not in subject:
            _fail()
        if row.unsupported_detection_observed or row.unsupported_correlation_observed:
            _fail()
        risk = row.risk_assessment
        results.append(AnalysisResultResponse(
            ip=row.subject_ip,
            risk_level=risk.risk_level,
            detections=_detections(row),
            correlation=_relations(subject["correlation"]),
            risk_factors=LegacyRiskProjection(
                likelihood_level=risk.likelihood.level,
                impact_level=risk.impact.level,
                confidence_level=risk.confidence.level,
                rationale_id="existing_assessment",
                limitation=_RISK_LIMITATION,
            ),
        ))
    summary = AnalysisSummary(
        total_sources=total_sources,
        total_ips=len(results),
        detected_ips=sum(any(item.is_detected for item in result.detections.values()) for result in results),
        high_risk_ips=sum(result.risk_level == "HIGH" for result in results),
    )
    return AnalysisResponse(
        analysis_id="not-persisted",
        status="completed",
        summary=summary,
        results=results,
        global_correlation=_global_counts(raw["global_correlation"]),
        ai_summary=None,
    )
