from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
import math
import re
from types import MappingProxyType
import unicodedata

from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
)
from app.models.schemas import DetectionResult, Evidence


_PROJECTION_ERROR_MESSAGE = "Investigation report projection failed."
_SCHEMA_VERSION = "1"
_CLASSIFICATION = "Sensitive — Security Investigation Data"
_LEVEL_RANK = MappingProxyType({"HIGH": 0, "MEDIUM": 1, "LOW": 2})

_DETECTION_SLOTS = MappingProxyType({
    "brute_force": "brute_force",
    "password_spray": "password_spraying_like",
    "path_traversal": "path_traversal",
})
_DETECTION_DISPLAY_NAMES = MappingProxyType({
    "brute_force": "Brute Force",
    "password_spraying_like": "Password Spraying-like",
    "path_traversal": "Path Traversal",
})
_CORRELATION_DISPLAY_NAMES = MappingProxyType({
    "failed_to_successful_login": "Failed Login → Successful Login",
    "brute_force_to_successful_login": (
        "Brute Force → Successful Login"
    ),
})
_CORRELATION_SLOTS = MappingProxyType({
    "authentication": "failed_to_successful_login",
    "post_authentication": "successful_login_to_file_access",
    "brute_force_to_success": "brute_force_to_successful_login",
    "password_spray_to_success": "password_spray_to_successful_login",
})

_STATIC_RATIONALES = frozenset({
    "Path Traversal 공격 패턴이 HTTP 요청에서 직접 확인됨",
    "URL 디코딩 이후 상위 경로 접근 패턴(../)이 확인됨",
    "실제 대상 파일 접근 성공 여부는 현재 로그만으로 확인할 수 없음",
    "단일 계정에 인증 실패가 집중됨",
    "Brute Force 탐지 조건을 충족함",
    "Brute Force 탐지 이후 동일 계정의 로그인 성공이 확인됨",
    "Password Spraying-like 탐지 조건을 충족함",
    "Password Spraying-like 탐지 이후 동일 계정의 로그인 성공이 확인됨",
    "인증 실패 이후 동일 계정의 로그인 성공이 확인됨",
    "공격으로 판단할 만큼 강한 인증 이상 징후가 확인되지 않음",
    "Path Traversal 공격 패턴이 확인됨",
    "요청이 애플리케이션에서 처리된 정황이 확인됨",
    "실제 민감 파일의 내용이 반환되었는지는 현재 로그만으로 확인되지 않음",
    "현재 로그만으로 실제 파일 접근 또는 정보 노출 여부는 확인되지 않음",
    "실제 대상 파일 접근 또는 정보 노출 여부를 판단할 HTTP 결과가 확인되지 않음",
    "인증 공격의 대상에 Privileged 계정이 포함됨",
    "인증 공격 패턴은 확인되었으나 Privileged 계정 대상은 확인되지 않음",
    "Privileged 계정이 인증 이상 행위의 대상으로 확인됨",
    "영향도를 높일 수 있는 대상 중요도 정보가 확인되지 않음",
    "HTTP 요청에서 Path Traversal 공격 패턴이 직접 확인됨",
    "실제 대상 파일 접근 성공 여부는 현재 로그에서 확인되지 않음",
    "Brute Force의 주요 행동 증거가 로그에서 직접 확인됨",
    "여러 계정에 대한 짧은 시간 내 인증 실패가 확인됨",
    "실제 비밀번호 재사용 여부는 로그에서 확인되지 않음",
    "동일 계정에서 인증 실패 이후 로그인 성공 전이가 확인됨",
    "이벤트 간 연관관계는 확인되지만 공격 행위 자체를 확정할 수는 없음",
    "로그인 성공 이후 동일 계정의 후속 파일 접근 행위가 확인됨",
    "정상적인 사용자 활동일 가능성을 배제할 수 없어 공격 행위 자체를 확정할 수는 없음",
    "짧은 시간 내 반복적인 인증 실패가 확인됨",
    "판단을 뒷받침할 충분한 공격 증거가 확인되지 않음",
})
_RATIONALE_PATTERNS = tuple(
    re.compile(pattern).fullmatch
    for pattern in (
        r"[0-9]+회의 인증 실패가 발생함",
        r"실패가 [0-9]+(?:\.[0-9]+)?초 내에 집중됨",
        r"[0-9]+개의 계정이 대상으로 확인됨",
        r"[0-9]+회의 인증 실패가 짧은 시간에 발생함",
        r"공격 요청에 대해 HTTP [0-9]+ 응답이 확인됨",
    )
)

_LIMITATION_CATALOG = (
    (
        "detection_not_compromise",
        "A detection is not confirmation of compromise.",
        frozenset(_DETECTION_DISPLAY_NAMES),
    ),
    (
        "spraying_like_not_credential_reuse",
        (
            "A Password Spraying-like observation does not establish "
            "reuse of the same credential."
        ),
        frozenset({"password_spraying_like"}),
    ),
    (
        "path_traversal_not_file_disclosure",
        (
            "An HTTP response and traversal pattern do not establish "
            "file access or data disclosure."
        ),
        frozenset({"path_traversal"}),
    ),
    (
        "correlation_not_causation",
        "A correlation is not causation or proof of compromise.",
        frozenset(_CORRELATION_DISPLAY_NAMES),
    ),
    (
        "successful_login_not_account_compromise",
        "A successful login does not establish account compromise.",
        frozenset(_CORRELATION_DISPLAY_NAMES),
    ),
)
_NEXT_STEP_CATALOG = (
    (
        "brute_force",
        "review_authentication_failures",
        (
            "Review authentication failure records for the observed time "
            "window and verify whether the activity matches an approved "
            "source or process."
        ),
    ),
    (
        "password_spraying_like",
        "review_cross_account_authentication",
        (
            "Review identity-provider authentication records for the "
            "affected account aliases and verify expected administrative "
            "or automated activity."
        ),
    ),
    (
        "path_traversal",
        "review_traversal_response_context",
        (
            "Review application, reverse-proxy, and file-access telemetry "
            "for the observed request and verify what response content or "
            "file access, if any, was recorded."
        ),
    ),
    (
        "failed_to_successful_login",
        "review_login_transition",
        (
            "Review identity-provider, MFA, device, and session records for "
            "the correlated login and verify whether the login was expected."
        ),
    ),
    (
        "brute_force_to_successful_login",
        "review_brute_force_login_transition",
        (
            "Review authentication, MFA, device, and session records around "
            "the Brute Force observation and correlated login."
        ),
    ),
)


class InvestigationReportProjectionError(ValueError):
    def __init__(self):
        super().__init__(_PROJECTION_ERROR_MESSAGE)


@dataclass(frozen=True)
class ReportSummaryProjection:
    analyzed_subject_count: int
    high_risk_subject_count: int
    medium_risk_subject_count: int
    low_risk_subject_count: int
    supported_detection_observation_count: int
    supported_correlation_observation_count: int
    linux_audit_process_observation_count: int | None
    shared_memory_review_observation_count: int | None
    session_process_co_observation_count: int | None


@dataclass(frozen=True)
class BruteForceEvidenceProjection:
    failed_attempt_count: int
    target_account_count: int
    time_window_seconds: int | float


@dataclass(frozen=True)
class PasswordSprayingLikeEvidenceProjection:
    failed_attempt_count: int
    target_account_count: int
    time_window_seconds: int | float


@dataclass(frozen=True)
class PathTraversalEvidenceProjection:
    request_path: str
    matched_pattern: str
    http_method: str | None
    response_status: int | None
    response_size_bytes: int | None


SupportedEvidenceProjection = (
    BruteForceEvidenceProjection
    | PasswordSprayingLikeEvidenceProjection
    | PathTraversalEvidenceProjection
)


@dataclass(frozen=True)
class DetectionDisplayItem:
    detection_type: str
    display_name: str
    evidence: SupportedEvidenceProjection


@dataclass(frozen=True)
class CorrelationDisplayItem:
    correlation_type: str
    display_name: str
    account_alias: str
    time_delta_seconds: int | float


@dataclass(frozen=True)
class AssessmentDimensionProjection:
    level: str
    rationale: tuple[str, ...]


@dataclass(frozen=True)
class RiskAssessmentProjection:
    risk_level: str
    likelihood: AssessmentDimensionProjection
    impact: AssessmentDimensionProjection
    confidence: AssessmentDimensionProjection


@dataclass(frozen=True)
class InterpretationLimitationItem:
    limitation_id: str
    text: str


@dataclass(frozen=True)
class FixedNextStepItem:
    next_step_id: str
    text: str


@dataclass(frozen=True)
class LinuxAuditAggregateProjection:
    process_observation_count: int | None
    process_outcome_success_count: int | None
    process_outcome_failure_count: int | None
    process_outcome_unknown_count: int | None
    process_argv_complete_count: int | None
    process_argv_incomplete_count: int | None
    process_path_complete_count: int | None
    process_path_incomplete_count: int | None
    shared_memory_review_observation_count: int | None
    session_process_co_observation_count: int | None
    session_process_observation_count: int | None
    session_process_outcome_success_count: int | None
    session_process_outcome_failure_count: int | None
    session_process_outcome_unknown_count: int | None
    session_shared_memory_observation_count: int | None
    sessions_with_shared_memory_observation_count: int | None


@dataclass(frozen=True)
class InvestigationSubjectRow:
    review_order: int
    subject_ip: str
    primary_detection_display_name: str | None
    notable_correlation_display_name: str | None
    review_reason: str
    detections: tuple[DetectionDisplayItem, ...]
    correlations: tuple[CorrelationDisplayItem, ...]
    risk_assessment: RiskAssessmentProjection
    unsupported_detection_observed: bool
    unsupported_correlation_observed: bool
    limitations: tuple[InterpretationLimitationItem, ...]
    next_steps: tuple[FixedNextStepItem, ...]


@dataclass(frozen=True)
class InvestigationReportProjection:
    schema_version: str
    classification: str
    summary: ReportSummaryProjection
    subjects: tuple[InvestigationSubjectRow, ...]
    linux_audit: LinuxAuditAggregateProjection | None


@dataclass(frozen=True)
class _PendingSubject:
    subject_ip: str
    ip_sort_key: tuple[int, bytes]
    detections: tuple[DetectionDisplayItem, ...]
    correlations: tuple[CorrelationDisplayItem, ...]
    risk_assessment: RiskAssessmentProjection
    unsupported_detection_observed: bool
    unsupported_correlation_observed: bool
    limitations: tuple[InterpretationLimitationItem, ...]
    next_steps: tuple[FixedNextStepItem, ...]


def _fail():
    raise InvestigationReportProjectionError() from None


def _strict_non_negative_int(value):
    if type(value) is not int or value < 0:
        _fail()
    return value


def _strict_non_negative_number(value):
    if type(value) is int:
        if value < 0:
            _fail()
        return value
    if type(value) is float and math.isfinite(value) and value >= 0:
        return value
    _fail()


def _strict_level(value):
    if type(value) is not str or value not in _LEVEL_RANK:
        _fail()
    return value


def _validate_rationale(value):
    if type(value) is not list or not value or len(value) > 5:
        _fail()
    validated = []
    for item in value:
        if type(item) is not str:
            _fail()
        if item not in _STATIC_RATIONALES and not any(
            matcher(item) is not None for matcher in _RATIONALE_PATTERNS
        ):
            _fail()
        validated.append(item)
    if len(set(validated)) != len(validated):
        _fail()
    return tuple(validated)


def _assessment_dimension(value):
    if type(value) is not dict:
        _fail()
    return AssessmentDimensionProjection(
        level=_strict_level(value.get("level")),
        rationale=_validate_rationale(value.get("rationale")),
    )


def _risk_assessment(result):
    if type(result) is not dict:
        _fail()
    risk_factors = result.get("risk_factors")
    if type(risk_factors) is not dict:
        _fail()
    return RiskAssessmentProjection(
        risk_level=_strict_level(result.get("risk_level")),
        likelihood=_assessment_dimension(risk_factors.get("likelihood")),
        impact=_assessment_dimension(risk_factors.get("impact")),
        confidence=_assessment_dimension(risk_factors.get("confidence")),
    )


def _evidence_by_type(detection, expected_types, source):
    if type(detection.evidence) is not list:
        _fail()
    if len(detection.evidence) != len(expected_types):
        _fail()

    evidence_by_type = {}
    for item in detection.evidence:
        if type(item) is not Evidence:
            _fail()
        if type(item.type) is not str or item.type in evidence_by_type:
            _fail()
        if type(item.source) is not str or item.source != source:
            _fail()
        evidence_by_type[item.type] = item

    if set(evidence_by_type) != set(expected_types):
        _fail()
    return evidence_by_type


def _authentication_evidence(detection):
    if detection.detection_type == "brute_force":
        target_type = "single_target_user"
        source = "brute_force_detector"
        evidence_type = BruteForceEvidenceProjection
    else:
        target_type = "multiple_target_users"
        source = "password_spray_detector"
        evidence_type = PasswordSprayingLikeEvidenceProjection

    items = _evidence_by_type(
        detection,
        (
            "multiple_login_failures",
            target_type,
            "failures_within_short_window",
        ),
        source,
    )
    return evidence_type(
        failed_attempt_count=_strict_non_negative_int(
            items["multiple_login_failures"].value
        ),
        target_account_count=_strict_non_negative_int(
            items[target_type].value
        ),
        time_window_seconds=_strict_non_negative_number(
            items["failures_within_short_window"].value
        ),
    )


def _path_traversal_evidence(detection):
    expected_order = (
        "url_decoded_path",
        "path_pattern",
        "url_decoded_query",
        "http_method",
        "http_status_code",
        "http_response_size",
    )
    if type(detection.evidence) is not list:
        _fail()
    if not 2 <= len(detection.evidence) <= len(expected_order):
        _fail()

    by_type = {}
    for item in detection.evidence:
        if type(item) is not Evidence:
            _fail()
        if (
            type(item.type) is not str
            or item.type not in expected_order
            or item.type in by_type
            or type(item.source) is not str
            or item.source != "path_traversal_detector"
        ):
            _fail()
        by_type[item.type] = item
    if not {"url_decoded_path", "path_pattern"}.issubset(by_type):
        _fail()

    for evidence_type in (
        "url_decoded_path",
        "path_pattern",
        "url_decoded_query",
        "http_method",
    ):
        if evidence_type in by_type and type(by_type[evidence_type].value) is not str:
            _fail()
    for evidence_type in ("http_status_code", "http_response_size"):
        if evidence_type in by_type:
            _strict_non_negative_int(by_type[evidence_type].value)

    return PathTraversalEvidenceProjection(
        request_path=by_type["url_decoded_path"].value,
        matched_pattern=by_type["path_pattern"].value,
        http_method=(
            by_type["http_method"].value
            if "http_method" in by_type
            else None
        ),
        response_status=(
            by_type["http_status_code"].value
            if "http_status_code" in by_type
            else None
        ),
        response_size_bytes=(
            by_type["http_response_size"].value
            if "http_response_size" in by_type
            else None
        ),
    )


def _project_detections(detections):
    if type(detections) is not dict or set(detections) != set(_DETECTION_SLOTS):
        _fail()

    projected = []
    unsupported = False
    for slot, expected_type in _DETECTION_SLOTS.items():
        detection = detections[slot]
        if type(detection) is not DetectionResult:
            _fail()
        if type(detection.is_detected) is not bool:
            _fail()
        if not detection.is_detected:
            if detection.detection_type is not None:
                _fail()
            if type(detection.evidence) is not list or detection.evidence:
                _fail()
            continue
        if type(detection.detection_type) is not str:
            _fail()
        if detection.detection_type != expected_type:
            unsupported = True
            continue

        if detection.detection_type in {"brute_force", "password_spraying_like"}:
            evidence = _authentication_evidence(detection)
        elif detection.detection_type == "path_traversal":
            evidence = _path_traversal_evidence(detection)
        else:
            _fail()
        projected.append(DetectionDisplayItem(
            detection_type=detection.detection_type,
            display_name=_DETECTION_DISPLAY_NAMES[detection.detection_type],
            evidence=evidence,
        ))

    projected.sort(key=lambda item: item.display_name.casefold())
    return tuple(projected), unsupported


def _correlation_candidates(correlation):
    if type(correlation) is not dict or set(correlation) != set(
        _CORRELATION_SLOTS
    ):
        _fail()
    candidates = []
    unsupported = False
    for slot, expected_type in _CORRELATION_SLOTS.items():
        result = correlation[slot]
        if type(result) is not dict:
            _fail()
        is_correlated = result.get("is_correlated")
        if type(is_correlated) is not bool:
            _fail()
        if not is_correlated:
            if (
                result.get("type") is not None
                or result.get("user") is not None
                or type(result.get("rationale")) is not list
                or result.get("rationale")
            ):
                _fail()
            continue
        correlation_type = result.get("type")
        if type(correlation_type) is not str:
            _fail()
        if correlation_type not in _CORRELATION_DISPLAY_NAMES:
            unsupported = True
            continue
        if correlation_type != expected_type:
            _fail()
        candidates.append((correlation_type, result))
    return tuple(candidates), unsupported


def _validated_account(value):
    if type(value) is not str or not value.strip():
        _fail()
    if any(unicodedata.category(character) == "Cc" for character in value):
        _fail()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    return value


def _account_aliases(candidate_groups):
    accounts = set()
    for candidates in candidate_groups:
        for _, result in candidates:
            accounts.add(_validated_account(result.get("user")))

    ordered_accounts = sorted(accounts, key=lambda value: value.encode("utf-8"))
    aliases = {
        account: f"Account {index}"
        for index, account in enumerate(ordered_accounts, start=1)
    }
    if len(aliases) != len(accounts) or len(set(aliases.values())) != len(accounts):
        _fail()
    if any(account not in aliases for account in accounts):
        _fail()
    return aliases


def _project_correlations(candidates, aliases):
    projected = []
    for correlation_type, result in candidates:
        account = _validated_account(result.get("user"))
        if account not in aliases:
            _fail()
        projected.append(CorrelationDisplayItem(
            correlation_type=correlation_type,
            display_name=_CORRELATION_DISPLAY_NAMES[correlation_type],
            account_alias=aliases[account],
            time_delta_seconds=_strict_non_negative_number(
                result.get("time_delta_seconds")
            ),
        ))
    projected.sort(
        key=lambda item: (
            item.display_name.casefold(),
            item.account_alias,
            item.time_delta_seconds,
        )
    )
    return tuple(projected)


def _limitations(observation_types):
    return tuple(
        InterpretationLimitationItem(limitation_id, text)
        for limitation_id, text, applies_to in _LIMITATION_CATALOG
        if observation_types & applies_to
    )


def _next_steps(observation_types):
    return tuple(
        FixedNextStepItem(next_step_id, text)
        for observation_type, next_step_id, text in _NEXT_STEP_CATALOG
        if observation_type in observation_types
    )


def _canonical_ip(value):
    if type(value) is not str:
        _fail()
    try:
        parsed = ip_address(value)
    except ValueError:
        _fail()
    if type(parsed) is IPv4Address:
        family = 4
    elif type(parsed) is IPv6Address:
        if parsed.scope_id is not None:
            _fail()
        family = 6
    else:
        _fail()
    return str(parsed), (family, parsed.packed)


def _review_reason(risk, detection_count, correlation_count):
    return (
        f"{risk.risk_level} risk; {detection_count} supported detection "
        f"observation(s); {correlation_count} supported correlation "
        f"observation(s); {risk.confidence.level} confidence."
    )


def _process_aggregate_projection(aggregate):
    if aggregate is None:
        return (None,) * 8
    if type(aggregate) is not dict or set(aggregate) != {
        "observation_count",
        "outcome_counts",
        "argv_completeness_counts",
        "path_completeness_counts",
    }:
        _fail()
    outcome = aggregate["outcome_counts"]
    argv = aggregate["argv_completeness_counts"]
    path = aggregate["path_completeness_counts"]
    if (
        type(outcome) is not dict
        or set(outcome) != {"success", "failure", "unknown"}
        or type(argv) is not dict
        or set(argv) != {"complete", "incomplete"}
        or type(path) is not dict
        or set(path) != {"complete", "incomplete"}
    ):
        _fail()
    counts = tuple(
        _strict_non_negative_int(value)
        for value in (
            aggregate["observation_count"],
            outcome["success"],
            outcome["failure"],
            outcome["unknown"],
            argv["complete"],
            argv["incomplete"],
            path["complete"],
            path["incomplete"],
        )
    )
    observation_count = counts[0]
    if (
        sum(counts[1:4]) != observation_count
        or sum(counts[4:6]) != observation_count
        or sum(counts[6:8]) != observation_count
    ):
        _fail()
    return counts


def _shared_memory_count(summary):
    if summary is None:
        return None
    if type(summary) is not SharedMemoryExecutionReviewSummary:
        _fail()
    return _strict_non_negative_int(
        summary.shared_memory_privileged_execution_observation_count
    )


def _session_process_counts(summary):
    if summary is None:
        return (None,) * 7
    if type(summary) is not SessionProcessReviewSummary:
        _fail()
    counts = tuple(
        _strict_non_negative_int(value)
        for value in (
            summary.session_co_observation_count,
            summary.process_observation_count,
            summary.process_outcome_success_count,
            summary.process_outcome_failure_count,
            summary.process_outcome_unknown_count,
            summary.shared_memory_privileged_execution_observation_count,
            summary.sessions_with_shared_memory_privileged_execution_count,
        )
    )
    session_count, process_count = counts[:2]
    shared_count = counts[5]
    sessions_with_shared = counts[6]
    if (
        sum(counts[2:5]) != process_count
        or shared_count > process_count
        or sessions_with_shared > session_count
        or (session_count == 0 and process_count > 0)
        or (session_count > 0 and process_count == 0)
        or (shared_count == 0 and sessions_with_shared > 0)
        or (shared_count > 0 and sessions_with_shared == 0)
    ):
        _fail()
    return counts


def _linux_audit_projection(
    process_execution_aggregate,
    process_detection_summary,
    session_process_review_summary,
):
    if (
        process_execution_aggregate is None
        and process_detection_summary is None
        and session_process_review_summary is None
    ):
        return None

    process = _process_aggregate_projection(process_execution_aggregate)
    shared = _shared_memory_count(process_detection_summary)
    session = _session_process_counts(session_process_review_summary)

    process_count = process[0]
    session_process_count = session[1]
    session_shared_count = session[5]
    if process_count is not None and shared is not None and shared > process_count:
        _fail()
    if (
        process_count is not None
        and session_process_count is not None
        and session_process_count > process_count
    ):
        _fail()
    if (
        shared is not None
        and session_shared_count is not None
        and session_shared_count > shared
    ):
        _fail()

    return LinuxAuditAggregateProjection(
        process_observation_count=process[0],
        process_outcome_success_count=process[1],
        process_outcome_failure_count=process[2],
        process_outcome_unknown_count=process[3],
        process_argv_complete_count=process[4],
        process_argv_incomplete_count=process[5],
        process_path_complete_count=process[6],
        process_path_incomplete_count=process[7],
        shared_memory_review_observation_count=shared,
        session_process_co_observation_count=session[0],
        session_process_observation_count=session[1],
        session_process_outcome_success_count=session[2],
        session_process_outcome_failure_count=session[3],
        session_process_outcome_unknown_count=session[4],
        session_shared_memory_observation_count=session[5],
        sessions_with_shared_memory_observation_count=session[6],
    )


def build_investigation_report_projection(
    analysis,
    *,
    process_execution_aggregate=None,
    process_detection_summary=None,
    session_process_review_summary=None,
):
    if type(analysis) is not dict or set(analysis) != {
        "results",
        "global_correlation",
    }:
        _fail()
    results = analysis["results"]
    if type(results) is not dict or type(analysis["global_correlation"]) is not dict:
        _fail()

    prepared = []
    canonical_ips = set()
    candidate_groups = []
    for subject_ip, result in results.items():
        canonical_ip, ip_sort_key = _canonical_ip(subject_ip)
        if canonical_ip in canonical_ips:
            _fail()
        canonical_ips.add(canonical_ip)
        if type(result) is not dict or set(result) != {
            "features",
            "detections",
            "correlation",
            "risk_factors",
            "risk_level",
        }:
            _fail()
        detections, unsupported_detection = _project_detections(
            result["detections"]
        )
        candidates, unsupported_correlation = _correlation_candidates(
            result["correlation"]
        )
        prepared.append((
            canonical_ip,
            ip_sort_key,
            detections,
            candidates,
            _risk_assessment(result),
            unsupported_detection,
            unsupported_correlation,
        ))
        candidate_groups.append(candidates)

    aliases = _account_aliases(candidate_groups)
    pending = []
    for (
        subject_ip,
        ip_sort_key,
        detections,
        candidates,
        risk,
        unsupported_detection,
        unsupported_correlation,
    ) in prepared:
        correlations = _project_correlations(candidates, aliases)
        observation_types = {
            item.detection_type for item in detections
        } | {
            item.correlation_type for item in correlations
        }
        pending.append(_PendingSubject(
            subject_ip=subject_ip,
            ip_sort_key=ip_sort_key,
            detections=detections,
            correlations=correlations,
            risk_assessment=risk,
            unsupported_detection_observed=unsupported_detection,
            unsupported_correlation_observed=unsupported_correlation,
            limitations=_limitations(observation_types),
            next_steps=_next_steps(observation_types),
        ))

    pending.sort(key=lambda item: (
        _LEVEL_RANK[item.risk_assessment.risk_level],
        0 if item.correlations else 1,
        _LEVEL_RANK[item.risk_assessment.confidence.level],
        (
            item.detections[0].display_name.casefold()
            if item.detections
            else "\U0010ffff"
        ),
        item.ip_sort_key,
    ))

    subjects = tuple(
        InvestigationSubjectRow(
            review_order=index,
            subject_ip=item.subject_ip,
            primary_detection_display_name=(
                item.detections[0].display_name if item.detections else None
            ),
            notable_correlation_display_name=(
                item.correlations[0].display_name if item.correlations else None
            ),
            review_reason=_review_reason(
                item.risk_assessment,
                len(item.detections),
                len(item.correlations),
            ),
            detections=item.detections,
            correlations=item.correlations,
            risk_assessment=item.risk_assessment,
            unsupported_detection_observed=(
                item.unsupported_detection_observed
            ),
            unsupported_correlation_observed=(
                item.unsupported_correlation_observed
            ),
            limitations=item.limitations,
            next_steps=item.next_steps,
        )
        for index, item in enumerate(pending, start=1)
    )

    linux_audit = _linux_audit_projection(
        process_execution_aggregate,
        process_detection_summary,
        session_process_review_summary,
    )
    risk_counts = {
        level: sum(
            subject.risk_assessment.risk_level == level for subject in subjects
        )
        for level in _LEVEL_RANK
    }
    summary = ReportSummaryProjection(
        analyzed_subject_count=len(subjects),
        high_risk_subject_count=risk_counts["HIGH"],
        medium_risk_subject_count=risk_counts["MEDIUM"],
        low_risk_subject_count=risk_counts["LOW"],
        supported_detection_observation_count=sum(
            len(subject.detections) for subject in subjects
        ),
        supported_correlation_observation_count=sum(
            len(subject.correlations) for subject in subjects
        ),
        linux_audit_process_observation_count=(
            linux_audit.process_observation_count if linux_audit else None
        ),
        shared_memory_review_observation_count=(
            linux_audit.shared_memory_review_observation_count
            if linux_audit
            else None
        ),
        session_process_co_observation_count=(
            linux_audit.session_process_co_observation_count
            if linux_audit
            else None
        ),
    )
    if (
        summary.analyzed_subject_count
        != summary.high_risk_subject_count
        + summary.medium_risk_subject_count
        + summary.low_risk_subject_count
    ):
        _fail()

    return InvestigationReportProjection(
        schema_version=_SCHEMA_VERSION,
        classification=_CLASSIFICATION,
        summary=summary,
        subjects=subjects,
        linux_audit=linux_audit,
    )
