from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
import math
from types import MappingProxyType
from typing import Literal
from zoneinfo import ZoneInfo

from app.analyzer.incident_case import (
    CASE_SPRAY_SUCCESS_STATUS,
    IncidentCase,
    IncidentCaseAssembly,
    IncidentCaseEvidenceScalar,
    IncidentCaseObservation,
    IncidentCaseRelation,
    IndependentObservation,
    UnsupportedCaseRule,
)


RiskLevel = Literal["HIGH", "MEDIUM", "LOW"]
TimelineCategory = Literal[
    "OBSERVED_FACT",
    "DETECTION_OBSERVATION",
    "SUPPORTED_RELATION",
]
TimestampState = Literal["TIMESTAMPED", "NO_TIME"]


_SCHEMA_VERSION = "1"
_CLASSIFICATION = "민감 정보 — 보안 조사 자료"
_PROJECTION_ERROR_MESSAGE = "Investigation case projection failed."
_ACCOUNT_ALIAS_STATUS = "ACCOUNT_REFERENCE_UNAVAILABLE"
_ACCOUNT_ALIAS_MESSAGE = (
    "계정 별칭을 안전하게 생성할 참조가 없어 표시하지 않습니다."
)
_KST = ZoneInfo("Asia/Seoul")
_LEVELS = frozenset({"HIGH", "MEDIUM", "LOW"})

_RULE_GROUPING_TEXT = MappingProxyType({
    "CASE-BRUTE-SUCCESS-01": (
        "Brute Force 탐지 관찰과 이후 동일 계정의 로그인 성공 관계가 "
        "기존 상관분석에서 확인되어 함께 검토합니다."
    ),
    "CASE-AUTH-TRANSITION-01": (
        "동일 계정의 로그인 실패 후 성공 관계가 기존 상관분석에서 "
        "확인되어 함께 검토합니다."
    ),
})
_RELATION_DISPLAY_NAMES = MappingProxyType({
    "failed_to_successful_login": "Failed Login → Successful Login",
    "brute_force_to_successful_login": (
        "Brute Force → Successful Login"
    ),
})
_OBSERVATION_DISPLAY_NAMES = MappingProxyType({
    "authentication_failure": "인증 실패 관찰",
    "authentication_success": "인증 성공 관찰",
    "brute_force": "Brute Force",
    "password_spraying_like": "Password Spraying-like",
    "path_traversal": "Path Traversal",
    "unsupported_detection": "지원되지 않는 탐지 관찰",
    "brute_force_invalid_contract": "Brute Force 계약 미검증 관찰",
    "brute_force_invalid_timestamp": "Brute Force 시간 미검증 관찰",
    "password_spraying_like_invalid_contract": (
        "Password Spraying-like 계약 미검증 관찰"
    ),
    "password_spraying_like_invalid_timestamp": (
        "Password Spraying-like 시간 미검증 관찰"
    ),
    "failed_to_successful_login": "Failed Login → Successful Login",
    "brute_force_to_successful_login": (
        "Brute Force → Successful Login"
    ),
    "password_spray_to_successful_login": (
        "Password Spraying-like → Successful Login"
    ),
    "successful_login_to_file_access": (
        "Successful Login → File Access"
    ),
    "failed_to_successful_login_invalid_timestamp": (
        "Failed Login → Successful Login 시간 미검증 관찰"
    ),
    "brute_force_to_successful_login_invalid_timestamp": (
        "Brute Force → Successful Login 시간 미검증 관찰"
    ),
    "unsupported_correlation": "지원되지 않는 관계 관찰",
})
_PHASE_ONE_DISPLAY_NAMES = MappingProxyType({
    "authentication_failure": "Authentication Failure",
    "authentication_success": "Authentication Success",
    "brute_force": "Brute Force",
    "password_spraying_like": "Password Spraying-like",
    "path_traversal": "Path Traversal",
    "unsupported_detection": "Unsupported detection",
    "brute_force_invalid_contract": "Brute Force",
    "brute_force_invalid_timestamp": "Brute Force",
    "password_spraying_like_invalid_contract": "Password Spraying-like",
    "password_spraying_like_invalid_timestamp": "Password Spraying-like",
    "failed_to_successful_login": "Failed Login → Successful Login",
    "brute_force_to_successful_login": (
        "Brute Force → Successful Login"
    ),
    "password_spray_to_successful_login": (
        "Password Spraying-like → Successful Login"
    ),
    "successful_login_to_file_access": (
        "Successful Login → File Access"
    ),
    "failed_to_successful_login_invalid_timestamp": (
        "Failed Login → Successful Login"
    ),
    "brute_force_to_successful_login_invalid_timestamp": (
        "Brute Force → Successful Login"
    ),
    "unsupported_correlation": "Unsupported correlation",
})
_CATEGORY_LABELS = MappingProxyType({
    "OBSERVED_FACT": "관찰된 사실",
    "DETECTION_OBSERVATION": "탐지 관찰",
    "SUPPORTED_RELATION": "지원되는 관계",
})
_CATEGORY_RANK = MappingProxyType({
    "OBSERVED_FACT": 0,
    "DETECTION_OBSERVATION": 1,
    "SUPPORTED_RELATION": 2,
})
_REPORT_LIMITATIONS = (
    (
        "case_not_confirmed_incident",
        "조사 사례는 확정된 보안 사고를 의미하지 않습니다.",
    ),
    (
        "detection_not_compromise",
        "탐지 관찰은 침해 확인을 의미하지 않습니다.",
    ),
    (
        "correlation_not_causation",
        "지원되는 관계는 인과관계를 의미하지 않습니다.",
    ),
    (
        "successful_login_not_attack_success",
        "로그인 성공 기록은 공격 성공을 입증하지 않습니다.",
    ),
    (
        "ip_not_identity",
        (
            "분석 대상 IP는 민감한 보안 조사 정보이며 공격자 또는 "
            "개인의 신원을 확정하지 않습니다."
        ),
    ),
    (
        "nat_proxy_shared_host_possible",
        (
            "NAT, proxy 또는 공유 시스템 때문에 동일 IP가 동일 사용자를 "
            "의미하지 않을 수 있습니다."
        ),
    ),
    (
        "retry_or_automation_possible",
        (
            "정상적인 재시도 또는 승인된 자동화가 유사한 관찰을 만들 "
            "수 있습니다."
        ),
    ),
)
_CASE_LIMITATIONS = MappingProxyType({
    "CASE-BRUTE-SUCCESS-01": (
        (
            "brute_relation_not_account_takeover",
            (
                "동일 계정의 후속 로그인 관계만으로 계정 탈취를 판단할 "
                "수 없습니다."
            ),
        ),
    ),
    "CASE-AUTH-TRANSITION-01": (
        (
            "transition_not_same_actor",
            (
                "실패 후 성공 관계만으로 이전 실패의 주체와 성공 주체가 "
                "동일하다고 판단할 수 없습니다."
            ),
        ),
    ),
})
_UNVERIFIED_ITEMS = (
    ("login_actor_legitimacy", "로그인 주체의 정당성은 확인되지 않았습니다."),
    ("mfa_approver", "MFA 승인 주체는 확인되지 않았습니다."),
    ("device_trust", "사용 장치의 신뢰 여부는 확인되지 않았습니다."),
    ("session_activity", "세션의 후속 활동은 확인되지 않았습니다."),
    ("account_compromise", "계정 침해 여부는 확인되지 않았습니다."),
    (
        "network_intermediary_effect",
        "NAT, proxy 또는 공유 시스템의 영향은 확인되지 않았습니다.",
    ),
    (
        "approved_automation",
        "승인된 자동화 또는 관리 작업 여부는 확인되지 않았습니다.",
    ),
)
_NEXT_STEPS = MappingProxyType({
    "CASE-BRUTE-SUCCESS-01": (
        (
            "review_failure_origin_and_window",
            "인증 실패의 출발지와 시간 범위를 확인하십시오.",
        ),
        (
            "review_correlated_login_context",
            "상관된 로그인의 IdP, MFA, 장치 및 세션 기록을 확인하십시오.",
        ),
        (
            "review_follow_on_session_activity",
            "후속 세션 활동을 확인하십시오.",
        ),
    ),
    "CASE-AUTH-TRANSITION-01": (
        (
            "compare_authentication_origin_and_time",
            "인증 실패와 성공의 출발지 및 시간대를 비교하십시오.",
        ),
        (
            "review_success_login_context",
            "성공 로그인의 MFA, 장치 및 세션 기록을 확인하십시오.",
        ),
        (
            "review_approved_user_or_automation",
            "승인된 사용자 또는 자동화 활동인지 확인하십시오.",
        ),
    ),
})
_INDEPENDENT_REASON_TEXT = MappingProxyType({
    "no_supported_relation": (
        "V1에서 지원되는 관계가 없어 독립 관찰로 유지되었습니다."
    ),
    "invalid_timestamp": (
        "검증된 시간 정보가 부족하여 자동 시간 결합에서 제외되었습니다."
    ),
    "relationship_not_proven": (
        "인증 사례와 안전하게 결합할 관계를 입증하지 못했습니다."
    ),
    "unsupported_for_case_assembly": (
        "V1 조사 사례 지원 범위 밖의 관찰이라 독립적으로 유지되었습니다."
    ),
})


class InvestigationCaseProjectionError(ValueError):
    def __init__(self):
        super().__init__(_PROJECTION_ERROR_MESSAGE)


@dataclass(frozen=True)
class InvestigationTimestampProjection:
    canonical_utc: datetime
    display_kst: str
    display_utc: str


@dataclass(frozen=True)
class InvestigationEvidenceProjection:
    evidence_id: Literal[
        "failed_attempt_count",
        "target_account_count",
        "time_window_seconds",
        "relation_time_delta_seconds",
    ]
    label: str
    value: int | float
    unit: str | None


@dataclass(frozen=True)
class InvestigationTimelineEntryProjection:
    sequence: int
    category: TimelineCategory
    category_label: str
    timestamp_state: TimestampState
    timestamp_state_label: Literal["시각 정보 있음", "시간 정보 없음"]
    start_time: InvestigationTimestampProjection | None
    end_time: InvestigationTimestampProjection | None
    display_title: str
    subject_label: Literal["분석 대상 IP"]
    subject_ip: str
    account_alias: None
    account_alias_status: Literal["ACCOUNT_REFERENCE_UNAVAILABLE"]
    detection_display_name: str | None
    relation_display_name: str | None
    evidence: tuple[InvestigationEvidenceProjection, ...]
    evidence_state: Literal["AVAILABLE", "APPROVED_EVIDENCE_UNAVAILABLE"]
    interpretation_label: str


@dataclass(frozen=True)
class InvestigationCaseAssessmentProjection:
    risk_label: Literal["포함된 최고 위험도"]
    included_highest_risk: RiskLevel
    confidence_label: Literal["포함된 최고 신뢰도"]
    included_highest_confidence: RiskLevel
    risk_context: str
    review_order_context: str


@dataclass(frozen=True)
class InvestigationCaseLimitationProjection:
    limitation_id: str
    label: Literal["해석 시 유의사항"]
    text: str


@dataclass(frozen=True)
class InvestigationCaseUnverifiedProjection:
    item_id: str
    label: Literal["확인되지 않은 사항"]
    text: str


@dataclass(frozen=True)
class InvestigationCaseNextStepProjection:
    step_id: str
    label: Literal["다음 조사 단계"]
    text: str


@dataclass(frozen=True)
class InvestigationCaseRowProjection:
    review_order: int
    case_label: str
    subject_label: Literal["분석 대상 IP"]
    subject_ip: str
    risk_label: Literal["포함된 최고 위험도"]
    included_highest_risk: RiskLevel
    confidence_label: Literal["포함된 최고 신뢰도"]
    included_highest_confidence: RiskLevel
    start_time: InvestigationTimestampProjection | None
    end_time: InvestigationTimestampProjection | None
    observation_count: int
    supporting_relation_count: int
    primary_detection_display_name: str | None
    primary_relation_display_name: str
    grouping_explanation: str
    account_alias: None
    account_alias_status: Literal["ACCOUNT_REFERENCE_UNAVAILABLE"]


@dataclass(frozen=True)
class InvestigationCaseDetailProjection:
    rule_code: Literal[
        "CASE-AUTH-TRANSITION-01",
        "CASE-BRUTE-SUCCESS-01",
    ]
    row: InvestigationCaseRowProjection
    timeline_label: Literal["시간순 조사 흐름"]
    timeline_entries: tuple[InvestigationTimelineEntryProjection, ...]
    timeline_entries_without_time: tuple[
        InvestigationTimelineEntryProjection, ...
    ]
    assessment: InvestigationCaseAssessmentProjection
    limitations: tuple[InvestigationCaseLimitationProjection, ...]
    unverified_items: tuple[InvestigationCaseUnverifiedProjection, ...]
    next_steps: tuple[InvestigationCaseNextStepProjection, ...]


@dataclass(frozen=True)
class IndependentObservationProjection:
    review_order: int
    label: Literal["독립 관찰"]
    category_label: str
    display_type: str
    subject_label: Literal["분석 대상 IP"]
    subject_ip: str
    existing_risk_level: RiskLevel
    existing_confidence: RiskLevel
    start_time: InvestigationTimestampProjection | None
    end_time: InvestigationTimestampProjection | None
    timestamp_state: TimestampState
    timestamp_state_label: Literal["시각 정보 있음", "시간 정보 없음"]
    account_alias: None
    account_alias_status: Literal["ACCOUNT_REFERENCE_UNAVAILABLE"]
    evidence: tuple[InvestigationEvidenceProjection, ...]
    evidence_state: Literal["AVAILABLE", "APPROVED_EVIDENCE_UNAVAILABLE"]
    reason_id: str
    reason_text: str


@dataclass(frozen=True)
class InvestigationCaseNoticeProjection:
    notice_id: str
    text: str
    context: str


@dataclass(frozen=True)
class InvestigationCaseSummaryProjection:
    case_count: int
    independent_observation_count: int
    high_case_count: int
    medium_case_count: int
    low_case_count: int
    cases_with_supported_relation_count: int
    supported_detection_observation_count: int
    supported_relation_observation_count: int
    observations_without_time_count: int
    spray_no_go_observation_count: int


@dataclass(frozen=True)
class InvestigationCaseProjection:
    schema_version: str
    classification: str
    title: Literal["조사 사례"]
    summary: InvestigationCaseSummaryProjection
    cases: tuple[InvestigationCaseDetailProjection, ...]
    independent_observations: tuple[IndependentObservationProjection, ...]
    report_limitations: tuple[InvestigationCaseLimitationProjection, ...]
    notices: tuple[InvestigationCaseNoticeProjection, ...]
    account_alias_status: Literal["ACCOUNT_REFERENCE_UNAVAILABLE"]
    account_alias_message: str


@dataclass(frozen=True)
class _PendingTimelineEntry:
    identity_order: int
    category: TimelineCategory
    start: datetime | None
    end: datetime | None
    display_title: str
    subject_ip: str
    detection_name: str | None
    relation_name: str | None
    evidence: tuple[InvestigationEvidenceProjection, ...]
    interpretation_label: str


def _fail() -> None:
    raise InvestigationCaseProjectionError() from None


def _level(value: object) -> RiskLevel:
    if type(value) is not str or value not in _LEVELS:
        _fail()
    return value


def _subject(value: object) -> str:
    if type(value) is not str:
        _fail()
    try:
        parsed = ip_address(value)
    except ValueError:
        _fail()
    if type(parsed) is IPv4Address:
        pass
    elif type(parsed) is IPv6Address and parsed.scope_id is None:
        pass
    else:
        _fail()
    if str(parsed) != value:
        _fail()
    return value


def _utc(value: object, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        _fail()
    return value


def _number(value: object) -> int | float:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and math.isfinite(value) and value >= 0:
        return value
    _fail()


def _format_timestamp(value: datetime) -> InvestigationTimestampProjection:
    value = _utc(value)
    fraction = f".{value.microsecond:06d}" if value.microsecond else ""
    kst = value.astimezone(_KST)
    kst_fraction = f".{kst.microsecond:06d}" if kst.microsecond else ""
    return InvestigationTimestampProjection(
        canonical_utc=value,
        display_kst=(
            f"{kst:%Y-%m-%d %H:%M:%S}{kst_fraction} "
            "KST (UTC+09:00)"
        ),
        display_utc=f"{value:%Y-%m-%dT%H:%M:%S}{fraction}Z",
    )


def _project_evidence(
    observation_type: str,
    evidence: tuple[IncidentCaseEvidenceScalar, ...],
) -> tuple[InvestigationEvidenceProjection, ...]:
    if type(evidence) is not tuple:
        _fail()
    if observation_type not in {"brute_force", "password_spraying_like"}:
        if evidence:
            _fail()
        return ()
    if len(evidence) != 3:
        _fail()
    failed, targets, window = evidence
    if (
        type(failed) is not IncidentCaseEvidenceScalar
        or failed.evidence_type != "failed_attempt_count"
        or type(failed.value) is not int
        or failed.value < 0
        or type(targets) is not IncidentCaseEvidenceScalar
        or targets.evidence_type != "target_account_count"
        or type(targets.value) is not int
        or targets.value < 0
        or type(window) is not IncidentCaseEvidenceScalar
        or window.evidence_type != "time_window_seconds"
    ):
        _fail()
    window_value = _number(window.value)
    return (
        InvestigationEvidenceProjection(
            "failed_attempt_count", "실패 횟수", failed.value, "회"
        ),
        InvestigationEvidenceProjection(
            "target_account_count", "대상 계정 수", targets.value, "개"
        ),
        InvestigationEvidenceProjection(
            "time_window_seconds", "시간 범위", window_value, "초"
        ),
    )


def _observation_category(observation: IncidentCaseObservation) -> TimelineCategory:
    if observation.observation_kind in {
        "authentication_failure_fact",
        "authentication_success_fact",
    }:
        return "OBSERVED_FACT"
    if observation.observation_kind == "supported_detection_observation":
        return "DETECTION_OBSERVATION"
    _fail()


def _observation_interpretation(category: TimelineCategory) -> str:
    if category == "OBSERVED_FACT":
        return "기존 상관분석에서 관계가 확인된 인증 관찰입니다."
    if category == "DETECTION_OBSERVATION":
        return "기존 결정적 탐지 규칙의 조건을 충족한 관찰입니다."
    _fail()


def _pending_observation(
    observation: IncidentCaseObservation,
    identity_order: int,
    case: IncidentCase,
) -> _PendingTimelineEntry:
    if type(observation) is not IncidentCaseObservation:
        _fail()
    if (
        type(observation.observation_type) is not str
        or observation.observation_type not in _OBSERVATION_DISPLAY_NAMES
        or type(observation.observation_kind) is not str
        or type(observation.source_category) is not str
    ):
        _fail()
    if observation.display_name != _PHASE_ONE_DISPLAY_NAMES[
        observation.observation_type
    ]:
        _fail()
    if observation.subject_ip != case.subject_ip:
        _fail()
    if (
        _level(observation.existing_risk_level) != case.included_highest_risk
        or _level(observation.existing_confidence)
        != case.included_highest_confidence
    ):
        _fail()
    if observation.source_category not in {"authentication", "analysis_rule"}:
        _fail()
    category = _observation_category(observation)
    start = _utc(observation.start_time_utc, optional=True)
    end = _utc(observation.end_time_utc, optional=True)
    if end is not None and (start is None or end < start):
        _fail()
    evidence = _project_evidence(observation.observation_type, observation.evidence)
    display_name = _OBSERVATION_DISPLAY_NAMES[observation.observation_type]
    return _PendingTimelineEntry(
        identity_order=identity_order,
        category=category,
        start=start,
        end=end,
        display_title=(
            f"{display_name} 탐지 관찰"
            if category == "DETECTION_OBSERVATION"
            else display_name
        ),
        subject_ip=case.subject_ip,
        detection_name=(display_name if category == "DETECTION_OBSERVATION" else None),
        relation_name=None,
        evidence=evidence,
        interpretation_label=_observation_interpretation(category),
    )


def _pending_relation(
    relation: IncidentCaseRelation,
    identity_order: int,
    case: IncidentCase,
) -> _PendingTimelineEntry:
    if type(relation) is not IncidentCaseRelation:
        _fail()
    if (
        type(relation.relation_type) is not str
        or relation.relation_type not in _RELATION_DISPLAY_NAMES
    ):
        _fail()
    display_name = _RELATION_DISPLAY_NAMES[relation.relation_type]
    if relation.display_name != display_name or relation.subject_ip != case.subject_ip:
        _fail()
    failure = _utc(relation.failure_timestamp_utc)
    success = _utc(relation.success_timestamp_utc)
    delta = _number(relation.time_delta_seconds)
    if failure >= success or (success - failure).total_seconds() != delta:
        _fail()
    if (
        type(relation.failure_observation_order) is not int
        or type(relation.success_observation_order) is not int
        or not 1 <= relation.failure_observation_order <= len(case.observations)
        or not 1 <= relation.success_observation_order <= len(case.observations)
    ):
        _fail()
    failure_observation = case.observations[
        relation.failure_observation_order - 1
    ]
    success_observation = case.observations[
        relation.success_observation_order - 1
    ]
    if (
        failure_observation.observation_kind != "authentication_failure_fact"
        or success_observation.observation_kind != "authentication_success_fact"
        or failure_observation.start_time_utc != failure
        or success_observation.start_time_utc != success
    ):
        _fail()
    evidence = (
        InvestigationEvidenceProjection(
            "relation_time_delta_seconds", "시간 차이", delta, "초"
        ),
    )
    return _PendingTimelineEntry(
        identity_order=identity_order,
        category="SUPPORTED_RELATION",
        start=failure,
        end=success,
        display_title=display_name,
        subject_ip=case.subject_ip,
        detection_name=None,
        relation_name=display_name,
        evidence=evidence,
        interpretation_label=(
            "기존 상관분석이 계산한 지원 관계이며 인과관계를 의미하지 "
            "않습니다."
        ),
    )


def _timeline_sort_key(item: _PendingTimelineEntry) -> tuple:
    far_future = datetime.max.replace(tzinfo=timezone.utc)
    return (
        item.start is None,
        item.start or far_future,
        _CATEGORY_RANK[item.category],
        item.display_title.encode("utf-8"),
        item.identity_order,
    )


def _timeline_entry(
    pending: _PendingTimelineEntry,
    sequence: int,
) -> InvestigationTimelineEntryProjection:
    start = _format_timestamp(pending.start) if pending.start is not None else None
    end = _format_timestamp(pending.end) if pending.end is not None else None
    return InvestigationTimelineEntryProjection(
        sequence=sequence,
        category=pending.category,
        category_label=_CATEGORY_LABELS[pending.category],
        timestamp_state="TIMESTAMPED" if start is not None else "NO_TIME",
        timestamp_state_label=(
            "시각 정보 있음" if start is not None else "시간 정보 없음"
        ),
        start_time=start,
        end_time=end,
        display_title=pending.display_title,
        subject_label="분석 대상 IP",
        subject_ip=pending.subject_ip,
        account_alias=None,
        account_alias_status=_ACCOUNT_ALIAS_STATUS,
        detection_display_name=pending.detection_name,
        relation_display_name=pending.relation_name,
        evidence=pending.evidence,
        evidence_state=("AVAILABLE" if pending.evidence else "APPROVED_EVIDENCE_UNAVAILABLE"),
        interpretation_label=pending.interpretation_label,
    )


def _timeline(case: IncidentCase) -> tuple[
    tuple[InvestigationTimelineEntryProjection, ...],
    tuple[InvestigationTimelineEntryProjection, ...],
]:
    pending = []
    for order, observation in enumerate(case.observations, start=1):
        pending.append(_pending_observation(observation, order, case))
    relation_offset = len(case.observations)
    for order, relation in enumerate(case.relations, start=1):
        pending.append(_pending_relation(
            relation,
            relation_offset + order,
            case,
        ))
    pending.sort(key=_timeline_sort_key)
    projected = tuple(
        _timeline_entry(item, sequence)
        for sequence, item in enumerate(pending, start=1)
    )
    timestamped = tuple(
        item for item in projected if item.timestamp_state == "TIMESTAMPED"
    )
    without_time = tuple(
        item for item in projected if item.timestamp_state == "NO_TIME"
    )
    return timestamped, without_time


def _fixed_limitations(
    items: tuple[tuple[str, str], ...],
) -> tuple[InvestigationCaseLimitationProjection, ...]:
    return tuple(
        InvestigationCaseLimitationProjection(
            limitation_id=item_id,
            label="해석 시 유의사항",
            text=text,
        )
        for item_id, text in items
    )


def _assessment(case: IncidentCase) -> InvestigationCaseAssessmentProjection:
    return InvestigationCaseAssessmentProjection(
        risk_label="포함된 최고 위험도",
        included_highest_risk=_level(case.included_highest_risk),
        confidence_label="포함된 최고 신뢰도",
        included_highest_confidence=_level(case.included_highest_confidence),
        risk_context=(
            "기존 분석 대상 위험도 중 가장 높은 값이며 새 위험 점수가 "
            "아닙니다."
        ),
        review_order_context=(
            "조사 순서는 검토 탐색을 위한 값이며 새로운 보안 점수나 "
            "판정이 아닙니다."
        ),
    )


def _unverified_items() -> tuple[InvestigationCaseUnverifiedProjection, ...]:
    return tuple(
        InvestigationCaseUnverifiedProjection(
            item_id=item_id,
            label="확인되지 않은 사항",
            text=text,
        )
        for item_id, text in _UNVERIFIED_ITEMS
    )


def _next_steps(rule_code: str) -> tuple[InvestigationCaseNextStepProjection, ...]:
    if rule_code not in _NEXT_STEPS:
        _fail()
    return tuple(
        InvestigationCaseNextStepProjection(
            step_id=step_id,
            label="다음 조사 단계",
            text=text,
        )
        for step_id, text in _NEXT_STEPS[rule_code]
    )


def _validate_case_range(case: IncidentCase) -> tuple[datetime | None, datetime | None]:
    start = _utc(case.start_time_utc, optional=True)
    end = _utc(case.end_time_utc, optional=True)
    duration = case.duration_seconds
    if start is None or end is None:
        if start is not None or end is not None or duration is not None:
            _fail()
        return start, end
    duration = _number(duration)
    if end < start or (end - start).total_seconds() != duration:
        _fail()
    observation_starts = tuple(
        _utc(observation.start_time_utc)
        for observation in case.observations
        if observation.start_time_utc is not None
    )
    observation_ends = tuple(
        _utc(observation.end_time_utc or observation.start_time_utc)
        for observation in case.observations
        if observation.start_time_utc is not None
    )
    if (
        not observation_starts
        or min(observation_starts) != start
        or max(observation_ends) != end
    ):
        _fail()
    return start, end


def _project_case(
    case: IncidentCase,
    review_order: int,
) -> InvestigationCaseDetailProjection:
    if (
        type(case) is not IncidentCase
        or type(case.rule_id) is not str
        or case.rule_id not in _RULE_GROUPING_TEXT
    ):
        _fail()
    subject_ip = _subject(case.subject_ip)
    if type(case.observations) is not tuple or type(case.relations) is not tuple:
        _fail()
    if any(
        type(observation) is not IncidentCaseObservation
        for observation in case.observations
    ) or any(
        type(relation) is not IncidentCaseRelation
        or type(relation.relation_type) is not str
        for relation in case.relations
    ):
        _fail()
    if not case.relations:
        _fail()
    relation_types = tuple(
        relation.relation_type for relation in case.relations
    )
    if case.rule_id == "CASE-BRUTE-SUCCESS-01":
        if relation_types not in {
            ("brute_force_to_successful_login",),
            (
                "brute_force_to_successful_login",
                "failed_to_successful_login",
            ),
        }:
            _fail()
    elif relation_types != ("failed_to_successful_login",):
        _fail()
    start, end = _validate_case_range(case)
    timeline, without_time = _timeline(case)
    if (
        type(case.has_observation_without_timestamp) is not bool
        or case.has_observation_without_timestamp != bool(without_time)
    ):
        _fail()
    detection_names = tuple(
        entry.detection_display_name
        for entry in timeline + without_time
        if entry.detection_display_name is not None
    )
    relation_names = tuple(
        entry.relation_display_name
        for entry in timeline + without_time
        if entry.relation_display_name is not None
    )
    if not relation_names:
        _fail()
    if case.rule_id == "CASE-BRUTE-SUCCESS-01":
        if "Brute Force" not in detection_names or (
            "Brute Force → Successful Login" not in relation_names
        ):
            _fail()
    elif case.rule_id == "CASE-AUTH-TRANSITION-01":
        if "Failed Login → Successful Login" not in relation_names:
            _fail()
    row = InvestigationCaseRowProjection(
        review_order=review_order,
        case_label=f"조사 사례 {review_order}",
        subject_label="분석 대상 IP",
        subject_ip=subject_ip,
        risk_label="포함된 최고 위험도",
        included_highest_risk=_level(case.included_highest_risk),
        confidence_label="포함된 최고 신뢰도",
        included_highest_confidence=_level(case.included_highest_confidence),
        start_time=_format_timestamp(start) if start is not None else None,
        end_time=_format_timestamp(end) if end is not None else None,
        observation_count=len(case.observations),
        supporting_relation_count=len(case.relations),
        primary_detection_display_name=(
            detection_names[0] if detection_names else None
        ),
        primary_relation_display_name=relation_names[0],
        grouping_explanation=_RULE_GROUPING_TEXT[case.rule_id],
        account_alias=None,
        account_alias_status=_ACCOUNT_ALIAS_STATUS,
    )
    return InvestigationCaseDetailProjection(
        rule_code=case.rule_id,
        row=row,
        timeline_label="시간순 조사 흐름",
        timeline_entries=timeline,
        timeline_entries_without_time=without_time,
        assessment=_assessment(case),
        limitations=_fixed_limitations(_CASE_LIMITATIONS[case.rule_id]),
        unverified_items=_unverified_items(),
        next_steps=_next_steps(case.rule_id),
    )


def _independent_category(observation: IncidentCaseObservation) -> str:
    if observation.observation_kind in {
        "supported_detection_observation",
        "unsupported_detection_observation",
    }:
        return "탐지 관찰"
    if observation.observation_kind == "supported_correlation_relation":
        return "지원되는 관계"
    if observation.observation_kind == "unsupported_correlation_relation":
        return "지원 범위 밖의 관계"
    _fail()


def _independent_reason(item: IndependentObservation) -> str:
    if (
        type(item.reason) is not str
        or item.reason not in _INDEPENDENT_REASON_TEXT
    ):
        _fail()
    observation_type = item.observation.observation_type
    if observation_type == "path_traversal":
        return "Path Traversal은 V1 인증 사례와 자동 결합하지 않습니다."
    if observation_type in {
        "password_spraying_like",
        "password_spray_to_successful_login",
    }:
        return (
            "Password Spraying-like 관찰은 유지되었지만 성공 로그인 "
            "계정이 탐지 대상에 포함됨을 형식이 보장된 내부 계약으로 "
            "입증하지 못해 자동 사례 "
            "결합을 수행하지 않았습니다."
        )
    return _INDEPENDENT_REASON_TEXT[item.reason]


def _project_independent(
    item: IndependentObservation,
    review_order: int,
) -> IndependentObservationProjection:
    if type(item) is not IndependentObservation:
        _fail()
    observation = item.observation
    if type(observation) is not IncidentCaseObservation:
        _fail()
    if (
        type(observation.observation_type) is not str
        or observation.observation_type not in _OBSERVATION_DISPLAY_NAMES
        or type(observation.observation_kind) is not str
        or type(observation.source_category) is not str
    ):
        _fail()
    if observation.display_name != _PHASE_ONE_DISPLAY_NAMES[
        observation.observation_type
    ]:
        _fail()
    if observation.source_category != "analysis_rule":
        _fail()
    subject_ip = _subject(observation.subject_ip)
    start = _utc(observation.start_time_utc, optional=True)
    end = _utc(observation.end_time_utc, optional=True)
    if end is not None and (start is None or end < start):
        _fail()
    evidence = _project_evidence(observation.observation_type, observation.evidence)
    return IndependentObservationProjection(
        review_order=review_order,
        label="독립 관찰",
        category_label=_independent_category(observation),
        display_type=_OBSERVATION_DISPLAY_NAMES[observation.observation_type],
        subject_label="분석 대상 IP",
        subject_ip=subject_ip,
        existing_risk_level=_level(observation.existing_risk_level),
        existing_confidence=_level(observation.existing_confidence),
        start_time=_format_timestamp(start) if start is not None else None,
        end_time=_format_timestamp(end) if end is not None else None,
        timestamp_state="TIMESTAMPED" if start is not None else "NO_TIME",
        timestamp_state_label=(
            "시각 정보 있음" if start is not None else "시간 정보 없음"
        ),
        account_alias=None,
        account_alias_status=_ACCOUNT_ALIAS_STATUS,
        evidence=evidence,
        evidence_state=("AVAILABLE" if evidence else "APPROVED_EVIDENCE_UNAVAILABLE"),
        reason_id=item.reason,
        reason_text=_independent_reason(item),
    )


def _notices(
    summary: InvestigationCaseSummaryProjection,
) -> tuple[InvestigationCaseNoticeProjection, ...]:
    notices = []
    if summary.case_count == 0:
        notices.append(InvestigationCaseNoticeProjection(
            "no_cases",
            "지원되는 규칙으로 구성된 조사 사례가 없습니다.",
            "이는 보안 문제의 부재를 의미하지 않습니다.",
        ))
    if summary.independent_observation_count == 0:
        notices.append(InvestigationCaseNoticeProjection(
            "no_independent_observations",
            "표시할 독립 관찰이 없습니다.",
            "독립 관찰 수는 조사 사례의 보안 결론을 변경하지 않습니다.",
        ))
    if summary.observations_without_time_count > 0:
        notices.append(InvestigationCaseNoticeProjection(
            "observations_without_time",
            "시간 정보가 없는 관찰은 시간순 항목 뒤에 분리됩니다.",
            "현재 시각이나 사례 시작·종료 시각으로 보완하지 않습니다.",
        ))
    if summary.supported_detection_observation_count == 0:
        notices.append(InvestigationCaseNoticeProjection(
            "no_detection_observations",
            "표시할 탐지 관찰이 없습니다.",
            "이는 보안 문제 또는 악의적 활동의 부재를 의미하지 않습니다.",
        ))
    if summary.supported_relation_observation_count == 0:
        notices.append(InvestigationCaseNoticeProjection(
            "no_supported_relations",
            "표시할 지원되는 관계가 없습니다.",
            "이는 관계 또는 악의적 활동의 부재를 뜻하지 않습니다.",
        ))
    if summary.case_count == 0:
        notices.append(InvestigationCaseNoticeProjection(
            "no_next_steps",
            "표시할 조사 사례별 다음 조사 단계가 없습니다.",
            "독립 관찰과 원본 시스템 기록을 별도로 검토하십시오.",
        ))
    if summary.spray_no_go_observation_count > 0:
        notices.append(InvestigationCaseNoticeProjection(
            "spray_case_no_go",
            (
                "Password Spraying-like 관찰은 독립 관찰로 유지되었습니다."
            ),
            (
                "성공 로그인 계정이 탐지 대상에 포함됨을 형식이 보장된 "
                "내부 계약으로 입증하지 못해 "
                "자동 사례 결합을 수행하지 않았으며, 이는 보안 문제의 "
                "부재를 의미하지 않습니다."
            ),
        ))
    return tuple(notices)


def _validate_unsupported_rules(
    rules: tuple[UnsupportedCaseRule, ...],
) -> None:
    if type(rules) is not tuple or len(rules) != 1:
        _fail()
    rule = rules[0]
    if (
        type(rule) is not UnsupportedCaseRule
        or rule.rule_id != "CASE-SPRAY-SUCCESS-01"
        or rule.status_code != CASE_SPRAY_SUCCESS_STATUS
    ):
        _fail()


def build_investigation_case_projection(
    assembly: IncidentCaseAssembly,
) -> InvestigationCaseProjection:
    if type(assembly) is not IncidentCaseAssembly:
        _fail()
    if type(assembly.cases) is not tuple or type(
        assembly.independent_observations
    ) is not tuple:
        _fail()
    _validate_unsupported_rules(assembly.unsupported_case_rules)
    cases = tuple(
        _project_case(case, review_order)
        for review_order, case in enumerate(assembly.cases, start=1)
    )
    independent = tuple(
        _project_independent(item, review_order)
        for review_order, item in enumerate(
            assembly.independent_observations,
            start=1,
        )
    )
    risk_counts = {
        level: sum(
            case.row.included_highest_risk == level for case in cases
        )
        for level in ("HIGH", "MEDIUM", "LOW")
    }
    without_time_count = sum(
        len(case.timeline_entries_without_time) for case in cases
    ) + sum(
        item.timestamp_state == "NO_TIME" for item in independent
    )
    spray_count = sum(
        item.display_type.startswith("Password Spraying-like")
        for item in independent
    )
    supported_detection_count = sum(
        entry.category == "DETECTION_OBSERVATION"
        for case in cases
        for entry in case.timeline_entries + case.timeline_entries_without_time
    ) + sum(
        item.category_label == "탐지 관찰"
        and item.display_type != "지원되지 않는 탐지 관찰"
        for item in independent
    )
    supported_relation_count = sum(
        entry.category == "SUPPORTED_RELATION"
        for case in cases
        for entry in case.timeline_entries + case.timeline_entries_without_time
    ) + sum(
        item.category_label == "지원되는 관계"
        and item.display_type != "지원되지 않는 관계 관찰"
        for item in independent
    )
    summary = InvestigationCaseSummaryProjection(
        case_count=len(cases),
        independent_observation_count=len(independent),
        high_case_count=risk_counts["HIGH"],
        medium_case_count=risk_counts["MEDIUM"],
        low_case_count=risk_counts["LOW"],
        cases_with_supported_relation_count=sum(
            bool(case.row.supporting_relation_count) for case in cases
        ),
        supported_detection_observation_count=supported_detection_count,
        supported_relation_observation_count=supported_relation_count,
        observations_without_time_count=without_time_count,
        spray_no_go_observation_count=spray_count,
    )
    if summary.case_count != (
        summary.high_case_count
        + summary.medium_case_count
        + summary.low_case_count
    ):
        _fail()
    return InvestigationCaseProjection(
        schema_version=_SCHEMA_VERSION,
        classification=_CLASSIFICATION,
        title="조사 사례",
        summary=summary,
        cases=cases,
        independent_observations=independent,
        report_limitations=_fixed_limitations(_REPORT_LIMITATIONS),
        notices=_notices(summary),
        account_alias_status=_ACCOUNT_ALIAS_STATUS,
        account_alias_message=_ACCOUNT_ALIAS_MESSAGE,
    )
