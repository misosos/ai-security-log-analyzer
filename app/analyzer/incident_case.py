from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
import math
from types import MappingProxyType
import unicodedata
from typing import Literal

from app.models.schemas import DetectionResult, Evidence


CaseRuleId = Literal[
    "CASE-AUTH-TRANSITION-01",
    "CASE-BRUTE-SUCCESS-01",
]
ObservationKind = Literal[
    "authentication_failure_fact",
    "authentication_success_fact",
    "supported_detection_observation",
    "unsupported_detection_observation",
    "supported_correlation_relation",
    "unsupported_correlation_relation",
]
IndependentReason = Literal[
    "no_supported_relation",
    "unsupported_for_case_assembly",
    "invalid_timestamp",
    "relationship_not_proven",
]
RiskLevel = Literal["HIGH", "MEDIUM", "LOW"]


CASE_RULE_PRECEDENCE: tuple[CaseRuleId, ...] = (
    "CASE-BRUTE-SUCCESS-01",
    "CASE-AUTH-TRANSITION-01",
)
SUPPORTED_CASE_RULES: tuple[CaseRuleId, ...] = CASE_RULE_PRECEDENCE
CASE_SPRAY_SUCCESS_STATUS = (
    "NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP"
)

_ASSEMBLY_ERROR_MESSAGES = MappingProxyType({
    "invalid_input": "Incident case assembly failed: invalid input contract.",
    "ambiguous_membership": (
        "Incident case assembly failed: ambiguous observation membership."
    ),
})
_RANK = MappingProxyType({"HIGH": 0, "MEDIUM": 1, "LOW": 2})
_DETECTION_TYPES = MappingProxyType({
    "brute_force": "brute_force",
    "password_spray": "password_spraying_like",
    "path_traversal": "path_traversal",
})
_DETECTION_NAMES = MappingProxyType({
    "brute_force": "Brute Force",
    "password_spraying_like": "Password Spraying-like",
    "path_traversal": "Path Traversal",
    "unsupported_detection": "Unsupported detection",
})
_CORRELATION_TYPES = MappingProxyType({
    "authentication": "failed_to_successful_login",
    "post_authentication": "successful_login_to_file_access",
    "brute_force_to_success": "brute_force_to_successful_login",
    "password_spray_to_success": "password_spray_to_successful_login",
})
_CORRELATION_NAMES = MappingProxyType({
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
    "unsupported_correlation": "Unsupported correlation",
})
_RELATION_RANK = MappingProxyType({
    "brute_force_to_successful_login": 0,
    "failed_to_successful_login": 1,
})
_OBSERVATION_RANK = MappingProxyType({
    "authentication_failure_fact": 0,
    "authentication_success_fact": 0,
    "supported_detection_observation": 1,
    "unsupported_detection_observation": 2,
    "supported_correlation_relation": 3,
    "unsupported_correlation_relation": 4,
})


class IncidentCaseAssemblyError(ValueError):
    def __init__(self, code: str):
        message = _ASSEMBLY_ERROR_MESSAGES.get(
            code,
            _ASSEMBLY_ERROR_MESSAGES["invalid_input"],
        )
        self.code = (
            code if code in _ASSEMBLY_ERROR_MESSAGES else "invalid_input"
        )
        super().__init__(message)


@dataclass(frozen=True)
class IncidentCaseDetectionInput:
    slot: Literal["brute_force", "password_spray", "path_traversal"]
    detection: DetectionResult = field(repr=False)


@dataclass(frozen=True)
class IncidentCaseCorrelationInput:
    slot: Literal[
        "authentication",
        "post_authentication",
        "brute_force_to_success",
        "password_spray_to_success",
    ]
    is_correlated: bool
    correlation_type: str | None
    account: str | None = field(repr=False)
    failure_timestamp: datetime | None = None
    success_timestamp: datetime | None = None
    time_delta_seconds: int | float | None = None


@dataclass(frozen=True)
class IncidentCaseSubjectInput:
    subject_ip: str
    target_accounts: tuple[str, ...] = field(repr=False)
    detections: tuple[IncidentCaseDetectionInput, ...] = ()
    correlations: tuple[IncidentCaseCorrelationInput, ...] = ()
    risk_level: RiskLevel = "LOW"
    confidence: RiskLevel = "LOW"


@dataclass(frozen=True)
class IncidentCaseEvidenceScalar:
    evidence_type: Literal[
        "failed_attempt_count",
        "target_account_count",
        "time_window_seconds",
    ]
    value: int | float


@dataclass(frozen=True)
class IncidentCaseObservation:
    observation_kind: ObservationKind
    observation_type: str
    display_name: str
    subject_ip: str
    start_time_utc: datetime | None
    end_time_utc: datetime | None
    source_category: Literal["authentication", "analysis_rule"]
    evidence: tuple[IncidentCaseEvidenceScalar, ...]
    existing_risk_level: RiskLevel
    existing_confidence: RiskLevel


@dataclass(frozen=True)
class IncidentCaseRelation:
    relation_type: Literal[
        "failed_to_successful_login",
        "brute_force_to_successful_login",
    ]
    display_name: str
    subject_ip: str
    failure_observation_order: int
    success_observation_order: int
    failure_timestamp_utc: datetime
    success_timestamp_utc: datetime
    time_delta_seconds: int | float


@dataclass(frozen=True)
class IncidentCase:
    rule_id: CaseRuleId
    subject_ip: str
    observations: tuple[IncidentCaseObservation, ...]
    relations: tuple[IncidentCaseRelation, ...]
    included_highest_risk: RiskLevel
    included_highest_confidence: RiskLevel
    start_time_utc: datetime | None
    end_time_utc: datetime | None
    duration_seconds: int | float | None
    has_observation_without_timestamp: bool


@dataclass(frozen=True)
class IndependentObservation:
    observation: IncidentCaseObservation
    reason: IndependentReason


@dataclass(frozen=True)
class UnsupportedCaseRule:
    rule_id: Literal["CASE-SPRAY-SUCCESS-01"]
    status_code: Literal[
        "NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP"
    ]


@dataclass(frozen=True)
class IncidentCaseAssembly:
    cases: tuple[IncidentCase, ...]
    independent_observations: tuple[IndependentObservation, ...]
    unsupported_case_rules: tuple[UnsupportedCaseRule, ...]


@dataclass(frozen=True)
class _DetectionCandidate:
    key: tuple
    observation: IncidentCaseObservation
    slot: str
    target_accounts: tuple[str, ...] = field(default=(), repr=False)
    valid_for_grouping: bool = False


@dataclass(frozen=True)
class _RelationCandidate:
    key: tuple
    observation: IncidentCaseObservation
    slot: str
    relation_type: str
    account: str = field(repr=False)
    failure_timestamp: datetime | None = None
    success_timestamp: datetime | None = None
    time_delta_seconds: int | float | None = None
    valid_for_grouping: bool = False


def _fail(code: str = "invalid_input") -> None:
    raise IncidentCaseAssemblyError(code) from None


def _level(value: object) -> RiskLevel:
    if type(value) is not str or value not in _RANK:
        _fail()
    return value


def _canonical_ip(value: object) -> tuple[str, tuple[int, bytes]]:
    if type(value) is not str:
        _fail()
    try:
        parsed = ip_address(value)
    except ValueError:
        _fail()
    if type(parsed) is IPv4Address:
        family = 4
    elif type(parsed) is IPv6Address and parsed.scope_id is None:
        family = 6
    else:
        _fail()
    return str(parsed), (family, parsed.packed)


def _account(value: object) -> str:
    if type(value) is not str or not value.strip():
        _fail()
    if any(unicodedata.category(character) == "Cc" for character in value):
        _fail()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail()
    return value


def _utc(value: object) -> datetime | None:
    if type(value) is not datetime or value.tzinfo is None:
        return None
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        return None
    return value.astimezone(timezone.utc)


def _non_negative_number(value: object) -> int | float | None:
    if type(value) is int and value >= 0:
        return value
    if type(value) is float and math.isfinite(value) and value >= 0:
        return value
    return None


def _non_negative_int(value: object) -> int | None:
    if type(value) is int and value >= 0:
        return value
    return None


def _optional_time_sort_key(value: datetime | None) -> tuple[bool, datetime]:
    return (
        value is None,
        value or datetime.max.replace(tzinfo=timezone.utc),
    )


def _evidence_map(
    detection: DetectionResult,
    expected_types: tuple[str, ...],
    expected_source: str,
) -> dict[str, Evidence] | None:
    if type(detection.evidence) is not list:
        return None
    by_type = {}
    for item in detection.evidence:
        if (
            type(item) is not Evidence
            or type(item.type) is not str
            or item.type in by_type
            or item.source != expected_source
        ):
            return None
        by_type[item.type] = item
    if set(by_type) != set(expected_types):
        return None
    return by_type


def _authentication_detection_candidate(
    subject_ip: str,
    detection_input: IncidentCaseDetectionInput,
    target_accounts: tuple[str, ...],
    risk: RiskLevel,
    confidence: RiskLevel,
) -> _DetectionCandidate:
    detection = detection_input.detection
    detection_type = _DETECTION_TYPES[detection_input.slot]
    target_type = (
        "single_target_user"
        if detection_input.slot == "brute_force"
        else "multiple_target_users"
    )
    source = (
        "brute_force_detector"
        if detection_input.slot == "brute_force"
        else "password_spray_detector"
    )
    items = _evidence_map(
        detection,
        (
            "multiple_login_failures",
            target_type,
            "failures_within_short_window",
        ),
        source,
    )
    start = None
    end = None
    evidence = ()
    valid = False
    reason_type = detection_type
    if items is not None:
        failed_count = _non_negative_int(
            items["multiple_login_failures"].value
        )
        target_count = _non_negative_int(items[target_type].value)
        window = _non_negative_number(
            items["failures_within_short_window"].value
        )
        time_range = items["multiple_login_failures"].time_range
        if type(time_range) is tuple and len(time_range) == 2:
            start = _utc(time_range[0])
            end = _utc(time_range[1])
        timestamps_valid = (
            start is not None
            and end is not None
            and start <= end
        )
        if (
            failed_count is not None
            and target_count is not None
            and window is not None
            and timestamps_valid
            and (end - start).total_seconds() == window
            and window <= 60
            and target_count == len(target_accounts)
        ):
            evidence = (
                IncidentCaseEvidenceScalar(
                    "failed_attempt_count", failed_count
                ),
                IncidentCaseEvidenceScalar(
                    "target_account_count", target_count
                ),
                IncidentCaseEvidenceScalar("time_window_seconds", window),
            )
            valid = True
        else:
            invalid_timestamp = not timestamps_valid
            start = None
            end = None
            reason_type = (
                f"{detection_type}_invalid_timestamp"
                if invalid_timestamp
                else f"{detection_type}_invalid_contract"
            )

    observation = IncidentCaseObservation(
        observation_kind="supported_detection_observation",
        observation_type=reason_type,
        display_name=_DETECTION_NAMES[detection_type],
        subject_ip=subject_ip,
        start_time_utc=start,
        end_time_utc=end,
        source_category="analysis_rule",
        evidence=evidence,
        existing_risk_level=risk,
        existing_confidence=confidence,
    )
    key = (
        subject_ip,
        detection_input.slot,
        detection_type,
        start,
        end,
        evidence,
    )
    return _DetectionCandidate(
        key=key,
        observation=observation,
        slot=detection_input.slot,
        target_accounts=target_accounts,
        valid_for_grouping=(
            valid and detection_input.slot == "brute_force"
        ),
    )


def _path_or_unsupported_detection_candidate(
    subject_ip: str,
    detection_input: IncidentCaseDetectionInput,
    risk: RiskLevel,
    confidence: RiskLevel,
) -> _DetectionCandidate:
    detection = detection_input.detection
    expected_type = _DETECTION_TYPES[detection_input.slot]
    supported = detection.detection_type == expected_type
    timestamp = None
    if supported and type(detection.evidence) is list:
        timestamps = [
            _utc(item.timestamp)
            for item in detection.evidence
            if type(item) is Evidence and item.timestamp is not None
        ]
        if timestamps and all(item is not None for item in timestamps):
            timestamp = min(timestamps)
    observation_type = (
        expected_type if supported else "unsupported_detection"
    )
    observation = IncidentCaseObservation(
        observation_kind=(
            "supported_detection_observation"
            if supported
            else "unsupported_detection_observation"
        ),
        observation_type=observation_type,
        display_name=_DETECTION_NAMES[observation_type],
        subject_ip=subject_ip,
        start_time_utc=timestamp,
        end_time_utc=None,
        source_category="analysis_rule",
        evidence=(),
        existing_risk_level=risk,
        existing_confidence=confidence,
    )
    return _DetectionCandidate(
        key=(
            subject_ip,
            detection_input.slot,
            observation_type,
            timestamp,
        ),
        observation=observation,
        slot=detection_input.slot,
    )


def _detection_candidates(
    subject_ip: str,
    detection_inputs: tuple[IncidentCaseDetectionInput, ...],
    target_accounts: tuple[str, ...],
    risk: RiskLevel,
    confidence: RiskLevel,
) -> tuple[_DetectionCandidate, ...]:
    candidates = {}
    for item in detection_inputs:
        if type(item) is not IncidentCaseDetectionInput:
            _fail()
        if item.slot not in _DETECTION_TYPES:
            _fail()
        detection = item.detection
        if type(detection) is not DetectionResult:
            _fail()
        if type(detection.is_detected) is not bool:
            _fail()
        if not detection.is_detected:
            if detection.detection_type is not None or detection.evidence != []:
                _fail()
            continue
        if type(detection.detection_type) is not str:
            _fail()
        if (
            detection.detection_type == _DETECTION_TYPES[item.slot]
            and item.slot in {"brute_force", "password_spray"}
        ):
            candidate = _authentication_detection_candidate(
                subject_ip,
                item,
                target_accounts,
                risk,
                confidence,
            )
        else:
            candidate = _path_or_unsupported_detection_candidate(
                subject_ip,
                item,
                risk,
                confidence,
            )
        candidates.setdefault(candidate.key, candidate)
    return tuple(
        sorted(
            candidates.values(),
            key=lambda candidate: (
                candidate.slot,
                candidate.observation.observation_type,
                _optional_time_sort_key(
                    candidate.observation.start_time_utc
                ),
                _optional_time_sort_key(
                    candidate.observation.end_time_utc
                ),
                tuple(
                    (item.evidence_type, item.value)
                    for item in candidate.observation.evidence
                ),
            ),
        )
    )


def _relation_candidate(
    subject_ip: str,
    item: IncidentCaseCorrelationInput,
    risk: RiskLevel,
    confidence: RiskLevel,
) -> _RelationCandidate | None:
    if type(item.is_correlated) is not bool:
        _fail()
    if not item.is_correlated:
        if (
            item.correlation_type is not None
            or item.account is not None
            or item.failure_timestamp is not None
            or item.success_timestamp is not None
            or item.time_delta_seconds is not None
        ):
            _fail()
        return None
    if type(item.correlation_type) is not str:
        _fail()
    account = _account(item.account)
    expected_type = _CORRELATION_TYPES[item.slot]
    type_matches = item.correlation_type == expected_type
    supported_type = item.correlation_type in {
        "failed_to_successful_login",
        "brute_force_to_successful_login",
    }
    failure = _utc(item.failure_timestamp)
    success = _utc(item.success_timestamp)
    delta = _non_negative_number(item.time_delta_seconds)
    valid_endpoints = (
        failure is not None
        and success is not None
        and delta is not None
        and failure < success
        and (success - failure).total_seconds() == delta
        and delta <= 60
    )
    valid = type_matches and supported_type and valid_endpoints
    if type_matches and item.correlation_type in _CORRELATION_NAMES:
        safe_type = item.correlation_type
        display_name = _CORRELATION_NAMES[safe_type]
        kind = "supported_correlation_relation"
    else:
        safe_type = "unsupported_correlation"
        display_name = _CORRELATION_NAMES[safe_type]
        kind = "unsupported_correlation_relation"
    if supported_type and type_matches and not valid_endpoints:
        safe_type = f"{item.correlation_type}_invalid_timestamp"
        display_name = _CORRELATION_NAMES[item.correlation_type]
    observation = IncidentCaseObservation(
        observation_kind=kind,
        observation_type=safe_type,
        display_name=display_name,
        subject_ip=subject_ip,
        start_time_utc=failure if valid_endpoints else None,
        end_time_utc=success if valid_endpoints else None,
        source_category="analysis_rule",
        evidence=(),
        existing_risk_level=risk,
        existing_confidence=confidence,
    )
    key = (
        subject_ip,
        item.slot,
        item.correlation_type,
        account,
        failure,
        success,
        delta,
    )
    return _RelationCandidate(
        key=key,
        observation=observation,
        slot=item.slot,
        relation_type=item.correlation_type,
        account=account,
        failure_timestamp=failure,
        success_timestamp=success,
        time_delta_seconds=delta,
        valid_for_grouping=valid,
    )


def _relation_candidates(
    subject_ip: str,
    relation_inputs: tuple[IncidentCaseCorrelationInput, ...],
    risk: RiskLevel,
    confidence: RiskLevel,
) -> tuple[_RelationCandidate, ...]:
    candidates = {}
    for item in relation_inputs:
        if type(item) is not IncidentCaseCorrelationInput:
            _fail()
        if item.slot not in _CORRELATION_TYPES:
            _fail()
        candidate = _relation_candidate(subject_ip, item, risk, confidence)
        if candidate is not None:
            candidates.setdefault(candidate.key, candidate)
    return tuple(
        sorted(
            candidates.values(),
            key=lambda candidate: (
                candidate.slot,
                candidate.relation_type,
                candidate.account.encode("utf-8"),
                _optional_time_sort_key(candidate.failure_timestamp),
                _optional_time_sort_key(candidate.success_timestamp),
                candidate.time_delta_seconds is None,
                candidate.time_delta_seconds
                if candidate.time_delta_seconds is not None
                else math.inf,
            ),
        )
    )


def _fact_observation(
    kind: Literal[
        "authentication_failure_fact",
        "authentication_success_fact",
    ],
    subject_ip: str,
    timestamp: datetime,
    risk: RiskLevel,
    confidence: RiskLevel,
) -> IncidentCaseObservation:
    return IncidentCaseObservation(
        observation_kind=kind,
        observation_type=(
            "authentication_failure"
            if kind == "authentication_failure_fact"
            else "authentication_success"
        ),
        display_name=(
            "Authentication Failure"
            if kind == "authentication_failure_fact"
            else "Authentication Success"
        ),
        subject_ip=subject_ip,
        start_time_utc=timestamp,
        end_time_utc=None,
        source_category="authentication",
        evidence=(),
        existing_risk_level=risk,
        existing_confidence=confidence,
    )


def _observation_sort_key(observation: IncidentCaseObservation) -> tuple:
    return (
        observation.start_time_utc is None,
        observation.start_time_utc or datetime.max.replace(tzinfo=timezone.utc),
        observation.end_time_utc or observation.start_time_utc
        or datetime.max.replace(tzinfo=timezone.utc),
        _OBSERVATION_RANK[observation.observation_kind],
        observation.observation_type,
    )


def _build_case(
    rule_id: CaseRuleId,
    subject_ip: str,
    risk: RiskLevel,
    confidence: RiskLevel,
    detection: _DetectionCandidate | None,
    specific_relation: _RelationCandidate,
    supporting_relations: tuple[_RelationCandidate, ...],
) -> IncidentCase:
    failure = specific_relation.failure_timestamp
    success = specific_relation.success_timestamp
    if failure is None or success is None:
        _fail()
    observations = [
        _fact_observation(
            "authentication_failure_fact",
            subject_ip,
            failure,
            risk,
            confidence,
        ),
        _fact_observation(
            "authentication_success_fact",
            subject_ip,
            success,
            risk,
            confidence,
        ),
    ]
    if detection is not None:
        observations.append(detection.observation)
    observations.sort(key=_observation_sort_key)
    observations_tuple = tuple(observations)
    failure_order = next(
        index
        for index, observation in enumerate(observations_tuple, start=1)
        if observation.observation_kind == "authentication_failure_fact"
    )
    success_order = next(
        index
        for index, observation in enumerate(observations_tuple, start=1)
        if observation.observation_kind == "authentication_success_fact"
    )
    relations = []
    for candidate in (specific_relation,) + supporting_relations:
        delta = candidate.time_delta_seconds
        if type(delta) not in {int, float}:
            _fail()
        relations.append(IncidentCaseRelation(
            relation_type=candidate.relation_type,
            display_name=_CORRELATION_NAMES[candidate.relation_type],
            subject_ip=subject_ip,
            failure_observation_order=failure_order,
            success_observation_order=success_order,
            failure_timestamp_utc=failure,
            success_timestamp_utc=success,
            time_delta_seconds=delta,
        ))
    relations.sort(key=lambda relation: _RELATION_RANK[relation.relation_type])
    known_starts = [
        observation.start_time_utc
        for observation in observations_tuple
        if observation.start_time_utc is not None
    ]
    known_ends = [
        observation.end_time_utc or observation.start_time_utc
        for observation in observations_tuple
        if observation.start_time_utc is not None
    ]
    start = min(known_starts) if known_starts else None
    end = max(known_ends) if known_ends else None
    duration = (end - start).total_seconds() if start and end else None
    return IncidentCase(
        rule_id=rule_id,
        subject_ip=subject_ip,
        observations=observations_tuple,
        relations=tuple(relations),
        included_highest_risk=risk,
        included_highest_confidence=confidence,
        start_time_utc=start,
        end_time_utc=end,
        duration_seconds=duration,
        has_observation_without_timestamp=any(
            observation.start_time_utc is None
            for observation in observations_tuple
        ),
    )


def _independent(
    observation: IncidentCaseObservation,
    reason: IndependentReason,
) -> IndependentObservation:
    return IndependentObservation(observation=observation, reason=reason)


def _assemble_subject(
    subject: IncidentCaseSubjectInput,
) -> tuple[tuple[IncidentCase, ...], tuple[IndependentObservation, ...]]:
    canonical_ip, _ = _canonical_ip(subject.subject_ip)
    risk = _level(subject.risk_level)
    confidence = _level(subject.confidence)
    if type(subject.target_accounts) is not tuple:
        _fail()
    target_accounts = tuple(_account(value) for value in subject.target_accounts)
    if len(set(target_accounts)) != len(target_accounts):
        _fail()
    if type(subject.detections) is not tuple or type(subject.correlations) is not tuple:
        _fail()
    detections = _detection_candidates(
        canonical_ip,
        subject.detections,
        target_accounts,
        risk,
        confidence,
    )
    relations = _relation_candidates(
        canonical_ip,
        subject.correlations,
        risk,
        confidence,
    )

    consumed_detections = set()
    consumed_relations = set()
    consumed_facts = set()
    cases = []
    brute_detections = [
        detection
        for detection in detections
        if detection.slot == "brute_force" and detection.valid_for_grouping
    ]
    brute_relations = [
        relation
        for relation in relations
        if relation.slot == "brute_force_to_success"
        and relation.valid_for_grouping
    ]
    generic_relations = [
        relation
        for relation in relations
        if relation.slot == "authentication" and relation.valid_for_grouping
    ]

    for relation in brute_relations:
        matching_detections = [
            detection
            for detection in brute_detections
            if relation.account in detection.target_accounts
            and detection.observation.start_time_utc is not None
            and detection.observation.end_time_utc is not None
            and relation.failure_timestamp is not None
            and detection.observation.start_time_utc
            <= relation.failure_timestamp
            <= detection.observation.end_time_utc
            and relation.success_timestamp is not None
            and (
                relation.success_timestamp
                - detection.observation.start_time_utc
            ).total_seconds()
            <= 120
        ]
        if len(matching_detections) > 1:
            _fail("ambiguous_membership")
        if not matching_detections:
            continue
        detection = matching_detections[0]
        if detection.key in consumed_detections:
            _fail("ambiguous_membership")
        fact_keys = {
            (relation.account, "failure", relation.failure_timestamp),
            (relation.account, "success", relation.success_timestamp),
        }
        if consumed_facts & fact_keys:
            _fail("ambiguous_membership")
        supporting = tuple(
            generic
            for generic in generic_relations
            if generic.account == relation.account
            and generic.failure_timestamp == relation.failure_timestamp
            and generic.success_timestamp == relation.success_timestamp
            and generic.time_delta_seconds == relation.time_delta_seconds
        )
        case = _build_case(
            "CASE-BRUTE-SUCCESS-01",
            canonical_ip,
            risk,
            confidence,
            detection,
            relation,
            supporting,
        )
        if case.duration_seconds is None or case.duration_seconds > 120:
            continue
        cases.append(case)
        consumed_detections.add(detection.key)
        consumed_relations.add(relation.key)
        consumed_relations.update(item.key for item in supporting)
        consumed_facts.update(fact_keys)

    for relation in generic_relations:
        if relation.key in consumed_relations:
            continue
        fact_keys = {
            (relation.account, "failure", relation.failure_timestamp),
            (relation.account, "success", relation.success_timestamp),
        }
        if consumed_facts & fact_keys:
            continue
        endpoint = (
            relation.account,
            relation.failure_timestamp,
            relation.success_timestamp,
        )
        if any(
            other.key not in consumed_relations
            and other is not relation
            and (
                other.account,
                other.failure_timestamp,
                other.success_timestamp,
            ) != endpoint
            and (
                other.failure_timestamp == relation.failure_timestamp
                or other.success_timestamp == relation.success_timestamp
            )
            for other in generic_relations
        ):
            _fail("ambiguous_membership")
        cases.append(_build_case(
            "CASE-AUTH-TRANSITION-01",
            canonical_ip,
            risk,
            confidence,
            None,
            relation,
            (),
        ))
        consumed_relations.add(relation.key)
        consumed_facts.update(fact_keys)

    independent = []
    for detection in detections:
        if detection.key in consumed_detections:
            continue
        reason: IndependentReason
        if detection.observation.start_time_utc is None and (
            "invalid_timestamp" in detection.observation.observation_type
        ):
            reason = "invalid_timestamp"
        elif detection.slot in {"password_spray", "path_traversal"}:
            reason = "unsupported_for_case_assembly"
        else:
            reason = "no_supported_relation"
        independent.append(_independent(detection.observation, reason))
    for relation in relations:
        if relation.key in consumed_relations:
            continue
        if "invalid_timestamp" in relation.observation.observation_type:
            reason = "invalid_timestamp"
        elif relation.slot in {
            "post_authentication",
            "password_spray_to_success",
        } or relation.observation.observation_kind == (
            "unsupported_correlation_relation"
        ):
            reason = "unsupported_for_case_assembly"
        else:
            reason = "relationship_not_proven"
        independent.append(_independent(relation.observation, reason))
    return tuple(cases), tuple(independent)


def _case_sort_key(case: IncidentCase) -> tuple:
    _, ip_key = _canonical_ip(case.subject_ip)
    return (
        _RANK[case.included_highest_risk],
        0 if case.relations else 1,
        _RANK[case.included_highest_confidence],
        case.start_time_utc is None,
        case.start_time_utc or datetime.max.replace(tzinfo=timezone.utc),
        ip_key,
        CASE_RULE_PRECEDENCE.index(case.rule_id),
        tuple(relation.relation_type for relation in case.relations),
    )


def _independent_sort_key(item: IndependentObservation) -> tuple:
    observation = item.observation
    _, ip_key = _canonical_ip(observation.subject_ip)
    return (
        _RANK[observation.existing_risk_level],
        _RANK[observation.existing_confidence],
        observation.start_time_utc is None,
        observation.start_time_utc or datetime.max.replace(tzinfo=timezone.utc),
        ip_key,
        _OBSERVATION_RANK[observation.observation_kind],
        observation.observation_type,
        observation.end_time_utc or observation.start_time_utc
        or datetime.max.replace(tzinfo=timezone.utc),
        tuple(
            (evidence.evidence_type, evidence.value)
            for evidence in observation.evidence
        ),
        item.reason,
    )


def assemble_incident_cases(
    subjects: tuple[IncidentCaseSubjectInput, ...],
) -> IncidentCaseAssembly:
    if type(subjects) is not tuple:
        _fail()
    canonical_subjects = set()
    cases = []
    independent = []
    prepared = []
    for subject in subjects:
        if type(subject) is not IncidentCaseSubjectInput:
            _fail()
        canonical_ip, ip_key = _canonical_ip(subject.subject_ip)
        if canonical_ip in canonical_subjects:
            _fail("ambiguous_membership")
        canonical_subjects.add(canonical_ip)
        prepared.append((ip_key, subject))
    for _, subject in sorted(prepared, key=lambda item: item[0]):
        subject_cases, subject_independent = _assemble_subject(subject)
        cases.extend(subject_cases)
        independent.extend(subject_independent)
    cases.sort(key=_case_sort_key)
    independent.sort(key=_independent_sort_key)
    return IncidentCaseAssembly(
        cases=tuple(cases),
        independent_observations=tuple(independent),
        unsupported_case_rules=(
            UnsupportedCaseRule(
                rule_id="CASE-SPRAY-SUCCESS-01",
                status_code=CASE_SPRAY_SUCCESS_STATUS,
            ),
        ),
    )
