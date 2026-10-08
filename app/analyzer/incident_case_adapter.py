from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
import math
from types import MappingProxyType
import unicodedata

from app.analyzer.incident_case import (
    IncidentCaseAssemblyError,
    IncidentCaseCorrelationInput,
    IncidentCaseDetectionInput,
    IncidentCaseSubjectInput,
    assemble_incident_cases,
)
from app.analyzer.incident_case_projection import (
    InvestigationCaseProjection,
    InvestigationCaseProjectionError,
    build_investigation_case_projection,
)
from app.models.schemas import DetectionResult, Evidence


_MAX_INTEGER = (1 << 63) - 1
_LEVELS = frozenset({"HIGH", "MEDIUM", "LOW"})
_ANALYSIS_KEYS = frozenset({"results", "global_correlation"})
_SUBJECT_KEYS = frozenset({
    "features",
    "detections",
    "correlation",
    "risk_factors",
    "risk_level",
})
_FEATURE_KEYS = frozenset({
    "failure_count",
    "target_users",
    "login_succeeded",
    "within_window",
    "window_seconds",
    "average_interval",
    "interval_variability",
    "unique_target_count",
})
_DETECTION_TYPES = MappingProxyType({
    "brute_force": "brute_force",
    "password_spray": "password_spraying_like",
    "path_traversal": "path_traversal",
})
_CORRELATION_TYPES = MappingProxyType({
    "authentication": "failed_to_successful_login",
    "post_authentication": "successful_login_to_file_access",
    "brute_force_to_success": "brute_force_to_successful_login",
    "password_spray_to_success": "password_spray_to_successful_login",
})
_RISK_FACTOR_KEYS = frozenset({
    "likelihood",
    "impact",
    "confidence",
    "evidence",
    "account_context",
})
_ERROR_MESSAGES = MappingProxyType({
    "invalid_input_type": (
        "Incident case adapter failed: invalid input type."
    ),
    "unsupported_result_shape": (
        "Incident case adapter failed: unsupported result shape."
    ),
    "invalid_detection_contract": (
        "Incident case adapter failed: invalid detection contract."
    ),
    "invalid_correlation_contract": (
        "Incident case adapter failed: invalid correlation contract."
    ),
    "invalid_risk": (
        "Incident case adapter failed: invalid risk contract."
    ),
    "invalid_timestamp": (
        "Incident case adapter failed: invalid timestamp contract."
    ),
    "ambiguous_membership": (
        "Incident case adapter failed: ambiguous observation membership."
    ),
    "downstream_assembly_failure": (
        "Incident case adapter failed: case assembly failed."
    ),
    "downstream_projection_failure": (
        "Incident case adapter failed: case projection failed."
    ),
})


class IncidentCaseAdapterError(ValueError):
    def __init__(self, code: str):
        safe_code = (
            code if code in _ERROR_MESSAGES else "unsupported_result_shape"
        )
        self.code = safe_code
        super().__init__(_ERROR_MESSAGES[safe_code])


def _fail(code: str) -> None:
    raise IncidentCaseAdapterError(code) from None


def _exact_dict(value, keys: frozenset[str], code: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        _fail(code)
    return value


def _non_negative_int(value, code: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        _fail(code)
    return value


def _non_negative_number(value, code: str) -> int | float:
    if type(value) is int:
        if 0 <= value <= _MAX_INTEGER:
            return value
        _fail(code)
    if (
        type(value) is float
        and math.isfinite(value)
        and 0 <= value <= _MAX_INTEGER
    ):
        return value
    _fail(code)


def _canonical_utc(value) -> datetime:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        _fail("invalid_timestamp")
    return value


def _optional_canonical_utc(value) -> datetime | None:
    if type(value) is datetime and value.tzinfo is timezone.utc:
        return value
    return None


def _canonical_subject(value) -> tuple[str, tuple[int, bytes]]:
    if type(value) is not str:
        _fail("unsupported_result_shape")
    try:
        parsed = ip_address(value)
    except ValueError:
        _fail("unsupported_result_shape")
    if type(parsed) is IPv4Address:
        family = 4
    elif type(parsed) is IPv6Address and parsed.scope_id is None:
        family = 6
    else:
        _fail("unsupported_result_shape")
    return str(parsed), (family, parsed.packed)


def _account(value, code: str = "unsupported_result_shape") -> str:
    if type(value) is not str or not value.strip():
        _fail(code)
    if any(unicodedata.category(character) == "Cc" for character in value):
        _fail(code)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _fail(code)
    return value


def _rationale(value, code: str, *, allow_empty: bool = False) -> None:
    if (
        type(value) is not list
        or len(value) > 5
        or (not allow_empty and not value)
        or any(type(item) is not str for item in value)
    ):
        _fail(code)


def _features(value) -> tuple[dict, tuple[str, ...]]:
    features = _exact_dict(
        value,
        _FEATURE_KEYS,
        "unsupported_result_shape",
    )
    failure_count = _non_negative_int(
        features["failure_count"],
        "unsupported_result_shape",
    )
    target_users = features["target_users"]
    if type(target_users) is not list:
        _fail("unsupported_result_shape")
    accounts = tuple(_account(account) for account in target_users)
    if len(set(accounts)) != len(accounts):
        _fail("ambiguous_membership")
    unique_target_count = _non_negative_int(
        features["unique_target_count"],
        "unsupported_result_shape",
    )
    if unique_target_count != len(accounts) or unique_target_count > failure_count:
        _fail("unsupported_result_shape")
    if (
        type(features["login_succeeded"]) is not bool
        or type(features["within_window"]) is not bool
    ):
        _fail("unsupported_result_shape")
    window = _non_negative_number(
        features["window_seconds"],
        "unsupported_result_shape",
    )
    _non_negative_number(
        features["average_interval"],
        "unsupported_result_shape",
    )
    _non_negative_number(
        features["interval_variability"],
        "unsupported_result_shape",
    )
    if features["within_window"] and window > 60:
        _fail("unsupported_result_shape")
    return features, accounts


def _evidence_item(value, source: str) -> Evidence:
    if type(value) is not Evidence or value.source != source:
        _fail("invalid_detection_contract")
    return value


def _authentication_detection(
    slot: str,
    detection: DetectionResult,
    features: dict,
    target_accounts: tuple[str, ...],
) -> DetectionResult:
    if slot == "brute_force":
        target_type = "single_target_user"
        source = "brute_force_detector"
    else:
        target_type = "multiple_target_users"
        source = "password_spray_detector"

    if type(detection.evidence) is not list or len(detection.evidence) != 3:
        _fail("invalid_detection_contract")
    failed = None
    targets = None
    window = None
    for raw_item in detection.evidence:
        item = _evidence_item(raw_item, source)
        if item.type == "multiple_login_failures" and failed is None:
            failed = item
        elif item.type == target_type and targets is None:
            targets = item
        elif item.type == "failures_within_short_window" and window is None:
            window = item
        else:
            _fail("invalid_detection_contract")
    if failed is None or targets is None or window is None:
        _fail("invalid_detection_contract")

    failed_count = _non_negative_int(
        failed.value,
        "invalid_detection_contract",
    )
    target_count = _non_negative_int(
        targets.value,
        "invalid_detection_contract",
    )
    window_seconds = _non_negative_number(
        window.value,
        "invalid_detection_contract",
    )
    if window_seconds > 60:
        _fail("invalid_detection_contract")
    if (
        failed.timestamp is not None
        or targets.timestamp is not None
        or targets.time_range is not None
        or window.timestamp is not None
        or window.time_range is not None
    ):
        _fail("invalid_detection_contract")
    if (
        failed_count != features["failure_count"]
        or target_count != features["unique_target_count"]
        or target_count != len(target_accounts)
        or window_seconds != features["window_seconds"]
        or not features["within_window"]
    ):
        _fail("invalid_detection_contract")

    time_range = failed.time_range
    start = None
    end = None
    if type(time_range) is tuple and len(time_range) == 2:
        start = _optional_canonical_utc(time_range[0])
        end = _optional_canonical_utc(time_range[1])
    if start is not None and end is not None:
        if (
            start > end
            or (end - start).total_seconds() != window_seconds
        ):
            _fail("invalid_detection_contract")
        approved_time_range = (start, end)
    else:
        approved_time_range = None

    return DetectionResult(
        is_detected=True,
        detection_type=detection.detection_type,
        evidence=[
            Evidence(
                type="multiple_login_failures",
                value=failed_count,
                source=source,
                time_range=approved_time_range,
            ),
            Evidence(
                type=target_type,
                value=target_count,
                source=source,
            ),
            Evidence(
                type="failures_within_short_window",
                value=window_seconds,
                source=source,
            ),
        ],
    )


def _path_detection(detection: DetectionResult) -> DetectionResult:
    if type(detection.evidence) is not list or not 2 <= len(detection.evidence) <= 6:
        _fail("invalid_detection_contract")
    seen = set()
    pattern = None
    timestamps = []
    timestamps_valid = True
    for raw_item in detection.evidence:
        item = _evidence_item(raw_item, "path_traversal_detector")
        if item.type in seen or item.type not in {
            "url_decoded_path",
            "path_pattern",
            "url_decoded_query",
            "http_method",
            "http_status_code",
            "http_response_size",
        }:
            _fail("invalid_detection_contract")
        seen.add(item.type)
        if item.time_range is not None:
            _fail("invalid_detection_contract")
        if item.timestamp is None:
            timestamps_valid = False
        else:
            timestamp = _optional_canonical_utc(item.timestamp)
            if timestamp is None:
                timestamps_valid = False
            else:
                timestamps.append(timestamp)
        if item.type in {
            "url_decoded_path",
            "path_pattern",
            "url_decoded_query",
            "http_method",
        }:
            if type(item.value) is not str:
                _fail("invalid_detection_contract")
            if item.type == "path_pattern":
                if item.value not in {"../", "..\\"}:
                    _fail("invalid_detection_contract")
                pattern = item
        else:
            _non_negative_int(item.value, "invalid_detection_contract")
    if not {"url_decoded_path", "path_pattern"}.issubset(seen):
        _fail("invalid_detection_contract")

    approved_evidence = []
    if (
        timestamps_valid
        and timestamps
        and len(set(timestamps)) == 1
        and pattern is not None
    ):
        approved_evidence.append(Evidence(
            "path_pattern",
            pattern.value,
            "path_traversal_detector",
            timestamp=timestamps[0],
        ))
    return DetectionResult(True, "path_traversal", approved_evidence)


def _detection_input(
    slot: str,
    raw_detection,
    features: dict,
    target_accounts: tuple[str, ...],
) -> IncidentCaseDetectionInput:
    if type(raw_detection) is not DetectionResult:
        _fail("invalid_detection_contract")
    if type(raw_detection.is_detected) is not bool:
        _fail("invalid_detection_contract")
    if not raw_detection.is_detected:
        if raw_detection.detection_type is not None or raw_detection.evidence != []:
            _fail("invalid_detection_contract")
        detection = DetectionResult(False, None, [])
    else:
        if type(raw_detection.detection_type) is not str:
            _fail("invalid_detection_contract")
        expected_type = _DETECTION_TYPES[slot]
        if raw_detection.detection_type != expected_type:
            if type(raw_detection.evidence) is not list:
                _fail("invalid_detection_contract")
            detection = DetectionResult(True, "unsupported_detection", [])
        elif slot in {"brute_force", "password_spray"}:
            detection = _authentication_detection(
                slot,
                raw_detection,
                features,
                target_accounts,
            )
        else:
            detection = _path_detection(raw_detection)
    return IncidentCaseDetectionInput(slot=slot, detection=detection)


def _detections(
    value,
    features: dict,
    target_accounts: tuple[str, ...],
) -> tuple[IncidentCaseDetectionInput, ...]:
    detections = _exact_dict(
        value,
        frozenset(_DETECTION_TYPES),
        "invalid_detection_contract",
    )
    return tuple(
        _detection_input(
            slot,
            detections[slot],
            features,
            target_accounts,
        )
        for slot in _DETECTION_TYPES
    )


def _correlation_input(slot: str, value) -> IncidentCaseCorrelationInput:
    if type(value) is not dict:
        _fail("invalid_correlation_contract")
    is_correlated = value.get("is_correlated")
    if type(is_correlated) is not bool:
        _fail("invalid_correlation_contract")
    if not is_correlated:
        _exact_dict(
            value,
            frozenset({"is_correlated", "type", "user", "rationale"}),
            "invalid_correlation_contract",
        )
        if value["type"] is not None or value["user"] is not None:
            _fail("invalid_correlation_contract")
        _rationale(
            value["rationale"],
            "invalid_correlation_contract",
            allow_empty=True,
        )
        if value["rationale"]:
            _fail("invalid_correlation_contract")
        return IncidentCaseCorrelationInput(
            slot=slot,
            is_correlated=False,
            correlation_type=None,
            account=None,
        )

    if slot == "post_authentication":
        _exact_dict(
            value,
            frozenset({
                "is_correlated",
                "type",
                "user",
                "success_timestamp",
                "file_access_timestamp",
                "time_delta_seconds",
                "rationale",
            }),
            "invalid_correlation_contract",
        )
        failure = _canonical_utc(value["success_timestamp"])
        success = _canonical_utc(value["file_access_timestamp"])
    else:
        _exact_dict(
            value,
            frozenset({
                "is_correlated",
                "type",
                "user",
                "failure_timestamp",
                "success_timestamp",
                "time_delta_seconds",
                "rationale",
            }),
            "invalid_correlation_contract",
        )
        failure = _canonical_utc(value["failure_timestamp"])
        success = _canonical_utc(value["success_timestamp"])

    correlation_type = value["type"]
    if (
        type(correlation_type) is not str
        or correlation_type != _CORRELATION_TYPES[slot]
    ):
        _fail("invalid_correlation_contract")
    account = _account(value["user"], "invalid_correlation_contract")
    delta = _non_negative_number(
        value["time_delta_seconds"],
        "invalid_correlation_contract",
    )
    _rationale(value["rationale"], "invalid_correlation_contract")
    if (
        failure >= success
        or (success - failure).total_seconds() != delta
        or delta > 60
    ):
        _fail("invalid_correlation_contract")
    return IncidentCaseCorrelationInput(
        slot=slot,
        is_correlated=True,
        correlation_type=correlation_type,
        account=account,
        failure_timestamp=failure,
        success_timestamp=success,
        time_delta_seconds=delta,
    )


def _correlations(value) -> tuple[IncidentCaseCorrelationInput, ...]:
    correlations = _exact_dict(
        value,
        frozenset(_CORRELATION_TYPES),
        "invalid_correlation_contract",
    )
    return tuple(
        _correlation_input(slot, correlations[slot])
        for slot in _CORRELATION_TYPES
    )


def _risk(result: dict) -> tuple[str, str]:
    risk_level = result["risk_level"]
    if type(risk_level) is not str or risk_level not in _LEVELS:
        _fail("invalid_risk")
    factors = _exact_dict(
        result["risk_factors"],
        _RISK_FACTOR_KEYS,
        "invalid_risk",
    )
    if (
        type(factors["likelihood"]) is not dict
        or type(factors["impact"]) is not dict
        or type(factors["evidence"]) is not list
        or type(factors["account_context"]) is not dict
    ):
        _fail("invalid_risk")
    confidence = _exact_dict(
        factors["confidence"],
        frozenset({"level", "rationale"}),
        "invalid_risk",
    )
    confidence_level = confidence["level"]
    if type(confidence_level) is not str or confidence_level not in _LEVELS:
        _fail("invalid_risk")
    _rationale(confidence["rationale"], "invalid_risk")
    return risk_level, confidence_level


def _subject_input(subject_ip, value) -> tuple[
    tuple[int, bytes],
    IncidentCaseSubjectInput,
]:
    canonical_ip, ip_sort_key = _canonical_subject(subject_ip)
    result = _exact_dict(
        value,
        _SUBJECT_KEYS,
        "unsupported_result_shape",
    )
    features, target_accounts = _features(result["features"])
    risk_level, confidence = _risk(result)
    return ip_sort_key, IncidentCaseSubjectInput(
        subject_ip=canonical_ip,
        target_accounts=target_accounts,
        detections=_detections(
            result["detections"],
            features,
            target_accounts,
        ),
        correlations=_correlations(result["correlation"]),
        risk_level=risk_level,
        confidence=confidence,
    )


def _build_subject_inputs(analysis_result: dict) -> tuple[
    IncidentCaseSubjectInput,
    ...,
]:
    if type(analysis_result) is not dict:
        _fail("invalid_input_type")
    analysis = _exact_dict(
        analysis_result,
        _ANALYSIS_KEYS,
        "unsupported_result_shape",
    )
    results = analysis["results"]
    if type(results) is not dict or type(analysis["global_correlation"]) is not dict:
        _fail("unsupported_result_shape")
    prepared = []
    canonical_subjects = set()
    for subject_ip, result in results.items():
        ip_sort_key, subject = _subject_input(subject_ip, result)
        if subject.subject_ip in canonical_subjects:
            _fail("ambiguous_membership")
        canonical_subjects.add(subject.subject_ip)
        prepared.append((ip_sort_key, subject))
    prepared.sort(key=lambda item: item[0])
    return tuple(subject for _, subject in prepared)


def project_investigation_cases_from_analysis(
    analysis_result: dict,
) -> InvestigationCaseProjection:
    subjects = _build_subject_inputs(analysis_result)
    try:
        assembly = assemble_incident_cases(subjects)
    except IncidentCaseAssemblyError as error:
        code = (
            "ambiguous_membership"
            if error.code == "ambiguous_membership"
            else "downstream_assembly_failure"
        )
        raise IncidentCaseAdapterError(code) from None
    try:
        return build_investigation_case_projection(assembly)
    except InvestigationCaseProjectionError:
        raise IncidentCaseAdapterError(
            "downstream_projection_failure"
        ) from None
