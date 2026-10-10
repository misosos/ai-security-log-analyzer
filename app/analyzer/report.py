import math
import re
from datetime import datetime
from ipaddress import ip_address

from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
)
from app.models.schemas import Evidence
from app.analyzer.report_projection import (
    InvestigationReportProjectionError,
    _validate_rationale,
)
from app.analyzer.web_observation_projection import (
    WEB_TYPES, WEB_PATTERN_LABELS, WebObservationProjectionError,
    project_web_observation,
)
from app.analyzer.process_execution_classification import (
    CATEGORY_IDS, DISPLAY_NAMES, PRIORITIES, LIMITATIONS, NEXT_STEPS,
    NOTICES, IDENTITY_WARNING, COMM_LIMITATION, ARGV_LIMITATION,
    ProcessExecutionObservationAssembly,
)


_INVALID_EVIDENCE_MESSAGE = (
    "      Evidence unavailable: unsupported or malformed contract"
)
_SUPPORTED_DETECTION_TYPES = (
    "brute_force",
    "password_spraying_like",
    "path_traversal",
    *WEB_TYPES,
)
_SUPPORTED_RELATION_TYPES = frozenset({
    "failed_to_successful_login",
    "successful_login_to_file_access",
    "brute_force_to_successful_login",
    "password_spray_to_successful_login",
})
_ACCOUNT_NOTICE = "원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다."


def _safe_rationale_lines(value):
    try:
        return _validate_rationale(value)
    except InvestigationReportProjectionError:
        return ("근거 상세는 개인정보 보호를 위해 표시하지 않습니다.",)


def _safe_ip_list(value):
    if type(value) is not list:
        return "표시할 수 없음"
    try:
        if any(type(item) is not str for item in value):
            return "표시할 수 없음"
        return ", ".join(str(ip_address(item)) for item in value)
    except (ValueError, TypeError):
        return "표시할 수 없음"


def _is_non_negative_int(value):
    return type(value) is int and value >= 0


def _is_non_negative_number(value):
    if type(value) is int:
        return value >= 0
    return type(value) is float and math.isfinite(value) and value >= 0


def _safe_number(value):
    return str(value) if _is_non_negative_number(value) else "표시할 수 없음"


def _safe_count(value):
    return str(value) if _is_non_negative_int(value) else "표시할 수 없음"


def _safe_timestamp(value):
    return str(value) if type(value) is datetime else "표시할 수 없음"


def _safe_bool(value):
    return str(value) if type(value) is bool else "표시할 수 없음"


def _safe_ip(value):
    if type(value) is not str:
        return "표시할 수 없음"
    try:
        return str(ip_address(value))
    except (ValueError, TypeError):
        return "표시할 수 없음"


def _safe_level(value):
    return value if type(value) is str and value in {"HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def _authentication_evidence_lines(detection):
    if detection.detection_type == "brute_force":
        target_type = "single_target_user"
        source = "brute_force_detector"
    else:
        target_type = "multiple_target_users"
        source = "password_spray_detector"

    expected = (
        ("multiple_login_failures", _is_non_negative_int),
        (target_type, _is_non_negative_int),
        ("failures_within_short_window", _is_non_negative_number),
    )

    if type(detection.evidence) is not list or len(detection.evidence) != 3:
        return None

    for item, (expected_type, value_validator) in zip(
        detection.evidence,
        expected,
    ):
        if (
            type(item) is not Evidence
            or item.type != expected_type
            or item.source != source
            or not value_validator(item.value)
        ):
            return None

    values = [item.value for item in detection.evidence]
    return (
        ("Failed attempts", str(values[0])),
        ("Target accounts", str(values[1])),
        ("Time window", f"{values[2]} seconds"),
    )


def _path_traversal_evidence_lines(detection):
    expected = (
        ("url_decoded_path", "Request path", str, True, ""),
        ("path_pattern", "Matched pattern", str, True, ""),
        ("url_decoded_query", "Query", str, False, ""),
        ("http_method", "HTTP method", str, False, ""),
        ("http_status_code", "Response status", int, False, ""),
        ("http_response_size", "Response size", int, False, " bytes"),
    )

    if type(detection.evidence) is not list:
        return None
    if not 2 <= len(detection.evidence) <= len(expected):
        return None

    actual_index = 0
    lines = []

    for evidence_type, label, value_type, required, unit in expected:
        if actual_index >= len(detection.evidence):
            if required:
                return None
            continue

        item = detection.evidence[actual_index]
        if type(item) is not Evidence:
            return None

        if item.type != evidence_type:
            if required:
                return None
            continue

        if item.source != "path_traversal_detector":
            return None
        if type(item.value) is not value_type:
            return None
        if value_type is int and item.value < 0:
            return None

        display_value = (
            "개인정보 보호를 위해 표시하지 않습니다."
            if evidence_type in {"url_decoded_path", "url_decoded_query"}
            else f"{item.value}{unit}"
        )
        lines.append((label, display_value))
        actual_index += 1

    if actual_index != len(detection.evidence):
        return None
    values_by_label = dict(lines)
    if values_by_label.get("Matched pattern") not in {"../", "..\\"}:
        return None
    method = values_by_label.get("HTTP method")
    if method is not None and re.fullmatch(r"[A-Z]{1,16}", method) is None:
        return None

    return tuple(lines)


def _detection_evidence_lines(detection):
    if detection.detection_type in WEB_TYPES:
        try:
            approved = project_web_observation(detection.detection_type, detection)
        except WebObservationProjectionError:
            return None
        lines = [
            ("Pattern category", WEB_PATTERN_LABELS[approved.pattern_id]),
            ("Observed requests", str(approved.request_count)),
        ]
        if approved.detection_type == "web_scanning_like":
            lines.extend((
                ("Distinct targets", str(approved.distinct_target_count)),
                ("Client errors", str(approved.client_error_count)),
                ("Time window", f"{approved.time_window_seconds} seconds"),
            ))
        return tuple(lines)
    if detection.detection_type in {
        "brute_force",
        "password_spraying_like",
    }:
        return _authentication_evidence_lines(detection)

    if detection.detection_type == "path_traversal":
        return _path_traversal_evidence_lines(detection)

    return None


def print_detection_result(detections):

    print("Detection:")

    for detection_name, detection in detections.items():

        if not detection.is_detected:
            continue

        if detection.detection_type in _SUPPORTED_DETECTION_TYPES:
            print(f"  - {detection.detection_type}")
        else:
            print("  - unsupported detection type")

        print("    Evidence:")

        evidence_lines = _detection_evidence_lines(detection)

        if evidence_lines is None:
            print(_INVALID_EVIDENCE_MESSAGE)
            continue

        for label, value in evidence_lines:
            print(f"      {label:<16}: {value}")


def print_correlation_result(correlation):

    print("Correlation:")

    for correlation_name, result in correlation.items():

        if not result.get("is_correlated", False):
            continue

        relation_type = result.get("type")
        print(f"  - {relation_type if relation_type in _SUPPORTED_RELATION_TYPES else '지원 범위 밖의 관계'}")

        if result.get("user") is not None:

            print(f"    계정: {_ACCOUNT_NOTICE}")

        if result.get("time_delta_seconds") is not None:

            print(
                f"    Time delta: "
                f"{_safe_number(result['time_delta_seconds'])} seconds"
            )

        if result.get("source_ips"):

            print(
                f"    Source IPs: "
                f"{_safe_ip_list(result['source_ips'])}"
            )

        if result.get("failure_count") is not None:

            print(
                f"    Failure count: "
                f"{_safe_count(result['failure_count'])}"
            )

        if result.get("time_window_seconds") is not None:

            print(
                f"    Time window: "
                f"{_safe_number(result['time_window_seconds'])} seconds"
            )


def print_risk_result(result):

    print("Risk:")

    print(
        f"  Risk        : "
        f"{_safe_level(result.get('risk_level'))}"
    )

    risk_factors = result.get(
        "risk_factors",
        {},
    )

    likelihood = risk_factors.get(
        "likelihood",
        {},
    )

    impact = risk_factors.get(
        "impact",
        {},
    )

    confidence = risk_factors.get(
        "confidence",
        {},
    )

    print("Assessment:")

    print(
        f"  Likelihood  : "
        f"{_safe_level(likelihood.get('level'))}"
    )

    for rationale in _safe_rationale_lines(likelihood.get("rationale", [])):

        print(
            f"    - {rationale}"
        )

    print(
        f"  Impact      : "
        f"{_safe_level(impact.get('level'))}"
    )

    for rationale in _safe_rationale_lines(impact.get("rationale", [])):

        print(
            f"    - {rationale}"
        )

    print(
        f"  Confidence  : "
        f"{_safe_level(confidence.get('level'))}"
    )

    for rationale in _safe_rationale_lines(confidence.get("rationale", [])):

        print(
            f"    - {rationale}"
        )


def print_global_correlation(
    global_correlation,
):

    multi_ip_results = global_correlation.get(
        "multi_ip_authentication",
        [],
    )

    distributed_success_results = global_correlation.get(
        "distributed_authentication_to_success",
        [],
    )

    lifecycle_results = [
        result
        for result in global_correlation.get(
            "linux_audit_session_lifecycle",
            [],
        ) or []
        if isinstance(result, dict)
        and result.get("is_correlated") is True
    ]

    login_start_results = [
        result
        for result in global_correlation.get(
            "linux_audit_login_start_co_observation",
            [],
        ) or []
        if isinstance(result, dict)
        and result.get("is_correlated") is True
    ]

    if multi_ip_results or distributed_success_results:
        print(
            "\n===== Global Correlation ====="
        )

    for multi_ip_result in multi_ip_results:

        print(
            "  - Multi-IP Authentication Failure"
        )

        print(f"    계정: {_ACCOUNT_NOTICE}")

        print(
            f"    Source IPs: "
            f"{_safe_ip_list(multi_ip_result.get('source_ips', []))}"
        )

        print(
            f"    Failure count: "
            f"{_safe_count(multi_ip_result.get('failure_count'))}"
        )

        print(
            f"    Time window: "
            f"{_safe_number(multi_ip_result.get('time_window_seconds'))} seconds"
        )

        print("    - 상관관계는 인과관계를 입증하지 않습니다.")

    for result in distributed_success_results:

        print(
            "  - Distributed Authentication Failures "
            "→ Successful Login"
        )

        print(f"    계정: {_ACCOUNT_NOTICE}")
        print(
            "    Failure source IPs: "
            f"{_safe_ip_list(result.get('failure_source_ips', []))}"
        )
        print(
            f"    Failure count: {_safe_count(result.get('failure_count'))}"
        )
        print(
            "    Failure time range: "
            f"{_safe_timestamp(result.get('failure_start_timestamp'))} → "
            f"{_safe_timestamp(result.get('failure_end_timestamp'))}"
        )
        print(
            f"    Success timestamp: "
            f"{_safe_timestamp(result.get('success_timestamp'))}"
        )
        print(
            f"    Success source IP: "
            f"{_safe_ip(result.get('success_source_ip'))}"
        )
        print(
            "    Success from failure source: "
            f"{_safe_bool(result.get('success_from_failure_source'))}"
        )
        print(
            "    Last failure → success: "
            f"{_safe_number(result.get('time_delta_seconds'))} seconds"
        )

        print("    - 상관관계는 인과관계를 입증하지 않습니다.")

    if not lifecycle_results and not login_start_results:
        return

    print(
        "\n===== Telemetry Relations ====="
    )

    for result in lifecycle_results:

        print(
            "  - Linux Audit 세션 시작/종료 연관"
        )

        fields = (
            ("Linux Audit 세션 ID", "audit_session_id"),
            ("시작 이벤트 관찰", "start_timestamp"),
            ("종료 이벤트 관찰", "end_timestamp"),
            (
                "시작/종료 이벤트 간 관찰 간격",
                "observed_session_lifecycle_interval_seconds",
            ),
        )

        for label, field in fields:
            value = result.get(field)

            if value is None:
                continue

            suffix = "초" if field.endswith("_seconds") else ""
            if field.endswith("_timestamp"):
                safe_value = _safe_timestamp(value)
            elif field.endswith("_seconds"):
                safe_value = _safe_number(value)
            else:
                safe_value = _safe_count(value)
            print(f"    {label}: {safe_value}{suffix}")

    if lifecycle_results:
        print(
            "    ※ 이 연관은 Linux Audit에서 관찰된 시작/종료 "
            "이벤트와 source-scoped context의 일치를 나타냅니다."
        )
        print(
            "      물리적 세션 동일성, 사용자·공격자 활동, 침해 또는 "
            "인과관계를 확인하지 않습니다."
        )

    if lifecycle_results and login_start_results:
        print()

    for result in login_start_results:
        print(
            "  - Linux Audit 로그인·세션 시작 이벤트 공동 관찰"
        )

        fields = (
            ("Linux Audit 세션 ID", "audit_session_id"),
            ("USER_LOGIN 이벤트 관찰 시각", "login_timestamp"),
            ("USER_START 이벤트 관찰 시각", "start_timestamp"),
        )

        for label, field in fields:
            value = result.get(field)

            if value is None:
                continue

            safe_value = (
                _safe_timestamp(value)
                if field.endswith("_timestamp")
                else _safe_count(value)
            )
            print(f"    {label}: {safe_value}")

    if login_start_results:
        print(
            "    ※ 이 공동 관찰은 일치하는 source-scoped Linux Audit "
            "context에서"
        )
        print(
            "      USER_LOGIN 및 USER_START 이벤트가 각각 관찰되었음을 "
            "나타냅니다."
        )
        print(
            "      표시 순서는 이벤트 순서나 전이를 의미하지 않으며, "
            "물리적 세션"
        )
        print(
            "      동일성, PAM transaction, SSH connection, "
            "사용자·공격자 활동,"
        )
        print(
            "      침해 또는 인과관계를 확인하지 않습니다."
        )


def _print_process_execution_aggregate(
    aggregate,
    process_detection_summary=None,
):

    review_count = 0

    if process_detection_summary is not None:
        if type(process_detection_summary) is not (
            SharedMemoryExecutionReviewSummary
        ):
            raise TypeError("invalid process detection summary")

        review_count = (
            process_detection_summary
            .shared_memory_privileged_execution_observation_count
        )

        if type(review_count) is not int or review_count < 0:
            raise ValueError("invalid process detection summary count")

    if aggregate is None:
        if review_count > 0:
            raise ValueError(
                "process detection summary requires process telemetry"
            )
        return

    observation_count = aggregate.get(
        "observation_count",
        0,
    )

    if observation_count == 0:
        if review_count > 0:
            raise ValueError(
                "process detection summary requires process telemetry"
            )
        return

    outcome_counts = aggregate.get(
        "outcome_counts",
        {},
    )
    argv_counts = aggregate.get(
        "argv_completeness_counts",
        {},
    )
    path_counts = aggregate.get(
        "path_completeness_counts",
        {},
    )

    print(
        "\n===== Process Execution Telemetry ====="
    )
    print(
        "Linux Audit 프로세스 실행 관찰 집계"
    )
    print(f"  관찰 수: {observation_count}")
    print("  SYSCALL outcome 관찰:")
    print(f"    success: {outcome_counts.get('success', 0)}")
    print(f"    failure: {outcome_counts.get('failure', 0)}")
    print(f"    unknown: {outcome_counts.get('unknown', 0)}")
    print("  argv evidence completeness:")
    print(f"    complete: {argv_counts.get('complete', 0)}")
    print(f"    incomplete: {argv_counts.get('incomplete', 0)}")
    print("  PATH evidence completeness:")
    print(f"    complete: {path_counts.get('complete', 0)}")
    print(f"    incomplete: {path_counts.get('incomplete', 0)}")
    print(
        "  ※ Linux Audit 프로세스 실행 관찰의 집계입니다."
    )
    print(
        "    success는 syscall 관찰 결과이며 프로그램 목적 달성 또는 "
        "공격 성공을 의미하지 않습니다."
    )
    print(
        "    completeness는 evidence 완전성일 뿐 정확성, 신뢰도 또는 "
        "안전성을 의미하지 않습니다."
    )

    if review_count > 0:
        print(
            "  shared-memory privileged execution 검토 관찰 수: "
            f"{review_count}"
        )
        print(
            "  ※ 이 값은 shared-memory directory 하위 executable path와"
        )
        print(
            "    effective root context의 successful syscall이 함께 "
            "관찰된 검토 건수입니다."
        )
        print(
            "    unique process, malware, confirmed attack 또는 "
            "compromise 건수를 의미하지 않습니다."
        )


def _validated_session_process_review_counts(summary):
    if summary is None:
        return None
    if type(summary) is not SessionProcessReviewSummary:
        raise ValueError("invalid session-process review summary")

    counts = (
        summary.session_co_observation_count,
        summary.process_observation_count,
        summary.process_outcome_success_count,
        summary.process_outcome_failure_count,
        summary.process_outcome_unknown_count,
        summary.shared_memory_privileged_execution_observation_count,
        summary.sessions_with_shared_memory_privileged_execution_count,
    )
    if not all(type(count) is int and count >= 0 for count in counts):
        raise ValueError("invalid session-process review summary count")

    (
        session_count,
        process_count,
        success_count,
        failure_count,
        unknown_count,
        shared_memory_count,
        sessions_with_shared_memory_count,
    ) = counts
    if process_count != success_count + failure_count + unknown_count:
        raise ValueError("invalid session-process outcome counts")
    if shared_memory_count > process_count:
        raise ValueError("invalid session-process shared-memory count")
    if sessions_with_shared_memory_count > session_count:
        raise ValueError("invalid session-process session count")
    if session_count == 0 and process_count > 0:
        raise ValueError("process count requires a session observation")
    if session_count > 0 and process_count == 0:
        raise ValueError("session observation requires a process count")
    if process_count == 0 and shared_memory_count > 0:
        raise ValueError("shared-memory count requires a process count")
    if shared_memory_count == 0 and sessions_with_shared_memory_count > 0:
        raise ValueError("shared-memory session count requires an observation")

    return counts


def _print_session_process_review_summary(counts):
    if counts is None or counts[0] == 0:
        return

    (
        session_count,
        process_count,
        success_count,
        failure_count,
        unknown_count,
        shared_memory_count,
        sessions_with_shared_memory_count,
    ) = counts

    print("\n===== Session–Process Co-Observation =====")
    print("Linux Audit 세션–프로세스 공동 관찰 요약")
    print(f"  공동 관찰 세션 수: {session_count}")
    print(f"  세션 구간 내 프로세스 관찰 수: {process_count}")
    print("  SYSCALL outcome 관찰:")
    print(f"    success: {success_count}")
    print(f"    failure: {failure_count}")
    print(f"    unknown: {unknown_count}")
    print(
        "  세션에 연결된 shared-memory privileged execution 관찰 수: "
        f"{shared_memory_count}"
    )
    print(
        "  해당 관찰이 포함된 세션 수: "
        f"{sessions_with_shared_memory_count}"
    )
    print(
        "  ※ 동일 Linux Audit scope의 session lifecycle과 process "
        "event가 함께 관찰된 집계입니다."
    )
    print(
        "    동일 사용자의 직접 실행이나 인과관계를 증명하지 않습니다."
    )
    print(
        "    success는 syscall 관찰 결과이며 프로그램 목적 달성이나 "
        "공격 성공을 의미하지 않습니다."
    )
    print(
        "    shared-memory count는 malware, confirmed attack, "
        "compromise 또는 incident 수가 아닙니다."
    )


def _print_process_execution_classification(assembly):
    if type(assembly) is not ProcessExecutionObservationAssembly:
        raise ValueError("invalid_process_execution_classification")
    summary = assembly.summary
    if (
        type(summary.eligible_execution_count) is not int
        or type(summary.classified_execution_count) is not int
        or type(summary.category_observation_count) is not int
        or min(summary.eligible_execution_count, summary.classified_execution_count,
               summary.category_observation_count) < 0
        or summary.classified_execution_count > summary.eligible_execution_count
        or type(summary.categories) is not tuple
        or type(assembly.observations) is not tuple
        or summary.category_observation_count != len(assembly.observations)
        or tuple(category.category_id for category in summary.categories) != CATEGORY_IDS
        or tuple(category.display_name for category in summary.categories) != DISPLAY_NAMES
        or tuple(category.review_priority for category in summary.categories) != PRIORITIES
        or assembly.interpretation_notices != NOTICES
        or assembly.bounded_warnings not in ((), (IDENTITY_WARNING,))
        or any(item.category_id not in CATEGORY_IDS for item in assembly.observations)
        or any(type(item.confidence) is not str or item.confidence not in {"HIGH", "MEDIUM", "LOW"}
               for item in assembly.observations)
        or any(item.display_name != DISPLAY_NAMES[CATEGORY_IDS.index(item.category_id)]
               or item.limitations not in (
                   (LIMITATIONS[CATEGORY_IDS.index(item.category_id)],),
                   (LIMITATIONS[CATEGORY_IDS.index(item.category_id)], COMM_LIMITATION),
                   (LIMITATIONS[CATEGORY_IDS.index(item.category_id)], ARGV_LIMITATION),
               )
               or item.next_steps != (NEXT_STEPS[CATEGORY_IDS.index(item.category_id)],)
               for item in assembly.observations)
    ):
        raise ValueError("invalid_process_execution_classification")
    print("\nLinux 프로세스 실행 조사 후보")
    if not assembly.observations:
        print("정해진 Linux 프로세스 실행 조사 후보가 없습니다.")
        print("이는 안전하거나 정상임을 의미하지 않으며 현재 분류 범위에서 추가 후보가 없다는 뜻입니다.")
    for category in summary.categories:
        if category.observation_count == 0:
            continue
        counts = category.outcome_counts
        print(f"- {category.display_name}: {category.observation_count}건")
        print(f"  - 성공 {counts.success} / 실패 {counts.failure} / 미상 {counts.unknown}")
        print(f"  - 검토 우선순위: {category.review_priority}")
        confidences = tuple(item.confidence for item in assembly.observations
                            if item.category_id == category.category_id)
        print(f"  - 신뢰도: {min(confidences, key={'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}.get)}")
    for notice in assembly.interpretation_notices:
        print(f"  ※ {notice}")
    for warning in assembly.bounded_warnings:
        print(f"  ※ {warning}")
    if assembly.observations:
        print("  해석 한계·다음 조사 단계:")
        for category in summary.categories:
            if category.observation_count:
                observation = next(item for item in assembly.observations
                                   if item.category_id == category.category_id)
                print(f"  - {category.display_name}: {observation.limitations[0]}")
                if any(COMM_LIMITATION in item.limitations for item in assembly.observations
                       if item.category_id == category.category_id):
                    print(f"    {COMM_LIMITATION}")
                if any(ARGV_LIMITATION in item.limitations for item in assembly.observations
                       if item.category_id == category.category_id):
                    print(f"    {ARGV_LIMITATION}")
                print(f"    다음 단계: {observation.next_steps[0]}")


def print_analysis_result(
    analysis,
    *,
    process_execution_aggregate=None,
    process_detection_summary=None,
    session_process_review_summary=None,
    process_execution_classification=None,
):

    session_process_counts = _validated_session_process_review_counts(
        session_process_review_summary
    )

    if session_process_counts is not None:
        session_shared_memory_count = session_process_counts[5]
        if process_detection_summary is None:
            if session_shared_memory_count > 0:
                raise ValueError(
                    "session-linked count requires overall review count"
                )
        else:
            if type(process_detection_summary) is not (
                SharedMemoryExecutionReviewSummary
            ):
                raise ValueError("invalid process detection summary")
            overall_count = (
                process_detection_summary
                .shared_memory_privileged_execution_observation_count
            )
            if type(overall_count) is not int or overall_count < 0:
                raise ValueError("invalid process detection summary count")
            if session_shared_memory_count > overall_count:
                raise ValueError(
                    "session-linked count exceeds overall review count"
                )

    results = analysis["results"]

    for ip, result in results.items():

        print(
            f"\n===== {_safe_ip(ip)} ====="
        )

        print_detection_result(
            result["detections"]
        )

        print_risk_result(result)

        print_correlation_result(
            result.get(
                "correlation",
                {},
            )
        )

    _print_process_execution_aggregate(
        process_execution_aggregate,
        process_detection_summary,
    )

    if process_execution_classification is not None:
        _print_process_execution_classification(process_execution_classification)

    _print_session_process_review_summary(session_process_counts)

    print_global_correlation(
        analysis.get(
            "global_correlation",
            {},
        )
    )
