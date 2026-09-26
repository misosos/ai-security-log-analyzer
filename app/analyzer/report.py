from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
)


def print_detection_result(detections):

    print("Detection:")

    for detection_name, detection in detections.items():

        if not detection.is_detected:
            continue

        print(
            f"  - {detection.detection_type}"
        )

        print("    Evidence:")

        for evidence in detection.evidence:

            print(
                f"      - {evidence.value}"
            )


def print_correlation_result(correlation):

    print("Correlation:")

    for correlation_name, result in correlation.items():

        if not result.get("is_correlated", False):
            continue

        print(
            f"  - {result.get('type')}"
        )

        if result.get("user") is not None:

            print(
                f"    User: {result['user']}"
            )

        if result.get("time_delta_seconds") is not None:

            print(
                f"    Time delta: "
                f"{result['time_delta_seconds']} seconds"
            )

        if result.get("source_ips"):

            print(
                f"    Source IPs: "
                f"{', '.join(result['source_ips'])}"
            )

        if result.get("failure_count") is not None:

            print(
                f"    Failure count: "
                f"{result['failure_count']}"
            )

        if result.get("time_window_seconds") is not None:

            print(
                f"    Time window: "
                f"{result['time_window_seconds']} seconds"
            )


def print_risk_result(result):

    print("Risk:")

    print(
        f"  Risk        : "
        f"{result.get('risk_level', 'UNKNOWN')}"
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
        f"{likelihood.get('level', 'UNKNOWN')}"
    )

    for rationale in likelihood.get(
        "rationale",
        [],
    ):

        print(
            f"    - {rationale}"
        )

    print(
        f"  Impact      : "
        f"{impact.get('level', 'UNKNOWN')}"
    )

    for rationale in impact.get(
        "rationale",
        [],
    ):

        print(
            f"    - {rationale}"
        )

    print(
        f"  Confidence  : "
        f"{confidence.get('level', 'UNKNOWN')}"
    )

    for rationale in confidence.get(
        "rationale",
        [],
    ):

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

        print(
            f"    User: "
            f"{multi_ip_result.get('user')}"
        )

        print(
            f"    Source IPs: "
            f"{', '.join(multi_ip_result.get('source_ips', []))}"
        )

        print(
            f"    Failure count: "
            f"{multi_ip_result.get('failure_count')}"
        )

        print(
            f"    Time window: "
            f"{multi_ip_result.get('time_window_seconds')} seconds"
        )

        for rationale in multi_ip_result.get(
            "rationale",
            [],
        ):

            print(
                f"    - {rationale}"
            )

    for result in distributed_success_results:

        print(
            "  - Distributed Authentication Failures "
            "→ Successful Login"
        )

        print(f"    User: {result.get('user')}")
        print(
            "    Failure source IPs: "
            f"{', '.join(result.get('failure_source_ips', []))}"
        )
        print(
            f"    Failure count: {result.get('failure_count')}"
        )
        print(
            "    Failure time range: "
            f"{result.get('failure_start_timestamp')} → "
            f"{result.get('failure_end_timestamp')}"
        )
        print(
            f"    Success timestamp: "
            f"{result.get('success_timestamp')}"
        )
        print(
            f"    Success source IP: "
            f"{result.get('success_source_ip')}"
        )
        print(
            "    Success from failure source: "
            f"{result.get('success_from_failure_source')}"
        )
        print(
            "    Last failure → success: "
            f"{result.get('time_delta_seconds')} seconds"
        )

        for rationale in result.get("rationale", []):
            print(f"    - {rationale}")

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
            ("계정", "user"),
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
            print(f"    {label}: {value}{suffix}")

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
            ("계정", "user"),
            ("Linux Audit 세션 ID", "audit_session_id"),
            ("USER_LOGIN 이벤트 관찰 시각", "login_timestamp"),
            ("USER_START 이벤트 관찰 시각", "start_timestamp"),
        )

        for label, field in fields:
            value = result.get(field)

            if value is None:
                continue

            print(f"    {label}: {value}")

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


def print_analysis_result(
    analysis,
    *,
    process_execution_aggregate=None,
    process_detection_summary=None,
    session_process_review_summary=None,
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
            f"\n===== {ip} ====="
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

    _print_session_process_review_summary(session_process_counts)

    print_global_correlation(
        analysis.get(
            "global_correlation",
            {},
        )
    )
