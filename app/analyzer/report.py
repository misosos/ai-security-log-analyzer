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


def print_analysis_result(analysis):

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

    print_global_correlation(
        analysis.get(
            "global_correlation",
            {},
        )
    )
