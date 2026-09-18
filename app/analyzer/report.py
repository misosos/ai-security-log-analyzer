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

    if not multi_ip_results and not distributed_success_results:
        return

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
