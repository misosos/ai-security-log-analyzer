def format_evidence(evidence):
    evidence_messages = {
        "multiple_login_failures": f"{evidence.value}회 로그인 실패",
        "single_target_user": "단일 계정 대상",
        "multiple_target_users": f"{evidence.value}개의 계정을 대상으로 시도",
        "failures_within_short_window": f"{evidence.value}초 이내에 반복 발생",
        "url_decoded_path": f"요청 경로: {evidence.value}",
        "path_pattern": f"탐지 패턴: {evidence.value}",
        "url_decoded_query": f"요청 파라미터: {evidence.value}",
        "http_method": f"HTTP 메서드: {evidence.value}",
        "http_status_code": f"HTTP 상태 코드: {evidence.value}",
        "http_response_size": f"응답 크기: {evidence.value} bytes",
    }

    return evidence_messages.get(
        evidence.type,
        f"{evidence.type}: {evidence.value}",
    )


def print_analysis_result(result):
    print("분석 결과:")

    for ip, analysis in result.items():
        print(f"\n===== {ip} =====")

        print("Detection:")

        detection_names = {
            "brute_force": "Brute Force",
            "password_spraying_like": "Password Spraying-like",
            "path_traversal": "Path Traversal",
        }

        for detection_name, detection in analysis["detections"].items():
            if not detection.is_detected:
                continue

            display_name = detection_names.get(
                detection.detection_type,
                detection.detection_type,
            )

            print(f"  - {display_name}")

            print("    Evidence:")
            for evidence in detection.evidence:
                print(f"      - {format_evidence(evidence)}")

        print("Risk:")
        print(f"  Risk        : {analysis['risk_level']}")

        print("Assessment:")

        likelihood = analysis["risk_factors"]["likelihood"]
        impact = analysis["risk_factors"]["impact"]
        confidence = analysis["risk_factors"]["confidence"]

        print(f"  Likelihood  : {likelihood['level']}")
        for reason in likelihood["rationale"]:
            print(f"    - {reason}")

        print(f"  Impact      : {impact['level']}")
        for reason in impact["rationale"]:
            print(f"    - {reason}")

        print(f"  Confidence  : {confidence['level']}")
        for reason in confidence["rationale"]:
            print(f"    - {reason}")

        print("Correlation:")

        correlation_names = {
            "failed_to_successful_login": "인증 실패 → 로그인 성공",
            "successful_login_to_file_access": "로그인 성공 → 파일 접근",
            "brute_force_to_successful_login": "Brute Force → 로그인 성공",
            "password_spray_to_successful_login": (
                "Password Spraying-like → 로그인 성공"
            ),
        }

        for correlation_name, correlation in analysis["correlation"].items():
            if not correlation["is_correlated"]:
                continue

            display_name = correlation_names.get(
                correlation["type"],
                correlation["type"],
            )

            print(f"  - {display_name}")
            print(f"    User: {correlation['user']}")
            print(
                f"    Time delta: "
                f"{correlation['time_delta_seconds']} seconds"
            )