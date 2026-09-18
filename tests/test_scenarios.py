from app.analyzer.pipeline import (
    load_normalized_logs,
    detect_attacks,
    correlate_attacks,
    assess_risk,
)


def test_normal_user_activity_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/normal.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["192.168.1.10"]

    assert all(
        not detection.is_detected
        for detection in analysis["detections"].values()
    )

    assert analysis["risk_level"] == "LOW"


def test_brute_force_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/brute_force.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["192.168.1.20"]

    assert analysis["detections"]["brute_force"].is_detected is True
    assert analysis["detections"]["brute_force"].detection_type == "brute_force"

    assert analysis["risk_level"] == "HIGH"

def test_password_spray_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/brute_force.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["192.168.1.30"]

    assert analysis["detections"]["password_spray"].is_detected is True
    assert (
        analysis["detections"]["password_spray"].detection_type
        == "password_spraying_like"
    )

    assert analysis["risk_level"] == "HIGH"


def test_slow_attack_boundary_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/brute_force.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["192.168.1.40"]

    assert analysis["detections"]["brute_force"].is_detected is False
    assert analysis["risk_factors"]["likelihood"]["level"] == "LOW"


def test_brute_force_to_success_scenario():
    log_sources = [
        {
            "source": "ssh",
            "path": "sample_logs/ssh_auth.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["10.0.0.5"]

    assert analysis["detections"]["brute_force"].is_detected is True

    correlation = analysis["correlation"]["brute_force_to_success"]

    assert correlation["is_correlated"] is True
    assert correlation["type"] == "brute_force_to_successful_login"
    assert correlation["user"] == "admin"
    assert correlation["time_delta_seconds"] == 11.0

    assert analysis["risk_level"] == "HIGH"


def test_path_traversal_scenario():
    log_sources = [
        {
            "source": "access",
            "path": "sample_logs/web_shell.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    analysis = result["results"]["192.168.1.60"]

    detection = analysis["detections"]["path_traversal"]

    assert detection.is_detected is True
    assert detection.detection_type == "path_traversal"

    assert analysis["risk_factors"]["likelihood"]["level"] == "HIGH"
    assert analysis["risk_factors"]["impact"]["level"] == "MEDIUM"

    assert (
        "실제 민감 파일의 내용이 반환되었는지는 현재 로그만으로 확인되지 않음"
        in analysis["risk_factors"]["impact"]["rationale"]
    )


def test_distributed_same_account_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/distributed_auth_attack.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    # IP별 분석 결과는 5개
    ip_results = result["results"]

    assert len(ip_results) == 5

    for ip in [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
    ]:
        analysis = ip_results[ip]

        assert analysis["features"]["failure_count"] == 1

        assert (
            analysis["detections"]["brute_force"].is_detected
            is False
        )

    # 전체 로그 기준 Multi-IP Correlation 확인
    multi_ip_results = result["global_correlation"][
        "multi_ip_authentication"
    ]

    assert len(multi_ip_results) == 1

    multi_ip_result = multi_ip_results[0]

    assert multi_ip_result["is_correlated"] is True

    assert (
        multi_ip_result["type"]
        == "multi_ip_authentication_failure"
    )

    assert multi_ip_result["user"] == "admin"

    assert multi_ip_result["source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
    ]

    assert multi_ip_result["failure_count"] == 5

    assert multi_ip_result["time_window_seconds"] == 8.0

    assert result["global_correlation"][
        "distributed_authentication_to_success"
    ] == []


def test_distributed_authentication_to_success_scenario():
    log_sources = [
        {
            "source": "application",
            "path": "sample_logs/distributed_auth_success.log",
        }
    ]

    logs = load_normalized_logs(log_sources)
    result = detect_attacks(logs)
    result = correlate_attacks(logs, result)
    result = assess_risk(result)

    for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
        analysis = result["results"][ip]
        assert analysis["features"]["failure_count"] == 1
        assert (
            analysis["detections"]["brute_force"].is_detected
            is False
        )

    global_correlation = result["global_correlation"]

    assert len(global_correlation["multi_ip_authentication"]) == 1
    assert len(
        global_correlation[
            "distributed_authentication_to_success"
        ]
    ) == 1

    correlation = global_correlation[
        "distributed_authentication_to_success"
    ][0]

    assert correlation["user"] == "admin"
    assert correlation["failure_source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert correlation["failure_count"] == 3
    assert correlation["success_source_ip"] == "10.0.0.4"
    assert correlation["success_from_failure_source"] is False
    assert correlation["time_delta_seconds"] == 15.0

    assert all(
        "compromise" not in rationale.lower()
        for rationale in correlation["rationale"]
    )
