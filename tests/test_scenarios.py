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

    analysis = result["192.168.1.10"]

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

    analysis = result["192.168.1.20"]

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

    analysis = result["192.168.1.30"]

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

    analysis = result["192.168.1.40"]

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

    analysis = result["10.0.0.5"]

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

    analysis = result["192.168.1.60"]

    detection = analysis["detections"]["path_traversal"]

    assert detection.is_detected is True
    assert detection.detection_type == "path_traversal"

    assert analysis["risk_factors"]["likelihood"]["level"] == "HIGH"
    assert analysis["risk_factors"]["impact"]["level"] == "MEDIUM"

    assert (
        "실제 민감 파일의 내용이 반환되었는지는 현재 로그만으로 확인되지 않음"
        in analysis["risk_factors"]["impact"]["rationale"]
    )