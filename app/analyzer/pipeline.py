from app.loader.file_loader import load_log_lines
from app.parser.registry import get_parser
from app.detector.brute_force import (
    summarize_ip_failures,
    detect_brute_force,
)
from app.detector.password_spray import detect_password_spray
from app.detector.web_attack import detect_path_traversal
from app.correlation.attack_chain import correlate_authentication_transition
from app.analyzer.risk import (
    load_account_metadata,
    build_risk_context,
    get_account_context,
    evaluate_account_privilege_risk,
    build_risk_factors,
    evaluate_risk_level,
)
from app.models.schemas import DetectionResult


def load_normalized_logs(log_sources):

    logs = []

    for config in log_sources:

        parser = get_parser(config["source"])

        for line in load_log_lines(config["path"]):

            parsed = parser(line)

            if parsed is not None:
                logs.append(parsed)

    return logs


def group_logs_by_ip(logs):

    grouped = {}

    for log in logs:

        if log.src_ip is None:
            continue

        if log.src_ip not in grouped:
            grouped[log.src_ip] = []

        grouped[log.src_ip].append(log)

    return grouped


def create_empty_detection():

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )


def create_empty_detections():

    return {
        "brute_force": create_empty_detection(),
        "password_spray": create_empty_detection(),
        "path_traversal": create_empty_detection(),
    }


def create_empty_features():

    return {
        "failure_count": 0,
        "target_users": [],
        "login_succeeded": False,
        "within_window": False,
        "window_seconds": 0,
        "average_interval": 0,
        "interval_variability": 0,
        "unique_target_count": 0,
    }


def create_empty_result():

    return {
        "features": create_empty_features(),
        "detections": create_empty_detections(),
    }


def detect_attacks(logs):

    grouped_logs = group_logs_by_ip(logs)

    feature_results = summarize_ip_failures(logs)

    results = {}

    for ip in grouped_logs:

        results[ip] = create_empty_result()

        if ip in feature_results:
            results[ip]["features"] = feature_results[ip]

    for ip, result in results.items():

        ip_logs = grouped_logs[ip]

        failures = [
            log
            for log in ip_logs
            if log.event_type == "login_failed"
        ]

        if failures:

            brute_force_result = detect_brute_force(
                result["features"],
                failures,
            )

            result["detections"]["brute_force"] = (
                brute_force_result
            )

            spray_result = detect_password_spray(
                result["features"],
                failures,
            )

            result["detections"]["password_spray"] = (
                spray_result
            )

    for log in logs:

        if log.src_ip is None:
            continue

        if log.event_type != "http_request":
            continue

        if log.http is None:
            continue

        path_result = detect_path_traversal(
            log.http.path,
            log.http.query,
            log.http.method,
            log.http.status_code,
            log.http.response_size,
        )

        if path_result.is_detected:

            result = results[log.src_ip]

            result["detections"]["path_traversal"] = (
                path_result
            )

    return results


def correlate_attacks(logs, results):

    grouped_logs = group_logs_by_ip(logs)

    for ip, result in results.items():

        ip_logs = grouped_logs.get(ip, [])

        correlation_result = correlate_authentication_transition(
            ip_logs
        )

        result["correlation"] = correlation_result

    return results


def assess_risk(results):

    account_metadata = load_account_metadata()

    for ip, result in results.items():

        risk_context = build_risk_context(result)

        account_context = get_account_context(
            risk_context,
            account_metadata
        )

        account_privilege_risk = evaluate_account_privilege_risk(
            account_context
        )

        risk_factors = build_risk_factors(
            risk_context,
            account_privilege_risk
        )

        risk_factors["account_context"] = account_context

        result["risk_factors"] = risk_factors

        risk_level = evaluate_risk_level(result)

        result["risk_level"] = risk_level

    return results