from app.loader.file_loader import load_log_lines
from app.loader.linux_audit_loader import load_linux_audit_events
from app.parser.registry import get_parser, get_timezone
from app.detector.brute_force import (
    summarize_ip_failures,
    detect_brute_force,
)
from app.detector.password_spray import detect_password_spray
from app.detector.web_attack import detect_path_traversal
from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_post_authentication_activity,
    correlate_brute_force_to_success,
    correlate_password_spray_to_success,
    correlate_multi_ip_authentication,
    correlate_distributed_authentication_to_success,
)
from app.analyzer.risk import (
    load_account_metadata,
    build_risk_context,
    get_account_context,
    evaluate_account_privilege_risk,
    build_risk_factors,
    evaluate_risk_level,
)
from app.models.schemas import DetectionResult
from app.parser.time_utils import normalize_to_utc
from app.parser.linux_audit import parse_linux_audit_events


def load_normalized_logs(log_sources):

    logs = []

    for config in log_sources:

        source = config["source"]

        if source == "linux_audit":
            audit_events = load_linux_audit_events(
                config["path"],
                source_identity=source,
            )

            for audit_event in audit_events:
                logs.extend(
                    parse_linux_audit_events(audit_event)
                )

            continue

        parser = get_parser(source)
        timezone = get_timezone(source)

        for line in load_log_lines(config["path"]):

            parsed = parser(line, timezone)

            if parsed is not None:
                parsed.timestamp = normalize_to_utc(
                    parsed.timestamp
                )

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
            log.timestamp,
        )

        if path_result.is_detected:

            result = results[log.src_ip]

            result["detections"]["path_traversal"] = (
                path_result
            )

    return results


def correlate_attacks(logs, results):

    grouped_logs = group_logs_by_ip(logs)

    # 전체 로그를 기준으로 수행하는 Correlation
    multi_ip_results = correlate_multi_ip_authentication(
        logs
    )

    distributed_success_results = (
        correlate_distributed_authentication_to_success(
            logs,
            multi_ip_results,
        )
    )

    # IP별 Correlation
    for ip, result in results.items():

        ip_logs = grouped_logs.get(ip, [])

        authentication_result = (
            correlate_authentication_transition(
                ip_logs
            )
        )

        post_authentication_result = (
            correlate_post_authentication_activity(
                ip_logs
            )
        )

        brute_force_result = (
            correlate_brute_force_to_success(
                ip_logs,
                result["detections"]["brute_force"],
            )
        )

        password_spray_result = (
            correlate_password_spray_to_success(
                ip_logs,
                result["detections"]["password_spray"],
            )
        )

        result["correlation"] = {
            "authentication": authentication_result,
            "post_authentication": post_authentication_result,
            "brute_force_to_success": brute_force_result,
            "password_spray_to_success": password_spray_result,
        }

    # IP별 결과와 전체 로그 Correlation을 분리
    return {
        "results": results,
        "global_correlation": {
            "multi_ip_authentication": multi_ip_results,
            "distributed_authentication_to_success": (
                distributed_success_results
            ),
        },
    }


def assess_risk(analysis):

    results = analysis["results"]

    account_metadata = load_account_metadata()

    for ip, result in results.items():

        risk_context = build_risk_context(result)

        account_context = get_account_context(
            risk_context,
            account_metadata,
        )

        account_privilege_risk = (
            evaluate_account_privilege_risk(
                account_context
            )
        )

        risk_factors = build_risk_factors(
            risk_context,
            account_privilege_risk,
        )

        risk_factors["account_context"] = account_context

        result["risk_factors"] = risk_factors

        risk_level = evaluate_risk_level(result)

        result["risk_level"] = risk_level

    return analysis
