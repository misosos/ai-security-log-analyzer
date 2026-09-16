from app.loader.file_loader import load_log_lines
from app.parser.registry import get_parser
from app.detector.brute_force import summarize_ip_failures
from app.detector.password_spray import detect_password_spray
from app.correlation.attack_chain import correlate_authentication_transition
from app.analyzer.risk import (
    load_account_metadata,
    get_account_context,
    evaluate_account_privilege_risk,
    build_risk_factors,
    evaluate_risk_level,
)


def load_normalized_logs(log_sources):

    logs = []

    for config in log_sources:

        parser = get_parser(config["source"])

        for line in load_log_lines(config["path"]):

            parsed = parser(line)

            logs.append(parsed)

    return logs


def detect_attacks(logs):

    results = summarize_ip_failures(logs)

    for ip, features in results.items():

        ip_logs = [
            log for log in logs
            if log.src_ip == ip
        ]

        failures = [
            log for log in ip_logs
            if log.event_type == "login_failed"
        ]

        spray_result = detect_password_spray(
            features,
            failures
        )

        features["detections"]["password_spray"] = spray_result

    return results


def correlate_attacks(logs, results):

    for ip, features in results.items():

        ip_logs = [
            log for log in logs
            if log.src_ip == ip
        ]

        correlation_result = correlate_authentication_transition(
            ip_logs
        )

        features["correlation"] = correlation_result

    return results


def assess_risk(results):

    account_metadata = load_account_metadata()

    for ip, features in results.items():

        account_context = get_account_context(
            features,
            account_metadata
        )

        account_privilege_risk = evaluate_account_privilege_risk(
            account_context
        )

        risk_factors = build_risk_factors(
            features,
            account_privilege_risk
        )

        risk_factors["account_context"] = account_context

        features["risk_factors"] = risk_factors

        risk_level = evaluate_risk_level(features)

        features["risk_level"] = risk_level

    return results