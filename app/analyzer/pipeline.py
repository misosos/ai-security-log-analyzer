from app.loader.file_loader import load_log_lines
from app.parser.registry import get_parser
from app.detector.brute_force import summarize_ip_failures
from app.detector.password_spray import detect_password_spray


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