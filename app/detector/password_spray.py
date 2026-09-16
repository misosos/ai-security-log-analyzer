
from app.models.schemas import Evidence
from datetime import datetime

def parse_timestamp(timestamp):
    return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

def detect_password_spray(features, failures):
    evidence = []
    timestamps = [
        parse_timestamp(log.timestamp)
        for log in failures
    ]
    start_time = min(timestamps)
    end_time = max(timestamps)

    enough_failures = features["failure_count"] >= 4
    multiple_targets = features["unique_target_count"] >= 3
    concentrated_in_time = features["within_window"]

    if enough_failures:
        evidence.append(
            Evidence(
                type="multiple_login_failures",
                value=features["failure_count"],
                source="password_spray_detector",
                time_range=(
                    start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    end_time.strftime("%Y-%m-%d %H:%M:%S")
                )
            )
        )

    if multiple_targets:
        evidence.append(
            Evidence(
                type="multiple_target_users",
                value=features["unique_target_count"],
                source="password_spray_detector"
            )
        )

    if concentrated_in_time:
        evidence.append(
            Evidence(
                type="failures_within_short_window",
                value=features["window_seconds"],
                source="password_spray_detector"
            )
        )

    if enough_failures and multiple_targets and concentrated_in_time:
        return {
            "is_detected": True,
            "detection_type": "password_spraying_like",
            "evidence": evidence,
        }

    return {
        "is_detected": False,
        "detection_type": None,
        "evidence": []
    }
