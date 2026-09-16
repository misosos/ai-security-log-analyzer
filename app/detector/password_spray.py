from app.models.schemas import Evidence, DetectionResult


def detect_password_spray(features, failures):
    evidence = []

    enough_failures = (
        features["failure_count"] >= 4
    )

    multiple_targets = (
        features["unique_target_count"] >= 3
    )

    concentrated_in_time = (
        features["within_window"]
    )

    if (
        enough_failures
        and multiple_targets
        and concentrated_in_time
    ):
        timestamps = [
            log.timestamp
            for log in failures
        ]

        start_time = min(timestamps)
        end_time = max(timestamps)

        evidence.append(
            Evidence(
                type="multiple_login_failures",
                value=features["failure_count"],
                source="password_spray_detector",
                time_range=(
                    start_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    end_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                ),
            )
        )

        evidence.append(
            Evidence(
                type="multiple_target_users",
                value=features["unique_target_count"],
                source="password_spray_detector",
            )
        )

        evidence.append(
            Evidence(
                type="failures_within_short_window",
                value=features["window_seconds"],
                source="password_spray_detector",
            )
        )

        return DetectionResult(
            is_detected=True,
            detection_type="password_spraying_like",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )