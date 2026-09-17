from app.models.schemas import Evidence, DetectionResult


def is_login_failure(log):
    return log.event_type == "login_failed"


def group_failures_by_ip(logs):
    failures = {}

    for log in logs:
        if not is_login_failure(log):
            continue

        ip = log.src_ip

        if ip not in failures:
            failures[ip] = []

        failures[ip].append(log)

    return failures


def is_within_window(logs, window_seconds):
    if not logs:
        return False

    timestamps = [
        log.timestamp
        for log in logs
    ]

    start = min(timestamps)
    end = max(timestamps)

    return (end - start).total_seconds() <= window_seconds


def summarize_ip_failures(logs):
    grouped = group_failures_by_ip(logs)
    results = {}

    for ip, failures in grouped.items():
        users = set()

        for log in failures:
            user = log.user

            if user:
                users.add(user)

        features = {
            "failure_count": len(failures),
            "target_users": sorted(users),
            "login_succeeded": has_login_success(logs, ip),
            "within_window": is_within_window(
                failures,
                60
            ),
            "window_seconds": get_failure_window_seconds(
                failures
            ),
            "average_interval": get_average_interval(
                failures
            ),
            "interval_variability": get_interval_variability(
                failures
            ),
            "unique_target_count": len(users),
        }

        results[ip] = features

    return results


def has_login_success(logs, ip):
    for log in logs:
        if (
            log.src_ip == ip
            and log.event_type == "user_login"
        ):
            return True

    return False


def get_failure_window_seconds(logs):
    if not logs:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    start = min(timestamps)
    end = max(timestamps)

    return (end - start).total_seconds()


def get_average_interval(logs):
    if len(logs) < 2:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    timestamps.sort()

    intervals = []

    for i in range(1, len(timestamps)):
        interval = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds()

        intervals.append(interval)

    return sum(intervals) / len(intervals)


def get_interval_variability(logs):
    if len(logs) < 3:
        return 0

    timestamps = [
        log.timestamp
        for log in logs
    ]

    timestamps.sort()

    intervals = []

    for i in range(1, len(timestamps)):
        interval = (
            timestamps[i] - timestamps[i - 1]
        ).total_seconds()

        intervals.append(interval)

    average = sum(intervals) / len(intervals)

    differences = []

    for interval in intervals:
        differences.append(
            abs(interval - average)
        )

    average_difference = (
        sum(differences) / len(differences)
    )

    return average_difference


def detect_brute_force(features, failures):
    evidence = []

    enough_failures = (
        features["failure_count"] >= 5
    )

    single_target = (
        features["unique_target_count"] == 1
    )

    concentrated_in_time = (
        features["within_window"]
    )

    if (
        enough_failures
        and single_target
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
                source="brute_force_detector",
                time_range=(
                    start_time,
                    end_time,
                ),
            )
        )

        evidence.append(
            Evidence(
                type="single_target_user",
                value=features["unique_target_count"],
                source="brute_force_detector",
            )
        )

        evidence.append(
            Evidence(
                type="failures_within_short_window",
                value=features["window_seconds"],
                source="brute_force_detector",
            )
        )

        return DetectionResult(
            is_detected=True,
            detection_type="brute_force",
            evidence=evidence,
        )

    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )