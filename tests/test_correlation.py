from datetime import datetime, timedelta, timezone

from app.analyzer.pipeline import correlate_attacks

from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_post_authentication_activity,
    correlate_brute_force_to_success,
    correlate_password_spray_to_success,
)

from app.models.schemas import (
    NormalizedEvent,
    DetectionResult,
)


def make_event(
    timestamp,
    event_type,
    user,
    src_ip="192.168.1.20",
):
    if isinstance(timestamp, str):
        timestamp = datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        )

    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event_type,
        source="application",
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw="test log",
    )


def test_failed_login_followed_by_successful_login():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "user_login",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is True
    assert result["type"] == "failed_to_successful_login"
    assert result["user"] == "admin"
    assert result["time_delta_seconds"] == 8.0


def test_correlation_at_window_boundary():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:01:00",
            "user_login",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is True
    assert result["time_delta_seconds"] == 60.0


def test_correlation_outside_window():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:01:01",
            "user_login",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is False


def test_different_users_are_not_correlated():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "user_login",
            "alice",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is False


def test_success_followed_by_failure_is_not_correlated():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "user_login",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "login_failed",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is False


def test_only_failed_login_is_not_correlated():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "login_failed",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is False


def test_only_successful_login_is_not_correlated():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "user_login",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is False


def test_selects_closest_failure_before_success():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "user_login",
            "admin",
        ),
    ]

    result = correlate_authentication_transition(logs)

    assert result["is_correlated"] is True

    assert result["failure_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        5,
    )

    assert result["success_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        8,
    )

    assert result["time_delta_seconds"] == 3.0


def test_successful_login_followed_by_file_access():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "user_login",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:20",
            "file_access",
            "admin",
        ),
    ]

    result = correlate_post_authentication_activity(logs)

    assert result["is_correlated"] is True
    assert result["type"] == "successful_login_to_file_access"
    assert result["user"] == "admin"
    assert result["time_delta_seconds"] == 20.0


def test_pipeline_correlates_authentication_and_post_authentication():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "user_login",
            "admin",
        ),
        make_event(
            "2026-09-16 10:00:20",
            "file_access",
            "admin",
        ),
    ]

    results = {
        "192.168.1.20": {
            "features": {},
            "detections": {
                "brute_force": DetectionResult(
                    is_detected=False,
                    detection_type=None,
                    evidence=[],
                ),
                "password_spray": DetectionResult(
                    is_detected=False,
                    detection_type=None,
                    evidence=[],
                ),
            }
        }
    }

    result = correlate_attacks(
        logs,
        results,
    )

    correlation = result["192.168.1.20"]["correlation"]

    assert correlation["authentication"]["is_correlated"] is True
    assert correlation["post_authentication"]["is_correlated"] is True


def test_correlation_handles_different_timezones():
    failed = NormalizedEvent(
        timestamp=datetime(
            2026,
            9,
            14,
            11,
            0,
            0,
            tzinfo=timezone(timedelta(hours=9)),
        ),
        event_type="login_failed",
        source="application",
        user="admin",
        src_ip="192.168.1.20",
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw="test log",
    )

    success = NormalizedEvent(
        timestamp=datetime(
            2026,
            9,
            14,
            2,
            0,
            30,
            tzinfo=timezone.utc,
        ),
        event_type="user_login",
        source="ssh",
        user="admin",
        src_ip="192.168.1.20",
        dst_ip=None,
        application="sshd",
        protocol="ssh",
        user_agent=None,
        raw="test log",
    )

    result = correlate_authentication_transition(
        [failed, success]
    )

    assert result["is_correlated"] is True
    assert result["time_delta_seconds"] == 30


def test_correlates_brute_force_to_successful_login():
    logs = [
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                1,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                3,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                5,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                7,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                9,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                20,
                tzinfo=timezone.utc,
            ),
            "user_login",
            "admin",
            src_ip="10.0.0.50",
        ),
    ]

    brute_force_detection = DetectionResult(
        is_detected=True,
        detection_type="brute_force",
        evidence=[],
    )

    result = correlate_brute_force_to_success(
        logs,
        brute_force_detection,
    )

    assert result["is_correlated"] is True
    assert result["type"] == (
        "brute_force_to_successful_login"
    )
    assert result["user"] == "admin"
    assert result["time_delta_seconds"] == 11


def test_pipeline_correlates_brute_force_to_successful_login():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            "2026-09-16 10:00:02",
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            "2026-09-16 10:00:04",
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            "2026-09-16 10:00:06",
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "login_failed",
            "admin",
            src_ip="10.0.0.50",
        ),
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.50",
        ),
    ]

    results = {
        "10.0.0.50": {
            "features": {
                "failure_count": 5,
                "target_users": ["admin"],
                "login_succeeded": True,
                "within_window": True,
                "window_seconds": 8.0,
                "average_interval": 2.0,
                "interval_variability": 0,
                "unique_target_count": 1,
            },
            "detections": {
                "brute_force": DetectionResult(
                    is_detected=True,
                    detection_type="brute_force",
                    evidence=[],
                ),
                "password_spray": DetectionResult(
                    is_detected=False,
                    detection_type=None,
                    evidence=[],
                ),
            },
        }
    }

    result = correlate_attacks(
        logs,
        results,
    )

    correlation = result["10.0.0.50"]["correlation"]

    assert correlation["brute_force_to_success"]["is_correlated"] is True
    assert correlation["brute_force_to_success"]["type"] == (
        "brute_force_to_successful_login"
    )
    assert correlation["brute_force_to_success"]["user"] == "admin"
    assert correlation["brute_force_to_success"]["time_delta_seconds"] == 12


def test_correlates_password_spray_to_successful_login():
    logs = [
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                1,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.60",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                3,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "alice",
            src_ip="10.0.0.60",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                5,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "bob",
            src_ip="10.0.0.60",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                7,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "guest",
            src_ip="10.0.0.60",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                12,
                tzinfo=timezone.utc,
            ),
            "login_failed",
            "admin",
            src_ip="10.0.0.60",
        ),
        make_event(
            datetime(
                2026,
                9,
                14,
                2,
                0,
                20,
                tzinfo=timezone.utc,
            ),
            "user_login",
            "admin",
            src_ip="10.0.0.60",
        ),
    ]

    password_spray_detection = DetectionResult(
        is_detected=True,
        detection_type="password_spraying_like",
        evidence=[],
    )

    result = correlate_password_spray_to_success(
        logs,
        password_spray_detection,
    )

    assert result["is_correlated"] is True
    assert result["type"] == (
        "password_spray_to_successful_login"
    )
    assert result["user"] == "admin"
    assert result["time_delta_seconds"] == 8

def test_pipeline_correlates_password_spray_to_successful_login():
    logs = [
        make_event(
            "2026-09-16 10:00:00",
            "login_failed",
            "admin",
            src_ip="10.0.0.60",
        ),
        make_event(
            "2026-09-16 10:00:02",
            "login_failed",
            "alice",
            src_ip="10.0.0.60",
        ),
        make_event(
            "2026-09-16 10:00:04",
            "login_failed",
            "bob",
            src_ip="10.0.0.60",
        ),
        make_event(
            "2026-09-16 10:00:06",
            "login_failed",
            "guest",
            src_ip="10.0.0.60",
        ),
        make_event(
            "2026-09-16 10:00:08",
            "login_failed",
            "admin",
            src_ip="10.0.0.60",
        ),
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.60",
        ),
    ]

    results = {
        "10.0.0.60": {
            "features": {
                "failure_count": 5,
                "target_users": [
                    "admin",
                    "alice",
                    "bob",
                    "guest",
                ],
                "login_succeeded": True,
                "within_window": True,
                "window_seconds": 8.0,
                "average_interval": 2.0,
                "interval_variability": 0,
                "unique_target_count": 4,
            },
            "detections": {
                "password_spray": DetectionResult(
                    is_detected=True,
                    detection_type="password_spraying_like",
                    evidence=[],
                ),
                "brute_force": DetectionResult(
                    is_detected=False,
                    detection_type=None,
                    evidence=[],
                ),
            },
        }
    }

    result = correlate_attacks(
        logs,
        results,
    )

    correlation = result["10.0.0.60"]["correlation"]

    assert correlation[
        "password_spray_to_success"
    ]["is_correlated"] is True

    assert correlation[
        "password_spray_to_success"
    ]["type"] == (
        "password_spray_to_successful_login"
    )

    assert correlation[
        "password_spray_to_success"
    ]["user"] == "admin"

    assert correlation[
        "password_spray_to_success"
    ]["time_delta_seconds"] == 12