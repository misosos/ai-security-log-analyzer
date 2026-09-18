from copy import deepcopy
from datetime import datetime, timedelta, timezone

from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks,
    load_normalized_logs,
)

from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_post_authentication_activity,
    correlate_brute_force_to_success,
    correlate_password_spray_to_success,
    correlate_multi_ip_authentication,
    correlate_distributed_authentication_to_success,
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
            },
        }
    }

    result = correlate_attacks(
        logs,
        results,
    )

    correlation = result["results"]["192.168.1.20"]["correlation"]

    assert correlation["authentication"]["is_correlated"] is True
    assert (
        correlation["post_authentication"]["is_correlated"]
        is True
    )


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

    correlation = result["results"]["10.0.0.50"]["correlation"]

    assert (
        correlation["brute_force_to_success"]["is_correlated"]
        is True
    )

    assert correlation["brute_force_to_success"]["type"] == (
        "brute_force_to_successful_login"
    )

    assert correlation["brute_force_to_success"]["user"] == "admin"

    assert (
        correlation["brute_force_to_success"]["time_delta_seconds"]
        == 12
    )


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

    correlation = result["results"]["10.0.0.60"]["correlation"]

    assert (
        correlation["password_spray_to_success"]["is_correlated"]
        is True
    )

    assert (
        correlation["password_spray_to_success"]["type"]
        == "password_spray_to_successful_login"
    )

    assert (
        correlation["password_spray_to_success"]["user"]
        == "admin"
    )

    assert (
        correlation["password_spray_to_success"]["time_delta_seconds"]
        == 12
    )


def test_correlates_same_account_from_multiple_ips():
    logs = [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.0.3",
        ),
        make_event(
            "2026-09-16 10:00:07",
            "login_failed",
            "admin",
            src_ip="10.0.0.4",
        ),
        make_event(
            "2026-09-16 10:00:09",
            "login_failed",
            "admin",
            src_ip="10.0.0.5",
        ),
    ]

    results = correlate_multi_ip_authentication(logs)

    assert len(results) == 1

    result = results[0]

    assert result["is_correlated"] is True
    assert result["type"] == "multi_ip_authentication_failure"
    assert result["user"] == "admin"

    assert result["source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
    ]

    assert result["failure_count"] == 5
    assert result["failure_start_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        1,
    )
    assert result["failure_end_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        9,
    )
    assert result["time_window_seconds"] == 8.0


def test_pipeline_correlates_same_account_from_multiple_ips():
    logs = [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.0.3",
        ),
        make_event(
            "2026-09-16 10:00:07",
            "login_failed",
            "admin",
            src_ip="10.0.0.4",
        ),
        make_event(
            "2026-09-16 10:00:09",
            "login_failed",
            "admin",
            src_ip="10.0.0.5",
        ),
    ]

    results = {
        "10.0.0.1": {
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
            },
        },
        "10.0.0.2": {
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
            },
        },
        "10.0.0.3": {
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
            },
        },
        "10.0.0.4": {
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
            },
        },
        "10.0.0.5": {
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
            },
        },
    }

    result = correlate_attacks(
        logs,
        results,
    )

    multi_ip_results = result["global_correlation"][
        "multi_ip_authentication"
    ]

    assert len(multi_ip_results) == 1

    multi_ip_result = multi_ip_results[0]

    assert multi_ip_result["is_correlated"] is True
    assert multi_ip_result["type"] == (
        "multi_ip_authentication_failure"
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


def test_collects_multi_ip_authentication_for_multiple_users():
    logs = [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.0.3",
        ),
        make_event(
            "2026-09-16 10:01:01",
            "login_failed",
            "alice",
            src_ip="10.0.1.1",
        ),
        make_event(
            "2026-09-16 10:01:03",
            "login_failed",
            "alice",
            src_ip="10.0.1.2",
        ),
        make_event(
            "2026-09-16 10:01:05",
            "login_failed",
            "alice",
            src_ip="10.0.1.3",
        ),
    ]

    results = correlate_multi_ip_authentication(logs)

    assert [result["user"] for result in results] == [
        "admin",
        "alice",
    ]

    assert results[0]["source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert results[1]["source_ips"] == [
        "10.0.1.1",
        "10.0.1.2",
        "10.0.1.3",
    ]


def test_multi_ip_authentication_order_is_deterministic():
    logs = [
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "alice",
            src_ip="10.0.1.3",
        ),
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "alice",
            src_ip="10.0.1.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "alice",
            src_ip="10.0.1.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.0.3",
        ),
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
    ]

    forward_results = correlate_multi_ip_authentication(logs)
    reversed_results = correlate_multi_ip_authentication(
        list(reversed(logs))
    )

    assert forward_results == reversed_results
    assert [result["user"] for result in forward_results] == [
        "admin",
        "alice",
    ]


def test_multi_ip_authentication_returns_empty_collection():
    logs = [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
    ]

    result = correlate_multi_ip_authentication(logs)

    assert result == []


def test_multi_ip_authentication_keeps_first_campaign_per_user():
    logs = [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.0.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.0.3",
        ),
        make_event(
            "2026-09-16 11:00:01",
            "login_failed",
            "admin",
            src_ip="10.0.1.1",
        ),
        make_event(
            "2026-09-16 11:00:03",
            "login_failed",
            "admin",
            src_ip="10.0.1.2",
        ),
        make_event(
            "2026-09-16 11:00:05",
            "login_failed",
            "admin",
            src_ip="10.0.1.3",
        ),
    ]

    results = correlate_multi_ip_authentication(logs)

    assert len(results) == 1
    assert results[0]["source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert results[0]["failure_start_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        1,
    )
    assert results[0]["failure_end_timestamp"] == datetime(
        2026,
        9,
        16,
        10,
        0,
        5,
    )
    assert results[0]["time_window_seconds"] == 4.0


def make_distributed_failure_logs(user="admin"):
    return [
        make_event(
            "2026-09-16 10:00:01",
            "login_failed",
            user,
            src_ip="10.0.0.1",
        ),
        make_event(
            "2026-09-16 10:00:03",
            "login_failed",
            user,
            src_ip="10.0.0.2",
        ),
        make_event(
            "2026-09-16 10:00:05",
            "login_failed",
            user,
            src_ip="10.0.0.3",
        ),
    ]


def correlate_distributed_success(logs, success_window_seconds=60):
    failures = correlate_multi_ip_authentication(logs)

    return correlate_distributed_authentication_to_success(
        logs,
        failures,
        success_window_seconds=success_window_seconds,
    )


def test_correlates_distributed_failures_to_same_user_success():
    logs = make_distributed_failure_logs()
    logs.append(
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        )
    )

    results = correlate_distributed_success(logs)

    assert len(results) == 1
    result = results[0]

    assert result["is_correlated"] is True
    assert result["type"] == (
        "distributed_authentication_failures_to_successful_login"
    )
    assert result["user"] == "admin"
    assert result["failure_source_ips"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert result["failure_count"] == 3
    assert result["failure_start_timestamp"] == datetime(
        2026, 9, 16, 10, 0, 1
    )
    assert result["failure_end_timestamp"] == datetime(
        2026, 9, 16, 10, 0, 5
    )
    assert result["failure_duration_seconds"] == 4.0
    assert result["success_timestamp"] == datetime(
        2026, 9, 16, 10, 0, 20
    )
    assert result["success_source_ip"] == "10.0.0.4"
    assert result["success_from_failure_source"] is False
    assert result["time_delta_seconds"] == 15.0
    assert any(
        "인과관계를 확인할 수 없음" in rationale
        for rationale in result["rationale"]
    )


def test_distributed_success_uses_failure_correlations_as_source_of_truth():
    failure_correlations = [
        {
            "user": "admin",
            "source_ips": [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3",
            ],
            "failure_count": 3,
            "failure_start_timestamp": datetime(
                2026, 9, 16, 10, 0, 1
            ),
            "failure_end_timestamp": datetime(
                2026, 9, 16, 10, 0, 5
            ),
        }
    ]
    logs = [
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        )
    ]

    results = correlate_distributed_authentication_to_success(
        logs,
        failure_correlations,
    )

    assert len(results) == 1
    assert results[0]["failure_count"] == 3
    assert results[0]["time_delta_seconds"] == 15.0


def test_distributed_success_requires_valid_same_user_subsequent_event():
    failures = make_distributed_failure_logs()

    invalid_success_sets = [
        [],
        [
            make_event(
                "2026-09-16 09:59:59",
                "user_login",
                "admin",
            )
        ],
        [
            make_event(
                "2026-09-16 10:01:06",
                "user_login",
                "admin",
            )
        ],
        [
            make_event(
                "2026-09-16 10:00:20",
                "user_login",
                "alice",
            )
        ],
        [
            make_event(
                "2026-09-16 10:00:05",
                "user_login",
                "admin",
            )
        ],
    ]

    for success_logs in invalid_success_sets:
        assert correlate_distributed_success(
            failures + success_logs
        ) == []


def test_distributed_success_source_membership_is_context_only():
    for success_ip, expected_membership in [
        ("10.0.0.2", True),
        ("10.0.0.4", False),
    ]:
        logs = make_distributed_failure_logs()
        logs.append(
            make_event(
                "2026-09-16 10:00:20",
                "user_login",
                "admin",
                src_ip=success_ip,
            )
        )

        results = correlate_distributed_success(logs)

        assert len(results) == 1
        assert results[0]["success_source_ip"] == success_ip
        assert (
            results[0]["success_from_failure_source"]
            is expected_membership
        )


def test_distributed_success_selects_nearest_event_deterministically():
    logs = make_distributed_failure_logs() + [
        make_event(
            "2026-09-16 10:00:40",
            "user_login",
            "admin",
            src_ip="10.0.0.5",
        ),
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        ),
    ]

    forward = correlate_distributed_success(logs)
    reversed_result = correlate_distributed_success(
        list(reversed(logs))
    )

    assert forward == reversed_result
    assert forward[0]["success_source_ip"] == "10.0.0.4"
    assert forward[0]["time_delta_seconds"] == 15.0


def test_distributed_success_requires_qualifying_failure_campaign():
    logs = make_distributed_failure_logs()[:2]
    logs.append(
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
        )
    )

    assert correlate_multi_ip_authentication(logs) == []
    assert correlate_distributed_success(logs) == []


def test_distributed_success_preserves_multiple_users():
    admin_logs = make_distributed_failure_logs("admin")
    alice_logs = [
        make_event(
            datetime(2026, 9, 16, 10, 1, second),
            "login_failed",
            "alice",
            src_ip=f"10.0.1.{index}",
        )
        for index, second in enumerate((1, 3, 5), start=1)
    ]
    logs = admin_logs + alice_logs + [
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        ),
        make_event(
            "2026-09-16 10:01:20",
            "user_login",
            "alice",
            src_ip="10.0.1.4",
        ),
    ]

    results = correlate_distributed_success(logs)

    assert [result["user"] for result in results] == [
        "admin",
        "alice",
    ]


def test_distributed_success_handles_timezone_aware_timestamps():
    utc = timezone.utc
    kst = timezone(timedelta(hours=9))
    logs = [
        make_event(
            datetime(2026, 9, 16, 1, 0, second, tzinfo=utc),
            "login_failed",
            "admin",
            src_ip=f"10.0.0.{index}",
        )
        for index, second in enumerate((1, 3, 5), start=1)
    ]
    logs.append(
        make_event(
            datetime(2026, 9, 16, 10, 0, 20, tzinfo=kst),
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        )
    )

    result = correlate_distributed_success(logs)[0]

    assert result["time_delta_seconds"] == 15.0


def test_distributed_success_window_is_inclusive_and_uses_last_failure():
    logs = make_distributed_failure_logs()
    logs.append(
        make_event(
            "2026-09-16 10:01:05",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        )
    )

    result = correlate_distributed_success(logs)[0]

    assert result["time_delta_seconds"] == 60.0
    assert result["failure_duration_seconds"] == 4.0


def test_pipeline_exposes_both_global_collections_and_isolates_risk():
    logs = make_distributed_failure_logs()
    logs.append(
        make_event(
            "2026-09-16 10:00:20",
            "user_login",
            "admin",
            src_ip="10.0.0.4",
        )
    )

    correlated = correlate_attacks(logs, detect_attacks(logs))

    assert len(
        correlated["global_correlation"][
            "multi_ip_authentication"
        ]
    ) == 1
    assert len(
        correlated["global_correlation"][
            "distributed_authentication_to_success"
        ]
    ) == 1

    without_new_global = deepcopy(correlated)
    without_new_global["global_correlation"][
        "distributed_authentication_to_success"
    ] = []

    with_global_risk = assess_risk(deepcopy(correlated))
    without_global_risk = assess_risk(without_new_global)

    assert with_global_risk["results"] == (
        without_global_risk["results"]
    )


def test_pipeline_exposes_linux_audit_session_lifecycle_and_isolates_risk(
    tmp_path,
):
    path = tmp_path / "session-lifecycle.log"
    path.write_text(
        "\n".join([
            "node=host-a type=USER_START "
            "msg=audit(1790200000.001:801): "
            "uid=0 auid=1000 ses=71 "
            "msg='op=PAM:session_open acct=training-user "
            "exe=/usr/sbin/sshd hostname=remote-a "
            "addr=198.51.100.80 terminal=ssh res=success'",
            "node=host-a type=USER_END "
            "msg=audit(1790200010.001:802): "
            "uid=0 auid=1000 ses=71 "
            "msg='op=PAM:session_close acct=training-user "
            "exe=/usr/sbin/sshd hostname=remote-a "
            "addr=198.51.100.80 terminal=ssh res=success'",
        ]),
        encoding="utf-8",
    )
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "feed-a",
        "path": path,
    }])
    correlated = correlate_attacks(logs, detect_attacks(logs))

    lifecycle = correlated["global_correlation"][
        "linux_audit_session_lifecycle"
    ]

    assert len(lifecycle) == 1
    assert lifecycle[0]["type"] == (
        "linux_audit_session_lifecycle"
    )
    assert lifecycle[0]["source_instance"] == "feed-a"
    assert lifecycle[0]["node"] == "host-a"
    assert lifecycle[0][
        "observed_session_lifecycle_interval_seconds"
    ] == 10.0

    without_lifecycle = deepcopy(correlated)
    without_lifecycle["global_correlation"][
        "linux_audit_session_lifecycle"
    ] = []

    assert assess_risk(deepcopy(correlated))["results"] == (
        assess_risk(without_lifecycle)["results"]
    )


def test_pipeline_exposes_login_start_co_observation_and_isolates_risk():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "phase-3l-openssh-pam-pty",
        "path": (
            "sample_logs/"
            "linux_audit_openssh_pam_pty_source_derived.log"
        ),
    }])
    correlated = correlate_attacks(logs, detect_attacks(logs))

    observations = correlated["global_correlation"][
        "linux_audit_login_start_co_observation"
    ]

    assert len(observations) == 1
    assert observations[0]["type"] == (
        "linux_audit_login_start_co_observation"
    )
    assert observations[0]["source_instance"] == (
        "phase-3l-openssh-pam-pty"
    )
    assert observations[0]["node"] == "fixture-sshd-pam"
    assert observations[0]["start_timestamp"] < (
        observations[0]["login_timestamp"]
    )
    assert "observed_login_to_start_interval_seconds" not in (
        observations[0]
    )
    assert correlated["global_correlation"][
        "linux_audit_session_lifecycle"
    ] == []

    without_observation = deepcopy(correlated)
    without_observation["global_correlation"][
        "linux_audit_login_start_co_observation"
    ] = []

    assert assess_risk(deepcopy(correlated))["results"] == (
        assess_risk(without_observation)["results"]
    )


def test_pipeline_preserves_presence_only_and_ambiguous_empty_semantics():
    fixture_paths = (
        "sample_logs/"
        "linux_audit_openssh_pam_non_pty_source_derived.log",
        "sample_logs/"
        "linux_audit_openssh_no_pam_source_derived.log",
        "sample_logs/"
        "linux_audit_login_start_ambiguous_synthetic.log",
    )

    for index, path in enumerate(fixture_paths):
        logs = load_normalized_logs([{
            "source": "linux_audit",
            "source_instance": f"phase-3l-negative-{index}",
            "path": path,
        }])
        correlated = correlate_attacks(logs, detect_attacks(logs))

        assert correlated["global_correlation"][
            "linux_audit_login_start_co_observation"
        ] == []


def test_util_linux_fixture_populates_independent_telemetry_relations():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "phase-3l-util-linux",
        "path": (
            "sample_logs/"
            "linux_audit_util_linux_login_pam_source_derived.log"
        ),
    }])
    correlated = correlate_attacks(logs, detect_attacks(logs))

    login_start = correlated["global_correlation"][
        "linux_audit_login_start_co_observation"
    ]
    start_end = correlated["global_correlation"][
        "linux_audit_session_lifecycle"
    ]

    assert len(login_start) == 1
    assert len(start_end) == 1
    assert login_start[0]["start_timestamp"] < (
        login_start[0]["login_timestamp"]
    )
    assert login_start[0]["type"] == (
        "linux_audit_login_start_co_observation"
    )
    assert start_end[0]["type"] == (
        "linux_audit_session_lifecycle"
    )
