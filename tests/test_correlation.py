from datetime import datetime

from app.models.schemas import NormalizedEvent
from app.analyzer.pipeline import correlate_attacks

from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_post_authentication_activity,
)


def make_event(
    timestamp,
    event_type,
    user,
    src_ip="192.168.1.20",
):
    return NormalizedEvent(
        timestamp=datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S",
        ),
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
            "detections": {},
        }
    }

    result = correlate_attacks(logs, results)

    correlation = result["192.168.1.20"]["correlation"]

    assert correlation["authentication"]["is_correlated"] is True
    assert correlation["post_authentication"]["is_correlated"] is True