
from app.detector.web_attack import (
    is_path_traversal,
    detect_path_traversal,
)
from app.detector.brute_force import detect_brute_force
from app.models.schemas import NormalizedEvent

from app.detector.password_spray import detect_password_spray
from app.models.schemas import NormalizedEvent


def test_path_traversal():
    assert is_path_traversal("/index.php") is False
    assert is_path_traversal("/../../etc/passwd") is True
    assert is_path_traversal("/..%2f..%2fetc/passwd") is True
    assert is_path_traversal("/%2e%2e/%2e%2e/etc/passwd") is True


def test_detect_path_traversal():
    result = detect_path_traversal("/..%2f..%2fetc/passwd")

    assert result.is_detected is True
    assert result.detection_type == "path_traversal"

    assert result.evidence[0].type == "url_decoded_path"
    assert result.evidence[0].value == "/../../etc/passwd"

    assert result.evidence[1].type == "path_pattern"
    assert result.evidence[1].value == "../"


def test_detect_password_spray():
    failures = [
        NormalizedEvent(
            timestamp="2026-09-11 10:00:01",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.30",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:03",
            event_type="login_failed",
            source="auth_log",
            user="alice",
            src_ip="192.168.1.30",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:05",
            event_type="login_failed",
            source="auth_log",
            user="bob",
            src_ip="192.168.1.30",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:07",
            event_type="login_failed",
            source="auth_log",
            user="guest",
            src_ip="192.168.1.30",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
    ]

    features = {
        "failure_count": 4,
        "unique_target_count": 4,
        "within_window": True,
        "window_seconds": 6.0,
    }

    result = detect_password_spray(
        features,
        failures,
    )

    assert result.is_detected is True
    assert result.detection_type == "password_spraying_like"

    assert len(result.evidence) == 3

    assert result.evidence[0].type == "multiple_login_failures"
    assert result.evidence[0].value == 4

    assert result.evidence[1].type == "multiple_target_users"
    assert result.evidence[1].value == 4

    assert result.evidence[2].type == "failures_within_short_window"
    assert result.evidence[2].value == 6.0


def test_detect_brute_force():
    failures = [
        NormalizedEvent(
            timestamp="2026-09-11 10:00:01",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.20",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:05",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.20",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:09",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.20",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:13",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.20",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
        NormalizedEvent(
            timestamp="2026-09-11 10:00:17",
            event_type="login_failed",
            source="auth_log",
            user="admin",
            src_ip="192.168.1.20",
            dst_ip=None,
            application=None,
            protocol=None,
            user_agent=None,
            raw="login failed",
        ),
    ]

    features = {
        "failure_count": 5,
        "unique_target_count": 1,
        "within_window": True,
        "window_seconds": 16.0,
    }

    result = detect_brute_force(
        features,
        failures,
    )

    assert result.is_detected is True
    assert result.detection_type == "brute_force"

    assert len(result.evidence) == 3

    assert result.evidence[0].type == "multiple_login_failures"
    assert result.evidence[0].value == 5

    assert result.evidence[1].type == "single_target_user"
    assert result.evidence[1].value == 1

    assert result.evidence[2].type == "failures_within_short_window"
    assert result.evidence[2].value == 16.0
