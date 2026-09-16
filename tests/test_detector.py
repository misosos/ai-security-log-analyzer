from app.detector.web_attack import (
    is_path_traversal,
    detect_path_traversal,
)
from app.detector.brute_force import (
    detect_brute_force,
    summarize_ip_failures,
)
from app.detector.password_spray import detect_password_spray
from app.models.schemas import NormalizedEvent

from datetime import datetime, timedelta, timezone

def test_path_traversal():
    assert is_path_traversal("/index.php") is False
    assert is_path_traversal("/../../etc/passwd") is True
    assert is_path_traversal("/..%2f..%2fetc/passwd") is True
    assert is_path_traversal("/%2e%2e/%2e%2e/etc/passwd") is True
    assert is_path_traversal(
        "/%252e%252e/%252e%252e/etc/passwd"
    ) is True
    assert is_path_traversal(
        r"..\..\Windows\System32"
    ) is True
    assert is_path_traversal(
        r"..\../etc/passwd"
    ) is True
    assert is_path_traversal(
        "/download?file=report..pdf"
    ) is False

    assert is_path_traversal(
        "/download?name=alice..bob"
    ) is False


def test_detect_path_traversal():
    result = detect_path_traversal(
        "/..%2f..%2fetc/passwd"
    )

    assert result.is_detected is True
    assert result.detection_type == "path_traversal"

    assert result.evidence[0].type == "url_decoded_path"
    assert result.evidence[0].value == "/../../etc/passwd"

    assert result.evidence[1].type == "path_pattern"
    assert result.evidence[1].value == "../"


def test_detect_password_spray():
    failures = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 3),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 5),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 7),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 5),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 9),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 13),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 17),
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


def test_detect_brute_force_below_failure_threshold():
    failures = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 5),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 9),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 13),
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
        "failure_count": 4,
        "unique_target_count": 1,
        "within_window": True,
        "window_seconds": 12.0,
    }

    result = detect_brute_force(
        features,
        failures,
    )

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []


def test_detect_brute_force_outside_time_window():
    failures = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 16),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 31),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 46),
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
            timestamp=datetime(2026, 9, 11, 10, 1, 2),
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
        "within_window": False,
        "window_seconds": 61.0,
    }

    result = detect_brute_force(
        features,
        failures,
    )

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []


def test_detect_password_spray_with_too_few_targets():
    failures = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 3),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 5),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 7),
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
    ]

    features = {
        "failure_count": 4,
        "unique_target_count": 2,
        "within_window": True,
        "window_seconds": 6.0,
    }

    result = detect_password_spray(
        features,
        failures,
    )

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []


def test_detect_password_spray_outside_time_window():
    failures = [
        NormalizedEvent(
            timestamp=datetime(2026, 9, 11, 10, 0, 1),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 16),
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
            timestamp=datetime(2026, 9, 11, 10, 0, 31),
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
            timestamp=datetime(2026, 9, 11, 10, 1, 2),
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
        "within_window": False,
        "window_seconds": 61.0,
    }

    result = detect_password_spray(
        features,
        failures,
    )

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []

def test_brute_force_with_irregular_intervals():
    logs = [
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 1,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.20",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 8,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.20",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 21,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.20",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 37,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.20",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 55,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.20",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
    ]

    features = summarize_ip_failures(logs)

    result = detect_brute_force(
        features["10.0.0.20"],
        logs,
    )

    assert result.is_detected is True
    assert result.detection_type == "brute_force"

def test_multiple_targets_are_not_brute_force():
    logs = [
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 1,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.30",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 3,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="alice",
            src_ip="10.0.0.30",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 5,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="bob",
            src_ip="10.0.0.30",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 7,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="guest",
            src_ip="10.0.0.30",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 9,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.30",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
    ]

    features = summarize_ip_failures(logs)

    result = detect_brute_force(
        features["10.0.0.30"],
        logs,
    )

    assert result.is_detected is False


def test_password_spray_outside_time_window_with_enough_failures():
    logs = [
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 0, 0,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.40",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 1, 0,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="alice",
            src_ip="10.0.0.40",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 2, 0,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="bob",
            src_ip="10.0.0.40",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 3, 0,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="guest",
            src_ip="10.0.0.40",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
        NormalizedEvent(
            timestamp=datetime(
                2026, 9, 14, 11, 10, 0,
                tzinfo=timezone.utc,
            ),
            event_type="login_failed",
            source="ssh",
            user="admin",
            src_ip="10.0.0.40",
            dst_ip=None,
            application="sshd",
            protocol="ssh",
            user_agent=None,
            raw="test",
        ),
    ]

    features = summarize_ip_failures(logs)

    result = detect_password_spray(
        features["10.0.0.40"],
        logs,
    )

    assert result.is_detected is False


def test_detect_path_traversal_in_query():
    result = detect_path_traversal(
        path="/download",
        query="file=../../etc/passwd",
        method="GET",
        status_code=200,
        response_size=2048,
    )

    assert result.is_detected is True
    assert result.detection_type == "path_traversal"

    evidence_types = [
        evidence.type
        for evidence in result.evidence
    ]

    assert "url_decoded_query" in evidence_types
    assert "path_pattern" in evidence_types
    assert "http_method" in evidence_types
    assert "http_status_code" in evidence_types
    assert "http_response_size" in evidence_types