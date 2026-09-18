from datetime import datetime, timedelta, timezone

from app.parser.access_log import parse_access_log
from app.parser.auth_log import parse_auth_log
from app.parser.registry import get_parser
from app.parser.ssh_auth import parse_ssh_auth_log

from app.analyzer.pipeline import load_normalized_logs
from app.models.schemas import NormalizedEvent


def test_parse_access_log():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET /index.php HTTP/1.1" 200 1024'

    result = parse_access_log(line)

    assert result.src_ip == "192.168.1.10"
    assert result.timestamp == datetime(
        2026,
        9,
        14,
        12,
        0,
        1,
        tzinfo=timezone(timedelta(hours=9)),
    )

    assert result.http.method == "GET"
    assert result.http.path == "/index.php"
    assert result.http.status_code == 200
    assert result.http.response_size == 1024


def test_parse_access_log_without_response_size():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET /index.php HTTP/1.1" 200 -'

    result = parse_access_log(line)

    assert result.http.status_code == 200
    assert result.http.response_size is None


def test_parse_access_log_invalid_request():
    line = '192.168.1.10 - - [14/Sep/2026:12:00:01 +0900] "GET" 200 1024'

    result = parse_access_log(line)

    assert result is None


def test_parse_access_log_server_error():
    line = '192.168.1.30 - - [14/Sep/2026:12:02:20 +0900] "POST /api/login HTTP/1.1" 500 128'

    result = parse_access_log(line)

    assert result.src_ip == "192.168.1.30"
    assert result.http.method == "POST"
    assert result.http.path == "/api/login"
    assert result.http.status_code == 500
    assert result.http.response_size == 128


def test_get_access_parser():
    parser = get_parser("access")

    assert parser is parse_access_log


def test_load_normalized_logs_applies_utc_normalization():
    log_sources = [
        {
            "source": "ssh",
            "path": "sample_logs/ssh_auth.log",
        }
    ]

    logs = load_normalized_logs(log_sources)

    assert logs

    assert logs[0].timestamp == datetime(
        2026,
        9,
        14,
        2,
        0,
        1,
        tzinfo=timezone.utc,
    )

    assert logs[0].authentication.outcome == "failure"
    assert logs[0].authentication.method == "password"


def test_parse_application_login_failure_authentication_context():
    line = (
        "2026-09-11 10:00:01 INFO login_failed "
        "user=admin ip=192.168.1.20"
    )

    result = parse_auth_log(line, "Asia/Seoul")

    assert result.event_type == "login_failed"
    assert result.user == "admin"
    assert result.src_ip == "192.168.1.20"
    assert result.application is None
    assert result.protocol is None
    assert result.authentication is not None
    assert result.authentication.outcome == "failure"
    assert result.authentication.method is None
    assert result.authentication.service is None


def test_parse_application_login_success_authentication_context():
    line = (
        "2026-09-11 10:00:01 INFO user_login "
        "user=alice ip=192.168.1.10"
    )

    result = parse_auth_log(line, "Asia/Seoul")

    assert result.event_type == "user_login"
    assert result.user == "alice"
    assert result.src_ip == "192.168.1.10"
    assert result.authentication is not None
    assert result.authentication.outcome == "success"
    assert result.authentication.method is None
    assert result.authentication.service is None


def test_parse_application_non_authentication_event_has_no_context():
    line = (
        "2026-09-11 10:01:12 INFO file_access "
        "user=alice file=report.pdf"
    )

    result = parse_auth_log(line, "Asia/Seoul")

    assert result.event_type == "file_access"
    assert result.authentication is None


def test_parse_application_explicit_authentication_service():
    line = (
        "2026-09-11 10:00:01 INFO user_login "
        "user=alice ip=192.168.1.10 service=admin_portal"
    )

    result = parse_auth_log(line, "Asia/Seoul")

    assert result.application is None
    assert result.authentication.service == "admin_portal"


def test_parse_ssh_failed_password_authentication_context():
    line = (
        "2026-09-14 11:00:01 sshd Failed password "
        "for admin from 10.0.0.5"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "login_failed"
    assert result.user == "admin"
    assert result.src_ip == "10.0.0.5"
    assert result.application == "sshd"
    assert result.protocol == "ssh"
    assert result.authentication.outcome == "failure"
    assert result.authentication.method == "password"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port is None
    assert result.authentication.invalid_user is None


def test_parse_ssh_accepted_password_authentication_context():
    line = (
        "2026-09-14 11:00:20 sshd Accepted password "
        "for admin from 10.0.0.5"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "user_login"
    assert result.user == "admin"
    assert result.src_ip == "10.0.0.5"
    assert result.application == "sshd"
    assert result.protocol == "ssh"
    assert result.authentication.outcome == "success"
    assert result.authentication.method == "password"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port is None
    assert result.authentication.invalid_user is None


def test_parse_realistic_ssh_failed_password():
    line = (
        "2026-09-14 11:00:01 auth01 sshd[4101]: "
        "Failed password for admin from 198.51.100.10 "
        "port 49152 ssh2"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "login_failed"
    assert result.user == "admin"
    assert result.src_ip == "198.51.100.10"
    assert result.application == "sshd"
    assert result.protocol == "ssh"
    assert result.authentication.outcome == "failure"
    assert result.authentication.method == "password"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port == 49152
    assert result.authentication.invalid_user is False


def test_parse_realistic_ssh_accepted_password():
    line = (
        "2026-09-14 11:00:05 sshd[4102]: "
        "Accepted password for alice from 198.51.100.11 "
        "port 49153 ssh2"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "user_login"
    assert result.user == "alice"
    assert result.src_ip == "198.51.100.11"
    assert result.authentication.outcome == "success"
    assert result.authentication.method == "password"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port == 49153
    assert result.authentication.invalid_user is False


def test_parse_realistic_ssh_failed_publickey():
    line = (
        "2026-09-14 11:00:09 auth01 sshd[4103]: "
        "Failed publickey for deploy from 198.51.100.12 "
        "port 49154 ssh2: ED25519 "
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "login_failed"
    assert result.user == "deploy"
    assert result.src_ip == "198.51.100.12"
    assert result.authentication.outcome == "failure"
    assert result.authentication.method == "publickey"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port == 49154
    assert result.authentication.invalid_user is False
    assert "ED25519" in result.raw
    assert (
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        in result.raw
    )


def test_parse_realistic_ssh_accepted_publickey():
    line = (
        "2026-09-14 11:00:13 auth01 sshd[4104]: "
        "Accepted publickey for deploy from 198.51.100.12 "
        "port 49155 ssh2: ED25519 "
        "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "user_login"
    assert result.user == "deploy"
    assert result.src_ip == "198.51.100.12"
    assert result.authentication.outcome == "success"
    assert result.authentication.method == "publickey"
    assert result.authentication.service == "sshd"
    assert result.authentication.source_port == 49155
    assert result.authentication.invalid_user is False
    assert "ED25519" in result.raw
    assert (
        "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        in result.raw
    )


def test_parse_realistic_ssh_invalid_user_failure():
    line = (
        "2026-09-14 11:00:17 auth01 sshd[4105]: "
        "Failed password for invalid user ghost from "
        "198.51.100.13 port 49156 ssh2"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type == "login_failed"
    assert result.user == "ghost"
    assert result.src_ip == "198.51.100.13"
    assert result.authentication.outcome == "failure"
    assert result.authentication.method == "password"
    assert result.authentication.source_port == 49156
    assert result.authentication.invalid_user is True


def test_load_realistic_ssh_fixture_normalizes_timezone():
    logs = load_normalized_logs([
        {
            "source": "ssh",
            "path": "sample_logs/ssh_auth_realistic.log",
        }
    ])

    assert len(logs) == 5
    assert logs[0].timestamp == datetime(
        2026,
        9,
        14,
        2,
        0,
        1,
        tzinfo=timezone.utc,
    )
    assert logs[2].authentication.method == "publickey"
    assert logs[4].authentication.invalid_user is True


def test_parse_ssh_unsupported_event_preserves_existing_behavior():
    line = "2026-09-14 11:00:01 sshd Connection closed"

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type is None
    assert result.user is None
    assert result.src_ip is None
    assert result.authentication is None


def test_parse_ssh_malformed_authentication_message_conservatively():
    line = (
        "2026-09-14 11:00:01 auth01 sshd[4101]: "
        "Failed password for admin from 198.51.100.10 "
        "port invalid ssh2"
    )

    result = parse_ssh_auth_log(line, "Asia/Seoul")

    assert result.event_type is None
    assert result.user is None
    assert result.src_ip is None
    assert result.authentication is None


def test_manual_normalized_event_defaults_authentication_to_none():
    event = NormalizedEvent(
        timestamp=datetime(
            2026,
            9,
            14,
            2,
            0,
            1,
            tzinfo=timezone.utc,
        ),
        event_type="login_failed",
        source="application",
        user="admin",
        src_ip="10.0.0.5",
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw="test log",
    )

    assert event.authentication is None
    assert event.linux_audit is None
