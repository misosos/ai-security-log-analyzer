import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.analyzer.pipeline import group_logs_by_ip
from app.loader.file_loader import preprocess_log_line
from app.main import analyze
from app.local_investigation_api import _TextInputError, _compatible, _validate_text
from app.parser import registry
from app.parser.time_utils import normalize_to_utc


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "sample_logs" / "compatibility"
MANIFEST = CORPUS / "profiles.json"
ALLOWED_STATUS = {
    "SUPPORTED_VERIFIED", "PARSED_PARTIAL", "IGNORED", "REJECTED",
    "FALSE_ACCEPT", "NOT_TESTED",
}


def _profiles():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["profiles"]


def _fixture_path(relative):
    path = (CORPUS / relative).resolve()
    assert path.is_relative_to(CORPUS.resolve())
    assert not path.is_symlink()
    assert path.is_file()
    return path


def _parse_profile(profile):
    parser = registry.get_parser(profile["source"])
    zone = registry.get_timezone(profile["source"])
    observations = []
    for raw in _fixture_path(profile["fixture"]).read_text(encoding="utf-8").splitlines():
        line = preprocess_log_line(raw)
        if not line:
            continue
        try:
            event = parser(line, zone)
            if event is not None:
                event.timestamp = normalize_to_utc(event.timestamp)
        except (ValueError, IndexError, TypeError):
            observations.append(("REJECTED", None))
        else:
            observations.append(("IGNORED", None) if event is None else ("PARSED", event))
    return observations


def test_compatibility_manifest_replays_each_synthetic_fixture():
    profiles = _profiles()
    assert len(profiles) == 21
    for profile in profiles:
        assert profile["expected"] in ALLOWED_STATUS
        assert _parse_profile(profile)


@pytest.mark.parametrize("profile", _profiles(), ids=lambda item: item["id"])
def test_profile_disposition_matches_observed_parser_behavior(profile):
    observations = _parse_profile(profile)
    statuses = {status for status, _event in observations}
    # Keep the initial Phase 36.9B observation immutable while checking the
    # remediation result separately when the profile had a false acceptance.
    expected = profile.get("expected_after_r1", profile["expected"])
    if expected == "SUPPORTED_VERIFIED":
        assert statuses == {"PARSED"}
    elif expected == "PARSED_PARTIAL":
        assert "PARSED" in statuses
        assert statuses <= {"PARSED", "REJECTED"}
    elif expected in {"IGNORED", "REJECTED"}:
        assert statuses == {expected}
    elif expected == "FALSE_ACCEPT":
        assert statuses == {"PARSED"}
    else:
        pytest.fail("Fixture profile cannot be marked NOT_TESTED in an executed corpus.")


def test_application_and_ssh_fields_and_timezone_are_exact_for_supported_profiles():
    app = _parse_profile(next(p for p in _profiles() if p["id"] == "APP-AUTH-01"))[0][1]
    ssh = _parse_profile(next(p for p in _profiles() if p["id"] == "SSH-NORM-01"))[0][1]

    assert (app.event_type, app.user, app.src_ip) == (
        "login_failed", "analyst", "192.0.2.11",
    )
    assert (app.authentication.outcome, app.authentication.method) == ("failure", None)
    assert app.timestamp == datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)
    assert (ssh.event_type, ssh.user, ssh.src_ip) == (
        "login_failed", "analyst", "192.0.2.12",
    )
    assert (ssh.authentication.outcome, ssh.authentication.method) == ("failure", "password")
    assert ssh.authentication.source_port == 51000
    assert ssh.timestamp == datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)

    app_success = _parse_profile(
        next(p for p in _profiles() if p["id"] == "APP-AUTH-SUCCESS")
    )[0][1]
    assert (app_success.event_type, app_success.authentication.outcome) == (
        "user_login", "success",
    )


def test_ssh_publickey_invalid_user_and_optional_port_behavior_are_observed():
    event = _parse_profile(
        next(p for p in _profiles() if p["id"] == "SSH-NORM-INVALID-USER-PUBKEY")
    )[0][1]
    assert event.authentication.outcome == "failure"
    assert event.authentication.method == "publickey"
    assert event.user == "guest"
    assert event.src_ip == "2001:db8::12"
    assert event.authentication.source_port == 51001
    assert event.authentication.invalid_user is True

    no_port = _parse_profile(
        next(p for p in _profiles() if p["id"] == "SSH-NORM-NO-PORT")
    )[0][1]
    assert (no_port.event_type, no_port.authentication.method) == (
        "user_login", "publickey",
    )
    assert no_port.authentication.source_port is None


@pytest.mark.parametrize(
    ("profile_id", "source_ip", "path", "query", "status", "size", "timestamp"),
    [
        ("ACCESS-APACHE-CLF-IP-SUBSET", "192.0.2.20", "/items", "q=one%2Ftwo", 200, 10,
         datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)),
        ("ACCESS-APACHE-COMBINED", "192.0.2.21", "/health", None, 204, 0,
         datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)),
        ("ACCESS-NGINX-COMBINED", "192.0.2.22", "/search", "q=blue", 200, 48,
         datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)),
        ("ACCESS-IPV6-SIZE-DASH", "2001:db8::23", "/empty", None, 304, None,
         datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)),
    ],
)
def test_access_core_fields_and_explicit_offset(profile_id, source_ip, path, query,
                                               status, size, timestamp):
    event = _parse_profile(next(p for p in _profiles() if p["id"] == profile_id))[0][1]
    assert event.event_type == "http_request"
    assert event.src_ip == source_ip
    assert event.http.method == "GET"
    assert event.http.path == path
    assert event.http.query == query
    assert event.http.status_code == status
    assert event.http.response_size == size
    assert event.timestamp == timestamp
    # Combined-format referer and User-Agent aren't represented by HttpContext.
    assert event.user_agent is None


def test_access_timestamp_day_month_year_rollover_is_normalized_by_offset():
    from app.parser.access_log import parse_access_log

    month = parse_access_log(
        '192.0.2.40 - - [31/Jan/2026:23:30:00 -0200] "GET /m HTTP/1.1" 200 1'
    )
    year = parse_access_log(
        '192.0.2.41 - - [31/Dec/2026:23:30:00 -0200] "GET /y HTTP/1.1" 200 1'
    )
    assert normalize_to_utc(month.timestamp) == datetime(2026, 2, 1, 1, 30, tzinfo=timezone.utc)
    assert normalize_to_utc(year.timestamp) == datetime(2027, 1, 1, 1, 30, tzinfo=timezone.utc)


@pytest.mark.parametrize("status", [100, 599])
def test_access_three_digit_status_boundary_is_preserved(status):
    from app.parser.access_log import parse_access_log

    event = parse_access_log(
        f'192.0.2.42 - - [30/Oct/2026:09:00:00 +0000] "GET /status HTTP/1.1" {status} 0'
    )
    assert event.http.status_code == status


def test_application_naive_time_uses_configured_asia_seoul_zone():
    app = _parse_profile(next(p for p in _profiles() if p["id"] == "APP-AUTH-01"))[0][1]
    assert app.timestamp.tzinfo is timezone.utc
    assert app.timestamp.isoformat() == "2026-10-30T00:00:00+00:00"


def test_hostname_clf_is_not_misrepresented_as_source_ip():
    # Apache 2.4 permits %h to be a hostname when HostnameLookups is enabled.
    # The parser currently accepts this valid CLF variant as src_ip; this must fail closed.
    observations = _parse_profile(next(p for p in _profiles() if p["id"] == "ACCESS-CLF-HOSTNAME"))
    assert observations[0][0] == "REJECTED"


def test_non_sshd_authentication_phrase_is_not_misclassified_as_ssh():
    observations = _parse_profile(
        next(p for p in _profiles() if p["id"] == "SSH-NON-SSHD-PHRASE")
    )
    assert observations[0][0] == "REJECTED"


def test_invalid_http_status_is_not_admitted_as_normalized_request():
    observations = _parse_profile(next(p for p in _profiles() if p["id"] == "ACCESS-INVALID-STATUS"))
    assert observations[0][0] == "REJECTED"


def test_remediated_false_accept_fixtures_do_not_reach_ip_grouping():
    hostname_profile = next(p for p in _profiles() if p["id"] == "ACCESS-CLF-HOSTNAME")
    invalid_status_profile = next(p for p in _profiles() if p["id"] == "ACCESS-INVALID-STATUS")
    ssh_profile = next(p for p in _profiles() if p["id"] == "SSH-NON-SSHD-PHRASE")
    for profile in (hostname_profile, invalid_status_profile, ssh_profile):
        status, event = _parse_profile(profile)[0]
        assert status == "REJECTED"
        assert event is None
        assert group_logs_by_ip([event] if event else []) == {}


def test_false_accept_fixtures_are_stopped_before_analysis_result_keys():
    hostname_path = str(_fixture_path("access/access_hostname_clf.log"))
    status_path = str(_fixture_path("access/access_invalid_status_999.log"))
    with pytest.raises(ValueError):
        analyze([{"source": "access", "path": hostname_path}])
    with pytest.raises(ValueError):
        analyze([{"source": "access", "path": status_path}])

    ssh_path = str(_fixture_path("ssh/ssh_other_program_auth_phrase.log"))
    with pytest.raises(ValueError):
        analyze([{"source": "ssh", "path": ssh_path}])


@pytest.mark.parametrize("address", [
    "192.0.2.20", "2001:db8::20",
])
def test_access_accepts_only_ip_literal_source_addresses(address):
    from app.parser.access_log import parse_access_log

    event = parse_access_log(
        f'{address} - - [30/Oct/2026:09:00:00 +0000] "GET /x HTTP/1.1" 200 1'
    )
    assert event.src_ip == address


@pytest.mark.parametrize("address", [
    "synthetic-host.example", "999.2.3.4", "192.0.2.20:443",
    "[2001:db8::20]", "2001:db8:::20", "fe80::1%lo0",
])
def test_access_rejects_non_literal_or_decorated_source_addresses(address):
    from app.parser.access_log import parse_access_log

    with pytest.raises(ValueError):
        parse_access_log(
            f'{address} - - [30/Oct/2026:09:00:00 +0000] "GET /x HTTP/1.1" 200 1'
        )


@pytest.mark.parametrize("status,accepted", [
    ("99", False), ("099", False), ("100", True), ("200", True), ("301", True),
    ("404", True), ("500", True), ("599", True), ("600", False),
    ("999", False), ("000", False), ("abc", False), ("", False),
])
def test_access_status_is_three_digits_in_100_to_599_range(status, accepted):
    from app.parser.access_log import parse_access_log

    line = f'192.0.2.30 - - [30/Oct/2026:09:00:00 +0000] "GET /x HTTP/1.1" {status} 1'
    if accepted:
        assert parse_access_log(line).http.status_code == int(status)
    else:
        with pytest.raises(ValueError):
            parse_access_log(line)


@pytest.mark.parametrize("process", ["web-worker", "fake-sshd", "sshd-helper", "", "sshd[123]"])
def test_ssh_authentication_phrase_requires_supported_sshd_process(process):
    from app.parser.ssh_auth import parse_ssh_auth_log

    line = f"2026-10-30 09:00:00 {process} Failed password for user from 192.0.2.50 port 22 ssh2"
    with pytest.raises(ValueError):
        parse_ssh_auth_log(line, "Asia/Seoul")


def test_ssh_process_marker_in_message_body_does_not_authorize_event():
    from app.parser.ssh_auth import parse_ssh_auth_log

    line = (
        "2026-10-30 09:00:00 web-worker message mentions sshd: "
        "Failed password for user from 192.0.2.50 port 22 ssh2"
    )
    with pytest.raises(ValueError):
        parse_ssh_auth_log(line, "Asia/Seoul")


@pytest.mark.parametrize("line", [
    "2026-10-30 09:00:00 sshd Failed password for user from 192.0.2.50",
    "2026-10-30 09:00:00 synthetic-host sshd[123]: Accepted publickey for user from 192.0.2.50 port 22 ssh2",
])
def test_ssh_supported_process_forms_keep_explicit_authentication_meaning(line):
    from app.parser.ssh_auth import parse_ssh_auth_log

    event = parse_ssh_auth_log(line, "Asia/Seoul")
    assert event.event_type in {"login_failed", "user_login"}
    assert event.authentication.service == "sshd"


@pytest.mark.parametrize("source,fixture", [
    ("access", "access/access_hostname_clf.log"),
    ("access", "access/access_invalid_status_999.log"),
    ("ssh", "ssh/ssh_other_program_auth_phrase.log"),
])
def test_text_api_rejects_false_accept_fixtures_before_analysis(source, fixture):
    from fastapi.testclient import TestClient
    from app.api import create_app

    text = (CORPUS / fixture).read_text(encoding="utf-8")
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    response = client.post(
        "/api/v1/investigations/text",
        json={"schema_version": 1, "source": source, "log_text": text},
    )
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert text not in response.text


@pytest.mark.parametrize("source,fixture,upload_field", [
    ("access", "access/access_hostname_clf.log", "access_file"),
    ("access", "access/access_invalid_status_999.log", "access_file"),
    ("ssh", "ssh/ssh_other_program_auth_phrase.log", "ssh_file"),
])
def test_file_api_rejects_false_accept_fixtures_before_analysis(source, fixture, upload_field):
    from fastapi.testclient import TestClient
    from app.api import create_app

    sample_names = {
        "application_file": "brute_force.log",
        "ssh_file": "ssh_auth.log",
        "access_file": "web_shell.log",
    }
    files = []
    for field, sample_name in sample_names.items():
        path = CORPUS / fixture if field == upload_field else ROOT / "sample_logs" / sample_name
        files.append((field, ("synthetic.log", path.read_bytes(), "text/plain")))
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    response = client.post("/api/v1/investigations", files=files)
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert response.json()["field"] == upload_field
    assert (CORPUS / fixture).read_text(encoding="utf-8") not in response.text


def test_text_input_gate_rejects_false_accept_candidates():
    cases = (
        ("ssh", "ssh/ssh_other_program_auth_phrase.log"),
        ("access", "access/access_hostname_clf.log"),
        ("access", "access/access_invalid_status_999.log"),
    )
    for source, fixture in cases:
        text = _fixture_path(fixture).read_text(encoding="utf-8")
        with pytest.raises(_TextInputError) as error:
            _validate_text(source, text)
        assert error.value.code == "PARSER_INCOMPATIBLE"


def test_unsupported_syslog_and_json_formats_do_not_create_auth_or_http_events():
    for profile in _profiles():
        if profile["id"] in {"SSH-SYSLOG-3164", "SSH-SYSLOG-5424", "ACCESS-CUSTOM-JSON"}:
            observations = _parse_profile(profile)
            assert all(event is None for _status, event in observations)


def test_upload_and_text_preflight_match_parser_acceptance_for_changed_profiles():
    valid_access = '192.0.2.51 - - [30/Oct/2026:09:00:00 +0000] "GET /ok HTTP/1.1" 200 1'
    valid_ssh = "2026-10-30 09:00:00 sshd: Failed password for user from 192.0.2.51"
    cases = (
        ("access", valid_access, True),
        ("ssh", valid_ssh, True),
        ("access", "synthetic-host.example - - [30/Oct/2026:09:00:00 +0000] \"GET / HTTP/1.1\" 200 1", False),
        ("access", '192.0.2.51 - - [30/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 999 1', False),
        ("ssh", "2026-10-30 09:00:00 web-worker Failed password for user from 192.0.2.51", False),
    )
    for source, line, expected in cases:
        assert _compatible(source, line) is expected


def test_live_parser_reports_false_accept_fixtures_as_rejected_records():
    from app.live_monitoring.core import LiveTailRecord
    from app.live_monitoring.parser_adapter import parse_live_records

    for source, fixture in (
        ("access", "access/access_hostname_clf.log"),
        ("access", "access/access_invalid_status_999.log"),
        ("ssh", "ssh/ssh_other_program_auth_phrase.log"),
    ):
        payload = _fixture_path(fixture).read_text(encoding="utf-8").strip()
        record = LiveTailRecord(source, 1, payload, len(payload.encode("utf-8")))
        batch = parse_live_records(source, (record,))
        assert batch.parsed_count == 0
        assert batch.ignored_count == 0
        assert batch.rejected_count == 1
        assert batch.outcomes[0].event is None


def test_synthetic_canary_is_mapped_to_the_observed_request_path():
    from app.parser.access_log import parse_access_log

    marker = "SYNTHETIC-COMPAT-CANARY-ONLY"
    event = parse_access_log(
        f'192.0.2.50 - - [30/Oct/2026:09:00:00 +0000] "GET /{marker} HTTP/1.1" 200 1'
    )
    assert event.raw.endswith(marker + " HTTP/1.1\" 200 1")
    assert marker not in event.src_ip
    assert marker not in event.event_type
    assert event.user is None or marker not in event.user
    assert marker not in event.http.method
    assert event.http.path == "/" + marker
    assert marker not in str(event.http.status_code)
    assert marker not in str(event.http.response_size)
