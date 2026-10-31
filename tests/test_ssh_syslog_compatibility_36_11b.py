from datetime import timezone
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analyzer.pipeline import load_normalized_logs
from app.api import create_app
from app.main import analyze
from app.live_monitoring import LiveTailRecord, parse_live_records
from app.parser.ssh_auth import parse_ssh_auth_log


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "sample_logs" / "ssh_syslog_compatibility" / "manifest.json"


def _rfc5424(message, *, timestamp="2026-11-01T01:30:12Z", app="sshd",
             pri="34", version="1", hostname="node.example.test",
             procid="1234", msgid="AUTH", structured_data="-"):
    return (
        f"<{pri}>{version} {timestamp} {hostname} {app} {procid} "
        f"{msgid} {structured_data} {message}"
    )


@pytest.mark.parametrize(("line", "expected_time", "expected_user", "expected_ip", "expected_port", "outcome", "method", "invalid_user"), [
    (_rfc5424("Failed password for admin from 192.0.2.10 port 54321 ssh2"), "2026-11-01T01:30:12+00:00", "admin", "192.0.2.10", 54321, "failure", "password", False),
    (_rfc5424("Failed password for invalid user guest from 2001:db8::10 port 22 ssh2"), "2026-11-01T01:30:12+00:00", "guest", "2001:db8::10", 22, "failure", "password", True),
    (_rfc5424("Accepted password for analyst from 192.0.2.11 port 2200 ssh2", timestamp="2026-11-01T10:30:12+09:00"), "2026-11-01T01:30:12+00:00", "analyst", "192.0.2.11", 2200, "success", "password", False),
    (_rfc5424("Accepted publickey for deploy from 192.0.2.12 port 44322 ssh2: ED25519 SHA256:synthetic", timestamp="2026-11-01T05:30:12-05:00"), "2026-11-01T10:30:12+00:00", "deploy", "192.0.2.12", 44322, "success", "publickey", False),
    (_rfc5424("Failed publickey for admin from 2001:db8::20 port 65535 ssh2", timestamp="2026-11-01T10:30:12.123456+00:00"), "2026-11-01T10:30:12.123456+00:00", "admin", "2001:db8::20", 65535, "failure", "publickey", False),
    (_rfc5424("Failed password for admin from 192.0.2.13 port 1 ssh2", timestamp="2026-12-31T23:59:59Z", procid="-"), "2026-12-31T23:59:59+00:00", "admin", "192.0.2.13", 1, "failure", "password", False),
    (_rfc5424("Failed password for admin from 192.0.2.25", timestamp="2026-11-01T01:30:12.1Z", msgid="-"), "2026-11-01T01:30:12.100000+00:00", "admin", "192.0.2.25", None, "failure", "password", None),
])
def test_rfc5424_ssh_events_have_exact_normalized_fields(
    line, expected_time, expected_user, expected_ip, expected_port,
    outcome, method, invalid_user,
):
    event = parse_ssh_auth_log(line, "Asia/Seoul")
    assert event.timestamp.isoformat() == expected_time
    assert event.timestamp.tzinfo is timezone.utc
    assert event.event_type == ("login_failed" if outcome == "failure" else "user_login")
    assert (event.user, event.src_ip, event.application, event.protocol) == (
        expected_user, expected_ip, "sshd", "ssh"
    )
    assert event.authentication.outcome == outcome
    assert event.authentication.method == method
    assert event.authentication.source_port == expected_port
    assert event.authentication.invalid_user is invalid_user


@pytest.mark.parametrize("line", [
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", pri="192"),
    "<034>1 2026-11-01T01:30:12Z node.example.test sshd 1234 AUTH - Failed password for admin from 192.0.2.1 port 22 ssh2",
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", pri="-1"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", version="2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", app="fake-sshd"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", app="web-worker"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", procid="pid"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", msgid="bad id"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", structured_data="[meta x=\"y\"]"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="-"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12-00:00"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-02-30T01:30:12Z"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12.1234567Z"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12+24:00"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12+01:60"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", timestamp="2026-11-01T01:30:12+23:60"),
    _rfc5424("Failed password for admin from host.invalid port 22 ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1:22 port 22 ssh2"),
    _rfc5424("Failed password for admin from 2001:db8::1%en0 port 22 ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 0 ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 65536 ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port x ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", hostname="sshd", app="web-worker"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2", msgid="sshd", app="web-worker"),
    "prefix <34>1 2026-11-01T01:30:12Z host sshd 1234 AUTH - Failed password for admin from 192.0.2.1 port 22 ssh2",
    "<34>1 Nov  1 10:30:12 node sshd[1234]: Failed password for admin from 192.0.2.1 port 22 ssh2",
    "<34>1 2026-11-01T01:30:12Z host sshd 1234 AUTH -",
    "<34>1 2026-11-01T01:30:12Z host sshd 1234 AUTH - Failed password for admin from 192.0.2.1 port 22 ssh2\x01",
    _rfc5424("Failed password for admin\u202efrom 192.0.2.1 port 22 ssh2"),
    _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2") + ("x" * 8192),
    "<34>1 2026-11-01T01:30:12Z  node.example.test sshd 1234 AUTH - Failed password for admin from 192.0.2.1 port 22 ssh2",
])
def test_invalid_or_unsupported_syslog_records_fail_closed(line):
    with pytest.raises((ValueError, IndexError)):
        parse_ssh_auth_log(line, "Asia/Seoul")


def test_rfc3164_year_and_timezone_are_never_inferred():
    line = "Nov  1 10:30:12 node sshd[1234]: Failed password for admin from 192.0.2.1 port 22 ssh2"
    with pytest.raises((ValueError, IndexError)):
        parse_ssh_auth_log(line, "Asia/Seoul")


def test_rfc5424_error_does_not_echo_untrusted_record():
    canary = "PRIVATE-SYSLOG-CANARY"
    line = _rfc5424(f"Failed password for {canary} from 192.0.2.1 port 0 ssh2")
    with pytest.raises(ValueError) as error:
        parse_ssh_auth_log(line, "Asia/Seoul")
    assert canary not in str(error.value)
    assert line not in str(error.value)


def test_existing_iso_ssh_parser_contract_is_preserved():
    line = "2026-11-01 10:30:12 server01 sshd[1234]: Failed password for invalid user admin from 192.0.2.10 port 54321 ssh2"
    event = parse_ssh_auth_log(line, "Asia/Seoul")
    assert event.timestamp.isoformat() == "2026-11-01T10:30:12+09:00"
    assert event.src_ip == "192.0.2.10"
    assert event.authentication.invalid_user is True


def test_rfc5424_batch_and_live_parser_are_identical(tmp_path):
    line = _rfc5424("Failed password for admin from 192.0.2.1 port 22 ssh2")
    path = tmp_path / "ssh.log"
    path.write_text(line + "\n", encoding="utf-8")
    batch = load_normalized_logs(({"source": "ssh", "path": path},))
    live = parse_live_records("ssh", (LiveTailRecord("ssh", 1, line, len(line.encode())),))
    assert live.parsed_count == 1
    assert live.outcomes[0].event == batch[0]
    assert batch[0].timestamp.isoformat() == "2026-11-01T01:30:12+00:00"


def test_live_parser_rejects_yearless_rfc3164_without_timestamp_inference():
    line = "Nov  1 10:30:12 node sshd[1234]: Failed password for admin from 192.0.2.1 port 22 ssh2"
    live = parse_live_records("ssh", (LiveTailRecord("ssh", 1, line, len(line.encode())),))
    assert live.rejected_count == 1
    assert live.outcomes[0].status == "REJECTED"
    assert live.outcomes[0].event is None


def test_text_api_rejects_yearless_rfc3164_without_echoing_input():
    line = "Nov  1 10:30:12 node sshd[1234]: Failed password for synthetic_user from 192.0.2.1 port 22 ssh2"
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/investigations/text", json={
            "schema_version": 1, "source": "ssh", "log_text": line,
        })
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert "synthetic_user" not in response.text
    assert "192.0.2.1" not in response.text


def test_text_api_accepts_rfc5424_and_keeps_closed_privacy_projection():
    line = _rfc5424("Failed password for synthetic_user from 192.0.2.1 port 22 ssh2")
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/investigations/text", json={
            "schema_version": 1, "source": "ssh", "log_text": line,
        })
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"schema_version", "input_scope", "result"}
    serialized = json.dumps(body, sort_keys=True)
    assert "synthetic_user" not in serialized
    assert "192.0.2.1" not in serialized
    assert "node.example.test" not in serialized
    assert "1234" not in serialized


def test_rfc5424_file_api_acceptance_and_rfc3164_rejection(tmp_path):
    ssh_path = tmp_path / "ssh.log"
    ssh_path.write_text(_rfc5424("Failed password for synthetic_user from 192.0.2.1 port 22 ssh2") + "\n", encoding="utf-8")
    other = ROOT / "sample_logs" / "brute_force.log"
    access = ROOT / "sample_logs" / "web_shell.log"
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/investigations", files=[
            (field, ("synthetic.log", path.read_bytes(), "text/plain"))
            for field, path in (("application_file", other), ("ssh_file", ssh_path), ("access_file", access))
        ])
    assert response.status_code == 200, response.text
    serialized = json.dumps(response.json(), sort_keys=True)
    assert "synthetic_user" not in serialized
    assert "192.0.2.1" not in serialized
    rfc3164 = tmp_path / "yearless.log"
    rfc3164.write_text(
        "Nov  1 10:30:12 node sshd[1234]: Failed password for admin from 192.0.2.1 port 22 ssh2\n",
        encoding="utf-8",
    )
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        rejected = client.post("/api/v1/investigations", files=[
            (field, ("synthetic.log", path.read_bytes(), "text/plain"))
            for field, path in (("application_file", other), ("ssh_file", rfc3164), ("access_file", access))
        ])
    assert rejected.status_code == 400
    assert rejected.json()["error_code"] == "PARSER_INCOMPATIBLE"


def test_rfc5424_batch_events_reach_existing_brute_and_spray_detectors(tmp_path):
    brute_lines = [
        _rfc5424(
            f"Failed password for admin from 192.0.2.50 port {2200 + index} ssh2",
            timestamp=f"2026-11-01T01:30:{index:02d}Z",
            procid=str(1100 + index),
        )
        for index in range(10, 15)
    ]
    brute_path = tmp_path / "brute.log"
    brute_path.write_text("\n".join(brute_lines) + "\n", encoding="utf-8")
    brute_result = analyze(({"source": "ssh", "path": brute_path},))
    brute_ip = brute_result["results"]["192.0.2.50"]
    assert brute_ip["detections"]["brute_force"].is_detected is True

    spray_lines = [
        _rfc5424(
            f"Failed password for {user} from 192.0.2.51 port {2300 + index} ssh2",
            timestamp=f"2026-11-01T01:31:{index:02d}Z",
            procid=str(1200 + index),
        )
        for index, user in enumerate(("alpha", "bravo", "charlie", "delta"), 10)
    ]
    spray_path = tmp_path / "spray.log"
    spray_path.write_text("\n".join(spray_lines) + "\n", encoding="utf-8")
    spray_result = analyze(({"source": "ssh", "path": spray_path},))
    spray_ip = spray_result["results"]["192.0.2.51"]
    assert spray_ip["detections"]["password_spray"].is_detected is True


def test_rfc5424_authentication_transition_uses_existing_observation_contract(tmp_path):
    lines = (
        _rfc5424(
            "Failed password for analyst from 192.0.2.60 port 33221 ssh2",
            timestamp="2026-11-01T01:30:00Z", procid="1301",
        ),
        _rfc5424(
            "Accepted password for analyst from 192.0.2.60 port 33221 ssh2",
            timestamp="2026-11-01T01:30:10Z", procid="1302",
        ),
    )
    path = tmp_path / "transition.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = analyze(({"source": "ssh", "path": path},))
    relation = result["results"]["192.0.2.60"]["correlation"]["authentication"]
    assert relation["is_correlated"] is True
    assert relation["type"] == "failed_to_successful_login"
    assert relation["user"] == "analyst"
    assert relation["time_delta_seconds"] == 10.0
    assert "compromise" not in " ".join(relation["rationale"]).lower()


def test_independent_synthetic_corpus_has_30_plus_labeled_cases():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert set(manifest) == {"version", "cases"}
    assert manifest["version"] == 1
    assert len(manifest["cases"]) >= 30
    assert len({case["id"] for case in manifest["cases"]}) == len(manifest["cases"])
    assert {case["label"] for case in manifest["cases"]} >= {"SUPPORTED", "UNSUPPORTED"}
    assert all(set(case) == {"id", "label", "line", "expected"} for case in manifest["cases"])
    for case in manifest["cases"]:
        if case["label"] == "UNSUPPORTED":
            with pytest.raises((ValueError, IndexError)):
                parse_ssh_auth_log(case["line"], "Asia/Seoul")
            continue
        event = parse_ssh_auth_log(case["line"], "Asia/Seoul")
        expected = case["expected"]
        assert event.event_type == expected["event_type"], case["id"]
        assert event.user == expected["user"], case["id"]
        assert event.src_ip == expected["src_ip"], case["id"]
        assert event.authentication.source_port == expected["port"], case["id"]
        assert event.timestamp.isoformat() == expected["utc"], case["id"]
