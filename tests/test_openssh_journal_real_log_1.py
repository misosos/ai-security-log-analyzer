"""Bounded journalctl short-iso compatibility; synthetic data, not a Linux capture."""

from datetime import timezone
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.analyzer.html_report import render_investigation_report_html
from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.report_projection import build_investigation_report_projection
from app.api import build_analysis_response, create_app
from app.input_quality_36_12a import assess_record, evaluate_source_text
from app.live_monitoring import LiveDetectionAccumulator, LiveTailRecord, parse_live_records
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.main import analyze
from app.parser.ssh_auth import parse_ssh_auth_log


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "openssh_journal_short_iso.log"
MESSAGE = "Failed password for journal-user from 192.0.2.71 port 41001 ssh2"


def _journal(message=MESSAGE, *, timestamp="2026-04-17T14:00:00+0530",
             hostname="journal-node.example.test", process="sshd[7312]"):
    return f"{timestamp} {hostname} {process}: {message}"


@pytest.mark.parametrize("message,event_type,user,ip,method,port,invalid", [
    (MESSAGE, "login_failed", "journal-user", "192.0.2.71", "password", 41001, False),
    ("Failed password for invalid user visitor from 2001:db8::71 port 1 ssh2",
     "login_failed", "visitor", "2001:db8::71", "password", 1, True),
    ("Accepted publickey for deploy from 2001:db8::72 port 65535 ssh2: ED25519 SHA256:synthetic-key",
     "user_login", "deploy", "2001:db8::72", "publickey", 65535, False),
    ("Accepted password for analyst from 192.0.2.73 port 41002 ssh2",
     "user_login", "analyst", "192.0.2.73", "password", 41002, False),
    ("Failed publickey for invalid user visitor from 192.0.2.74 port 41003 ssh2: RSA SHA256:synthetic-key",
     "login_failed", "visitor", "192.0.2.74", "publickey", 41003, True),
])
@pytest.mark.parametrize("process", ["sshd[7312]", "sshd"])
def test_journal_authentication_fields(message, event_type, user, ip, method, port, invalid, process):
    line = _journal(message, process=process)
    event = parse_ssh_auth_log(line, "America/New_York")
    assert event.timestamp.isoformat() == "2026-04-17T08:30:00+00:00"
    assert event.timestamp.tzinfo is timezone.utc
    assert (event.event_type, event.user, event.src_ip) == (event_type, user, ip)
    assert (event.source, event.application, event.protocol, event.dst_ip) == ("ssh", "sshd", "ssh", None)
    assert event.authentication.outcome == ("failure" if event_type == "login_failed" else "success")
    assert event.authentication.method == method
    assert event.authentication.source_port == port
    assert event.authentication.invalid_user is invalid
    assert event.raw == line  # Internal contract only; public projections checked below.


@pytest.mark.parametrize("timestamp", [
    "2026-04-17T14:00:00+0530", "2026-04-17T14:00:00+05:30",
    "2026-04-17T08:30:00+0000", "2026-04-17T08:30:00+00:00",
    "2026-04-17T04:30:00-0400", "2026-04-17T04:30:00-04:00",
])
def test_explicit_offsets_have_same_absolute_time_without_registry_timezone(timestamp):
    event = parse_ssh_auth_log(_journal(timestamp=timestamp))
    assert event.timestamp.isoformat() == "2026-04-17T08:30:00+00:00"


REJECTED = [
    _journal(process="web-worker[7312]"), _journal(process="fake-sshd[7312]"),
    _journal(process="sshd-session[7312]"), _journal(process="sshd[pid]"),
    _journal(process="sshd[７３１２]"), _journal(hostname=""),
    _journal(hostname="node\u202e.example"), _journal(hostname="h" * 256),
    _journal(MESSAGE.replace("192.0.2.71", "host.example.test")),
    _journal(MESSAGE.replace("192.0.2.71", "192.0.2.999")),
    _journal(MESSAGE.replace("192.0.2.71", "2001:db8::71%eth0")),
    _journal(MESSAGE.replace("41001", "0")), _journal(MESSAGE.replace("41001", "65536")),
    _journal(MESSAGE.replace("41001", "-1")), _journal(MESSAGE.replace("41001", "x")),
    _journal(MESSAGE.replace("41001", "４１００１")),
    _journal("Failed password for journal-user from 192.0.2.71"),
    _journal("Accepted publickey for journal-user from"),
    _journal(MESSAGE.replace("ssh2", "ssh3")),
    _journal(MESSAGE.replace("password", "keyboard-interactive/pam")),
    _journal(MESSAGE + " unrecognized suffix"), _journal(MESSAGE + "\n" + MESSAGE),
    _journal(MESSAGE + "\x01"), _journal(MESSAGE.replace("journal-user", "user\u202e")),
    *[_journal(timestamp=value) for value in (
        "2026-04-17T14:00:00", "2026-04-17T14:00:00Z",
        "2026-04-17T14:00:00-0000", "2026-04-17T14:00:00-00:00",
        "2026-04-17T14:00:00+2400", "2026-04-17T14:00:00+01:60",
        "2026-02-30T14:00:00+0530", "2026-04-17T25:00:00+0530",
        "2026-04-17T14:00:60+0530", "2026-04-17T14:00:00.123456+0530",
        "0001-01-01T00:00:00+0100",
    )],
    "Apr 17 14:00:00 journal-node sshd[7312]: " + MESSAGE,
    "[1234.567890] journal-node sshd[7312]: " + MESSAGE,
    '{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"' + MESSAGE + '"}',
    "2026-04-17T14:00:00+0530 sshd[7312]: " + MESSAGE,
]


@pytest.mark.parametrize("line", REJECTED, ids=[f"rejected-{index}" for index in range(len(REJECTED))])
def test_invalid_or_out_of_profile_journal_is_not_an_authentication_event(line):
    with pytest.raises(ValueError) as error:
        parse_ssh_auth_log(line, "Asia/Seoul")
    assert "journal-user" not in str(error.value)
    assert line not in str(error.value)
    live = parse_live_records("ssh", (LiveTailRecord("ssh", 1, line, len(line.encode())),))
    assert live.rejected_count == 1
    assert live.outcomes[0].event is None


def test_overlong_journal_record_is_rejected_without_echoing_input():
    line = _journal(MESSAGE + ": " + "x" * 8192)
    with pytest.raises(ValueError) as error:
        parse_ssh_auth_log(line)
    assert str(error.value) == "Unsupported journal short-iso record."


@pytest.mark.parametrize("message", [
    "Server listening on 0.0.0.0 port 22.",
    "Connection closed by authenticating user journal-user 192.0.2.71 port 41001 [preauth]",
    "Postponed publickey for journal-user from 192.0.2.71 port 41001 ssh2",
    "Partial publickey for journal-user from 192.0.2.71 port 41001 ssh2",
    "pam_unix(sshd:auth): authentication failure; user=journal-user",
])
def test_unrelated_sshd_messages_preserve_existing_non_event_contract(message):
    event = parse_ssh_auth_log(_journal(message))
    assert (event.event_type, event.user, event.src_ip, event.authentication) == (None, None, None, None)
    assert assess_record("ssh", _journal(message)) == ("parsed", None, False)


@pytest.mark.parametrize("line,reason", [
    (_journal(timestamp="2026-02-30T14:00:00+0530"), "invalid_timestamp"),
    (_journal(process="fake-sshd[7312]"), "invalid_header"),
    (_journal(MESSAGE.replace("192.0.2.71", "invalid")), "invalid_address"),
    (_journal(MESSAGE.replace("41001", "70000")), "invalid_port"),
    (_journal("Failed password for journal-user from"), "incomplete_record"),
])
def test_existing_input_quality_categories_cover_new_profile(line, reason):
    quality = evaluate_source_text("ssh", _journal() + "\n" + line)
    assert quality.recognition_status == "partial"
    assert (quality.recognized_lines, quality.unrecognized_lines) == (1, 1)
    assert quality.reason_counts.model_dump()[reason] == 1


def test_fixed_validation_input_batch_live_and_existing_pipeline(tmp_path):
    # Fixed independent fixture; expected time/counts are not generated by the parser.
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    batch = load_normalized_logs(({"source": "ssh", "path": FIXTURE},))
    live = parse_live_records("ssh", tuple(
        LiveTailRecord("ssh", index, line, len(line.encode()))
        for index, line in enumerate(lines, 1)
    ))
    assert live.parsed_count == len(batch) == 6
    assert [item.event for item in live.outcomes] == batch
    assert [item.event_type for item in batch] == ["login_failed"] * 5 + ["user_login"]
    assert [item.authentication.source_port for item in batch] == list(range(42001, 42007))
    assert batch[0].timestamp.isoformat() == "2026-04-17T08:30:00+00:00"
    assert batch[-1].timestamp.isoformat() == "2026-04-17T08:30:10+00:00"
    result = analyze(({"source": "ssh", "path": FIXTURE},))
    subject = result["results"]["198.51.100.87"]
    assert subject["detections"]["brute_force"].is_detected is True
    relation = subject["correlation"]["authentication"]
    assert relation["type"] == "failed_to_successful_login"
    assert relation["is_correlated"] is True
    # Existing correlation selects the closest preceding same-account failure.
    assert relation["time_delta_seconds"] == 6.0
    assert subject["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert subject["risk_factors"]

    # Same observed events in the already-supported RFC profile must preserve
    # the complete deterministic result, including correlation and risk.
    reference = tmp_path / "reference.log"
    reference.write_text("\n".join(
        f"<34>1 {event.timestamp.isoformat()} ref.example.test sshd 7000 AUTH - "
        + line.split(": ", 1)[1]
        for event, line in zip(batch, lines)
    ) + "\n", encoding="utf-8")
    assert analyze(({"source": "ssh", "path": reference},)) == result
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    proposal = detection.prepare(live)
    candidate = analysis.prepare(proposal)
    detection.commit(proposal)
    analysis.commit(candidate)
    assert analysis._state._results == result["results"]
    assert analysis.snapshot().case_count == 1
    public = build_analysis_response(result, 1).model_dump_json()
    html = render_investigation_report_html(build_investigation_report_projection(result))
    for canary in ("journal-fixture-user", "198.51.100.87", "journal-fixture-node", "synthetic-key-canary"):
        assert canary not in public + html


def test_journal_events_reach_existing_spray_rule_without_threshold_changes(tmp_path):
    lines = [
        _journal(
            f"Failed password for {user} from 2001:db8::88 port {43000 + index} ssh2",
            timestamp=f"2026-04-18T03:10:{index:02d}-0400",
        )
        for index, user in enumerate(("one", "two", "three", "four"))
    ]
    path = tmp_path / "spray.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = analyze(({"source": "ssh", "path": path},))
    subject = result["results"]["2001:db8::88"]
    assert subject["detections"]["password_spray"].is_detected is True
    assert subject["detections"]["brute_force"].is_detected is False


@pytest.mark.parametrize("mode", ["text", "file"])
def test_local_apis_accept_journal_without_disclosing_new_input_fields(mode):
    text = FIXTURE.read_text(encoding="utf-8")
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        if mode == "text":
            response = client.post("/api/v1/investigations/text", json={
                "schema_version": 1, "source": "ssh", "log_text": text,
            })
        else:
            response = client.post("/api/v1/investigations", files=[
                ("application_file", ("application.log", (ROOT / "sample_logs/brute_force.log").read_bytes(), "text/plain")),
                ("ssh_file", ("ssh.log", text.encode(), "text/plain")),
                ("access_file", ("access.log", (ROOT / "sample_logs/web_shell.log").read_bytes(), "text/plain")),
            ])
    assert response.status_code == 200, response.text
    body = response.json()
    result = body["result"] if mode == "text" else body
    assert result["case_summary"]["case_count"] >= 1
    ssh_quality = next(item for item in result["input_quality"]["by_source"] if item["source"] == "ssh")
    assert ssh_quality["recognition_status"] == "complete"
    assert ssh_quality["recognized_lines"] == 6
    assert result["report_export"]["html"]
    serialized = json.dumps(body)
    for canary in ("journal-fixture-user", "198.51.100.87", "journal-fixture-node", "synthetic-key-canary", "42006"):
        assert canary not in serialized


def test_text_api_rejects_truncated_authentication_with_fixed_private_error():
    line = _journal("Failed password for journal-user from 192.0.2.71")
    with TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/v1/investigations/text", json={
            "schema_version": 1, "source": "ssh", "log_text": line,
        })
    assert response.status_code == 400
    assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
    assert "journal-user" not in response.text
    assert "192.0.2.71" not in response.text
