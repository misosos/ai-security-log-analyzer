from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from app.api import create_app
from app.input_quality_36_12a import (
    InputQualityProjection,
    InputQualitySummary,
    aggregate_input_quality,
    evaluate_source_text,
)


APP = "2026-11-01 10:30:12 INFO login_failed user=quality-user ip=192.0.2.10"
SSH_ISO = (
    "2026-11-01 10:30:12 sshd Failed password for quality-user "
    "from 192.0.2.11 port 54321 ssh2: synthetic"
)
SSH_RFC5424 = (
    "<34>1 2026-11-01T10:30:12+09:00 node.example sshd 1234 - - "
    "Failed password for quality-user from 192.0.2.12 port 54321 ssh2"
)
ACCESS = (
    '192.0.2.13 - - [01/Nov/2026:10:30:12 +0000] '
    '"GET /health HTTP/1.1" 200 12 "-" "SyntheticAgent/1.0"'
)


def test_quality_module_and_closed_projection_are_available():
    summary = evaluate_source_text("application", APP)
    assert isinstance(summary, InputQualitySummary)
    assert summary.schema_version == "1"
    assert summary.source == "application"
    assert summary.recognition_status == "complete"
    assert summary.recognized_lines == 1


@pytest.mark.parametrize("source,line", [
    ("application", APP),
    ("ssh", SSH_ISO),
    ("ssh", SSH_RFC5424),
    ("access", ACCESS),
])
def test_supported_profiles_are_recognized(source, line):
    summary = evaluate_source_text(source, line)
    assert summary.total_lines == summary.nonempty_lines == 1
    assert summary.recognized_lines == 1
    assert summary.unrecognized_lines == summary.ignored_lines == 0
    assert summary.recognition_status == "complete"


def test_malformed_mixed_input_is_partial_and_reasons_are_fixed():
    summary = evaluate_source_text("ssh", SSH_ISO + "\n" + "not ssh auth")
    assert summary.recognized_lines == 1
    assert summary.unrecognized_lines == 1
    assert summary.ignored_lines == 0
    assert summary.recognition_status == "partial"
    assert sum(summary.reason_counts.model_dump().values()) == 1


@pytest.mark.parametrize("text,total,nonempty,status", [
    ("", 0, 0, "empty"),
    ("\n\r\n", 2, 0, "empty"),
    ("unrecognized SSH row", 1, 1, "none"),
    (SSH_ISO + "\r\n", 1, 1, "complete"),
    (SSH_ISO, 1, 1, "complete"),
])
def test_physical_line_accounting_and_recognition_states(text, total, nonempty, status):
    summary = evaluate_source_text("ssh", text)
    assert (summary.total_lines, summary.nonempty_lines) == (total, nonempty)
    assert summary.recognition_status == status
    assert summary.recognized_lines + summary.unrecognized_lines + summary.ignored_lines == total


def test_reason_categories_and_counts_are_closed_strict_and_nonnegative():
    summary = evaluate_source_text("ssh", "bad")
    assert set(summary.reason_counts.model_dump()) == {
        "unsupported_format", "invalid_timestamp", "invalid_address", "invalid_port",
        "invalid_header", "incomplete_record", "blank_line", "ignored_record",
        "other_rejected",
    }
    with pytest.raises(ValidationError):
        InputQualitySummary.model_validate({**summary.model_dump(), "unexpected": 1})
    with pytest.raises(ValidationError):
        InputQualitySummary.model_validate({**summary.model_dump(), "total_lines": True})
    with pytest.raises(ValidationError):
        InputQualitySummary.model_validate({**summary.model_dump(), "total_lines": -1})


@pytest.mark.parametrize("line,reason", [
    (SSH_RFC5424.replace("10:30:12+09:00", "not-a-time"), "invalid_timestamp"),
    (SSH_RFC5424.replace("192.0.2.12", "not-an-address"), "invalid_address"),
    (SSH_RFC5424.replace("port 54321", "port 70000"), "invalid_port"),
    (SSH_RFC5424.replace(" sshd 1234 ", " fake-sshd 1234 "), "invalid_header"),
    (SSH_RFC5424.replace(" ssh2", " ssh3"), "incomplete_record"),
])
def test_rejection_reasons_only_use_observable_parser_categories(line, reason):
    summary = evaluate_source_text("ssh", line)
    assert summary.unrecognized_lines == 1
    assert summary.reason_counts.model_dump()[reason] == 1
    assert summary.recognition_status == "none"


def test_access_address_and_invalid_application_timestamp_are_not_misclassified():
    bad_access = ACCESS.replace("192.0.2.13", "host.invalid")
    access_quality = evaluate_source_text("access", bad_access)
    app_quality = evaluate_source_text("application", "2026-99-01 10:30:12 INFO login_failed")
    assert access_quality.reason_counts.invalid_address == 1
    assert app_quality.reason_counts.invalid_timestamp == 1


def test_bounded_evaluator_accepts_512_records_and_rejects_oversized_lines_safely():
    short_app = "2026-11-01 10:30:12 INFO login_failed user=u"
    text = (short_app + "\n") * 511 + short_app
    summary = evaluate_source_text("application", text)
    assert summary.total_lines == summary.recognized_lines == 512
    with pytest.raises(ValueError) as error:
        evaluate_source_text("application", "x" * 2049)
    assert str(error.value) == "Input quality evaluation failed."


def test_unexpected_parser_failure_is_fixed_and_does_not_echo_record(monkeypatch):
    canary = "PRIVATE_INTERNAL_CANARY"

    def broken_parser(_line, _timezone=None):
        raise RuntimeError(canary)

    monkeypatch.setattr("app.input_quality_36_12a.get_parser", lambda _source: broken_parser)
    with pytest.raises(ValueError) as error:
        evaluate_source_text("application", APP)
    assert str(error.value) == "Input quality evaluation failed."
    assert canary not in str(error.value)


def test_canary_is_not_retained_in_repr_or_serialized_projection():
    canary = "PRIVATE_INPUT_QUALITY_CANARY"
    summary = evaluate_source_text("ssh", f"not ssh {canary}")
    projection = aggregate_input_quality({"ssh": summary})
    serialized = json.dumps(projection.model_dump(mode="json"), ensure_ascii=False)
    assert canary not in repr(summary)
    assert canary not in repr(projection)
    assert canary not in serialized
    with pytest.raises(ValidationError) as error:
        InputQualitySummary.model_validate({
            **summary.model_dump(), "unexpected": canary,
        })
    assert canary not in str(error.value)
    assert projection.aggregate.total_lines == 1
    assert projection.by_source[0].source == "ssh"


def test_aggregate_is_deterministic_and_keeps_source_counts_separate():
    first = aggregate_input_quality({
        "ssh": evaluate_source_text("ssh", SSH_ISO + "\nbad ssh"),
        "access": evaluate_source_text("access", ACCESS),
    })
    second = aggregate_input_quality({
        "access": evaluate_source_text("access", ACCESS),
        "ssh": evaluate_source_text("ssh", SSH_ISO + "\nbad ssh"),
    })
    assert first.model_dump_json() == second.model_dump_json()
    assert [item.source for item in first.by_source] == ["ssh", "access"]
    assert first.by_source[0].unrecognized_lines == 1
    assert first.by_source[1].unrecognized_lines == 0
    assert first.aggregate.total_lines == 3


def test_unknown_source_is_rejected_without_echoing_input():
    synthetic_canary = "UNTRUSTED-CANARY"
    with pytest.raises(ValueError) as error:
        evaluate_source_text("unknown", synthetic_canary)
    assert synthetic_canary not in str(error.value)
    assert "unknown" not in str(error.value)


def test_text_api_returns_quality_for_admitted_input_and_rejected_diagnostics_are_private():
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    accepted = client.post("/api/v1/investigations/text", json={
        "schema_version": 1, "source": "ssh", "log_text": SSH_RFC5424,
    })
    assert accepted.status_code == 200
    quality = accepted.json()["result"]["input_quality"]
    assert quality["aggregate"]["recognition_status"] == "complete"
    assert quality["by_source"][0]["source"] == "ssh"
    assert quality["aggregate"]["recognized_lines"] == 1

    canary = "PRIVATE_DIAGNOSTIC_CANARY"
    rejected = client.post("/api/v1/investigations/text", json={
        "schema_version": 1, "source": "ssh",
        "log_text": SSH_ISO + "\nnot a supported record " + canary,
    })
    assert rejected.status_code == 400
    body = rejected.json()
    assert body["error_code"] == "PARSER_INCOMPATIBLE"
    assert body["input_quality"]["aggregate"]["recognition_status"] == "partial"
    assert body["input_quality"]["aggregate"]["recognized_lines"] == 1
    assert body["input_quality"]["aggregate"]["unrecognized_lines"] == 1
    assert canary not in rejected.text


def test_file_api_keeps_source_quality_isolated_on_fail_closed_rejection():
    client = TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000))
    malformed = SSH_RFC5424.replace("10:30:12+09:00", "not-a-time")
    response = client.post("/api/v1/investigations", files=[
        ("application_file", ("app.log", (APP + "\n").encode(), "text/plain")),
        ("ssh_file", ("ssh.log", (SSH_RFC5424 + "\n" + malformed).encode(), "text/plain")),
        ("access_file", ("access.log", (ACCESS + "\n").encode(), "text/plain")),
    ])
    assert response.status_code == 400
    body = response.json()
    assert body["error_code"] == "PARSER_INCOMPATIBLE"
    quality = body["input_quality"]
    by_source = {item["source"]: item for item in quality["by_source"]}
    assert by_source["application"]["recognized_lines"] == 1
    assert by_source["ssh"]["recognized_lines"] == 1
    assert by_source["ssh"]["unrecognized_lines"] == 1
    assert by_source["access"]["recognized_lines"] == 1
    assert by_source["application"]["reason_counts"]["invalid_timestamp"] == 0
    assert by_source["ssh"]["reason_counts"]["invalid_timestamp"] == 1
