"""Characterize the existing batch loader/parser contract before live adaptation."""

from datetime import timezone

import pytest

from app.analyzer.pipeline import load_normalized_logs
from app.loader.file_loader import load_log_lines
from app.parser.registry import get_parser, get_timezone
from app.parser.time_utils import normalize_to_utc
from app.live_monitoring import LiveTailRecord, parse_live_records


def _record(role: str, sequence: int, payload: str) -> LiveTailRecord:
    return LiveTailRecord(role, sequence, payload, len(payload.encode("utf-8")))


@pytest.mark.parametrize("source", ("application", "ssh", "access"))
def test_batch_loader_strips_edges_and_skips_blank_lines(tmp_path, source):
    path = tmp_path / "lines.txt"
    path.write_text(" \tfirst  middle \t\n\t \n second\r\n", encoding="utf-8")
    assert tuple(load_log_lines(path)) == ("first  middle", "second")


@pytest.mark.parametrize(("source", "line", "expected_utc"), (
    ("application", "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1", "2026-01-01T18:04:05+00:00"),
    ("ssh", "2026-01-02 03:04:05 sshd: Failed password for synthetic from 192.0.2.1", "2026-01-01T18:04:05+00:00"),
    ("access", '192.0.2.1 - - [02/Jan/2026:03:04:05 +0900] "GET /safe HTTP/1.1" 200 1', "2026-01-01T18:04:05+00:00"),
))
def test_batch_pipeline_uses_registry_zone_and_normalizes_utc(tmp_path, source, line, expected_utc):
    path = tmp_path / "input.txt"
    path.write_text(f"  {line} \n", encoding="utf-8")
    events = load_normalized_logs(({"source": source, "path": path},))
    assert len(events) == 1
    assert events[0].timestamp.tzinfo is timezone.utc
    assert events[0].timestamp.isoformat() == expected_utc
    assert events[0].raw == line
    expected = get_parser(source)(line, get_timezone(source))
    expected.timestamp = normalize_to_utc(expected.timestamp)
    assert events[0] == expected


def test_batch_access_none_and_auth_parser_exception_are_distinct(tmp_path):
    parser = get_parser("access")
    assert parser("unsupported request", get_timezone("access")) is None
    path = tmp_path / "input.txt"
    path.write_text("unsupported request\n", encoding="utf-8")
    assert load_normalized_logs(({"source": "access", "path": path},)) == []
    path.write_text("malformed timestamp\n", encoding="utf-8")
    with pytest.raises((ValueError, IndexError)):
        load_normalized_logs(({"source": "application", "path": path},))


@pytest.mark.parametrize(("source", "fixture"), (
    ("application", "sample_logs/brute_force.log"),
    ("ssh", "sample_logs/ssh_auth.log"),
    ("access", "sample_logs/web_shell.log"),
))
def test_existing_sample_fixture_has_exact_batch_live_event_equality(source, fixture):
    from pathlib import Path

    path = Path(fixture)
    records = tuple(
        _record(source, index, line)
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
    )
    live = parse_live_records(source, records)
    batch = load_normalized_logs(({"source": source, "path": path},))
    assert tuple(item.event for item in live.outcomes if item.status == "PARSED") == tuple(batch)
    assert live.rejected_count == 0
    assert tuple(item.sequence for item in live.outcomes) == tuple(range(1, len(records) + 1))


@pytest.mark.parametrize(("source", "line"), (
    ("application", "2026-01-02 03:04:05 INFO user_login user=synthetic ip=192.0.2.1 application=demo protocol=https"),
    ("ssh", "2026-01-02 03:04:05 sshd: Accepted publickey for invalid user synthetic from 192.0.2.1 port 2222 ssh2: extra text"),
    ("access", '192.0.2.1 - - [02/Jan/2026:03:04:05 +0900] "GET /search?q=two+words%20ok HTTP/1.1" 404 -'),
))
def test_whitespace_and_nested_context_are_identical(tmp_path, source, line):
    path = tmp_path / "input.txt"
    payload = " \t" + line + "\t "
    path.write_text(payload + "\n", encoding="utf-8")
    batch = load_normalized_logs(({"source": source, "path": path},))
    live = parse_live_records(source, (_record(source, 1, payload),))
    assert len(batch) == 1
    assert live.outcomes[0].event == batch[0]
    assert live.outcomes[0].event.raw == line


def test_ssh_unsupported_message_is_parser_event_not_none(tmp_path):
    line = "2026-01-02 03:04:05 sshd: unrelated message"
    path = tmp_path / "ssh.txt"
    path.write_text(line + "\n", encoding="utf-8")
    batch = load_normalized_logs(({"source": "ssh", "path": path},))
    live = parse_live_records("ssh", (_record("ssh", 1, line),))
    assert live.outcomes[0].status == "PARSED"
    assert live.outcomes[0].event.event_type is None
    assert live.outcomes[0].event == batch[0]


@pytest.mark.parametrize(("source", "line", "status"), (
    ("application", "2026-01-02 03:04:05 INFO login_failed", "PARSED"),
    ("ssh", "2026-01-02 03:04:05 sshd: Failed password for synthetic from not-an-ip", "PARSED"),
    ("ssh", "2026-01-02 03:04:05 sshd: Accepted password for synthetic from 192.0.2.1 port 22 ssh2", "PARSED"),
    ("access", '192.0.2.1 - - [02/Jan/2026:03:04:05 +0900] "GET /safe" 200 1', "IGNORED"),
    ("access", '192.0.2.1 - - "GET /safe HTTP/1.1" 200 1', "IGNORED"),
))
def test_existing_parser_boundary_behavior_matches_batch(tmp_path, source, line, status):
    path = tmp_path / "input.txt"
    path.write_text(line + "\n", encoding="utf-8")
    batch = load_normalized_logs(({"source": source, "path": path},))
    live = parse_live_records(source, (_record(source, 1, line),))
    assert live.outcomes[0].status == status
    assert tuple(item.event for item in live.outcomes if item.status == "PARSED") == tuple(batch)
