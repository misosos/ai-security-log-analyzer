"""Lease ownership must retain records until the caller acknowledges success."""

from pathlib import Path

import pytest

from app.live_monitoring import LiveMonitorConfig, LiveParseError, open_live_tail_session, parse_live_records


LINE = "2026-01-02 03:04:05 INFO user_login user=synthetic ip=192.0.2.1"


def _session(tmp_path: Path):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path))
    with path.open("ab") as stream:
        stream.write((LINE + "\n").encode())
    assert session.poll_once() == 1
    return session


def test_unexpected_parser_failure_keeps_record_resident_until_release(tmp_path, monkeypatch):
    """The former destructive take path is absent; failure retains ownership."""
    from app.live_monitoring import parser_adapter

    session = _session(tmp_path)
    try:
        assert not hasattr(session, "take_records")
        lease = session.lease_records(max_records=1, max_bytes=2048)
        assert session.snapshot().queue_item_count == 1

        def broken(_role):
            raise RuntimeError("synthetic internal failure")

        monkeypatch.setattr(parser_adapter.registry, "get_parser", broken)
        with pytest.raises(LiveParseError):
            parse_live_records("application", lease.records)
        assert session.snapshot().queue_item_count == 1
        session.release_lease(lease)
        assert session.snapshot().available_item_count == 1
        assert LINE not in repr(session.snapshot())
    finally:
        session.close()


def test_lease_keeps_record_resident_until_ack(tmp_path):
    session = _session(tmp_path)
    try:
        lease = session.lease_records(max_records=1, max_bytes=2048)
        assert lease is not None
        assert session.snapshot().queue_item_count == 1
        session.release_lease(lease)
        retry = session.lease_records(max_records=1, max_bytes=2048)
        assert retry.records[0].sequence == lease.records[0].sequence
        session.acknowledge_lease(retry)
        assert session.snapshot().queue_item_count == 0
    finally:
        session.close()


def test_release_restores_fifo_ahead_of_new_append(tmp_path):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path))
    try:
        with path.open("ab") as stream:
            stream.write(b"one\ntwo\nthree\n")
        assert session.poll_once() == 3
        lease = session.lease_records(2, 2048)
        with path.open("ab") as stream:
            stream.write(b"four\n")
        assert session.poll_once() == 1
        assert session.snapshot().queue_item_count == 4
        session.release_lease(lease)
        retry = session.lease_records(4, 2048)
        assert tuple(item.sequence for item in retry.records) == (1, 2, 3, 4)
        assert tuple(item.payload for item in retry.records) == ("one", "two", "three", "four")
        assert retry.attempt == 2
        assert session.snapshot().queue_item_count == 4
        session.acknowledge_lease(retry)
        assert session.snapshot().queue_item_count == 0
    finally:
        session.close()


@pytest.mark.parametrize(("line", "status"), (
    (LINE, "PARSED"),
    ("   ", "IGNORED"),
    ("malformed timestamp", "REJECTED"),
))
def test_completed_parser_outcome_can_be_acknowledged(tmp_path, line, status):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path))
    try:
        with path.open("ab") as stream:
            stream.write((line + "\n").encode())
        session.poll_once()
        lease = session.lease_records(1, 2048)
        batch = parse_live_records(session.source_role, lease.records)
        assert batch.outcomes[0].status == status
        session.acknowledge_lease(lease)
        assert session.snapshot().acknowledged_record_count == 1
        assert session.snapshot().queue_item_count == 0
    finally:
        session.close()


def test_close_abandons_available_and_leased_without_ack(tmp_path):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path))
    with path.open("ab") as stream:
        stream.write(b"one\ntwo\nthree\n")
    session.poll_once()
    lease = session.lease_records(2, 2048)
    assert session.snapshot().available_item_count == 1
    session.close()
    session.close()
    snapshot = session.snapshot()
    assert (snapshot.queue_item_count, snapshot.abandoned_on_close_count) == (0, 3)
    assert (snapshot.acknowledged_record_count, snapshot.active_lease) == (0, False)
    assert session._queue.item_count == 0
    assert session._active_lease is None
    assert session._fd == -1
    for operation in (session.acknowledge_lease, session.release_lease):
        with pytest.raises(Exception) as raised:
            operation(lease)
        assert raised.value.code == "OPERATION_AFTER_CLOSE"
    with pytest.raises(Exception) as raised:
        session.lease_records(1, 1)
    assert raised.value.code == "OPERATION_AFTER_CLOSE"


def test_unexpected_failure_after_first_parse_has_no_partial_batch_and_can_retry(tmp_path, monkeypatch):
    from app.live_monitoring import parser_adapter

    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path))
    with path.open("ab") as stream:
        stream.write((LINE + "\n" + LINE + "\n").encode())
    session.poll_once()
    lease = session.lease_records(2, 2048)
    original = parser_adapter.registry.get_parser
    calls = 0

    def dispatch(role):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic internal failure")
        return original(role)

    monkeypatch.setattr(parser_adapter.registry, "get_parser", dispatch)
    try:
        with pytest.raises(LiveParseError):
            parse_live_records("application", lease.records)
        assert session.snapshot().queue_item_count == 2
        session.release_lease(lease)
        retry = session.lease_records(2, 2048)
        assert tuple(item.sequence for item in retry.records) == (1, 2)
        assert retry.attempt == 2
        monkeypatch.setattr(parser_adapter.registry, "get_parser", original)
        parsed = parse_live_records("application", retry.records)
        assert parsed.parsed_count == 2
        session.acknowledge_lease(retry)
        assert session.snapshot().acknowledged_record_count == 2
    finally:
        session.close()
