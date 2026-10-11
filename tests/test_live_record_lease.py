"""Bounded single-active-lease ownership and accounting."""

from dataclasses import replace
from pathlib import Path

import pytest

from app.live_monitoring import LiveMonitorConfig, LiveMonitorError, LiveTailRecord, open_live_tail_session
from app.live_monitoring.core import MAX_QUEUE_BYTES, MAX_QUEUE_ITEMS


def _open(tmp_path: Path):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    return path, open_live_tail_session(LiveMonitorConfig("application", path))


def _append(path: Path, *lines: str):
    with path.open("ab") as stream:
        stream.write("".join(line + "\n" for line in lines).encode())


def test_empty_queue_has_no_lease_and_invalid_limits_are_fixed(tmp_path):
    _, session = _open(tmp_path)
    try:
        assert session.lease_records(1, 1) is None
        for args in ((True, 1), (1, False), (0, 1), (1, 0), (MAX_QUEUE_ITEMS + 1, 1), (1, MAX_QUEUE_BYTES + 1)):
            with pytest.raises(LiveMonitorError) as raised:
                session.lease_records(*args)
            assert raised.value.code == "INVALID_LEASE_LIMIT"
    finally:
        session.close()


def test_single_active_prefix_byte_limit_and_resident_accounting(tmp_path):
    path, session = _open(tmp_path)
    _append(path, "aa", "bbb", "cccc")
    try:
        assert session.poll_once() == 3
        before = session.snapshot()
        assert (before.queue_item_count, before.queue_byte_count) == (3, 9)
        with pytest.raises(LiveMonitorError) as raised:
            session.lease_records(3, 1)
        assert raised.value.code == "LEASE_LIMIT_TOO_SMALL"
        lease = session.lease_records(3, 5)
        assert (lease.item_count, lease.byte_count, lease.attempt) == (2, 5, 1)
        assert tuple(item.sequence for item in lease.records) == (1, 2)
        leased = session.snapshot()
        assert (leased.queue_item_count, leased.queue_byte_count) == (3, 9)
        assert (leased.available_item_count, leased.available_byte_count) == (1, 4)
        assert (leased.leased_item_count, leased.leased_byte_count) == (2, 5)
        assert leased.active_lease is True
        with pytest.raises(LiveMonitorError) as raised:
            session.lease_records(1, 10)
        assert raised.value.code == "ACTIVE_LEASE_EXISTS"
        session.acknowledge_lease(lease)
        after = session.snapshot()
        assert (after.queue_item_count, after.queue_byte_count) == (1, 4)
        assert (after.acknowledged_record_count, after.available_item_count) == (2, 1)
        assert after.active_lease is False
        next_lease = session.lease_records(1, 4)
        assert tuple(item.sequence for item in next_lease.records) == (3,)
        session.acknowledge_lease(next_lease)
        assert session.snapshot().queue_item_count == 0
    finally:
        session.close()


def test_foreign_stale_forged_and_mismatch_are_rejected(tmp_path):
    first_path = tmp_path / "first"
    second_path = tmp_path / "second"
    first_path.mkdir()
    second_path.mkdir()
    path, session = _open(first_path)
    _, other = _open(second_path)
    _append(path, "a", "b")
    try:
        session.poll_once()
        lease = session.lease_records(1, 10)
        with pytest.raises(LiveMonitorError) as raised:
            other.acknowledge_lease(lease)
        assert raised.value.code == "FOREIGN_LEASE"
        with pytest.raises(LiveMonitorError) as raised:
            session.acknowledge_lease(replace(lease, lease_id=lease.lease_id + 99))
        assert raised.value.code == "FORGED_LEASE"
        altered = LiveTailRecord("application", 1, "x", 1)
        with pytest.raises(LiveMonitorError) as raised:
            session.acknowledge_lease(replace(lease, records=(altered,)))
        assert raised.value.code == "LEASE_INVARIANT_MISMATCH"
        assert session.snapshot().queue_item_count == 2
        session.release_lease(lease)
        new_lease = session.lease_records(1, 10)
        assert new_lease.lease_id > lease.lease_id
        with pytest.raises(LiveMonitorError) as raised:
            session.acknowledge_lease(lease)
        assert raised.value.code == "STALE_LEASE"
        session.acknowledge_lease(new_lease)
    finally:
        session.close()
        other.close()


def test_double_settlement_and_cross_settlement_are_fixed_errors(tmp_path):
    path, session = _open(tmp_path)
    _append(path, "a", "b")
    try:
        session.poll_once()
        first = session.lease_records(1, 1)
        session.acknowledge_lease(first)
        for operation, expected in ((session.acknowledge_lease, "ACK_AFTER_ACK"), (session.release_lease, "RELEASE_AFTER_ACK")):
            with pytest.raises(LiveMonitorError) as raised:
                operation(first)
            assert raised.value.code == expected
        second = session.lease_records(1, 1)
        session.release_lease(second)
        for operation, expected in ((session.release_lease, "RELEASE_AFTER_RELEASE"), (session.acknowledge_lease, "ACK_AFTER_RELEASE")):
            with pytest.raises(LiveMonitorError) as raised:
                operation(second)
            assert raised.value.code == expected
        retry = session.lease_records(1, 1)
        assert retry.attempt == 2
        assert session.snapshot().released_lease_count == 1
        session.acknowledge_lease(retry)
    finally:
        session.close()


def test_failed_session_cannot_start_new_lease(tmp_path):
    path, session = _open(tmp_path)
    _append(path, "a")
    session.poll_once()
    path.write_bytes(b"")
    with pytest.raises(LiveMonitorError):
        session.poll_once()
    with pytest.raises(LiveMonitorError) as raised:
        session.lease_records(1, 1)
    assert raised.value.code == "INVALID_STATE_TRANSITION"
    session.close()
    assert session.snapshot().abandoned_on_close_count == 1


def test_leased_records_still_consume_queue_capacity(tmp_path):
    path, session = _open(tmp_path)
    _append(path, *("x" for _ in range(MAX_QUEUE_ITEMS)))
    try:
        assert session.poll_once() == 16
        assert session.poll_once() == 16
        lease = session.lease_records(1, 1)
        assert session.snapshot().queue_item_count == MAX_QUEUE_ITEMS
        _append(path, "overflow")
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "QUEUE_OVERFLOW"
        snapshot = session.snapshot()
        assert snapshot.leased_item_count == 1
        assert snapshot.queue_item_count == MAX_QUEUE_ITEMS
        assert snapshot.processed_complete_line_count == MAX_QUEUE_ITEMS
        assert lease.records[0].sequence == 1
    finally:
        session.close()


def test_release_invariant_failure_marks_failed_and_close_clears_raw(tmp_path):
    path, session = _open(tmp_path)
    _append(path, "a")
    session.poll_once()
    lease = session.lease_records(1, 1)
    session._queue._items[0] = LiveTailRecord("application", 1, "b", 1)
    with pytest.raises(LiveMonitorError) as raised:
        session.release_lease(lease)
    assert raised.value.code == "INTERNAL_OWNERSHIP_FAILURE"
    assert session.snapshot().state == "FAILED"
    with pytest.raises(LiveMonitorError) as raised:
        session.close()
    assert raised.value.code == "CLOSE_INVALID_OWNERSHIP"
    assert session.snapshot().state == "STOPPED"
    assert session.snapshot().abandoned_on_close_count == 1
    session.close()
