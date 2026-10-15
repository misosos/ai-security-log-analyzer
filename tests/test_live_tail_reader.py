import os
from pathlib import Path

import pytest

from app.live_monitoring import LiveMonitorConfig, LiveMonitorError, open_live_tail_session
from app.live_monitoring.core import (
    MAX_CHUNK_BYTES, MAX_COUNTER, MAX_LINE_BYTES, MAX_PARTIAL_BYTES, MAX_POLL_BYTES,
    MAX_QUEUE_BYTES, MAX_QUEUE_ITEMS, MAX_RECORDS_PER_POLL,
)


def _open(tmp_path: Path, initial: bytes = b"", role: str = "application"):
    path = (tmp_path / "input.log").resolve()
    path.write_bytes(initial)
    return path, open_live_tail_session(LiveMonitorConfig(role=role, path=path))


def _append(path: Path, data: bytes) -> None:
    with path.open("ab") as target:
        target.write(data)


def _ack_records(session, max_items=MAX_QUEUE_ITEMS):
    lease = session.lease_records(max_items, MAX_QUEUE_BYTES)
    if lease is None:
        return ()
    records = lease.records
    session.acknowledge_lease(lease)
    return records


def test_from_end_skips_existing_and_catches_append_before_first_poll(tmp_path):
    path, session = _open(tmp_path, b"old private line\n")
    try:
        _append(path, b"new line\n")
        assert session.poll_once() == 1
        assert [(r.sequence, r.payload) for r in _ack_records(session)] == [(1, "new line")]
        assert session.poll_once() == 0
    finally:
        session.close()


def test_empty_file_multiple_chunks_and_poll_record_cap(tmp_path):
    path, session = _open(tmp_path)
    try:
        _append(path, b"a\n" * (MAX_RECORDS_PER_POLL + 2))
        assert session.poll_once() == MAX_RECORDS_PER_POLL
        assert session.snapshot().queue_item_count == MAX_RECORDS_PER_POLL
        assert session.poll_once() == 2
        records = _ack_records(session)
        assert tuple(item.sequence for item in records) == tuple(range(1, 19))
        assert session.snapshot().queue_byte_count == 0
        assert MAX_CHUNK_BYTES < MAX_POLL_BYTES
    finally:
        session.close()


def test_partial_utf8_lf_crlf_and_close_does_not_invent_line(tmp_path):
    path, session = _open(tmp_path)
    try:
        _append(path, b"first\nsecond\r\n" + "가".encode()[:2])
        assert session.poll_once() == 2
        assert session.snapshot().partial_buffer_byte_count == 2
        _append(path, "가".encode()[2:] + b"\nlast partial")
        assert session.poll_once() == 1
        assert tuple(item.payload for item in _ack_records(session)) == (
            "first", "second", "가",
        )
        assert session.snapshot().partial_buffer_byte_count == len(b"last partial")
    finally:
        session.close()
    assert session.snapshot().partial_buffer_byte_count == 0
    assert session.snapshot().queue_item_count == 0


@pytest.mark.parametrize(("data", "code"), (
    (b"\xff\n", "INVALID_UTF8"),
    (b"a\x00b\n", "BINARY_INPUT"),
    (b"a\x01b\n", "BINARY_INPUT"),
    (b"a\rb\n", "BINARY_INPUT"),
))
def test_invalid_complete_line_fails_closed(tmp_path, data, code):
    path, session = _open(tmp_path)
    _append(path, data)
    with pytest.raises(LiveMonitorError) as raised:
        session.poll_once()
    assert raised.value.code == code
    assert session.snapshot().state == "FAILED"
    assert session.snapshot().rejected_line_count == 1
    session.close()


def test_line_limit_exact_and_one_over(tmp_path):
    path, session = _open(tmp_path)
    _append(path, b"a" * MAX_LINE_BYTES + b"\n")
    try:
        while session.snapshot().queue_item_count == 0:
            session.poll_once()
        assert _ack_records(session)[0].byte_count == MAX_LINE_BYTES
    finally:
        session.close()
    path, session = _open(tmp_path)
    _append(path, b"a" * (MAX_LINE_BYTES + 1) + b"\n")
    try:
        with pytest.raises(LiveMonitorError) as raised:
            while True:
                session.poll_once()
        assert raised.value.code == "LINE_TOO_LONG"
    finally:
        session.close()


def test_partial_limit_exact_then_exceeded(tmp_path):
    path, session = _open(tmp_path)
    _append(path, b"a" * MAX_PARTIAL_BYTES)
    try:
        session.poll_once()
        assert session.snapshot().partial_buffer_byte_count == MAX_PARTIAL_BYTES
        _append(path, b"b")
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "PARTIAL_BUFFER_EXCEEDED"
    finally:
        session.close()


def test_queue_item_limit_exact_then_visible_overflow(tmp_path):
    path, session = _open(tmp_path)
    _append(path, b"a\n" * (MAX_QUEUE_ITEMS + 1))
    try:
        assert session.poll_once() == MAX_RECORDS_PER_POLL
        assert session.poll_once() == MAX_RECORDS_PER_POLL
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "QUEUE_OVERFLOW"
        snapshot = session.snapshot()
        assert (snapshot.queue_item_count, snapshot.queue_byte_count) == (MAX_QUEUE_ITEMS, MAX_QUEUE_ITEMS)
        assert snapshot.overflow_count == 1
        assert snapshot.processed_complete_line_count == MAX_QUEUE_ITEMS
        assert session.snapshot().available_item_count == MAX_QUEUE_ITEMS
    finally:
        session.close()


def test_counter_limit_does_not_enqueue_unaccounted_record(tmp_path):
    path, session = _open(tmp_path)
    session._processed = MAX_COUNTER
    session._acknowledged = MAX_COUNTER  # Keep the new ownership ledger consistent.
    _append(path, b"not accepted\n")
    try:
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "COUNTER_LIMIT"
        assert session.snapshot().queue_item_count == 0
        assert session.snapshot().processed_complete_line_count == MAX_COUNTER
        assert session.snapshot().state == "FAILED"
    finally:
        session.close()


def test_queue_byte_limit_exact_then_visible_overflow(tmp_path):
    path, session = _open(tmp_path)
    _append(path, (b"x" * MAX_LINE_BYTES + b"\n") * (MAX_QUEUE_BYTES // MAX_LINE_BYTES))
    try:
        while session.snapshot().queue_byte_count < MAX_QUEUE_BYTES:
            session.poll_once()
        assert session.snapshot().queue_item_count < MAX_QUEUE_ITEMS
        _append(path, b"x" * MAX_LINE_BYTES + b"\n")
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "QUEUE_OVERFLOW"
        assert session.snapshot().queue_byte_count == MAX_QUEUE_BYTES
        # FAILED sessions cannot lease; close accounts for unprocessed resident records.
        assert session.snapshot().queue_byte_count == MAX_QUEUE_BYTES
    finally:
        session.close()


@pytest.mark.parametrize("change", ("truncate", "replace", "remove", "symlink"))
def test_source_changes_stop_instead_of_merging(tmp_path, change):
    path, session = _open(tmp_path, b"existing\n")
    _append(path, b"new\n")
    assert session.poll_once() == 1
    if change == "truncate":
        path.write_bytes(b"")
    elif change == "replace":
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"replacement\n")
        os.replace(replacement, path)
    elif change == "remove":
        path.unlink()
    else:
        path.unlink()
        path.symlink_to(tmp_path / "other")
    try:
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code in {
            "SOURCE_TRUNCATED", "SOURCE_REPLACED", "SOURCE_UNAVAILABLE", "SYMLINK_REJECTED",
        }
        assert session.snapshot().state == "FAILED"
        assert session.snapshot().warning_codes == (raised.value.code,)
        assert session.snapshot().queue_item_count == 1
    finally:
        session.close()


def test_observed_shrink_above_read_offset_fails_before_polling_more(tmp_path):
    path = tmp_path / "input.log"
    path.write_bytes(b"old\n" * 128)
    config = LiveMonitorConfig(role="application", path=path)
    session = open_live_tail_session(config, start_offset=4)
    try:
        assert path.stat().st_size > session._offset
        with path.open("r+b") as stream:
            stream.truncate(128)
        assert path.stat().st_size > session._offset
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "SOURCE_TRUNCATED"
        assert session.snapshot().state == "FAILED"
        assert session.snapshot().queue_item_count == 0
        assert session._fd == -1
    finally:
        session.close()


def test_shrink_during_read_fails_at_post_probe_without_ack(tmp_path, monkeypatch):
    import app.live_monitoring.core as module

    path, session = _open(tmp_path)
    _append(path, b"a" * (MAX_CHUNK_BYTES * 4))
    original_read = os.read
    changed = False

    def read_then_shrink(descriptor, amount):
        nonlocal changed
        data = original_read(descriptor, amount)
        if not changed:
            changed = True
            with path.open("r+b") as stream:
                stream.truncate(MAX_CHUNK_BYTES * 2)
        return data

    monkeypatch.setattr(module.os, "read", read_then_shrink)
    try:
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "SOURCE_TRUNCATED"
        assert session.snapshot().state == "FAILED"
        assert session.snapshot().acknowledged_record_count == 0
        assert session.snapshot().queue_item_count == 0
    finally:
        session.close()


def test_partial_is_not_merged_across_replacement(tmp_path):
    path, session = _open(tmp_path)
    _append(path, b"secret partial")
    assert session.poll_once() == 0
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"new\n")
    os.replace(replacement, path)
    with pytest.raises(LiveMonitorError) as raised:
        session.poll_once()
    assert raised.value.code == "SOURCE_REPLACED"
    assert session.snapshot().queue_item_count == 0
    session.close()


def test_permission_loss_is_fixed_failure(tmp_path):
    path, session = _open(tmp_path)
    path.chmod(0)
    try:
        with pytest.raises(LiveMonitorError) as raised:
            session.poll_once()
        assert raised.value.code == "PERMISSION_DENIED"
        assert session.snapshot().state == "FAILED"
    finally:
        path.chmod(0o600)
        session.close()


def test_poll_read_budget_and_repeatability(tmp_path, monkeypatch):
    import app.live_monitoring.core as module

    path, session = _open(tmp_path)
    _append(path, b"a" * 100 + b"\n" * 50)
    original_read = os.read
    sizes = []

    def bounded_read(descriptor, size):
        sizes.append(size)
        return original_read(descriptor, size)

    monkeypatch.setattr(module.os, "read", bounded_read)
    try:
        assert session.poll_once() <= MAX_RECORDS_PER_POLL
        assert sum(sizes) <= MAX_POLL_BYTES
        assert all(0 < size <= MAX_CHUNK_BYTES for size in sizes)
    finally:
        session.close()


def test_close_abandons_accepted_queue_and_never_reopens_path(tmp_path, monkeypatch):
    import app.live_monitoring.core as module

    path, session = _open(tmp_path)
    _append(path, b"accepted\npartial")
    assert session.poll_once() == 1
    session.close()

    def forbidden_reopen(_path):
        raise AssertionError("closed session tried to reopen source")

    monkeypatch.setattr(module, "_open_regular", forbidden_reopen)
    assert session.snapshot().state == "STOPPED"
    assert session.snapshot().partial_buffer_byte_count == 0
    assert session.snapshot().queue_item_count == 0
    assert session.snapshot().abandoned_on_close_count == 1
    with pytest.raises(LiveMonitorError) as raised:
        session.poll_once()
    assert raised.value.code == "POLL_AFTER_CLOSE"


def test_regular_source_only_and_descriptor_closed(tmp_path):
    source = (tmp_path / "input.log").resolve()
    source.symlink_to(tmp_path / "other")
    with pytest.raises(LiveMonitorError) as raised:
        open_live_tail_session(LiveMonitorConfig("ssh", source))
    assert raised.value.code == "SYMLINK_REJECTED"
    source.unlink()
    source.mkdir()
    with pytest.raises(LiveMonitorError) as raised:
        open_live_tail_session(LiveMonitorConfig("ssh", source))
    assert raised.value.code == "NON_REGULAR_SOURCE"
    source.rmdir()
    if hasattr(os, "mkfifo"):
        os.mkfifo(source)
        with pytest.raises(LiveMonitorError) as raised:
            open_live_tail_session(LiveMonitorConfig("ssh", source))
        assert raised.value.code == "NON_REGULAR_SOURCE"
        source.unlink()
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source))
    descriptor = session._fd
    session.close()
    session.close()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    with pytest.raises(LiveMonitorError) as raised:
        session.poll_once()
    assert raised.value.code == "POLL_AFTER_CLOSE"
    assert session.snapshot().state == "STOPPED"
