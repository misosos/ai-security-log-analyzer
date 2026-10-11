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


def test_from_end_skips_existing_and_catches_append_before_first_poll(tmp_path):
    path, session = _open(tmp_path, b"old private line\n")
    try:
        _append(path, b"new line\n")
        assert session.poll_once() == 1
        assert [(r.sequence, r.payload) for r in session.take_records()] == [(1, "new line")]
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
        records = session.take_records()
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
        assert tuple(item.payload for item in session.take_records()) == (
            "first", "second", "가",
        )
        assert session.snapshot().partial_buffer_byte_count == len(b"last partial")
    finally:
        session.close()
    assert session.snapshot().partial_buffer_byte_count == 0
    assert session.take_records() == ()


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
        assert session.take_records()[0].byte_count == MAX_LINE_BYTES
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
        assert tuple(r.sequence for r in session.take_records()) == tuple(range(1, MAX_QUEUE_ITEMS + 1))
    finally:
        session.close()


def test_counter_limit_does_not_enqueue_unaccounted_record(tmp_path):
    path, session = _open(tmp_path)
    session._processed = MAX_COUNTER
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
        session.take_records(1)
        assert session.snapshot().queue_byte_count == MAX_QUEUE_BYTES - MAX_LINE_BYTES
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
        assert session.take_records()[0].payload == "new"
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


def test_close_keeps_accepted_queue_but_never_reopens_path(tmp_path, monkeypatch):
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
    assert session.take_records()[0].payload == "accepted"
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
