"""Explicit worker steps preserve lease ownership and safe aggregates."""

from pathlib import Path

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker, LiveWorkerError, LiveWorkerState,
    open_live_tail_session,
)


GOOD = "2026-01-02 03:04:05 INFO user_login user=synthetic ip=192.0.2.1"


def make_worker(tmp_path: Path, *, max_records: int = 8):
    path = tmp_path / "source.log"
    path.write_bytes((GOOD + "\n").encode())
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    worker = LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), max_records, 4096)
    return path, session, worker


def append(path: Path, *lines: str) -> None:
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def test_no_data_and_from_end(tmp_path):
    path, session, worker = make_worker(tmp_path)
    try:
        result = worker.step()
        assert result.status == "NO_DATA"
        assert result.polled_record_count == 0
        assert result.leased_record_count == 0
        assert worker.snapshot().no_data_step_count == 1
        assert session.snapshot().acknowledged_record_count == 0
    finally:
        worker.close()


def test_partial_line_is_no_data_without_parsing(tmp_path):
    path, session, worker = make_worker(tmp_path)
    with path.open("ab") as stream:
        stream.write(GOOD.encode())
    try:
        result = worker.step()
        assert result.status == "NO_DATA"
        assert worker.snapshot().session.partial_buffer_byte_count == len(GOOD.encode())
        assert worker.snapshot().total_acknowledged == 0
    finally:
        worker.close()


def test_parsed_ignored_rejected_are_acknowledged_together(tmp_path):
    path, session, worker = make_worker(tmp_path)
    try:
        append(path, GOOD, "   ", "malformed timestamp")
        result = worker.step()
        assert result.status == "PROCESSED"
        assert (result.parsed_count, result.ignored_count, result.rejected_count) == (1, 1, 1)
        assert result.acknowledged_count == 3
        assert result.queue_remaining_count == 0
        snapshot = worker.snapshot()
        assert (snapshot.total_parsed, snapshot.total_ignored, snapshot.total_rejected) == (1, 1, 1)
        assert snapshot.total_acknowledged == 3
        assert snapshot.session.queue_item_count == 0
        assert snapshot.state is LiveWorkerState.READY
    finally:
        worker.close()


def test_one_bounded_lease_per_step(tmp_path):
    path, session, worker = make_worker(tmp_path, max_records=2)
    try:
        append(path, GOOD, GOOD, GOOD)
        first = worker.step()
        assert first.leased_record_count == 2
        assert first.queue_remaining_count == 1
        second = worker.step()
        assert second.leased_record_count == 1
        assert worker.snapshot().total_acknowledged == 3
    finally:
        worker.close()


def test_exact_session_single_worker_and_close(tmp_path):
    path, session, worker = make_worker(tmp_path)
    with pytest.raises(LiveWorkerError) as error:
        LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), 1, 1024)
    assert error.value.code == "SESSION_ALREADY_OWNED"
    with pytest.raises(LiveWorkerError):
        LiveProcessingWorker(object(), LiveDetectionAccumulator("application", 64, 65536), 1, 1024)
    with pytest.raises(LiveWorkerError):
        LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), True, 1024)
    worker.close()
    worker.close()
    assert session.snapshot().state == "STOPPED"
    assert session._fd == -1
    with pytest.raises(LiveWorkerError) as error:
        worker.step()
    assert error.value.code == "OPERATION_AFTER_CLOSE"


def test_ready_close_abandons_unprocessed_without_ack(tmp_path):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    session.poll_once()
    worker.close()
    assert worker.snapshot().session.abandoned_on_close_count == 1
    assert worker.snapshot().total_acknowledged == 0


@pytest.mark.parametrize("with_record", (False, True))
def test_step_calls_each_ownership_stage_exactly_once(tmp_path, monkeypatch, with_record):
    from app.live_monitoring import worker as worker_module

    path, session, worker = make_worker(tmp_path)
    if with_record:
        append(path, GOOD)
    names = ("poll_once", "lease_records", "acknowledge_lease", "release_lease")
    calls = {name: 0 for name in (*names, "parse_live_records", "_validate_batch")}
    for name in names:
        original = getattr(type(session), name)

        def counted(instance, *args, _name=name, _original=original):
            calls[_name] += 1
            return _original(instance, *args)

        monkeypatch.setattr(type(session), name, counted)
    for name in ("parse_live_records", "_validate_batch"):
        original = getattr(worker_module, name)

        def counted(*args, _name=name, _original=original):
            calls[_name] += 1
            return _original(*args)

        monkeypatch.setattr(worker_module, name, counted)
    try:
        worker.step()
        assert calls == {
            "poll_once": 1,
            "lease_records": int(with_record),
            "parse_live_records": int(with_record),
            "_validate_batch": int(with_record),
            "acknowledge_lease": int(with_record),
            "release_lease": 0,
        }
    finally:
        worker.close()


def test_append_release_retry_ack_smoke(tmp_path, monkeypatch):
    from app.live_monitoring import worker as worker_module

    path, session, worker = make_worker(tmp_path)
    assert worker.step().status == "NO_DATA"  # preexisting line is skipped
    append(path, GOOD, "   ", "malformed timestamp")
    result = worker.step()
    assert (result.parsed_count, result.ignored_count, result.rejected_count) == (1, 1, 1)
    assert session.snapshot().queue_item_count == 0
    append(path, GOOD)
    original = worker_module.parse_live_records
    monkeypatch.setattr(worker_module, "parse_live_records", lambda *_: (_ for _ in ()).throw(RuntimeError("private")))
    with pytest.raises(LiveWorkerError):
        worker.step()
    assert session.snapshot().available_item_count == 1
    assert worker.snapshot().state is LiveWorkerState.DEGRADED
    monkeypatch.setattr(worker_module, "parse_live_records", original)
    worker.resume_after_degraded()
    assert worker.step().parsed_count == 1
    assert session.snapshot().queue_item_count == 0
    worker.close()
    assert session._fd == -1
    assert session.snapshot().state == "STOPPED"
