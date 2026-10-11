"""Fault injection at parser, ownership and source boundaries."""

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveParseBatch, LiveParseOutcome, LiveProcessingWorker,
    LiveWorkerError, LiveWorkerState,
    open_live_tail_session,
)
from app.live_monitoring import worker as worker_module


GOOD = "2026-01-02 03:04:05 INFO user_login user=synthetic ip=192.0.2.1"


def make_worker(tmp_path):
    path = tmp_path / "source.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    return path, session, LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), 8, 4096)


def append(path, *lines):
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def test_unexpected_parser_failure_releases_and_explicit_resume(tmp_path, monkeypatch):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    original = worker_module.parse_live_records
    calls = 0

    def broken(role, records):
        nonlocal calls
        calls += 1
        raise RuntimeError("private parser diagnostic")

    monkeypatch.setattr(worker_module, "parse_live_records", broken)
    try:
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "PROCESSING_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert worker.snapshot().total_acknowledged == 0
        assert worker.snapshot().session.available_item_count == 1
        assert worker.snapshot().total_released == 1
        with pytest.raises(LiveWorkerError):
            worker.step()
        monkeypatch.setattr(worker_module, "parse_live_records", original)
        worker.resume_after_degraded()
        result = worker.step()
        assert result.parsed_count == 1
        assert worker.snapshot().session.max_attempt_count == 2
        assert worker.snapshot().total_acknowledged == 1
        assert calls == 1
    finally:
        worker.close()


def test_invariant_mismatch_releases(tmp_path, monkeypatch):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    monkeypatch.setattr(worker_module, "_validate_batch", lambda *_: (_ for _ in ()).throw(ValueError("private")))
    try:
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "PROCESSING_FAILURE"
        assert worker.snapshot().session.available_item_count == 1
        assert worker.snapshot().total_parsed == 0
    finally:
        worker.close()


@pytest.mark.parametrize("batch", (
    LiveParseBatch("ssh", (LiveParseOutcome(1, "IGNORED"),), 0, 1, 0),
    LiveParseBatch("application", (LiveParseOutcome(2, "IGNORED"),), 0, 1, 0),
))
def test_forged_but_well_typed_batch_never_acks(tmp_path, monkeypatch, batch):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    monkeypatch.setattr(worker_module, "parse_live_records", lambda *_: batch)
    try:
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "PROCESSING_FAILURE"
        assert worker.snapshot().session.available_item_count == 1
        assert worker.snapshot().total_acknowledged == 0
    finally:
        worker.close()


def test_ack_failure_never_releases(tmp_path, monkeypatch):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    monkeypatch.setattr(type(session), "acknowledge_lease", lambda *_: (_ for _ in ()).throw(RuntimeError("private")))
    try:
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "ACK_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker.snapshot().session.state == "FAILED"
        assert worker.snapshot().session.active_lease
        assert worker.snapshot().total_acknowledged == 0
        assert worker.snapshot().total_released == 0
    finally:
        worker.close()
    assert session.snapshot().abandoned_on_close_count == 1


def test_release_failure_never_guesses_recovery(tmp_path, monkeypatch):
    path, session, worker = make_worker(tmp_path)
    append(path, GOOD)
    monkeypatch.setattr(worker_module, "parse_live_records", lambda *_: (_ for _ in ()).throw(RuntimeError("private")))
    monkeypatch.setattr(type(session), "release_lease", lambda *_: (_ for _ in ()).throw(RuntimeError("private")))
    try:
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "OWNERSHIP_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker.snapshot().session.state == "FAILED"
        assert worker.snapshot().session.active_lease
        with pytest.raises(LiveWorkerError):
            worker.step()
    finally:
        worker.close()


def test_poll_failure_is_terminal_and_close_releases_descriptor(tmp_path):
    path, session, worker = make_worker(tmp_path)
    path.unlink()
    with pytest.raises(LiveWorkerError) as error:
        worker.step()
    assert error.value.code == "POLL_FAILURE"
    assert worker.snapshot().state is LiveWorkerState.FAILED
    assert worker.snapshot().session.state == "FAILED"
    worker.close()
    assert session._fd == -1


def test_reentrant_step_is_rejected(tmp_path, monkeypatch):
    path, session, worker = make_worker(tmp_path)
    original = type(session).poll_once

    def poll(instance):
        with pytest.raises(LiveWorkerError) as error:
            worker.step()
        assert error.value.code == "INVALID_STATE"
        with pytest.raises(LiveWorkerError) as close_error:
            worker.close()
        assert close_error.value.code == "INVALID_STATE"
        return original(instance)

    monkeypatch.setattr(type(session), "poll_once", poll)
    try:
        assert worker.step().status == "NO_DATA"
    finally:
        worker.close()
