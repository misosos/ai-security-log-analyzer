"""One-loop automatic polling, terminal states, notification, and cleanup."""

import asyncio
from pathlib import Path

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.runner import LiveMonitoringRunner, LiveRunnerError, LiveRunnerState
from app.live_monitoring.service import LiveMonitoringService
from app.live_monitoring.publication import LivePublicationBuffer
from app.live_monitoring.core import LiveTailSession


def _runtime(tmp_path: Path):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"past\n")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    worker = LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), 16, 4096)
    service = LiveMonitoringService(worker)
    runner = LiveMonitoringRunner(service)
    return path, session, worker, service, runner


def _append(path: Path, count: int, *, newline: bool = True):
    with path.open("ab") as stream:
        for number in range(count):
            stream.write((f"2026-01-02 03:04:{number:02d} INFO login_failed "
                          f"user=synthetic ip=192.0.2.1" + ("\n" if newline else "")).encode())


async def _turns_until(predicate):
    for _ in range(100):
        if predicate():
            return
        await asyncio.sleep(0)
    assert predicate()


def test_automatic_poll_from_end_partial_then_publication_and_stop(tmp_path, monkeypatch):
    path, session, worker, service, runner = _runtime(tmp_path)
    gate = asyncio.Event()

    async def wait_next(_self):
        await gate.wait()
        gate.clear()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)

    async def scenario():
        connection = service.open_connection(None)
        stream = connection.stream()
        assert b"event: snapshot" in await anext(stream)
        task = asyncio.create_task(runner.run())
        await _turns_until(lambda: worker.snapshot().step_revision == 1)
        assert worker.snapshot().total_parsed == 0  # FROM_END skips the old line.
        assert service.status().service_state == "RUNNING"
        _append(path, 1, newline=False)
        gate.set()
        await _turns_until(lambda: worker.snapshot().step_revision == 2)
        assert worker.snapshot().total_parsed == 0
        with path.open("ab") as output:
            output.write(b"\n")
        _append(path, 5)
        gate.set()
        await _turns_until(lambda: worker.snapshot().total_parsed == 6)
        assert service.status().latest_detection_revision == 1
        assert service.status().published_total == 1
        assert b"event: observation_changes" in await anext(stream)
        runner.request_stop()
        gate.set()
        await task
        await stream.aclose()
        await runner.shutdown()
        assert service.status().service_state == "STOPPED"
        assert service.status().active_connections == 0

    asyncio.run(scenario())
    assert session._fd == -1


def test_duplicate_runner_and_run_reentry_rejected(tmp_path, monkeypatch):
    _, _, _, service, runner = _runtime(tmp_path)
    with pytest.raises(LiveRunnerError):
        LiveMonitoringRunner(service)
    with pytest.raises(LiveRunnerError):
        LiveMonitoringRunner(service, poll_interval_seconds=0)
    gate = asyncio.Event()

    async def wait_next(_self):
        await gate.wait()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)

    async def scenario():
        task = asyncio.create_task(runner.run())
        await _turns_until(lambda: runner.state is LiveRunnerState.RUNNING)
        with pytest.raises(LiveRunnerError):
            await runner.run()
        runner.request_stop()
        gate.set()
        await task
        await runner.shutdown()
    asyncio.run(scenario())


def test_degraded_stops_without_auto_resume_and_emits_safe_status(tmp_path, monkeypatch):
    path, _, worker, service, runner = _runtime(tmp_path)
    _append(path, 1)
    import app.live_monitoring.worker as worker_module
    monkeypatch.setattr(worker_module, "parse_live_records", lambda *_: (_ for _ in ()).throw(
        RuntimeError("PRIVATE_PARSER_EXCEPTION")))

    async def scenario():
        stream = service.open_connection(None).stream()
        assert b"snapshot" in await anext(stream)
        await runner.run()
        assert runner.state is LiveRunnerState.DEGRADED
        assert worker.snapshot().state.value == "DEGRADED"
        assert worker.snapshot().session.available_item_count == 1
        status = service.status()
        assert status.service_state == "DEGRADED"
        assert status.fixed_error_code == "LIVE_RUNNER_DEGRADED"
        frame = await anext(stream)
        assert b"event: service_status" in frame and b"LIVE_RUNNER_DEGRADED" in frame
        assert b"PRIVATE_PARSER_EXCEPTION" not in frame
        await stream.aclose()
        await runner.shutdown()
    asyncio.run(scenario())


def test_terminal_poll_failure_keeps_web_service_readable(tmp_path):
    path, _, worker, service, runner = _runtime(tmp_path)
    path.unlink()

    async def scenario():
        await runner.run()
        assert runner.state is LiveRunnerState.FAILED
        assert service.status().service_state == "FAILED"
        assert service.status().fixed_error_code == "LIVE_RUNNER_FAILED"
        assert worker.snapshot().step_revision == 1
        await runner.shutdown()
    asyncio.run(scenario())


def test_notify_failure_does_not_roll_back_detection_or_retry(tmp_path, monkeypatch):
    path, _, worker, service, runner = _runtime(tmp_path)
    _append(path, 5)

    async def fail_notify(_self):
        raise RuntimeError("PRIVATE_NOTIFY_EXCEPTION")

    monkeypatch.setattr(LiveMonitoringService, "notify_change", fail_notify)

    async def scenario():
        await runner.run()
        assert runner.state is LiveRunnerState.FAILED
        assert service.status().published_total == 1
        assert worker.snapshot().total_acknowledged == 5
        assert worker.snapshot().step_revision == 1
        await runner.shutdown()
    asyncio.run(scenario())


def test_shutdown_timeout_is_fixed_and_attempts_fd_cleanup(tmp_path, monkeypatch):
    _, session, _, service, runner = _runtime(tmp_path)
    gate = asyncio.Event()

    async def wait_next(_self):
        await gate.wait()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)

    async def scenario():
        task = asyncio.create_task(runner.run())
        await _turns_until(lambda: runner.state is LiveRunnerState.RUNNING)
        with pytest.raises(LiveRunnerError) as caught:
            await runner.shutdown(0.001)
        assert caught.value.code == "SHUTDOWN_TIMEOUT"
        assert session._fd == -1
        gate.set()
        try:
            await task
        except asyncio.CancelledError:
            pass
    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ("ack", "publication"))
def test_terminal_settlement_failures_do_not_resume_or_expose_detail(tmp_path, monkeypatch, fault):
    path, session, worker, service, runner = _runtime(tmp_path)
    _append(path, 5)
    if fault == "ack":
        monkeypatch.setattr(LiveTailSession, "acknowledge_lease", lambda *_: (_ for _ in ()).throw(
            RuntimeError("PRIVATE_ACK_EXCEPTION")))
    else:
        monkeypatch.setattr(LivePublicationBuffer, "commit_prepared", lambda *_: (_ for _ in ()).throw(
            RuntimeError("PRIVATE_PUBLICATION_EXCEPTION")))

    async def scenario():
        await runner.run()
        assert runner.state is LiveRunnerState.FAILED
        snapshot = service.status()
        assert snapshot.service_state == "FAILED"
        assert snapshot.fixed_error_code == "LIVE_RUNNER_FAILED"
        assert "PRIVATE_" not in repr(runner) + repr(snapshot)
        assert worker.snapshot().step_revision == 1
        await runner.shutdown()
    asyncio.run(scenario())
    assert session._fd == -1


def test_cancellation_then_shutdown_closes_session(tmp_path, monkeypatch):
    _, session, _, _, runner = _runtime(tmp_path)
    entered = asyncio.Event()

    async def wait_next(_self):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(LiveMonitoringRunner, "_wait_next", wait_next)

    async def scenario():
        task = asyncio.create_task(runner.run())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await runner.shutdown()
        assert runner.state is LiveRunnerState.STOPPED
    asyncio.run(scenario())
    assert session._fd == -1


def test_unexpected_runner_snapshot_failure_is_terminal_and_fixed(tmp_path, monkeypatch):
    _, session, worker, service, runner = _runtime(tmp_path)

    async def scenario():
        with monkeypatch.context() as patch:
            patch.setattr(LivePublicationBuffer, "snapshot", lambda *_: (_ for _ in ()).throw(
                RuntimeError("PRIVATE_SNAPSHOT_EXCEPTION")))
            await runner.run()
        assert runner.state is LiveRunnerState.FAILED
        assert service.status().fixed_error_code == "LIVE_RUNNER_FAILED"
        assert worker.snapshot().step_revision == 0
        await runner.shutdown()
    asyncio.run(scenario())
    assert session._fd == -1


def test_runner_snapshot_and_repr_exclude_source_and_record_canaries(tmp_path, capsys):
    path, _, _, service, runner = _runtime(tmp_path)
    canary = "PRIVATE_ACCOUNT_CANARY"
    with path.open("ab") as stream:
        stream.write((f"2026-01-02 03:04:00 INFO login_failed user={canary} "
                      "ip=192.0.2.1\n").encode())

    assert runner.snapshot().state is LiveRunnerState.CREATED
    text = repr(runner) + repr(runner.snapshot()) + repr(service.status())
    assert canary not in text and str(path) not in text
    output = capsys.readouterr()
    assert canary not in output.out + output.err
    asyncio.run(service.close())
