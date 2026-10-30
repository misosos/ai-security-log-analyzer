"""Deterministic stream cursors, notification, slow clients and cleanup."""

import asyncio

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.service import LiveMonitoringService, LiveServiceError


def _service(tmp_path):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"past\n")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    accumulator = LiveDetectionAccumulator("application", 64, 65536)
    worker = LiveProcessingWorker(session, accumulator, 16, 4096)
    service = LiveMonitoringService(worker)
    return path, session, worker, service


def _append(path, first, count=1):
    with path.open("ab") as stream:
        for number in range(first, first + count):
            stream.write((f"2026-01-02 03:04:{number:02d} INFO login_failed "
                          "user=synthetic ip=192.0.2.1\n").encode())


def _append_timestamp(path, clock):
    with path.open("ab") as stream:
        stream.write((f"2026-01-02 {clock} INFO login_failed "
                      "user=synthetic ip=192.0.2.1\n").encode())


def test_notification_delivers_new_event_without_client_queue(tmp_path):
    path, session, worker, service = _service(tmp_path)

    async def scenario():
        stream = service.open_connection(None).stream()
        assert b"event: snapshot" in await anext(stream)
        _append(path, 0, 5)
        result = worker.step()
        await service.notify_change()
        frame = await anext(stream)
        assert b"event: observation_changes" in frame
        assert result.publication_event_id.encode() in frame
        assert service.status().active_connections == 1
        await stream.aclose()
        assert service.status().active_connections == 0
        await service.close()
    asyncio.run(scenario())
    assert session._fd == -1


def test_slow_consumer_gets_gap_after_eviction(tmp_path):
    path, _, worker, service = _service(tmp_path)
    service.publication_buffer._max_items = 2

    async def scenario():
        _append(path, 0, 5)
        first_id = worker.step().publication_event_id
        stream = service.open_connection(None).stream()
        assert b"event: snapshot" in await anext(stream)
        assert first_id.encode() in await anext(stream)
        assert b"event: analysis_changes" in await anext(stream)
        _append_timestamp(path, "03:03:59")
        worker.step()
        _append_timestamp(path, "03:03:58")
        worker.step()
        await service.notify_change()
        gap = await anext(stream)
        assert b"event: replay_gap" in gap
        assert b"EVICTED_EVENT_ID" in gap
        # Gap sends a fresh snapshot, then terminates this connection.
        assert b"event: snapshot" in await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert service.status().active_connections == 0
        await service.close()
    asyncio.run(scenario())


def test_two_cursors_independent_and_heartbeat_has_no_id(tmp_path, monkeypatch):
    path, _, worker, service = _service(tmp_path)
    _append(path, 0, 5)
    first_id = worker.step().publication_event_id
    _append_timestamp(path, "03:03:59")
    second_id = worker.step().publication_event_id

    async def immediate_timeout(_self, _generation):
        return False

    monkeypatch.setattr(LiveMonitoringService, "_wait_for_update", immediate_timeout)

    async def scenario():
        first = service.open_connection(None).stream()
        second = service.open_connection(first_id).stream()
        assert b"event: snapshot" in await anext(first)
        assert b"event: snapshot" in await anext(second)
        assert first_id.encode() in await anext(first)
        assert b"event: analysis_changes" in await anext(first)
        assert second_id.encode() in await anext(first)
        assert b"event: analysis_changes" in await anext(first)
        assert b"event: analysis_changes" in await anext(second)
        assert second_id.encode() in await anext(second)
        assert b"event: analysis_changes" in await anext(second)
        heartbeat = await anext(second)
        assert b"event: heartbeat\n" in heartbeat
        assert b"id:" not in heartbeat
        await first.aclose()
        await second.aclose()
        assert service.status().active_connections == 0
        await service.close()
    asyncio.run(scenario())


def test_cancel_and_generator_exception_release_slots(tmp_path, monkeypatch):
    _, _, _, service = _service(tmp_path)

    async def scenario():
        stream = service.open_connection(None).stream()
        await anext(stream)
        task = asyncio.create_task(anext(stream))
        await asyncio.sleep(0)  # cooperative scheduling only, no wall-clock wait
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert service.status().active_connections == 0

        stream2 = service.open_connection(None).stream()
        await anext(stream2)
        with monkeypatch.context() as patch:
            patch.setattr(type(service.publication_buffer), "replay_after",
                          lambda *_: (_ for _ in ()).throw(RuntimeError("SECRET_EXCEPTION")))
            await service.notify_change()
            assert b"LIVE_STREAM_FAILED" in await anext(stream2)
            with pytest.raises(StopAsyncIteration):
                await anext(stream2)
        assert service.status().active_connections == 0
        await service.close()
    asyncio.run(scenario())


def test_one_worker_cannot_be_owned_by_two_services(tmp_path):
    _, _, worker, service = _service(tmp_path)
    with pytest.raises(LiveServiceError):
        LiveMonitoringService(worker)
    asyncio.run(service.close())
