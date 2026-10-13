"""Loopback-only, read-only live status and bounded SSE transfer."""

import asyncio
import json

from fastapi.testclient import TestClient
import pytest

from app.api import create_app
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring import service as service_module
from app.live_monitoring.service import (
    LiveMonitoringService, LiveServiceError, encode_live_sse_event,
)


def _worker(tmp_path):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"past line\n")
    session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
    accumulator = LiveDetectionAccumulator("application", 64, 65536)
    worker = LiveProcessingWorker(session, accumulator, 16, 4096)
    return path, worker


def _append(path, start=0, count=5, *, canary="synthetic"):
    lines = (f"2026-01-02 03:04:{index:02d} INFO login_failed "
             f"user={canary} ip=192.0.2.1" for index in range(start, start + count))
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def _client(service=None, *, host="127.0.0.1", peer="127.0.0.1"):
    return TestClient(create_app(live_monitoring_service=service),
                      base_url=f"http://{host}:8000", client=(peer, 50000))


def _frames(data):
    return [item for item in data.split(b"\n\n") if item]


def test_sse_encoder_rejects_serialized_newline_without_leaking_payload(tmp_path, monkeypatch):
    _, worker = _worker(tmp_path)
    try:
        monkeypatch.setattr(service_module, "serialize_live_publication_snapshot",
                            lambda _snapshot: b'{"private":"LINE_CANARY\n"}')
        with pytest.raises(LiveServiceError) as raised:
            encode_live_sse_event("snapshot", worker.publication_buffer.snapshot())
        assert raised.value.code == "INVALID_SERVICE"
        assert "LINE_CANARY" not in repr(raised.value)
    finally:
        worker.close()


def test_default_app_is_fixed_disabled_without_changing_existing_routes():
    client = _client()
    for path in ("/api/v1/live/status", "/api/v1/live/events"):
        response = client.get(path)
        assert response.status_code == 404
        assert response.json()["error_code"] == "LIVE_MONITORING_NOT_ENABLED"
        assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.post("/api/v1/investigations/sample").status_code == 200


def test_explicit_status_is_safe_read_only_and_loopback_only(tmp_path, monkeypatch):
    _, worker = _worker(tmp_path)
    service = LiveMonitoringService(worker)
    client = _client(service)
    monkeypatch.setattr(LiveProcessingWorker, "step", lambda *_: pytest.fail("status stepped worker"))
    try:
        response = client.get("/api/v1/live/status")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-type"].startswith("application/json")
        body = response.json()
        assert set(body) == {
            "schema_version", "service_state", "session_id", "source_role", "worker_state",
            "publication_state", "latest_detection_revision", "available_event_count",
            "earliest_event_id", "latest_event_id", "active_observation_count",
            "published_total", "evicted_total", "replay_gap_total", "max_event_items",
            "max_event_bytes", "max_connections", "active_connections",
            "fixed_error_code", "recovery_action", "interpretation_notices", "capabilities",
            "analysis_available", "analysis_revision", "active_relation_count",
            "active_risk_count", "active_case_count", "analysis_state",
        }
        assert body["fixed_error_code"] is None and body["recovery_action"] is None
        assert body["available_event_count"] == 0
        assert body["source_role"] == "application"
        assert body["session_id"].startswith("LIVE-SESSION-")
        assert worker.snapshot().step_revision == 0
        assert _client(service, peer="192.0.2.10").get("/api/v1/live/status").json()["error_code"] == "LIVE_LOOPBACK_REQUIRED"
        # This Starlette TestClient version cannot parse bracketed IPv6 base URLs.
        assert _client(service, peer="::1").get(
            "/api/v1/live/status", headers={"Host": "[::1]:8000"},
        ).status_code == 200
        assert _client(service, host="localhost").get("/api/v1/live/status").json()["error_code"] == "LIVE_INVALID_HOST"
        assert client.get("/api/v1/live/status", headers={"X-Forwarded-For": "127.0.0.1"}).json()["error_code"] == "LIVE_FORWARDED_REQUEST_REJECTED"
        assert client.get("/api/v1/live/status", headers={"Origin": "http://outside.invalid"}).json()["error_code"] == "LIVE_ORIGIN_REJECTED"
    finally:
        asyncio.run(service.close())


def test_sse_initial_replay_gap_and_wire_contract(tmp_path):
    path, worker = _worker(tmp_path)
    service = LiveMonitoringService(worker)
    _append(path)
    result = worker.step()
    assert result.publication_event_id is not None

    async def scenario():
        connection = service.open_connection(None)
        stream = connection.stream()
        first = await anext(stream)
        second = await anext(stream)
        assert b"event: snapshot\n" in first
        assert second.startswith(b"id: LIVE-EVENT-")
        assert b"event: observation_changes\n" in second
        assert all(item.endswith(b"\n\n") for item in (first, second))
        assert b"\r" not in first + second
        await stream.aclose()
        assert service.status().active_connections == 0

        reconnected = service.open_connection(result.publication_event_id)
        stream = reconnected.stream()
        assert b"event: snapshot\n" in await anext(stream)
        await stream.aclose()
        assert service.status().active_connections == 0

        gap = service.open_connection("bad-private-id")
        stream = gap.stream()
        gap_frame = await anext(stream)
        assert b"event: replay_gap\n" in gap_frame
        assert b"MALFORMED_EVENT_ID" in gap_frame
        assert b"event: snapshot\n" in await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert service.status().active_connections == 0
        await service.close()
    asyncio.run(scenario())


def test_http_sse_headers_gap_termination_and_openapi(tmp_path, monkeypatch):
    _, worker = _worker(tmp_path)
    service = LiveMonitoringService(worker)
    client = _client(service)
    try:
        response = client.get("/api/v1/live/events", headers={"Last-Event-ID": "malformed"})
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/event-stream; charset=utf-8"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert [frame.split(b"\n")[0] for frame in _frames(response.content)] == [
            b"event: replay_gap", b"event: snapshot",
        ]
        assert client.get("/api/v1/live/events?last_event_id=x").json()["error_code"] == "LIVE_INVALID_LAST_EVENT_ID"
        assert client.get("/api/v1/live/events", headers=[
            ("Last-Event-ID", "first"), ("Last-Event-ID", "second"),
        ]).json()["error_code"] == "LIVE_INVALID_LAST_EVENT_ID"
        assert client.get("/api/v1/live/events", headers={
            "Forwarded": "for=192.0.2.1",
        }).json()["error_code"] == "LIVE_FORWARDED_REQUEST_REJECTED"
        schema = client.get("/openapi.json").text
        assert '"/api/v1/live/status"' in schema
        assert '"text/event-stream"' in schema
        for private in ("LiveTailRecord", "NormalizedEvent", "DetectionResult", "source_path", "argv"):
            assert private not in schema
        assert not any(path.startswith("/api/v1/live/") and path.endswith(("start", "stop"))
                       for path in client.get("/openapi.json").json()["paths"])
    finally:
        asyncio.run(service.close())


def test_connection_limit_close_and_safe_encoder(tmp_path):
    _, worker = _worker(tmp_path)
    service = LiveMonitoringService(worker)
    async def scenario():
        one = service.open_connection(None)
        two = service.open_connection(None)
        with pytest.raises(LiveServiceError) as raised:
            service.open_connection(None)
        assert raised.value.code == "STREAM_LIMIT"
        one.release()
        assert service.status().active_connections == 1
        stream = two.stream()
        assert b"event: snapshot" in await anext(stream)
        await service.close()
        assert b"event: stream_end" in await anext(stream)
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert service.status().active_connections == 0
        await service.close()
        with pytest.raises(LiveServiceError):
            service.open_connection(None)
    asyncio.run(scenario())
    for event_type, payload in (("heartbeat", None), ("stream_end", None), ("service_status", "READY")):
        wire = encode_live_sse_event(event_type, payload)
        assert wire.endswith(b"\n\n") and b"\nid:" not in wire
    with pytest.raises(LiveServiceError):
        encode_live_sse_event("observation_changes", {"raw": "private"})


def test_privacy_canaries_absent_from_http_sse_repr_and_openapi(tmp_path):
    path, worker = _worker(tmp_path)
    service = LiveMonitoringService(worker)
    account = "ACCOUNT_CANARY_PRIVATE"
    path_canary = "PATH_QUERY_CANARY_PRIVATE"
    _append(path, canary=account)
    with path.open("ab") as stream:
        stream.write((f"2026-01-02 03:04:05 INFO login_failed user={account} "
                      f"ip=192.0.2.1 note={path_canary}\n").encode())
    worker.step()
    client = _client(service)
    try:
        status = client.get("/api/v1/live/status").text
        gap = client.get("/api/v1/live/events", headers={
            "Last-Event-ID": "PRIVATE_LAST_EVENT_ID_CANARY",
        }).text
        schema = client.get("/openapi.json").text
        published = worker.publication_buffer.replay_after(None).events[0]
        data = encode_live_sse_event("observation_changes", published).decode()
        for value in (account, path_canary, "PRIVATE_LAST_EVENT_ID_CANARY", str(path)):
            assert all(value not in text for text in (status, gap, schema, data, repr(service)))
    finally:
        asyncio.run(service.close())
