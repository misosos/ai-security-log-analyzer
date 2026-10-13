"""Read-only, process-local status and bounded SSE transport over safe publications."""

import asyncio
import json
from collections.abc import AsyncIterator

from app.live_monitoring.publication import (
    LivePublicationEvent, LiveAnalysisPublicationEvent,
    LivePublicationSnapshot, LiveReplayResult,
    serialize_live_publication_event, serialize_live_analysis_publication_event,
    serialize_live_publication_snapshot,
)
from app.live_monitoring.worker import LiveProcessingWorker, LiveWorkerState
from app.models.live_monitoring import LiveStatusResponse


MAX_LIVE_CONNECTIONS = 2
HEARTBEAT_SECONDS = 15.0
_EVENT_TYPES = frozenset((
    "snapshot", "observation_changes", "analysis_changes", "replay_gap", "service_status",
    "heartbeat", "stream_end",
))
_NOTICES = (
    "규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.",
    "지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다.",
)
_CAPABILITIES = ("READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "NO_AUTOMATIC_POLLING", "NO_LLM")
_RUNNER_RECOVERY = {
    "LIVE_RUNNER_DEGRADED": "프로세스를 종료하고 로그와 설정을 확인한 뒤 다시 시작하십시오.",
    "LIVE_RUNNER_FAILED": "프로세스를 종료하고 로그와 설정을 확인한 뒤 다시 시작하십시오.",
    "LIVE_SHUTDOWN_TIMEOUT": "서버 종료 상태를 확인한 뒤 다시 시작하십시오.",
}


class LiveServiceError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in ("INVALID_SERVICE", "SERVICE_CLOSED", "STREAM_LIMIT") else "INVALID_SERVICE"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"LiveServiceError(code={self.code!r})"


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def encode_live_sse_event(event_type: str, payload: object = None) -> bytes:
    """Encode only known privacy-safe typed projections; no arbitrary data strings."""
    if type(event_type) is not str or event_type not in _EVENT_TYPES:
        raise LiveServiceError("INVALID_SERVICE")
    event_id = None
    if event_type == "snapshot" and type(payload) is LivePublicationSnapshot:
        data = serialize_live_publication_snapshot(payload)
    elif event_type == "observation_changes" and type(payload) is LivePublicationEvent:
        data = serialize_live_publication_event(payload)
        event_id = payload.event_id
    elif event_type == "analysis_changes" and type(payload) is LiveAnalysisPublicationEvent:
        data = serialize_live_analysis_publication_event(payload)
        event_id = payload.event_id
    elif event_type == "replay_gap" and type(payload) is LiveReplayResult and payload.status == "GAP":
        data = _json_bytes({
            "code": payload.gap_code,
            "snapshot": json.loads(serialize_live_publication_snapshot(payload.snapshot)),
            "earliest_event_id": payload.snapshot.earliest_available_event_id,
            "latest_event_id": payload.snapshot.latest_available_event_id,
            "recovery_action": payload.recovery_action,
        })
    elif event_type == "heartbeat" and payload is None:
        data = b'{"status":"CONNECTED"}'
    elif event_type == "stream_end" and payload in (None, "LIVE_STREAM_FAILED"):
        data = _json_bytes({"code": payload or "LIVE_STREAM_ENDED"})
    elif event_type == "service_status" and type(payload) is tuple and len(payload) == 2 and (
        type(payload[0]) is str and type(payload[1]) is str
        and payload[0] in ("DEGRADED", "FAILED") and payload[1] in _RUNNER_RECOVERY
    ):
        data = _json_bytes({"state": payload[0], "code": payload[1],
                            "recovery_action": _RUNNER_RECOVERY[payload[1]]})
    elif event_type == "service_status" and payload in ("READY", "DEGRADED", "FAILED", "STOPPED"):
        data = _json_bytes({"state": payload})
    else:
        raise LiveServiceError("INVALID_SERVICE")
    if any(byte in data for byte in (0, 10, 13)):
        raise LiveServiceError("INVALID_SERVICE")
    prefix = (f"id: {event_id}\n".encode("ascii") if event_id else b"")
    return prefix + f"event: {event_type}\n".encode("ascii") + b"data: " + data + b"\n\n"


class LiveMonitoringService:
    """One worker, one bounded publication source, no automatic processing."""

    __slots__ = ("_worker", "_condition", "_generation", "_connections", "_closed",
                 "_max_connections", "_heartbeat_seconds", "_runner_bound", "_runner_state",
                 "_runner_code")

    def __init__(self, worker: LiveProcessingWorker, *, max_connections: int = MAX_LIVE_CONNECTIONS,
                 heartbeat_seconds: float = HEARTBEAT_SECONDS):
        if (type(worker) is not LiveProcessingWorker or type(max_connections) is not int
            or not 1 <= max_connections <= MAX_LIVE_CONNECTIONS
            or type(heartbeat_seconds) not in (int, float)
            or isinstance(heartbeat_seconds, bool)
            or not 0 < heartbeat_seconds <= HEARTBEAT_SECONDS):
            raise LiveServiceError("INVALID_SERVICE")
        if worker.snapshot().state is not LiveWorkerState.READY:
            raise LiveServiceError("INVALID_SERVICE")
        if worker._service_bound:
            raise LiveServiceError("INVALID_SERVICE")
        worker._service_bound = True
        self._worker = worker
        self._condition = asyncio.Condition()
        self._generation = 0
        self._connections = 0
        self._closed = False
        self._runner_bound = False
        self._runner_state = "READY"
        self._runner_code: str | None = None
        self._max_connections = max_connections
        self._heartbeat_seconds = float(heartbeat_seconds)

    def __repr__(self) -> str:
        return f"LiveMonitoringService(closed={self._closed}, connections={self._connections})"

    @property
    def publication_buffer(self):
        return self._worker.publication_buffer

    def status(self) -> LiveStatusResponse:
        worker = self._worker.snapshot()
        publication = worker.publication
        analysis = worker.analysis
        state = ("STOPPED" if self._closed or worker.state is LiveWorkerState.STOPPED else
                 "STOPPING" if self._runner_state == "STOPPING" or worker.state is LiveWorkerState.STOPPING else
                 "FAILED" if self._runner_state == "FAILED" or worker.state is LiveWorkerState.FAILED else
                 "DEGRADED" if self._runner_state == "DEGRADED" or worker.state is LiveWorkerState.DEGRADED else
                 "RUNNING" if self._runner_state == "RUNNING" else
                 "RUNNING" if worker.state is LiveWorkerState.RUNNING_STEP else "READY")
        return LiveStatusResponse(
            schema_version="2", service_state=state,
            session_id=publication.session_id, source_role=worker.session.source_role,
            worker_state=worker.state.value, publication_state=publication.state,
            latest_detection_revision=publication.latest_committed_detection_revision,
            available_event_count=publication.item_count,
            earliest_event_id=publication.earliest_available_event_id,
            latest_event_id=publication.latest_available_event_id,
            active_observation_count=publication.active_observation_count,
            published_total=publication.published_total, evicted_total=publication.evicted_total,
            replay_gap_total=publication.replay_gap_total,
            max_event_items=publication.max_items, max_event_bytes=publication.max_bytes,
            max_connections=self._max_connections, active_connections=self._connections,
            fixed_error_code=self._runner_code,
            recovery_action=_RUNNER_RECOVERY.get(self._runner_code),
            interpretation_notices=_NOTICES,
            capabilities=(_CAPABILITIES if not self._runner_bound else
                          ("READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM")),
            analysis_available=analysis is not None,
            analysis_revision=analysis.revision if analysis is not None else None,
            active_relation_count=analysis.relation_count if analysis is not None else 0,
            active_risk_count=analysis.risk_count if analysis is not None else 0,
            active_case_count=analysis.case_count if analysis is not None else 0,
            analysis_state=("UNAVAILABLE" if analysis is None else
                            "FAILED" if state == "FAILED" else "AVAILABLE"),
        )

    async def set_runner_state(self, state: str, code: str | None = None) -> None:
        if (type(state) is not str or state not in ("RUNNING", "DEGRADED", "FAILED")
            or (state == "RUNNING" and code is not None)
            or (state in ("DEGRADED", "FAILED") and
                (type(code) is not str or code not in _RUNNER_RECOVERY))):
            raise LiveServiceError("INVALID_SERVICE")
        self._runner_state = state
        self._runner_code = code
        try:
            await self.notify_change()
        except Exception:
            # A failed notification never rolls back a terminal status.
            pass

    def open_connection(self, last_event_id: str | None) -> "LiveSSEConnection":
        if self._closed:
            raise LiveServiceError("SERVICE_CLOSED")
        if self._connections >= self._max_connections:
            raise LiveServiceError("STREAM_LIMIT")
        if last_event_id is not None and type(last_event_id) is not str:
            raise LiveServiceError("INVALID_SERVICE")
        self._connections += 1
        return LiveSSEConnection(self, last_event_id)

    async def notify_change(self) -> None:
        """Signal a completed external explicit worker step; store no payload."""
        if self._closed:
            return
        async with self._condition:
            self._generation += 1
            self._condition.notify_all()

    async def _wait_for_update(self, generation: int) -> bool:
        async with self._condition:
            if self._closed or self._generation != generation:
                return True
            try:
                await asyncio.wait_for(self._condition.wait(), timeout=self._heartbeat_seconds)
                return True
            except TimeoutError:
                return False

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._worker.close()
        finally:
            async with self._condition:
                self._generation += 1
                self._condition.notify_all()


class LiveSSEConnection:
    """Client cursor only; bounded buffer remains the sole event store."""

    __slots__ = ("_service", "_cursor", "_released")

    def __init__(self, service: LiveMonitoringService, cursor: str | None):
        self._service = service
        self._cursor = cursor
        self._released = False

    def __repr__(self) -> str:
        return "LiveSSEConnection(active)" if not self._released else "LiveSSEConnection(closed)"

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._service._connections -= 1

    async def stream(self) -> AsyncIterator[bytes]:
        try:
            first = True
            while True:
                service = self._service
                if service._closed or (not first and
                    service.publication_buffer.snapshot().state == "CLOSED"):
                    yield encode_live_sse_event("stream_end")
                    return
                generation = service._generation
                replay = service.publication_buffer.replay_after(self._cursor)
                if first:
                    if replay.status == "GAP":
                        yield encode_live_sse_event("replay_gap", replay)
                        yield encode_live_sse_event("snapshot", replay.snapshot)
                        return
                    yield encode_live_sse_event("snapshot", replay.snapshot)
                    first = False
                elif replay.status == "GAP":
                    yield encode_live_sse_event("replay_gap", replay)
                    yield encode_live_sse_event("snapshot", replay.snapshot)
                    return
                for event in replay.events:
                    yield encode_live_sse_event(
                        "observation_changes" if type(event) is LivePublicationEvent
                        else "analysis_changes", event)
                    self._cursor = event.event_id
                if service._runner_state in ("DEGRADED", "FAILED"):
                    yield encode_live_sse_event("service_status", (
                        service._runner_state, service._runner_code,
                    ))
                    return
                if service._closed or service.publication_buffer.snapshot().state == "CLOSED":
                    yield encode_live_sse_event("stream_end")
                    return
                if not await service._wait_for_update(generation):
                    yield encode_live_sse_event("heartbeat")
        except asyncio.CancelledError:
            raise
        except Exception:
            yield encode_live_sse_event("stream_end", "LIVE_STREAM_FAILED")
        finally:
            self.release()
