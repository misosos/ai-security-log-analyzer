"""Read-only v3 status and SSE over one internal pair publication cursor."""

import asyncio
import json
from collections.abc import AsyncIterator

from app.live_monitoring.multi_source import InternalPairRuntime, MultiSourceRuntimeError, ROLES
from app.live_monitoring.pair_publication import (
    MAX_PAIR_SNAPSHOT_BYTES, PairEvent, PairPublicationBuffer, PairPublicationError,
)
from app.live_monitoring.publication import MAX_PUBLICATION_BYTES, MAX_PUBLICATION_ITEMS
from app.live_monitoring.service import LiveServiceError, _NOTICES
from app.live_monitoring.worker import LiveWorkerState
from app.models.multi_source_live import PairRoleStatus, PairStatusResponse


HEARTBEAT_SECONDS = 15.0
POLL_INTERVAL_SECONDS = 0.5
MAX_CONNECTIONS = 2
_CAPABILITIES = ("READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM")


def _frame(kind: str, data: bytes, event_id: str | None = None) -> bytes:
    if b"\n" in data or b"\r" in data or b"\x00" in data:
        raise PairPublicationError("PAIR_PUBLICATION_FAILED")
    prefix = f"id: {event_id}\n".encode("ascii") if event_id else b""
    return prefix + f"event: {kind}\n".encode("ascii") + b"data: " + data + b"\n\n"


def _json(value: dict) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise PairPublicationError("PAIR_PUBLICATION_FAILED") from None


class PairMonitoringService:
    __slots__ = ("runtime", "publication", "_condition", "_generation", "_connections",
                 "_closed", "_runner_state", "_runner_code", "_last_step")

    def __init__(self, runtime: InternalPairRuntime, publication: PairPublicationBuffer):
        if type(runtime) is not InternalPairRuntime or type(publication) is not PairPublicationBuffer:
            raise LiveServiceError("INVALID_SERVICE")
        self.runtime = runtime
        self.publication = publication
        self._condition = asyncio.Condition()
        self._generation = 0
        self._connections = 0
        self._closed = False
        self._runner_state = "READY"
        self._runner_code = None
        self._last_step = {role: None for role in ROLES}

    @property
    def active_connections(self) -> int:
        return self._connections

    def status(self) -> PairStatusResponse:
        states = {role: worker.snapshot() for role, worker in self.runtime.workers.items()}
        if self._closed or self.runtime.state == "STOPPED":
            overall = "STOPPED"
        elif self.runtime.state == "FAILED" or self._runner_state == "FAILED" or any(
            item.state is LiveWorkerState.FAILED for item in states.values()
        ):
            overall = "FAILED"
        elif self.runtime.state == "DEGRADED" or self._runner_state == "DEGRADED" or any(
            item.state is LiveWorkerState.DEGRADED for item in states.values()
        ):
            overall = "DEGRADED"
        elif self._runner_state == "STOPPING":
            overall = "STOPPING"
        elif self._runner_state == "RUNNING":
            overall = "RUNNING"
        else:
            overall = "READY"
        roles = []
        for role in ROLES:
            worker = self.runtime.workers[role]
            item = states[role]
            analysis = item.analysis
            role_state = ("FAILED" if item.state is LiveWorkerState.FAILED else
                          "DEGRADED" if item.state is LiveWorkerState.DEGRADED else
                          "STOPPED" if item.state is LiveWorkerState.STOPPED else
                          "RUNNING" if item.state is LiveWorkerState.RUNNING_STEP else "READY")
            roles.append(PairRoleStatus(
                role=role, service_state=role_state,
                detection_revision=item.accumulator.revision,
                analysis_revision=analysis.revision if analysis else 0,
                active_observation_count=item.accumulator.active_observation_count,
                active_relation_count=analysis.relation_count if analysis else 0,
                active_risk_count=analysis.risk_count if analysis else 0,
                active_case_count=analysis.case_count if analysis else 0,
                checkpoint_available=(worker._checkpoint is not None
                                      and worker._checkpoint._checkpoint is not None),
                last_step_code=("FAILED" if role_state == "FAILED" else
                                "DEGRADED" if role_state == "DEGRADED" else
                                self._last_step[role]),
            ))
        status = PairStatusResponse(
            schema_version="3", service_state=overall,
            session_id=self.publication.session_id, roles=tuple(roles),
            available_event_count=self.publication.item_count,
            event_byte_count=self.publication.byte_count,
            earliest_event_id=self.publication.earliest_event_id,
            latest_event_id=self.publication.latest_event_id,
            published_total=self.publication.published_total,
            evicted_total=self.publication.evicted_total,
            replay_gap_total=self.publication.replay_gap_total,
            max_event_items=MAX_PUBLICATION_ITEMS, max_event_bytes=MAX_PUBLICATION_BYTES,
            max_connections=MAX_CONNECTIONS, active_connections=self._connections,
            fixed_error_code=self._runner_code,
            interpretation_notices=_NOTICES, capabilities=_CAPABILITIES,
        )
        if len(status.model_dump_json().encode("utf-8")) > MAX_PAIR_SNAPSHOT_BYTES:
            raise PairPublicationError("PAIR_SNAPSHOT_TOO_LARGE")
        return status

    def record_cycle(self, results: tuple[tuple[str, str], ...]) -> None:
        for role, code in results:
            if role in ROLES and code in ("NO_DATA", "PROCESSED"):
                self._last_step[role] = code

    async def notify_change(self) -> None:
        if self._closed:
            return
        async with self._condition:
            self._generation += 1
            self._condition.notify_all()

    async def _wait(self, generation: int) -> bool:
        async with self._condition:
            if self._closed or generation != self._generation:
                return True
            try:
                await asyncio.wait_for(self._condition.wait(), timeout=HEARTBEAT_SECONDS)
                return True
            except TimeoutError:
                return False

    def open_connection(self, cursor: str | None) -> "PairSSEConnection":
        if self._closed:
            raise LiveServiceError("SERVICE_CLOSED")
        if self._connections >= MAX_CONNECTIONS:
            raise LiveServiceError("STREAM_LIMIT")
        if cursor is not None and type(cursor) is not str:
            raise LiveServiceError("INVALID_SERVICE")
        self._connections += 1
        return PairSSEConnection(self, cursor)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.runtime.close()
        finally:
            self.publication.close()
            async with self._condition:
                self._generation += 1
                self._condition.notify_all()


class PairSSEConnection:
    __slots__ = ("_service", "_cursor", "_released")

    def __init__(self, service: PairMonitoringService, cursor: str | None):
        self._service = service
        self._cursor = cursor
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._service._connections -= 1

    async def stream(self) -> AsyncIterator[bytes]:
        try:
            first = True
            while True:
                service = self._service
                if service._closed:
                    yield _frame("stream_end", b'{"code":"PAIR_STREAM_ENDED"}')
                    return
                generation = service._generation
                replay = service.publication.replay_after(self._cursor)
                if replay.status == "GAP":
                    yield _frame("replay_gap", _json({
                        "schema_version": "3", "code": replay.gap_code,
                        "affected_roles": replay.affected_roles, "stale": True,
                        "recovery_action": "최신 snapshot을 다시 조회하십시오.",
                    }))
                    yield _frame("snapshot", service.status().model_dump_json().encode("utf-8"))
                    return
                if first:
                    yield _frame("snapshot", service.status().model_dump_json().encode("utf-8"))
                    first = False
                for event in replay.events:
                    yield _frame(event.event_type, event.encoded, event.event_id)
                    self._cursor = event.event_id
                if service._runner_state in ("DEGRADED", "FAILED"):
                    yield _frame("service_status", _json({
                        "schema_version": "3", "state": service._runner_state,
                        "code": service._runner_code,
                    }))
                    return
                if not await service._wait(generation):
                    yield _frame("heartbeat", b'{"status":"CONNECTED"}')
        except asyncio.CancelledError:
            raise
        except Exception:
            yield _frame("stream_end", b'{"code":"PAIR_STREAM_FAILED"}')
        finally:
            self.release()


class PairRunner:
    """One event-loop caller for pair cycle and notification; no retry."""

    __slots__ = ("service", "_stop", "_task")

    def __init__(self, service: PairMonitoringService):
        self.service = service
        self._stop = asyncio.Event()
        self._task = None

    @property
    def state(self) -> str:
        return self.service._runner_state

    async def _notify_safely(self) -> bool:
        try:
            await self.service.notify_change()
            return True
        except Exception:
            self.service._runner_state = "FAILED"
            self.service._runner_code = "PAIR_RUNNER_FAILED"
            return False

    async def run(self) -> None:
        if self._task is not None:
            raise LiveServiceError("INVALID_SERVICE")
        self._task = asyncio.current_task()
        self.service._runner_state = "RUNNING"
        if not await self._notify_safely():
            return
        while not self._stop.is_set():
            before = self.service.publication.published_total
            try:
                results = self.service.runtime.cycle()
                self.service.record_cycle(results)
            except MultiSourceRuntimeError:
                self.service._runner_state = ("DEGRADED" if self.service.runtime.state == "DEGRADED"
                                              else "FAILED")
                self.service._runner_code = ("PAIR_RUNNER_DEGRADED" if self.service._runner_state == "DEGRADED"
                                             else "PAIR_RUNNER_FAILED")
                await self._notify_safely()
                return
            except Exception:
                self.service._runner_state = "FAILED"
                self.service._runner_code = "PAIR_RUNNER_FAILED"
                await self._notify_safely()
                return
            if self.service.publication.published_total > before:
                if not await self._notify_safely():
                    return
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=POLL_INTERVAL_SECONDS)
            except TimeoutError:
                pass

    async def shutdown(self) -> None:
        self._stop.set()
        try:
            if self._task is not None and self._task is not asyncio.current_task():
                await asyncio.wait_for(self._task, timeout=5.0)
        finally:
            await self.service.close()
