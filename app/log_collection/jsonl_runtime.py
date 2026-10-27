"""Synthetic-only loopback runtime for the closed external-collector JSONL core."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import ipaddress
import socket
from typing import Any

from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records
from app.log_collection.jsonl_adapter import (
    AdapterErrorCode, BoundedJsonLinesQueue, JsonLinesDecoder,
    JsonlAdapterConfig, JsonlAdapterError,
)


class JsonlRuntimeErrorCode(str, Enum):
    CONFIG_INVALID = "JSONL_RUNTIME_CONFIG_INVALID"
    BIND_FAILED = "JSONL_RUNTIME_BIND_FAILED"
    PORT_IN_USE = "JSONL_RUNTIME_PORT_IN_USE"
    CONNECTION_LIMIT = "JSONL_RUNTIME_CONNECTION_LIMIT"
    READ_TIMEOUT = "JSONL_RUNTIME_READ_TIMEOUT"
    IDLE_TIMEOUT = "JSONL_RUNTIME_IDLE_TIMEOUT"
    DECODE_FAILED = "JSONL_RUNTIME_DECODE_FAILED"
    QUEUE_FULL = "JSONL_RUNTIME_QUEUE_FULL"
    PARSER_REJECTED = "JSONL_RUNTIME_PARSER_REJECTED"
    ANALYSIS_FAILED = "JSONL_RUNTIME_ANALYSIS_FAILED"
    SHUTDOWN_TIMEOUT = "JSONL_RUNTIME_SHUTDOWN_TIMEOUT"
    CLEANUP_FAILED = "JSONL_RUNTIME_CLEANUP_FAILED"
    STOPPED = "JSONL_RUNTIME_STOPPED"
    INTERNAL_FAILURE = "JSONL_RUNTIME_INTERNAL_FAILURE"


class JsonlRuntimeError(RuntimeError):
    def __init__(self, code: JsonlRuntimeErrorCode):
        self.code = code if isinstance(code, JsonlRuntimeErrorCode) else JsonlRuntimeErrorCode.INTERNAL_FAILURE
        super().__init__(self.code.value)

    def __repr__(self) -> str:
        return f"JsonlRuntimeError({self.code.value})"


class JsonlRuntimeState(str, Enum):
    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


_TRANSITIONS = {
    JsonlRuntimeState.CREATED: {JsonlRuntimeState.STARTING, JsonlRuntimeState.STOPPING},
    JsonlRuntimeState.STARTING: {JsonlRuntimeState.RUNNING, JsonlRuntimeState.FAILED,
                                 JsonlRuntimeState.STOPPING},
    JsonlRuntimeState.RUNNING: {JsonlRuntimeState.DEGRADED, JsonlRuntimeState.FAILED,
                                JsonlRuntimeState.STOPPING},
    JsonlRuntimeState.DEGRADED: {JsonlRuntimeState.FAILED, JsonlRuntimeState.STOPPING},
    JsonlRuntimeState.FAILED: {JsonlRuntimeState.STOPPING},
    JsonlRuntimeState.STOPPING: {JsonlRuntimeState.STOPPED},
    JsonlRuntimeState.STOPPED: {JsonlRuntimeState.STOPPED},
}


@dataclass(frozen=True, slots=True, repr=False)
class JsonlRuntimeConfig:
    source_role: str
    host: str = "127.0.0.1"
    port: int = 0
    test_only_ephemeral_port: bool = False
    max_connections: int = 2
    read_timeout_seconds: float = 1.0
    idle_timeout_seconds: float = 30.0
    shutdown_timeout_seconds: float = 2.0
    read_chunk_bytes: int = 4096
    history_records: int = 256
    history_bytes: int = 262144
    schema_version: str = "collector-jsonl-runtime/v1"

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host) if type(self.host) is str else None
            valid_host = ((self.host == "127.0.0.1" and address == ipaddress.ip_address("127.0.0.1"))
                          or (self.host == "::1" and address == ipaddress.ip_address("::1")))
            valid = (
                self.schema_version == "collector-jsonl-runtime/v1"
                and type(self.schema_version) is str
                and type(self.source_role) is str and self.source_role in {"application", "ssh"}
                and valid_host
                and type(self.test_only_ephemeral_port) is bool
                and type(self.port) is int
                and ((self.port == 0 and self.test_only_ephemeral_port)
                     or 1024 <= self.port <= 65535)
                and type(self.max_connections) is int and 1 <= self.max_connections <= 2
                and type(self.read_chunk_bytes) is int and 1 <= self.read_chunk_bytes <= 4096
                and type(self.history_records) is int and 1 <= self.history_records <= 256
                and type(self.history_bytes) is int and 1024 <= self.history_bytes <= 262144
                and type(self.read_timeout_seconds) in (int, float)
                and 0.05 <= self.read_timeout_seconds <= 30
                and type(self.idle_timeout_seconds) in (int, float)
                and self.read_timeout_seconds <= self.idle_timeout_seconds <= 300
                and type(self.shutdown_timeout_seconds) in (int, float)
                and 0.05 <= self.shutdown_timeout_seconds <= 10
            )
        except Exception:
            valid = False
        if not valid:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.CONFIG_INVALID)

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: object) -> "JsonlRuntimeConfig":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.CONFIG_INVALID)
        try:
            return cls(**value)
        except Exception:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.CONFIG_INVALID) from None

    def __repr__(self) -> str:
        return f"JsonlRuntimeConfig(source_role={self.source_role!r}, loopback_only=True)"


@dataclass(frozen=True, slots=True, repr=False)
class JsonlRuntimeSnapshot:
    schema_version: str
    source_role: str
    transport: str
    state: JsonlRuntimeState
    active_connections: int
    connection_limit: int
    received: int
    envelope_validated: int
    queue_accepted: int
    queue_rejected: int
    parser_recognized: int
    parser_unrecognized: int
    analysis_completed: int
    processing_dropped: int
    connection_rejected: int
    malformed: int
    terminal_failures: int
    queued_events: int
    queue_event_limit: int
    queued_bytes: int
    queue_byte_limit: int
    peak_queued_events: int
    peak_queued_bytes: int
    history_events: int
    history_bytes: int
    history_event_limit: int
    history_byte_limit: int
    last_success_at: str
    error_category: str

    def to_dict(self) -> dict[str, Any]:
        return {key: (value.value if isinstance(value, Enum) else value)
                for key, value in ((k, getattr(self, k)) for k in self.__dataclass_fields__)}

    def __repr__(self) -> str:
        return (f"JsonlRuntimeSnapshot(state={self.state.value}, received={self.received}, "
                f"analysis_completed={self.analysis_completed}, error_category={self.error_category!r})")


class JsonlCollectorRuntime:
    """Single-role, ephemeral, bounded; intentionally disconnected from public surfaces."""

    def __init__(self, config: JsonlRuntimeConfig):
        if type(config) is not JsonlRuntimeConfig:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.CONFIG_INVALID)
        self.config = config
        self._adapter = JsonlAdapterConfig(source_role=config.source_role)
        self._queue = BoundedJsonLinesQueue(self._adapter)
        self._detection = LiveDetectionAccumulator(config.source_role, config.history_records,
                                                   config.history_bytes)
        # Deliberately do not load account metadata or any user configuration.
        self._analysis = LiveAnalysisAccumulator(self._detection, ())
        self._server: asyncio.AbstractServer | None = None
        self._connections: dict[asyncio.Task, asyncio.StreamWriter] = {}
        self._closing: set[asyncio.Task] = set()
        self._worker: asyncio.Task | None = None
        self._queue_event = asyncio.Event()
        self._stop_lock = asyncio.Lock()
        self._state = JsonlRuntimeState.CREATED
        self._error = "NONE"
        self._counts = {name: 0 for name in (
            "received", "validated", "queue_accepted", "queue_rejected", "parser_recognized",
            "parser_unrecognized", "analysis_completed", "processing_dropped",
            "connection_rejected", "malformed", "terminal_failures")}
        self._peak_queued_events = self._peak_queued_bytes = 0
        self._last_success = "unavailable"
        self._stopping = False

    def __repr__(self) -> str:
        return f"JsonlCollectorRuntime(source_role={self.config.source_role!r}, state={self._state.value})"

    async def _create_server(self) -> asyncio.AbstractServer:
        family = socket.AF_INET if self.config.host == "127.0.0.1" else socket.AF_INET6
        return await asyncio.start_server(
            self._accept, host=self.config.host, port=self.config.port, family=family,
            limit=self.config.read_chunk_bytes, backlog=self.config.max_connections,
            reuse_address=True,
        )

    def _new_decoder(self) -> JsonLinesDecoder:
        return JsonLinesDecoder(self._adapter)

    def _spawn_worker_task(self) -> asyncio.Task:
        return asyncio.create_task(self._consume())

    def _spawn_connection_task(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter) -> asyncio.Task:
        return asyncio.create_task(self._handle_connection(reader, writer))

    def _transition(self, target: JsonlRuntimeState) -> None:
        if target not in _TRANSITIONS[self._state]:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
        self._state = target

    async def start(self) -> None:
        if self._state is not JsonlRuntimeState.CREATED:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
        self._transition(JsonlRuntimeState.STARTING)
        try:
            # Prepare the consumer before accepting any client.
            self._worker = self._spawn_worker_task()
            self._server = await self._create_server()
            self._transition(JsonlRuntimeState.RUNNING)
        except OSError as exc:
            self._state = JsonlRuntimeState.FAILED
            code = (JsonlRuntimeErrorCode.PORT_IN_USE if exc.errno == errno.EADDRINUSE
                    else JsonlRuntimeErrorCode.BIND_FAILED)
            self._error = code.value
            await self._cleanup_partial_start()
            raise JsonlRuntimeError(code) from None
        except Exception:
            self._state = JsonlRuntimeState.FAILED
            self._error = JsonlRuntimeErrorCode.INTERNAL_FAILURE.value
            await self._cleanup_partial_start()
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.INTERNAL_FAILURE) from None

    async def _cleanup_partial_start(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value
            try:
                await self._server.wait_closed()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value
            self._server = None
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except BaseException:
                pass
            self._worker = None

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._state is not JsonlRuntimeState.RUNNING or len(self._connections) >= self.config.max_connections:
            self._counts["connection_rejected"] += 1
            try:
                writer.close()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value
            self._schedule_writer_close(writer)
            return
        try:
            task = self._spawn_connection_task(reader, writer)
        except Exception:
            self._counts["connection_rejected"] += 1
            self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
            try:
                writer.close()
            except Exception:
                pass
            self._schedule_writer_close(writer)
            return
        self._connections[task] = writer
        task.add_done_callback(self._connection_done)

    async def _close_writer(self, writer: asyncio.StreamWriter) -> None:
        try:
            await writer.wait_closed()
        except Exception:
            pass

    def _schedule_writer_close(self, writer: asyncio.StreamWriter) -> None:
        try:
            task = asyncio.create_task(self._close_writer(writer))
            self._closing.add(task)
            task.add_done_callback(self._closing.discard)
        except Exception:
            try:
                writer.transport.abort()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value

    def _connection_done(self, task: asyncio.Task) -> None:
        self._connections.pop(task, None)
        if not task.cancelled():
            try:
                if task.exception() is not None:
                    self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
            except Exception:
                self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)

    def _fail(self, code: JsonlRuntimeErrorCode) -> None:
        if self._state in {JsonlRuntimeState.RUNNING, JsonlRuntimeState.DEGRADED}:
            self._state = JsonlRuntimeState.FAILED
            self._error = code.value
            if self._server is not None:
                self._server.close()

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter) -> None:
        decoder: JsonLinesDecoder | None = None
        loop = asyncio.get_running_loop()
        last_activity = loop.time()
        closed = False
        try:
            decoder = self._new_decoder()
            while self._state is JsonlRuntimeState.RUNNING:
                remaining = self.config.idle_timeout_seconds - (loop.time() - last_activity)
                if remaining <= 0:
                    self._counts["terminal_failures"] += 1
                    self._error = JsonlRuntimeErrorCode.IDLE_TIMEOUT.value
                    return
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(self.config.read_chunk_bytes),
                        timeout=min(self.config.read_timeout_seconds, remaining),
                    )
                except asyncio.TimeoutError:
                    self._counts["terminal_failures"] += 1
                    self._error = (JsonlRuntimeErrorCode.IDLE_TIMEOUT.value
                                   if loop.time() - last_activity >= self.config.idle_timeout_seconds
                                   else JsonlRuntimeErrorCode.READ_TIMEOUT.value)
                    return
                if not chunk:
                    result = decoder.close()
                    closed = True
                    if result.error_category is not None:
                        self._counts["malformed"] += 1
                    return
                last_activity = loop.time()
                # A delimiter marks a received record even when JSON validation rejects it.
                self._counts["received"] += chunk.count(b"\n")
                result = decoder.feed(chunk)
                records = result.records
                if records:
                    self._counts["validated"] += len(records)
                for index, envelope in enumerate(records):
                    try:
                        self._queue.enqueue(envelope)
                    except JsonlAdapterError as exc:
                        self._counts["queue_rejected"] += len(records) - index
                        if exc.code is AdapterErrorCode.QUEUE_FULL:
                            self._error = JsonlRuntimeErrorCode.QUEUE_FULL.value
                            if self._state is JsonlRuntimeState.RUNNING:
                                self._state = JsonlRuntimeState.DEGRADED
                                if self._server is not None:
                                    self._server.close()
                        else:
                            self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
                        return
                    self._counts["queue_accepted"] += 1
                    self._queue_event.set()
                    self._sync_peaks()
                    # Each connection yields after one admission to provide fairness.
                    await asyncio.sleep(0)
                if result.error_category is not None:
                    self._counts["malformed"] += 1
                    self._error = JsonlRuntimeErrorCode.DECODE_FAILED.value
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            self._counts["terminal_failures"] += 1
            self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
        finally:
            if decoder is not None and not closed:
                result = decoder.close()
                if result.error_category is not None and self._state not in {
                    JsonlRuntimeState.STOPPING, JsonlRuntimeState.STOPPED,
                }:
                    self._counts["malformed"] += 1
            try:
                writer.close()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value
            try:
                await writer.wait_closed()
            except Exception:
                self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value

    def _sync_peaks(self) -> None:
        snap = self._queue.snapshot()
        self._peak_queued_events = max(self._peak_queued_events, snap.queued_events)
        self._peak_queued_bytes = max(self._peak_queued_bytes, snap.queued_bytes)

    async def _consume(self) -> None:
        while not self._stopping:
            try:
                item = self._queue.dequeue()
            except Exception:
                self._fail(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
                return
            if item is None:
                self._queue_event.clear()
                if self._queue.snapshot().queued_events:
                    continue
                await self._queue_event.wait()
                continue
            try:
                self._process_item(item)
            except Exception:
                self._counts["processing_dropped"] += 1
                self._counts["terminal_failures"] += 1
                self._fail(JsonlRuntimeErrorCode.ANALYSIS_FAILED)
                return
            finally:
                item = None
            self._sync_peaks()

    def _process_item(self, item: Any) -> None:
        record = LiveTailRecord(item.source_role, item.receipt_id,
                                item.payload, item.payload_byte_count)
        batch = parse_live_records(self.config.source_role, (record,))
        self._counts["parser_recognized"] += batch.parsed_count
        self._counts["parser_unrecognized"] += batch.rejected_count + batch.ignored_count
        proposal = self._detection.prepare(batch)
        analysis_proposal = self._analysis.prepare(proposal)
        self._detection.prevalidate(proposal)
        self._detection.commit_prepared(proposal)
        self._analysis.commit(analysis_proposal)
        for outcome in batch.outcomes:
            if outcome.event is not None:
                outcome.event.raw = " " * len(outcome.event.raw.encode("utf-8", errors="strict"))
        self._counts["analysis_completed"] += 1
        self._last_success = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    async def wait_until_processed(self, count: int, timeout: float = 2.0) -> None:
        if type(count) is not int or count < 0:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.INTERNAL_FAILURE)
        async def wait() -> None:
            while self._counts["analysis_completed"] < count:
                if self._state is JsonlRuntimeState.DEGRADED:
                    raise JsonlRuntimeError(JsonlRuntimeErrorCode.QUEUE_FULL)
                if self._state is JsonlRuntimeState.FAILED:
                    try:
                        code = JsonlRuntimeErrorCode(self._error)
                    except ValueError:
                        code = JsonlRuntimeErrorCode.INTERNAL_FAILURE
                    raise JsonlRuntimeError(code)
                if self._state is JsonlRuntimeState.STOPPED:
                    raise JsonlRuntimeError(JsonlRuntimeErrorCode.STOPPED)
                await asyncio.sleep(0)
        try:
            await asyncio.wait_for(wait(), timeout)
        except asyncio.TimeoutError:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.READ_TIMEOUT) from None

    def internal_analysis_summary(self):
        return self._analysis.snapshot()

    def snapshot(self) -> JsonlRuntimeSnapshot:
        try:
            queue = self._queue.snapshot()
            history = self._detection.snapshot()
            return JsonlRuntimeSnapshot(
                "collector-jsonl-runtime-status/v1", self.config.source_role,
                "collector_jsonl_tcp", self._state, len(self._connections),
                self.config.max_connections, self._counts["received"], self._counts["validated"],
                self._counts["queue_accepted"], self._counts["queue_rejected"],
                self._counts["parser_recognized"], self._counts["parser_unrecognized"],
                self._counts["analysis_completed"], self._counts["processing_dropped"],
                self._counts["connection_rejected"], self._counts["malformed"],
                self._counts["terminal_failures"], queue.queued_events, queue.event_limit,
                queue.queued_bytes, queue.byte_limit, self._peak_queued_events,
                self._peak_queued_bytes, history.history_record_count,
                history.history_byte_count, self.config.history_records,
                self.config.history_bytes, self._last_success, self._error,
            )
        except Exception:
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.INTERNAL_FAILURE) from None

    async def stop(self) -> None:
        async with self._stop_lock:
            if self._state is JsonlRuntimeState.STOPPED:
                return
            if JsonlRuntimeState.STOPPING in _TRANSITIONS[self._state]:
                self._transition(JsonlRuntimeState.STOPPING)
            self._stopping = True
            failures = False
            if self._server is not None:
                try:
                    self._server.close()
                except Exception:
                    failures = True
                try:
                    await self._server.wait_closed()
                except Exception:
                    failures = True
                self._server = None
            tasks = tuple(self._connections)
            for task, writer in tuple(self._connections.items()):
                try:
                    writer.close()
                except Exception:
                    failures = True
                task.cancel()
            if tasks:
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True),
                                           self.config.shutdown_timeout_seconds)
                except Exception:
                    failures = True
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
            if self._worker is not None:
                self._worker.cancel()
                try:
                    await self._worker
                except asyncio.CancelledError:
                    pass
                except Exception:
                    failures = True
                self._worker = None
            try:
                self._counts["processing_dropped"] += self._queue.snapshot().queued_events
                self._queue.close()
            except Exception:
                failures = True
            for task in tuple(self._closing):
                try:
                    await task
                except Exception:
                    failures = True
            try:
                self._analysis.close()
            except Exception:
                failures = True
            try:
                self._detection.close()
            except Exception:
                failures = True
            if self._state is JsonlRuntimeState.STOPPING:
                self._transition(JsonlRuntimeState.STOPPED)
        if failures:
            self._error = JsonlRuntimeErrorCode.CLEANUP_FAILED.value
            raise JsonlRuntimeError(JsonlRuntimeErrorCode.CLEANUP_FAILED) from None
