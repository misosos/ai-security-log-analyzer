"""Synthetic-only loopback TCP Syslog runtime; deliberately not wired to API/UI."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import uuid

from app.analyzer.risk import load_account_metadata
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records
from app.log_collection.framing import OctetCountingDecoder
from app.log_collection.models import (
    CollectionCoreError, CollectionErrorCode, TcpCollectionConfig,
)
from app.log_collection.queue import BoundedEventQueue


class TcpRuntimeErrorCode(str, Enum):
    INVALID_CONFIG = "INVALID_CONFIG"
    BIND_FAILED = "BIND_FAILED"
    PORT_IN_USE = "PORT_IN_USE"
    CONNECTION_LIMIT = "CONNECTION_LIMIT"
    READ_TIMEOUT = "READ_TIMEOUT"
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    FRAME_REJECTED = "FRAME_REJECTED"
    QUEUE_OVERLOAD = "QUEUE_OVERLOAD"
    PARSER_REJECTED = "PARSER_REJECTED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    PUBLICATION_FAILED = "PUBLICATION_FAILED"
    SHUTDOWN_FAILED = "SHUTDOWN_FAILED"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class TcpRuntimeError(Exception):
    def __init__(self, code: TcpRuntimeErrorCode):
        self.code = code if isinstance(code, TcpRuntimeErrorCode) else TcpRuntimeErrorCode.INTERNAL_FAILURE
        super().__init__(self.code.value)

    def __repr__(self) -> str:
        return f"TcpRuntimeError({self.code.value})"


class TcpRuntimeState(str, Enum):
    STARTING = "STARTING"
    LISTENING = "LISTENING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


_RUNTIME_TRANSITIONS = {
    TcpRuntimeState.STARTING: {TcpRuntimeState.LISTENING, TcpRuntimeState.FAILED,
                               TcpRuntimeState.STOPPING},
    TcpRuntimeState.LISTENING: {TcpRuntimeState.DEGRADED, TcpRuntimeState.FAILED,
                                TcpRuntimeState.STOPPING},
    TcpRuntimeState.DEGRADED: {TcpRuntimeState.FAILED, TcpRuntimeState.STOPPING},
    TcpRuntimeState.FAILED: {TcpRuntimeState.STOPPING},
    TcpRuntimeState.STOPPING: {TcpRuntimeState.STOPPED},
    TcpRuntimeState.STOPPED: {TcpRuntimeState.STOPPED},
}


@dataclass(frozen=True, slots=True, repr=False)
class TcpRuntimeConfig:
    schema_version: str
    source_role: str
    bind_family: str
    port: int
    connection_limit: int
    idle_timeout_seconds: float
    read_timeout_seconds: float
    parser_timezone: str
    startup_mode: str
    test_only_ephemeral_port: bool = False
    max_prefix_digits: int = 6
    max_frame_bytes: int = 8192
    max_connection_buffer_bytes: int = 8199
    max_queue_events: int = 256
    max_queue_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        strings = (self.schema_version, self.source_role, self.bind_family,
                   self.parser_timezone, self.startup_mode)
        if (any(type(v) is not str for v in strings)
                or self.schema_version != "tcp-syslog-runtime/v1"
                or self.source_role not in {"application", "ssh"}
                or self.bind_family not in {"ipv4", "ipv6"}
                or self.parser_timezone != "Asia/Seoul"
                or self.startup_mode != "synthetic_pilot"
                or type(self.test_only_ephemeral_port) is not bool
                or type(self.port) is not int
                or not ((self.port == 0 and self.test_only_ephemeral_port)
                        or 1024 <= self.port <= 65535)
                or type(self.connection_limit) is not int or not 1 <= self.connection_limit <= 2
                or type(self.idle_timeout_seconds) not in (int, float)
                or not 0.05 <= self.idle_timeout_seconds <= 300
                or type(self.read_timeout_seconds) not in (int, float)
                or not 0.01 <= self.read_timeout_seconds <= 30
                or type(self.max_queue_bytes) is not int
                or type(self.max_frame_bytes) is not int
                or self.max_queue_bytes < self.max_frame_bytes):
            raise TcpRuntimeError(TcpRuntimeErrorCode.INVALID_CONFIG)
        try:
            self.core_config()
        except Exception:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INVALID_CONFIG) from None

    def core_config(self) -> TcpCollectionConfig:
        return TcpCollectionConfig(
            schema_version="tcp-syslog-config/v1", source_role=self.source_role,
            transport="tcp_syslog_octet_counting", bind_scope="loopback_only",
            max_connections=self.connection_limit, max_prefix_digits=self.max_prefix_digits,
            max_frame_bytes=self.max_frame_bytes,
            max_connection_buffer_bytes=self.max_connection_buffer_bytes,
            max_queue_events=self.max_queue_events, max_queue_bytes=self.max_queue_bytes,
            invalid_frame_action="close_connection", incomplete_frame_action="reject_on_close",
        )

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_mapping(cls, value: object) -> "TcpRuntimeConfig":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise TcpRuntimeError(TcpRuntimeErrorCode.INVALID_CONFIG)
        try:
            return cls(**value)
        except Exception:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INVALID_CONFIG) from None

    def __repr__(self) -> str:
        return f"TcpRuntimeConfig(source_role={self.source_role!r}, bind_family={self.bind_family!r})"


@dataclass(frozen=True, slots=True, repr=False)
class TcpRuntimeSnapshot:
    schema_version: str
    source_role: str
    transport: str
    state: TcpRuntimeState
    active_connections: int
    connection_limit: int
    accepted_frames: int
    rejected_frames: int
    dropped_frames: int
    parsed_events: int
    parser_rejected_events: int
    analyzed_events: int
    rejected_connections: int
    queued_events: int
    queue_event_limit: int
    peak_queued_events: int
    queued_bytes: int
    queue_byte_limit: int
    peak_queued_bytes: int
    started_at: str
    last_success_at: str
    error_category: str
    next_action: str

    def to_dict(self) -> dict[str, object]:
        return {name: (value.value if isinstance(value, Enum) else value)
                for name, value in ((n, getattr(self, n)) for n in self.__dataclass_fields__)}

    def __repr__(self) -> str:
        return (f"TcpRuntimeSnapshot(state={self.state.value}, accepted_frames={self.accepted_frames}, "
                f"queued_events={self.queued_events})")


class TcpSyslogRuntime:
    """One fixed-loopback role, ephemeral in-memory epoch, no public publication."""

    def __init__(self, config: TcpRuntimeConfig):
        if type(config) is not TcpRuntimeConfig:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INVALID_CONFIG)
        self.config = config
        self.epoch_id = uuid.uuid4().hex
        core = config.core_config()
        self._queue = BoundedEventQueue(core)
        self._detection = LiveDetectionAccumulator(config.source_role, 256, 256 * 1024)
        metadata = load_account_metadata()
        account_metadata = tuple(sorted((name, item["privilege"])
                                         for name, item in metadata.items()))
        self._analysis = LiveAnalysisAccumulator(self._detection, account_metadata)
        self._server: asyncio.AbstractServer | None = None
        self._connection_tasks: set[asyncio.Task] = set()
        self._connections: dict[asyncio.Task, asyncio.StreamWriter] = {}
        self._closing_tasks: set[asyncio.Task] = set()
        self._processor_task: asyncio.Task | None = None
        self._queue_event = asyncio.Event()
        self._state = TcpRuntimeState.STARTING
        self._error = "NONE"
        self._accepted = self._rejected = self._parsed = self._parser_rejected = 0
        self._analyzed = self._settled = self._rejected_connections = 0
        self._dropped_after_dequeue = 0
        self._peak_queued_events = self._peak_queued_bytes = 0
        self._started_at = "unavailable"
        self._last_success = "unavailable"
        self._stop_lock = asyncio.Lock()
        self._stopping = False
        self._publication = None

    def __repr__(self) -> str:
        return (f"TcpSyslogRuntime(source_role={self.config.source_role!r}, "
                f"state={self._state.value})")

    def _transition(self, state: TcpRuntimeState) -> None:
        if state not in _RUNTIME_TRANSITIONS[self._state]:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        self._state = state
        if state in {TcpRuntimeState.FAILED, TcpRuntimeState.DEGRADED} and self._error == "NONE":
            self._error = "INTERNAL_FAILURE"

    async def _create_server(self, host: str, port: int) -> asyncio.AbstractServer:
        return await asyncio.start_server(
            self._accept, host=host, port=port,
            limit=self.config.max_connection_buffer_bytes, backlog=self.config.connection_limit,
            reuse_address=True,
        )

    def _spawn_connection_task(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter) -> asyncio.Task:
        return asyncio.create_task(self._handle_connection(reader, writer))

    async def _read_chunk(self, reader: asyncio.StreamReader) -> bytes:
        return await reader.read(min(4096, self.config.max_connection_buffer_bytes))

    async def start(self) -> None:
        if self._state != TcpRuntimeState.STARTING:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        host = "127.0.0.1" if self.config.bind_family == "ipv4" else "::1"
        try:
            server = await self._create_server(host, self.config.port)
            self._server = server
            self._started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            self._transition(TcpRuntimeState.LISTENING)
            self._processor_task = asyncio.create_task(self._process_queue())
            self._processor_task.add_done_callback(self._processor_done)
        except OSError as exc:
            self._state = TcpRuntimeState.FAILED
            self._error = (TcpRuntimeErrorCode.PORT_IN_USE.value if exc.errno == errno.EADDRINUSE
                           else TcpRuntimeErrorCode.BIND_FAILED.value)
            if self._server is not None:
                self._server.close()
                try:
                    await self._server.wait_closed()
                finally:
                    self._server = None
            raise TcpRuntimeError(TcpRuntimeErrorCode(self._error)) from None
        except Exception:
            self._state = TcpRuntimeState.FAILED
            self._error = "INTERNAL_FAILURE"
            await self._cleanup_start_failure()
            raise TcpRuntimeError(TcpRuntimeErrorCode.INTERNAL_FAILURE) from None

    async def _cleanup_start_failure(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
                await self._server.wait_closed()
            except Exception:
                pass
            finally:
                self._server = None

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._state != TcpRuntimeState.LISTENING or len(self._connections) >= self.config.connection_limit:
            self._rejected_connections += 1
            try:
                writer.close()
            except Exception:
                self._error = TcpRuntimeErrorCode.SHUTDOWN_FAILED.value
            task = asyncio.create_task(self._wait_rejected_writer(writer))
            self._closing_tasks.add(task)
            task.add_done_callback(self._closing_tasks.discard)
            return
        try:
            task = self._spawn_connection_task(reader, writer)
        except Exception:
            self._rejected_connections += 1
            self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
            try:
                writer.close()
            except Exception:
                try:
                    writer.transport.abort()
                except Exception:
                    self._error = TcpRuntimeErrorCode.SHUTDOWN_FAILED.value
            return
        self._connections[task] = writer
        self._connection_tasks.add(task)
        task.add_done_callback(self._connection_done)

    def _connection_done(self, task: asyncio.Task) -> None:
        self._connection_tasks.discard(task)
        self._connections.pop(task, None)
        try:
            if task.exception() is not None:
                self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        except asyncio.CancelledError:
            pass

    def _processor_done(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        try:
            if task.exception() is not None and self._state == TcpRuntimeState.LISTENING:
                self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        except Exception:
            self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)

    @staticmethod
    async def _wait_rejected_writer(writer: asyncio.StreamWriter) -> None:
        try:
            await writer.wait_closed()
        except Exception:
            return

    def _fail(self, code: TcpRuntimeErrorCode) -> None:
        if self._state in {TcpRuntimeState.LISTENING, TcpRuntimeState.DEGRADED}:
            self._state = TcpRuntimeState.FAILED
            self._error = code.value
            if self._server is not None:
                self._server.close()

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        decoder = OctetCountingDecoder(self.config.core_config())
        loop = asyncio.get_running_loop()
        last_complete = loop.time()
        decoder_closed = False
        try:
            while self._state == TcpRuntimeState.LISTENING:
                remaining = self.config.idle_timeout_seconds - (loop.time() - last_complete)
                if remaining <= 0:
                    incomplete = decoder.close()
                    decoder_closed = True
                    if incomplete.error_category is not None:
                        self._rejected += 1
                    self._error = TcpRuntimeErrorCode.IDLE_TIMEOUT.value
                    return
                try:
                    chunk = await asyncio.wait_for(self._read_chunk(reader),
                                                   timeout=min(self.config.read_timeout_seconds, remaining))
                except asyncio.TimeoutError:
                    incomplete = decoder.close()
                    decoder_closed = True
                    if incomplete.error_category is not None:
                        self._rejected += 1
                    if loop.time() - last_complete >= self.config.idle_timeout_seconds:
                        self._error = TcpRuntimeErrorCode.IDLE_TIMEOUT.value
                    else:
                        self._error = TcpRuntimeErrorCode.READ_TIMEOUT.value
                    return
                if not chunk:
                    result = decoder.close()
                    decoder_closed = True
                    if result.error_category is not None:
                        self._rejected += 1
                        self._error = TcpRuntimeErrorCode.FRAME_REJECTED.value
                    return
                result = decoder.feed(chunk)
                for frame_index, frame in enumerate(result.frames):
                    last_complete = loop.time()
                    try:
                        self._queue.enqueue(frame)
                    except CollectionCoreError as exc:
                        self._rejected += len(result.frames) - frame_index
                        if exc.code == CollectionErrorCode.QUEUE_FULL:
                            self._error = TcpRuntimeErrorCode.QUEUE_OVERLOAD.value
                            if self._state == TcpRuntimeState.LISTENING:
                                self._state = TcpRuntimeState.DEGRADED
                                if self._server is not None:
                                    self._server.close()
                        else:
                            self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
                        return
                    self._accepted += 1
                    self._queue_event.set()
                    self._sync_queue_status()
                frame_error = result.error_category
                frame = None
                result = None
                if frame_error is not None:
                    self._rejected += 1
                    self._error = TcpRuntimeErrorCode.FRAME_REJECTED.value
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            self._rejected += 1
            self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        finally:
            close_result = decoder.close() if not decoder_closed else None
            if close_result is not None and close_result.error_category is not None and self._state not in {
                TcpRuntimeState.STOPPING, TcpRuntimeState.STOPPED,
            }:
                self._rejected += 1
                self._error = TcpRuntimeErrorCode.FRAME_REJECTED.value
            try:
                writer.close()
            except Exception:
                self._error = TcpRuntimeErrorCode.SHUTDOWN_FAILED.value
            try:
                await writer.wait_closed()
            except Exception:
                self._error = TcpRuntimeErrorCode.SHUTDOWN_FAILED.value

    def _sync_queue_status(self) -> None:
        # Snapshot validation ensures the double-bound queue remains inside contract.
        snap = self._queue.snapshot()
        self._peak_queued_events = max(self._peak_queued_events, snap.queued_events)
        self._peak_queued_bytes = max(self._peak_queued_bytes, snap.queued_bytes)

    async def _process_queue(self) -> None:
        while not self._stopping:
            try:
                item = self._queue.dequeue()
            except Exception:
                self._fail(TcpRuntimeErrorCode.INTERNAL_FAILURE)
                return
            if item is None:
                self._queue_event.clear()
                if self._queue.snapshot().queued_events:
                    continue
                await self._queue_event.wait()
                continue
            self._sync_queue_status()
            try:
                record = LiveTailRecord(item.source_role, item.receipt_id, item.payload,
                                        item.payload_byte_count)
                parsed = parse_live_records(self.config.source_role, (record,))
                self._parsed += parsed.parsed_count
                self._parser_rejected += parsed.rejected_count
                detection_proposal = self._detection.prepare(parsed)
                analysis_proposal = self._analysis.prepare(detection_proposal)
                self._detection.prevalidate(detection_proposal)
                self._detection.commit_prepared(detection_proposal)
                self._analysis.commit(analysis_proposal)
                # Keep the accumulator's byte accounting while replacing source text.
                # The underlying detector/correlation/risk logic does not read raw.
                for outcome in parsed.outcomes:
                    if outcome.event is not None and outcome.event.raw:
                        outcome.event.raw = " " * len(outcome.event.raw.encode("utf-8", errors="strict"))
                self._analyzed += 1
                self._settled += 1
                self._last_success = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except Exception:
                self._dropped_after_dequeue += 1
                self._error = TcpRuntimeErrorCode.ANALYSIS_FAILED.value
                self._fail(TcpRuntimeErrorCode.ANALYSIS_FAILED)
                return
            finally:
                item = None
                record = None
                parsed = None
                detection_proposal = None
                analysis_proposal = None
            self._sync_queue_status()

    async def wait_until_processed(self, count: int, timeout: float = 2.0) -> None:
        if type(count) is not int or count < 0:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INTERNAL_FAILURE)
        async def poll() -> None:
            while self._settled < count:
                if self._state in {TcpRuntimeState.FAILED, TcpRuntimeState.STOPPED}:
                    return
                await asyncio.sleep(0.005)
        try:
            await asyncio.wait_for(poll(), timeout)
        except asyncio.TimeoutError:
            raise TcpRuntimeError(TcpRuntimeErrorCode.READ_TIMEOUT) from None

    def internal_analysis_summary(self):
        return self._analysis.snapshot()

    def snapshot(self) -> TcpRuntimeSnapshot:
        try:
            queue = self._queue.snapshot()
            return TcpRuntimeSnapshot(
                "tcp-syslog-runtime-status/v1", self.config.source_role,
                "tcp_syslog_octet_counting", self._state, len(self._connections),
                self.config.connection_limit, self._accepted, self._rejected,
                queue.dropped_count + self._dropped_after_dequeue,
                self._parsed, self._parser_rejected, self._analyzed,
                self._rejected_connections, queue.queued_events, queue.event_limit,
                self._peak_queued_events, queue.queued_bytes, queue.byte_limit,
                self._peak_queued_bytes, self._started_at, self._last_success,
                self._error, "STOP_RUNTIME" if self._state in {
                    TcpRuntimeState.FAILED, TcpRuntimeState.DEGRADED,
                } else ("INSPECT_STATUS" if self._error != "NONE" else "NONE"),
            )
        except Exception:
            raise TcpRuntimeError(TcpRuntimeErrorCode.INTERNAL_FAILURE) from None

    async def stop(self) -> None:
        async with self._stop_lock:
            if self._state == TcpRuntimeState.STOPPED:
                return
            if self._state != TcpRuntimeState.STOPPING:
                if TcpRuntimeState.STOPPING in _RUNTIME_TRANSITIONS[self._state]:
                    self._transition(TcpRuntimeState.STOPPING)
                else:
                    self._state = TcpRuntimeState.STOPPING
            self._stopping = True
            errors = False
            server, self._server = self._server, None
            if server is not None:
                try:
                    server.close()
                except Exception:
                    errors = True
            tasks = tuple(self._connection_tasks)
            for task in tasks:
                try:
                    task.cancel()
                except Exception:
                    errors = True
            writers = tuple(self._connections.values())
            for writer in writers:
                try:
                    writer.close()
                except Exception:
                    errors = True
                    try:
                        writer.transport.abort()
                    except Exception:
                        errors = True
            if self._processor_task is not None:
                try:
                    self._processor_task.cancel()
                except Exception:
                    errors = True
            try:
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                errors = True
            closing_tasks = tuple(self._closing_tasks)
            try:
                if closing_tasks:
                    await asyncio.gather(*closing_tasks, return_exceptions=True)
            except Exception:
                errors = True
            for writer in writers:
                try:
                    await writer.wait_closed()
                except asyncio.CancelledError:
                    current = asyncio.current_task()
                    if current is not None and current.cancelling():
                        raise
                    if not writer.is_closing():
                        errors = True
                except Exception:
                    errors = True
            if self._processor_task is not None:
                try:
                    await asyncio.gather(self._processor_task, return_exceptions=True)
                except Exception:
                    errors = True
            try:
                if server is not None:
                    await server.wait_closed()
            except Exception:
                errors = True
            try:
                self._queue.close()
            except Exception:
                errors = True
            try:
                self._sync_queue_status()
            except Exception:
                errors = True
            for close in (self._analysis.close, self._detection.close):
                try:
                    close()
                except Exception:
                    errors = True
            self._connections.clear()
            self._connection_tasks.clear()
            self._closing_tasks.clear()
            self._processor_task = None
            self._state = TcpRuntimeState.STOPPED
            if errors:
                self._error = TcpRuntimeErrorCode.SHUTDOWN_FAILED.value
