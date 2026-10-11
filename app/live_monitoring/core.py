"""Deterministic, bounded, one-file tail core without background work."""

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path

from app.live_monitoring.config import (
    LiveMonitorConfig,
    LiveMonitorError,
    _MESSAGES,
    _open_regular,
)


MAX_CHUNK_BYTES = 1024
MAX_POLL_BYTES = 4096
MAX_RECORDS_PER_POLL = 16
MAX_LINE_BYTES = 2048
MAX_PARTIAL_BYTES = 2048
MAX_QUEUE_ITEMS = 32
MAX_QUEUE_BYTES = 16 * 1024
MAX_COUNTER = (1 << 63) - 1

_TRANSITIONS = {
    "STARTING": frozenset(("RUNNING", "FAILED", "STOPPING")),
    "RUNNING": frozenset(("DEGRADED", "FAILED", "STOPPING")),
    "DEGRADED": frozenset(("FAILED", "STOPPING")),
    "FAILED": frozenset(("STOPPING",)),
    "STOPPING": frozenset(("STOPPED",)),
    "STOPPED": frozenset(),
}


def _bounded_increment(value: int) -> int:
    if type(value) is not int or not 0 <= value < MAX_COUNTER:
        raise LiveMonitorError("COUNTER_LIMIT")
    return value + 1


class LiveTailRecord:
    """Trusted parser input: payload is intentionally absent from repr/str."""

    __slots__ = ("role", "sequence", "byte_count", "_payload")

    def __init__(self, role: str, sequence: int, payload: str, byte_count: int):
        if (
            type(role) is not str
            or role not in ("application", "ssh", "access")
            or type(sequence) is not int
            or not 1 <= sequence <= MAX_COUNTER
            or type(payload) is not str
            or type(byte_count) is not int
            or not 0 <= byte_count <= MAX_LINE_BYTES
        ):
            raise LiveMonitorError("INTERNAL_FAILURE")
        try:
            encoded_size = len(payload.encode("utf-8"))
        except UnicodeError:
            raise LiveMonitorError("INTERNAL_FAILURE") from None
        if encoded_size != byte_count:
            raise LiveMonitorError("INTERNAL_FAILURE")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "byte_count", byte_count)
        object.__setattr__(self, "_payload", payload)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise LiveMonitorError("INTERNAL_FAILURE")

    @property
    def payload(self) -> str:
        """Explicit trusted access; never pass the whole record to public serializers."""
        return self._payload

    def __repr__(self) -> str:
        return (
            "LiveTailRecord("
            f"role={self.role!r}, sequence={self.sequence}, byte_count={self.byte_count}, "
            "payload=<private>)"
        )

    __str__ = __repr__


class _BoundedRecordQueue:
    __slots__ = ("_items", "_byte_count")

    def __init__(self) -> None:
        self._items: deque[LiveTailRecord] = deque()
        self._byte_count = 0

    @property
    def item_count(self) -> int:
        return len(self._items)

    @property
    def byte_count(self) -> int:
        return self._byte_count

    def put(self, record: LiveTailRecord) -> None:
        if type(record) is not LiveTailRecord:
            raise LiveMonitorError("INTERNAL_FAILURE")
        if (
            len(self._items) >= MAX_QUEUE_ITEMS
            or self._byte_count + record.byte_count > MAX_QUEUE_BYTES
        ):
            raise LiveMonitorError("QUEUE_OVERFLOW")
        self._items.append(record)
        self._byte_count += record.byte_count

    def take(self, max_items: int) -> tuple[LiveTailRecord, ...]:
        if type(max_items) is not int or not 1 <= max_items <= MAX_QUEUE_ITEMS:
            raise LiveMonitorError("INVALID_CONFIG")
        taken = []
        for _ in range(min(max_items, len(self._items))):
            record = self._items.popleft()
            self._byte_count -= record.byte_count
            taken.append(record)
        return tuple(taken)

    def __repr__(self) -> str:
        return f"BoundedRecordQueue(item_count={self.item_count}, byte_count={self.byte_count})"


@dataclass(frozen=True, slots=True)
class LiveTailSnapshot:
    schema_version: str
    source_role: str
    state: str
    revision: int
    processed_complete_line_count: int
    rejected_line_count: int
    queue_item_count: int
    queue_byte_count: int
    overflow_count: int
    partial_buffer_byte_count: int
    warning_codes: tuple[str, ...]
    error_code: str | None
    start_policy: str

    def __post_init__(self) -> None:
        counts = (
            self.revision, self.processed_complete_line_count,
            self.rejected_line_count, self.queue_item_count,
            self.queue_byte_count, self.overflow_count,
            self.partial_buffer_byte_count,
        )
        if (
            self.schema_version != "1"
            or self.source_role not in ("application", "ssh", "access")
            or self.state not in _TRANSITIONS
            or self.start_policy != "FROM_END"
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.queue_item_count > MAX_QUEUE_ITEMS
            or self.queue_byte_count > MAX_QUEUE_BYTES
            or self.partial_buffer_byte_count > MAX_PARTIAL_BYTES
            or self.queue_item_count > self.processed_complete_line_count
            or type(self.warning_codes) is not tuple
            or any(type(code) is not str or code not in _MESSAGES for code in self.warning_codes)
            or (self.error_code is not None and self.error_code not in _MESSAGES)
        ):
            raise LiveMonitorError("INTERNAL_FAILURE")


class LiveTailSession:
    """One explicit poll at a time; no detector, clock, thread or persistence."""

    __slots__ = (
        "_config", "_fd", "_identity", "_offset", "_partial", "_pending_chunk",
        "_queue", "_state", "_revision", "_processed", "_rejected",
        "_overflow", "_warnings", "_error_code", "_next_sequence",
    )

    def __init__(self, config: LiveMonitorConfig, descriptor: int, metadata: os.stat_result):
        self._config = config
        self._fd = descriptor
        self._identity = (metadata.st_dev, metadata.st_ino)
        self._offset = os.lseek(descriptor, 0, os.SEEK_END)
        self._partial = b""
        self._pending_chunk = b""
        self._queue = _BoundedRecordQueue()
        self._state = "STARTING"
        self._revision = 0
        self._processed = 0
        self._rejected = 0
        self._overflow = 0
        self._warnings: tuple[str, ...] = ()
        self._error_code: str | None = None
        self._next_sequence = 1
        self._transition("RUNNING")

    def __repr__(self) -> str:
        return (
            "LiveTailSession("
            f"source_role={self._config.role!r}, state={self._state!r}, "
            f"revision={self._revision})"
        )

    def _transition(self, next_state: str) -> None:
        if next_state not in _TRANSITIONS[self._state]:
            raise LiveMonitorError("INVALID_STATE_TRANSITION")
        next_revision = _bounded_increment(self._revision)
        self._state = next_state
        self._revision = next_revision

    def _close_descriptor(self) -> None:
        if self._fd >= 0:
            descriptor = self._fd
            self._fd = -1
            os.close(descriptor)

    def _fail(self, code: str) -> None:
        if self._state == "RUNNING":
            self._transition("DEGRADED")
        if self._state in ("STARTING", "DEGRADED"):
            self._transition("FAILED")
        self._error_code = code
        self._warnings = (code,)
        if code == "QUEUE_OVERFLOW":
            self._overflow = _bounded_increment(self._overflow)
        self._revision = _bounded_increment(self._revision)
        self._close_descriptor()

    def _probe_identity(self) -> None:
        descriptor, metadata = _open_regular(self._config.path)
        os.close(descriptor)
        if (metadata.st_dev, metadata.st_ino) != self._identity:
            raise LiveMonitorError("SOURCE_REPLACED")
        if os.fstat(self._fd).st_size < self._offset:
            raise LiveMonitorError("SOURCE_TRUNCATED")

    def _append_partial(self, segment: bytes) -> None:
        if len(self._partial) + len(segment) > MAX_PARTIAL_BYTES:
            raise LiveMonitorError("PARTIAL_BUFFER_EXCEEDED")
        self._partial += segment

    def _accept_line(self, line: bytes) -> None:
        if len(line) > MAX_LINE_BYTES:
            raise LiveMonitorError("LINE_TOO_LONG")
        if b"\x00" in line or any(
            byte < 32 and byte not in (9, 13) or byte == 127 for byte in line
        ):
            raise LiveMonitorError("BINARY_INPUT")
        if b"\r" in line[:-1]:
            raise LiveMonitorError("BINARY_INPUT")
        if line.endswith(b"\r"):
            line = line[:-1]
        try:
            payload = line.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise LiveMonitorError("INVALID_UTF8") from None
        record = LiveTailRecord(
            self._config.role, self._next_sequence, payload, len(line),
        )
        next_sequence = _bounded_increment(self._next_sequence)
        next_processed = _bounded_increment(self._processed)
        next_revision = _bounded_increment(self._revision)
        self._queue.put(record)
        self._next_sequence = next_sequence
        self._processed = next_processed
        self._revision = next_revision

    def _frame(self, data: bytes, remaining_records: int) -> int:
        accepted = 0
        while data and accepted < remaining_records:
            newline = data.find(b"\n")
            if newline < 0:
                self._append_partial(data)
                data = b""
                break
            if len(self._partial) + newline > MAX_LINE_BYTES:
                raise LiveMonitorError("LINE_TOO_LONG")
            self._append_partial(data[:newline])
            line = self._partial
            self._partial = b""
            self._accept_line(line)
            accepted += 1
            data = data[newline + 1:]
        if data:
            self._pending_chunk = data
        return accepted

    def poll_once(self) -> int:
        if self._state == "STOPPED":
            raise LiveMonitorError("POLL_AFTER_CLOSE")
        if self._state != "RUNNING":
            raise LiveMonitorError("INVALID_STATE_TRANSITION")
        try:
            self._probe_identity()
            read_budget = MAX_POLL_BYTES
            record_budget = MAX_RECORDS_PER_POLL
            accepted = 0
            while record_budget:
                if self._pending_chunk:
                    data = self._pending_chunk
                    self._pending_chunk = b""
                elif read_budget:
                    data = os.read(self._fd, min(MAX_CHUNK_BYTES, read_budget))
                    self._offset += len(data)
                    read_budget -= len(data)
                    if not data:
                        break
                else:
                    break
                count = self._frame(data, record_budget)
                accepted += count
                record_budget -= count
            self._probe_identity()
            return accepted
        except LiveMonitorError as error:
            if error.code not in ("SOURCE_REPLACED", "SOURCE_TRUNCATED", "SOURCE_UNAVAILABLE", "SYMLINK_REJECTED", "PERMISSION_DENIED"):
                self._rejected = _bounded_increment(self._rejected)
            self._fail(error.code)
            raise LiveMonitorError(error.code) from None
        except OSError:
            self._fail("SOURCE_UNAVAILABLE")
            raise LiveMonitorError("SOURCE_UNAVAILABLE") from None
        except Exception:
            self._fail("INTERNAL_FAILURE")
            raise LiveMonitorError("INTERNAL_FAILURE") from None

    def take_records(self, max_items: int = MAX_QUEUE_ITEMS) -> tuple[LiveTailRecord, ...]:
        next_revision = _bounded_increment(self._revision) if self._queue.item_count else self._revision
        taken = self._queue.take(max_items)
        if taken:
            self._revision = next_revision
        return taken

    def snapshot(self) -> LiveTailSnapshot:
        return LiveTailSnapshot(
            schema_version="1", source_role=self._config.role, state=self._state,
            revision=self._revision, processed_complete_line_count=self._processed,
            rejected_line_count=self._rejected, queue_item_count=self._queue.item_count,
            queue_byte_count=self._queue.byte_count, overflow_count=self._overflow,
            partial_buffer_byte_count=len(self._partial), warning_codes=self._warnings,
            error_code=self._error_code, start_policy=self._config.start_policy,
        )

    def close(self) -> None:
        if self._state == "STOPPED":
            return
        if self._state in ("STARTING", "RUNNING", "DEGRADED", "FAILED"):
            self._transition("STOPPING")
        self._close_descriptor()
        self._partial = b""
        self._pending_chunk = b""
        self._transition("STOPPED")


def open_live_tail_session(config: LiveMonitorConfig) -> LiveTailSession:
    if type(config) is not LiveMonitorConfig:
        raise LiveMonitorError("INVALID_CONFIG")
    descriptor, metadata = _open_regular(config.path)
    try:
        return LiveTailSession(config, descriptor, metadata)
    except Exception:
        os.close(descriptor)
        raise LiveMonitorError("INTERNAL_FAILURE") from None
