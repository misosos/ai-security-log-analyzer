"""Deterministic, bounded, one-file tail core without background work."""

from collections import deque
from dataclasses import dataclass, field
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
_NEXT_OWNER_TOKEN = 0

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


def _allocate_owner_token() -> int:
    """Process-local deterministic owner discriminator; not a public session ID."""
    global _NEXT_OWNER_TOKEN
    _NEXT_OWNER_TOKEN = _bounded_increment(_NEXT_OWNER_TOKEN)
    return _NEXT_OWNER_TOKEN


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


@dataclass(frozen=True, slots=True)
class LiveRecordLease:
    lease_id: int
    source_role: str
    records: tuple[LiveTailRecord, ...] = field(repr=False)
    item_count: int
    byte_count: int
    attempt: int
    _owner_token: int = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.lease_id) is not int or not 1 <= self.lease_id <= MAX_COUNTER
            or self.source_role not in ("application", "ssh", "access")
            or type(self.records) is not tuple or not self.records
            or any(type(record) is not LiveTailRecord for record in self.records)
            or type(self.item_count) is not int or self.item_count != len(self.records)
            or not 1 <= self.item_count <= MAX_QUEUE_ITEMS
            or type(self.byte_count) is not int
            or self.byte_count != sum(record.byte_count for record in self.records)
            or not 0 <= self.byte_count <= MAX_QUEUE_BYTES
            or type(self.attempt) is not int or not 1 <= self.attempt <= MAX_COUNTER
            or type(self._owner_token) is not int or not 1 <= self._owner_token <= MAX_COUNTER
            or any(record.role != self.source_role for record in self.records)
            or any(left.sequence >= right.sequence for left, right in zip(self.records, self.records[1:]))
        ):
            raise LiveMonitorError("LEASE_INVARIANT_MISMATCH")


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

    def prefix(self, max_items: int, max_bytes: int) -> tuple[LiveTailRecord, ...]:
        selected = []
        byte_count = 0
        for record in self._items:
            if len(selected) >= max_items:
                break
            if byte_count + record.byte_count > max_bytes:
                break
            selected.append(record)
            byte_count += record.byte_count
        return tuple(selected)

    def verify_prefix(self, records: tuple[LiveTailRecord, ...]) -> None:
        if len(records) > len(self._items):
            raise LiveMonitorError("LEASE_INVARIANT_MISMATCH")
        for queued, leased in zip(self._items, records):
            if (
                queued.role != leased.role
                or queued.sequence != leased.sequence
                or queued.byte_count != leased.byte_count
                or queued.payload != leased.payload
            ):
                raise LiveMonitorError("LEASE_INVARIANT_MISMATCH")

    def acknowledge_prefix(self, records: tuple[LiveTailRecord, ...]) -> None:
        self.verify_prefix(records)
        for _ in records:
            self._byte_count -= self._items.popleft().byte_count

    def clear(self) -> int:
        count = len(self._items)
        self._items.clear()
        self._byte_count = 0
        return count

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
    available_item_count: int
    available_byte_count: int
    leased_item_count: int
    leased_byte_count: int
    active_lease: bool
    acknowledged_record_count: int
    released_lease_count: int
    abandoned_on_close_count: int
    max_attempt_count: int
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
            self.partial_buffer_byte_count, self.available_item_count,
            self.available_byte_count, self.leased_item_count,
            self.leased_byte_count, self.acknowledged_record_count,
            self.released_lease_count, self.abandoned_on_close_count,
            self.max_attempt_count,
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
            or type(self.active_lease) is not bool
            or self.queue_item_count != self.available_item_count + self.leased_item_count
            or self.queue_byte_count != self.available_byte_count + self.leased_byte_count
            or self.active_lease != (self.leased_item_count > 0)
            or self.processed_complete_line_count != (
                self.queue_item_count + self.acknowledged_record_count + self.abandoned_on_close_count
            )
            or (self.state == "STOPPED" and self.queue_item_count != 0)
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
        "_owner_token", "_next_lease_id", "_active_lease", "_attempts",
        "_acknowledged", "_released", "_abandoned", "_max_attempt",
        "_last_settled_id", "_last_settlement",
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
        self._owner_token = _allocate_owner_token()
        self._next_lease_id = 1
        self._active_lease: LiveRecordLease | None = None
        self._attempts: dict[int, int] = {}
        self._acknowledged = 0
        self._released = 0
        self._abandoned = 0
        self._max_attempt = 0
        self._last_settled_id = 0
        self._last_settlement: str | None = None
        self._transition("RUNNING")

    @property
    def source_role(self) -> str:
        return self._config.role

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

    def lease_records(self, max_records: int, max_bytes: int) -> LiveRecordLease | None:
        if self._state == "STOPPED":
            raise LiveMonitorError("OPERATION_AFTER_CLOSE")
        if self._state != "RUNNING":
            raise LiveMonitorError("INVALID_STATE_TRANSITION")
        if (
            type(max_records) is not int or not 1 <= max_records <= MAX_QUEUE_ITEMS
            or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_QUEUE_BYTES
        ):
            raise LiveMonitorError("INVALID_LEASE_LIMIT")
        if self._active_lease is not None:
            raise LiveMonitorError("ACTIVE_LEASE_EXISTS")
        if not self._queue.item_count:
            return None
        selected = self._queue.prefix(max_records, max_bytes)
        if not selected:
            raise LiveMonitorError("LEASE_LIMIT_TOO_SMALL")
        next_attempts = {
            record.sequence: _bounded_increment(self._attempts.get(record.sequence, 0))
            for record in selected
        }
        next_revision = _bounded_increment(self._revision)
        next_lease_id = _bounded_increment(self._next_lease_id)
        lease = LiveRecordLease(
            lease_id=self._next_lease_id, source_role=self.source_role,
            records=selected, item_count=len(selected),
            byte_count=sum(record.byte_count for record in selected),
            attempt=max(next_attempts.values()), _owner_token=self._owner_token,
        )
        self._attempts.update(next_attempts)
        self._max_attempt = max(self._max_attempt, lease.attempt)
        self._next_lease_id = next_lease_id
        self._active_lease = lease
        self._revision = next_revision
        return lease

    def _validate_lease(self, lease: LiveRecordLease, operation: str) -> LiveRecordLease:
        if self._state == "STOPPED":
            raise LiveMonitorError("OPERATION_AFTER_CLOSE")
        if type(lease) is not LiveRecordLease:
            raise LiveMonitorError("FORGED_LEASE")
        if lease._owner_token != self._owner_token:
            raise LiveMonitorError("FOREIGN_LEASE")
        active = self._active_lease
        if active is None:
            if lease.lease_id == self._last_settled_id:
                code = {
                    ("ACK", "ACK"): "ACK_AFTER_ACK",
                    ("ACK", "RELEASE"): "ACK_AFTER_RELEASE",
                    ("RELEASE", "ACK"): "RELEASE_AFTER_ACK",
                    ("RELEASE", "RELEASE"): "RELEASE_AFTER_RELEASE",
                }.get((operation, self._last_settlement), "STALE_LEASE")
                raise LiveMonitorError(code)
            raise LiveMonitorError("STALE_LEASE" if lease.lease_id < self._next_lease_id else "FORGED_LEASE")
        if lease.lease_id != active.lease_id:
            raise LiveMonitorError("STALE_LEASE" if lease.lease_id < active.lease_id else "FORGED_LEASE")
        if (
            lease.source_role != active.source_role
            or lease.item_count != active.item_count
            or lease.byte_count != active.byte_count
            or lease.attempt != active.attempt
            or len(lease.records) != len(active.records)
            or any(
                left.role != right.role or left.sequence != right.sequence
                or left.byte_count != right.byte_count or left.payload != right.payload
                for left, right in zip(lease.records, active.records)
            )
        ):
            raise LiveMonitorError("LEASE_INVARIANT_MISMATCH")
        return active

    def acknowledge_lease(self, lease: LiveRecordLease) -> None:
        active = self._validate_lease(lease, "ACK")
        next_acknowledged = self._acknowledged + active.item_count
        if next_acknowledged > MAX_COUNTER:
            raise LiveMonitorError("COUNTER_LIMIT")
        next_revision = _bounded_increment(self._revision)
        try:
            self._queue.acknowledge_prefix(active.records)
        except Exception:
            self._fail("INTERNAL_OWNERSHIP_FAILURE")
            raise LiveMonitorError("INTERNAL_OWNERSHIP_FAILURE") from None
        for record in active.records:
            self._attempts.pop(record.sequence, None)
        self._active_lease = None
        self._acknowledged = next_acknowledged
        self._last_settled_id = active.lease_id
        self._last_settlement = "ACK"
        self._revision = next_revision

    def release_lease(self, lease: LiveRecordLease) -> None:
        active = self._validate_lease(lease, "RELEASE")
        next_released = _bounded_increment(self._released)
        next_revision = _bounded_increment(self._revision)
        try:
            self._queue.verify_prefix(active.records)
        except Exception:
            self._fail("INTERNAL_OWNERSHIP_FAILURE")
            raise LiveMonitorError("INTERNAL_OWNERSHIP_FAILURE") from None
        self._active_lease = None
        self._released = next_released
        self._last_settled_id = active.lease_id
        self._last_settlement = "RELEASE"
        self._revision = next_revision

    def snapshot(self) -> LiveTailSnapshot:
        leased_items = self._active_lease.item_count if self._active_lease else 0
        leased_bytes = self._active_lease.byte_count if self._active_lease else 0
        return LiveTailSnapshot(
            schema_version="1", source_role=self._config.role, state=self._state,
            revision=self._revision, processed_complete_line_count=self._processed,
            rejected_line_count=self._rejected, queue_item_count=self._queue.item_count,
            queue_byte_count=self._queue.byte_count, overflow_count=self._overflow,
            available_item_count=self._queue.item_count - leased_items,
            available_byte_count=self._queue.byte_count - leased_bytes,
            leased_item_count=leased_items, leased_byte_count=leased_bytes,
            active_lease=self._active_lease is not None,
            acknowledged_record_count=self._acknowledged,
            released_lease_count=self._released,
            abandoned_on_close_count=self._abandoned,
            max_attempt_count=self._max_attempt,
            partial_buffer_byte_count=len(self._partial), warning_codes=self._warnings,
            error_code=self._error_code, start_policy=self._config.start_policy,
        )

    def close(self) -> None:
        if self._state == "STOPPED":
            return
        if self._state in ("STARTING", "RUNNING", "DEGRADED", "FAILED"):
            self._transition("STOPPING")
        self._close_descriptor()
        invalid_ownership = False
        if self._active_lease is not None:
            try:
                self._queue.verify_prefix(self._active_lease.records)
            except Exception:
                invalid_ownership = True
        abandoned = self._queue.item_count
        if self._abandoned + abandoned > MAX_COUNTER:
            raise LiveMonitorError("COUNTER_LIMIT")
        self._abandoned += self._queue.clear()
        self._attempts.clear()
        self._active_lease = None
        self._partial = b""
        self._pending_chunk = b""
        if invalid_ownership:
            self._error_code = "CLOSE_INVALID_OWNERSHIP"
            self._warnings = ("CLOSE_INVALID_OWNERSHIP",)
        self._transition("STOPPED")
        if invalid_ownership:
            raise LiveMonitorError("CLOSE_INVALID_OWNERSHIP")


def open_live_tail_session(config: LiveMonitorConfig) -> LiveTailSession:
    if type(config) is not LiveMonitorConfig:
        raise LiveMonitorError("INVALID_CONFIG")
    descriptor, metadata = _open_regular(config.path)
    try:
        return LiveTailSession(config, descriptor, metadata)
    except Exception:
        os.close(descriptor)
        raise LiveMonitorError("INTERNAL_FAILURE") from None
