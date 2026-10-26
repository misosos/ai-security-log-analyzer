"""Bounded, network-independent JSON Lines envelope decoder for external collectors."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import json
import math
import re
from typing import Any


class AdapterErrorCode(str, Enum):
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_JSON = "INVALID_JSON"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    ROLE_MISMATCH = "ROLE_MISMATCH"
    FORBIDDEN_CONTROL = "FORBIDDEN_CONTROL"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RECORD_TOO_LARGE = "RECORD_TOO_LARGE"
    INCOMPLETE_RECORD = "INCOMPLETE_RECORD"
    DECODER_CLOSED = "DECODER_CLOSED"
    FEED_EVENT_LIMIT = "FEED_EVENT_LIMIT"
    QUEUE_FULL = "QUEUE_FULL"
    QUEUE_CLOSED = "QUEUE_CLOSED"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"


class AdapterState(str, Enum):
    STARTING = "STARTING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class JsonlAdapterError(ValueError):
    """Error carrying a fixed code and no caller-provided data."""

    def __init__(self, code: AdapterErrorCode):
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        return f"JsonlAdapterError({self.code.value})"


_FIELDS = frozenset({
    "schema_version", "source_role", "payload", "collector_instance_alias",
    "sequence_hint", "retry_hint",
})
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_SEQUENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z", re.ASCII)
_MAX_RECORD_BYTES = 65_536
_MAX_PAYLOAD_BYTES = 8_192
_MAX_QUEUE_EVENTS = 256
_MAX_QUEUE_BYTES = 1_048_576
_MAX_RECORDS_PER_FEED = 32


@dataclass(frozen=True, slots=True, repr=False)
class JsonlAdapterConfig:
    source_role: str
    max_record_bytes: int = _MAX_RECORD_BYTES
    max_payload_bytes: int = _MAX_PAYLOAD_BYTES
    max_connection_buffer_bytes: int = _MAX_RECORD_BYTES
    max_queue_events: int = _MAX_QUEUE_EVENTS
    max_queue_bytes: int = _MAX_QUEUE_BYTES

    def __post_init__(self) -> None:
        if type(self.source_role) is not str or self.source_role not in {"application", "ssh"}:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        bounds = {
            "max_record_bytes": (128, _MAX_RECORD_BYTES),
            "max_payload_bytes": (1, _MAX_PAYLOAD_BYTES),
            "max_connection_buffer_bytes": (128, _MAX_RECORD_BYTES),
            "max_queue_events": (1, _MAX_QUEUE_EVENTS),
            "max_queue_bytes": (1, _MAX_QUEUE_BYTES),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        if (self.max_connection_buffer_bytes < self.max_record_bytes
                or self.max_record_bytes < self.max_payload_bytes + 128):
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)

    def __repr__(self) -> str:
        return (f"JsonlAdapterConfig(source_role={self.source_role!r}, "
                f"max_record_bytes={self.max_record_bytes}, "
                f"max_payload_bytes={self.max_payload_bytes}, "
                f"max_queue_events={self.max_queue_events}, "
                f"max_queue_bytes={self.max_queue_bytes})")


@dataclass(frozen=True, slots=True, repr=False)
class JsonlEnvelope:
    source_role: str
    payload: str = field(repr=False)
    payload_byte_count: int
    collector_instance_alias: str = field(repr=False)
    sequence_hint: str | None = field(repr=False)
    retry_hint: bool

    def __repr__(self) -> str:
        return (f"JsonlEnvelope(source_role={self.source_role!r}, "
                f"payload_byte_count={self.payload_byte_count}, retry_hint={self.retry_hint})")


@dataclass(frozen=True, slots=True, repr=False)
class JsonlFeedResult:
    records: tuple[JsonlEnvelope, ...] = field(repr=False)
    buffered_bytes: int
    terminal: bool
    error_category: AdapterErrorCode | None

    def to_dict(self) -> dict[str, Any]:
        return {"record_count": len(self.records), "buffered_bytes": self.buffered_bytes,
                "terminal": self.terminal,
                "error_category": self.error_category.value if self.error_category else None}

    def __repr__(self) -> str:
        category = self.error_category.value if self.error_category else None
        return (f"JsonlFeedResult(record_count={len(self.records)}, "
                f"buffered_bytes={self.buffered_bytes}, terminal={self.terminal}, "
                f"error_category={category!r})")


class JsonLinesDecoder:
    """Incremental LF-delimited decoder. A malformed record closes this decoder."""

    __slots__ = ("config", "_buffer", "_terminal", "_close_result", "_accepted", "_rejected")

    def __init__(self, config: JsonlAdapterConfig):
        if not isinstance(config, JsonlAdapterConfig):
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        self.config = config
        self._buffer = bytearray()
        self._terminal = False
        self._close_result: JsonlFeedResult | None = None
        self._accepted = self._rejected = 0

    @property
    def validated_records(self) -> int:
        return self._accepted

    @property
    def rejected_records(self) -> int:
        return self._rejected

    def _result(self, records: tuple[JsonlEnvelope, ...] = (),
                error: AdapterErrorCode | None = None) -> JsonlFeedResult:
        return JsonlFeedResult(records, len(self._buffer), self._terminal, error)

    def _fail(self, code: AdapterErrorCode, records: list[JsonlEnvelope] | None = None) -> JsonlFeedResult:
        self._buffer.clear()
        self._terminal = True
        self._rejected += 1
        return self._result(tuple(records or ()), code)

    def feed(self, data: bytes) -> JsonlFeedResult:
        if self._terminal:
            return self._result(error=AdapterErrorCode.DECODER_CLOSED)
        if type(data) is not bytes:
            return self._fail(AdapterErrorCode.INTERNAL_FAILURE)
        if data.count(b"\n") > _MAX_RECORDS_PER_FEED:
            # Reject this call before accepting any prefix record; the caller
            # must split large batches into bounded feeds explicitly.
            return self._fail(AdapterErrorCode.FEED_EVENT_LIMIT)
        records: list[JsonlEnvelope] = []
        try:
            for byte in data:
                if byte == 0x0A:
                    if len(self._buffer) + 1 > self.config.max_record_bytes:
                        return self._fail(AdapterErrorCode.RECORD_TOO_LARGE, records)
                    record = bytes(self._buffer)
                    self._buffer.clear()
                    try:
                        parsed = self._parse_line(record)
                    except JsonlAdapterError as error:
                        return self._fail(error.code, records)
                    records.append(parsed)
                    self._accepted += 1
                    continue
                # Reserve one byte for the required LF delimiter.
                if len(self._buffer) + 2 > self.config.max_record_bytes:
                    return self._fail(AdapterErrorCode.RECORD_TOO_LARGE, records)
                self._buffer.append(byte)
                if len(self._buffer) > self.config.max_connection_buffer_bytes:
                    return self._fail(AdapterErrorCode.RECORD_TOO_LARGE, records)
            return self._result(tuple(records))
        except JsonlAdapterError as error:
            return self._fail(error.code, records)
        except Exception:
            return self._fail(AdapterErrorCode.INTERNAL_FAILURE, records)

    def _parse_line(self, raw: bytes) -> JsonlEnvelope:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_UTF8) from None
        if not raw or raw[:1] != b"{" or raw[-1:] != b"}":
            raise JsonlAdapterError(AdapterErrorCode.INVALID_JSON)

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise JsonlAdapterError(AdapterErrorCode.DUPLICATE_KEY)
                result[key] = value
            return result

        def reject_constant(_value: str) -> None:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_JSON)

        def finite_float(value: str) -> float:
            parsed = float(value)
            if not math.isfinite(parsed):
                raise JsonlAdapterError(AdapterErrorCode.INVALID_JSON)
            return parsed

        try:
            value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant,
                               parse_float=finite_float)
        except JsonlAdapterError:
            raise
        except Exception:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_JSON) from None
        if not isinstance(value, dict):
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        if set(value) - _FIELDS:
            raise JsonlAdapterError(AdapterErrorCode.UNKNOWN_FIELD)
        if set(value) != _FIELDS:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        version = value["schema_version"]
        role = value["source_role"]
        payload = value["payload"]
        alias = value["collector_instance_alias"]
        sequence = value["sequence_hint"]
        retry = value["retry_hint"]
        if type(version) is not int or version != 1:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        if type(role) is not str or role not in {"application", "ssh"}:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        if role != self.config.source_role:
            raise JsonlAdapterError(AdapterErrorCode.ROLE_MISMATCH)
        if type(payload) is not str:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        try:
            payload_bytes = payload.encode("utf-8", errors="strict")
            alias_bytes = alias.encode("utf-8", errors="strict") if type(alias) is str else b""
            sequence_bytes = sequence.encode("utf-8", errors="strict") if type(sequence) is str else b""
        except UnicodeEncodeError:
            raise JsonlAdapterError(AdapterErrorCode.INVALID_UTF8) from None
        if len(payload_bytes) > self.config.max_payload_bytes:
            raise JsonlAdapterError(AdapterErrorCode.PAYLOAD_TOO_LARGE)
        if not payload_bytes or any(byte < 0x20 or byte == 0x7F for byte in payload_bytes):
            raise JsonlAdapterError(AdapterErrorCode.FORBIDDEN_CONTROL)
        if (type(alias) is not str or not _ALIAS.fullmatch(alias)
                or type(sequence) is not str and sequence is not None
                or type(sequence) is str and not _SEQUENCE.fullmatch(sequence)
                or type(retry) is not bool):
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        return JsonlEnvelope(role, payload, len(payload_bytes), alias, sequence, retry)

    def close(self) -> JsonlFeedResult:
        if self._close_result is not None:
            return self._close_result
        if self._terminal:
            self._close_result = self._result()
        elif self._buffer:
            self._close_result = self._fail(AdapterErrorCode.INCOMPLETE_RECORD)
        else:
            self._terminal = True
            self._close_result = self._result()
        return self._close_result


@dataclass(frozen=True, slots=True, repr=False)
class QueuedJsonlEvent:
    source_role: str
    receipt_id: int
    payload: str = field(repr=False)
    payload_byte_count: int
    collector_instance_alias: str = field(repr=False)
    sequence_hint: str | None = field(repr=False)
    retry_hint: bool
    resident_data_bytes: int

    def __repr__(self) -> str:
        return (f"QueuedJsonlEvent(source_role={self.source_role!r}, receipt_id={self.receipt_id}, "
                f"payload_byte_count={self.payload_byte_count}, retry_hint={self.retry_hint})")


@dataclass(frozen=True, slots=True, repr=False)
class JsonlQueueSnapshot:
    queued_events: int
    queued_bytes: int
    event_limit: int
    byte_limit: int
    accepted: int
    rejected: int
    dequeued: int
    dropped: int
    closed: bool

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    def __repr__(self) -> str:
        return (f"JsonlQueueSnapshot(queued_events={self.queued_events}, "
                f"queued_bytes={self.queued_bytes}, accepted={self.accepted}, "
                f"rejected={self.rejected}, dequeued={self.dequeued}, dropped={self.dropped}, "
                f"closed={self.closed})")


@dataclass(frozen=True, slots=True, repr=False)
class JsonlStatusSnapshot:
    schema_version: str
    source_role: str
    transport: str
    state: AdapterState
    accepted_records: int
    rejected_records: int
    dropped_records: int
    queued_events: int
    queue_event_limit: int
    queued_bytes: int
    queue_byte_limit: int
    error_category: str
    next_action: str

    def to_dict(self) -> dict[str, Any]:
        return {name: (value.value if isinstance(value, Enum) else value)
                for name, value in ((key, getattr(self, key)) for key in self.__dataclass_fields__)}

    def __repr__(self) -> str:
        return (f"JsonlStatusSnapshot(state={self.state.value}, "
                f"accepted_records={self.accepted_records}, "
                f"rejected_records={self.rejected_records}, dropped_records={self.dropped_records})")


def safe_status_snapshot(config: JsonlAdapterConfig, queue: JsonlQueueSnapshot,
                         *, state: AdapterState = AdapterState.READY,
                         error_category: AdapterErrorCode | None = None) -> JsonlStatusSnapshot:
    """Project fixed counters and categories, never event metadata or content."""
    if not isinstance(config, JsonlAdapterConfig) or not isinstance(queue, JsonlQueueSnapshot):
        raise JsonlAdapterError(AdapterErrorCode.INTERNAL_FAILURE)
    try:
        state = AdapterState(state)
    except Exception:
        raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA) from None
    if error_category is not None and not isinstance(error_category, AdapterErrorCode):
        raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
    if (queue.event_limit != config.max_queue_events or queue.byte_limit != config.max_queue_bytes
            or queue.queued_events > queue.event_limit or queue.queued_bytes > queue.byte_limit):
        raise JsonlAdapterError(AdapterErrorCode.INTERNAL_FAILURE)
    return JsonlStatusSnapshot(
        "collector-jsonl-status/v1", config.source_role, "collector_jsonl", state,
        queue.accepted, queue.rejected, queue.dropped, queue.queued_events,
        queue.event_limit, queue.queued_bytes, queue.byte_limit,
        error_category.value if error_category else "NONE",
        "NONE" if state is AdapterState.READY else "INSPECT_FIXED_STATUS",
    )


class BoundedJsonLinesQueue:
    """FIFO queue bounded by event count and UTF-8 payload+metadata bytes."""

    __slots__ = ("config", "_items", "_bytes", "_next_id", "_accepted", "_rejected",
                 "_dequeued", "_dropped", "_closed")

    def __init__(self, config: JsonlAdapterConfig):
        if not isinstance(config, JsonlAdapterConfig):
            raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
        self.config = config
        self._items: deque[QueuedJsonlEvent] = deque()
        self._bytes = self._next_id = self._accepted = self._rejected = self._dequeued = self._dropped = 0
        self._closed = False

    def enqueue(self, envelope: JsonlEnvelope) -> QueuedJsonlEvent:
        if self._closed:
            self._rejected += 1
            raise JsonlAdapterError(AdapterErrorCode.QUEUE_CLOSED)
        try:
            if not isinstance(envelope, JsonlEnvelope) or envelope.source_role != self.config.source_role:
                raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
            if (type(envelope.payload) is not str
                    or type(envelope.collector_instance_alias) is not str
                    or envelope.sequence_hint is not None and type(envelope.sequence_hint) is not str
                    or type(envelope.retry_hint) is not bool):
                raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
            payload_size = len(envelope.payload.encode("utf-8", errors="strict"))
            alias_size = len(envelope.collector_instance_alias.encode("utf-8", errors="strict"))
            sequence_size = len(envelope.sequence_hint.encode("utf-8", errors="strict")) if envelope.sequence_hint else 0
            resident = payload_size + alias_size + sequence_size
            if (payload_size != envelope.payload_byte_count or payload_size > self.config.max_payload_bytes
                    or resident > self.config.max_queue_bytes or not payload_size
                    or any(ord(char) < 32 or ord(char) == 127 for char in envelope.payload)
                    or not _ALIAS.fullmatch(envelope.collector_instance_alias)
                    or envelope.sequence_hint is not None and not _SEQUENCE.fullmatch(envelope.sequence_hint)):
                raise JsonlAdapterError(AdapterErrorCode.INVALID_SCHEMA)
            if len(self._items) + 1 > self.config.max_queue_events or self._bytes + resident > self.config.max_queue_bytes:
                raise JsonlAdapterError(AdapterErrorCode.QUEUE_FULL)
            item = QueuedJsonlEvent(envelope.source_role, self._next_id + 1, envelope.payload,
                                    payload_size, envelope.collector_instance_alias,
                                    envelope.sequence_hint, envelope.retry_hint, resident)
            self._items.append(item)
            self._next_id += 1
            self._accepted += 1
            self._bytes += resident
            return item
        except JsonlAdapterError:
            self._rejected += 1
            raise
        except Exception:
            self._rejected += 1
            raise JsonlAdapterError(AdapterErrorCode.INTERNAL_FAILURE) from None

    def dequeue(self) -> QueuedJsonlEvent | None:
        if not self._items:
            return None
        try:
            item = self._items.popleft()
            self._bytes -= item.resident_data_bytes
            self._dequeued += 1
            return item
        except Exception:
            raise JsonlAdapterError(AdapterErrorCode.INTERNAL_FAILURE) from None

    def snapshot(self) -> JsonlQueueSnapshot:
        return JsonlQueueSnapshot(len(self._items), self._bytes, self.config.max_queue_events,
                                  self.config.max_queue_bytes, self._accepted, self._rejected,
                                  self._dequeued, self._dropped, self._closed)

    def close(self) -> None:
        if self._closed:
            return
        pending = len(self._items)
        try:
            self._items.clear()
        except Exception:
            self._items = deque()
            self._closed = True
            self._bytes = 0
            self._dropped += pending
            raise JsonlAdapterError(AdapterErrorCode.INTERNAL_FAILURE) from None
        self._bytes = 0
        self._dropped += pending
        self._closed = True
