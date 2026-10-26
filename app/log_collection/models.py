"""Closed configuration, error, and safe status contracts for collection core."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Mapping


class CollectionErrorCode(str, Enum):
    INVALID_CONFIG = "INVALID_CONFIG"
    INVALID_PREFIX = "INVALID_PREFIX"
    PREFIX_TOO_LONG = "PREFIX_TOO_LONG"
    FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
    CONNECTION_BUFFER_FULL = "CONNECTION_BUFFER_FULL"
    INVALID_UTF8 = "INVALID_UTF8"
    FORBIDDEN_CONTROL = "FORBIDDEN_CONTROL"
    INCOMPLETE_FRAME = "INCOMPLETE_FRAME"
    DECODER_CLOSED = "DECODER_CLOSED"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"
    QUEUE_FULL = "QUEUE_FULL"
    QUEUE_CLOSED = "QUEUE_CLOSED"
    INVALID_STATE = "INVALID_STATE"


class CollectionCoreError(Exception):
    """Sanitized error whose text never contains caller-provided values."""

    def __init__(self, code: CollectionErrorCode):
        self.code = code
        super().__init__(code.value)

    def __repr__(self) -> str:
        return f"CollectionCoreError({self.code.value})"


class CollectionState(str, Enum):
    STARTING = "STARTING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


_CONFIG_FIELDS = frozenset({
    "schema_version", "source_role", "transport", "bind_scope", "max_connections",
    "max_prefix_digits", "max_frame_bytes", "max_connection_buffer_bytes",
    "max_queue_events", "max_queue_bytes", "invalid_frame_action", "incomplete_frame_action",
})


@dataclass(frozen=True, slots=True, repr=False)
class TcpCollectionConfig:
    schema_version: str
    source_role: str
    transport: str
    bind_scope: str
    max_connections: int
    max_prefix_digits: int
    max_frame_bytes: int
    max_connection_buffer_bytes: int
    max_queue_events: int
    max_queue_bytes: int
    invalid_frame_action: str
    incomplete_frame_action: str

    def __post_init__(self) -> None:
        if any(type(getattr(self, name)) is not str for name in _CONFIG_FIELDS - {
            "max_connections", "max_prefix_digits", "max_frame_bytes",
            "max_connection_buffer_bytes", "max_queue_events", "max_queue_bytes",
        }):
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)
        constants = {
            "schema_version": "tcp-syslog-config/v1",
            "transport": "tcp_syslog_octet_counting",
            "bind_scope": "loopback_only",
            "invalid_frame_action": "close_connection",
            "incomplete_frame_action": "reject_on_close",
        }
        for name, expected in constants.items():
            if getattr(self, name) != expected:
                raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)
        if self.source_role not in {"application", "ssh"}:
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)
        bounds = {
            "max_connections": (1, 2), "max_prefix_digits": (1, 6),
            "max_frame_bytes": (1, 8192),
            "max_connection_buffer_bytes": (1, 8192 + 7),
            "max_queue_events": (1, 256), "max_queue_bytes": (1, 1024 * 1024),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)
        if (self.max_connection_buffer_bytes < self.max_frame_bytes + self.max_prefix_digits + 1
                or self.max_frame_bytes >= 10 ** self.max_prefix_digits):
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)

    def __repr__(self) -> str:
        return (f"TcpCollectionConfig(source_role={self.source_role!r}, "
                f"max_frame_bytes={self.max_frame_bytes}, max_queue_events={self.max_queue_events})")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(_CONFIG_FIELDS)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "TcpCollectionConfig":
        if not isinstance(value, Mapping) or set(value) != _CONFIG_FIELDS:
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG)
        try:
            return cls(**dict(value))
        except CollectionCoreError:
            raise
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG) from None

    @classmethod
    def from_json(cls, raw: str | bytes) -> "TcpCollectionConfig":
        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        try:
            if len(raw) > 4096:
                raise ValueError
            parsed = json.loads(raw, object_pairs_hook=pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            return cls.from_mapping(parsed)
        except CollectionCoreError:
            raise
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INVALID_CONFIG) from None

    def new_status(self) -> "CollectionStatus":
        return CollectionStatus(self)


@dataclass(frozen=True, slots=True, repr=False)
class StatusSnapshot:
    schema_version: str
    source_role: str
    transport: str
    state: CollectionState
    active_connections: int
    connection_limit: int
    accepted_frames: int
    rejected_frames: int
    dropped_frames: int
    queued_events: int
    queue_event_limit: int
    queued_bytes: int
    queue_byte_limit: int
    last_success_at: str
    error_category: str
    next_action: str

    def to_dict(self) -> dict[str, Any]:
        return {key: (value.value if isinstance(value, Enum) else value)
                for key, value in ((name, getattr(self, name)) for name in self.__dataclass_fields__)}

    def __repr__(self) -> str:
        return f"StatusSnapshot(state={self.state.value}, accepted_frames={self.accepted_frames})"


_TRANSITIONS = {
    CollectionState.STARTING: {CollectionState.READY, CollectionState.FAILED},
    CollectionState.READY: {CollectionState.DEGRADED, CollectionState.FAILED, CollectionState.STOPPED},
    CollectionState.DEGRADED: {CollectionState.FAILED, CollectionState.STOPPED},
    CollectionState.FAILED: {CollectionState.STOPPED},
    CollectionState.STOPPED: {CollectionState.STOPPED},
}


class CollectionStatus:
    __slots__ = ("_config", "_state", "_active", "_accepted", "_rejected", "_dropped",
                 "_queued_events", "_queued_bytes", "_last_success", "_error")

    def __init__(self, config: TcpCollectionConfig):
        self._config = config
        self._state = CollectionState.STARTING
        self._active = self._accepted = self._rejected = self._dropped = 0
        self._queued_events = self._queued_bytes = 0
        self._last_success: str | None = None
        self._error = "NONE"

    def transition(self, state: CollectionState, *, error_category: CollectionErrorCode | None = None) -> None:
        try:
            target = CollectionState(state)
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INVALID_STATE) from None
        if target not in _TRANSITIONS[self._state]:
            raise CollectionCoreError(CollectionErrorCode.INVALID_STATE)
        if error_category is not None and not isinstance(error_category, CollectionErrorCode):
            raise CollectionCoreError(CollectionErrorCode.INVALID_STATE)
        self._state = target
        if error_category is not None:
            self._error = error_category.value
        if target == CollectionState.STOPPED:
            self._active = 0

    def record_accepted(self, when: datetime) -> None:
        if not isinstance(when, datetime) or when.tzinfo is None or when.utcoffset() is None:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE)
        self._accepted += 1
        self._last_success = when.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def record_rejected(self, count: int = 1) -> None:
        if type(count) is not int or count < 1:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE)
        self._rejected += count

    def record_dropped(self, count: int = 1) -> None:
        if type(count) is not int or count < 1:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE)
        self._dropped += count

    def set_queue_usage(self, events: int, byte_count: int) -> None:
        if (type(events) is not int or type(byte_count) is not int or events < 0 or byte_count < 0
                or events > self._config.max_queue_events or byte_count > self._config.max_queue_bytes):
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE)
        self._queued_events, self._queued_bytes = events, byte_count

    def set_active_connections(self, count: int) -> None:
        if type(count) is not int or not 0 <= count <= self._config.max_connections or self._state in {CollectionState.FAILED, CollectionState.STOPPED}:
            raise CollectionCoreError(CollectionErrorCode.INVALID_STATE)
        self._active = count

    def _build_snapshot(self) -> StatusSnapshot:
        next_action = "NONE" if self._state == CollectionState.READY else "INSPECT_FIXED_STATUS"
        return StatusSnapshot("tcp-syslog-status/v1", self._config.source_role,
                              self._config.transport, self._state, self._active,
                              self._config.max_connections, self._accepted, self._rejected,
                              self._dropped, self._queued_events, self._config.max_queue_events,
                              self._queued_bytes, self._config.max_queue_bytes,
                              self._last_success or "unavailable", self._error, next_action)

    def snapshot(self) -> StatusSnapshot:
        try:
            return self._build_snapshot()
        except CollectionCoreError:
            raise
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE) from None
