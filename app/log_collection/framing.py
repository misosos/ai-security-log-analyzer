"""Bounded RFC 6587 octet-counting decoder; no sockets or parser integration."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.log_collection.models import CollectionCoreError, CollectionErrorCode, TcpCollectionConfig


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedFrame:
    source_role: str
    payload: str = field(repr=False)
    payload_byte_count: int

    def __repr__(self) -> str:
        return f"ValidatedFrame(source_role={self.source_role!r}, payload_byte_count={self.payload_byte_count})"


@dataclass(frozen=True, slots=True, repr=False)
class FeedResult:
    frames: tuple[ValidatedFrame, ...] = field(repr=False)
    buffered_bytes: int
    awaiting_bytes: int
    terminal: bool
    error_category: CollectionErrorCode | None

    def to_dict(self) -> dict[str, object]:
        return {"frame_count": len(self.frames), "buffered_bytes": self.buffered_bytes,
                "awaiting_bytes": self.awaiting_bytes, "terminal": self.terminal,
                "error_category": self.error_category.value if self.error_category else None}

    def __repr__(self) -> str:
        return (f"FeedResult(frame_count={len(self.frames)}, buffered_bytes={self.buffered_bytes}, "
                f"terminal={self.terminal}, error_category={self.error_category!r})")


def _append_payload(buffer: bytearray, data: bytes) -> None:
    buffer.extend(data)


def _decode_payload(data: bytes) -> str:
    return data.decode("utf-8", errors="strict")


class OctetCountingDecoder:
    __slots__ = ("_config", "_prefix", "_payload", "_expected", "_terminal", "_close_result")

    def __init__(self, config: TcpCollectionConfig):
        self._config = config
        self._prefix = bytearray()
        self._payload = bytearray()
        self._expected: int | None = None
        self._terminal = False
        self._close_result: FeedResult | None = None

    def snapshot(self) -> FeedResult:
        return self._result((), None)

    def _result(self, frames: tuple[ValidatedFrame, ...], error: CollectionErrorCode | None) -> FeedResult:
        buffered = len(self._prefix) + len(self._payload)
        awaiting = max(0, self._expected - len(self._payload)) if self._expected is not None else 1
        return FeedResult(frames, buffered, awaiting if buffered else 0, self._terminal, error)

    def _fail(self, code: CollectionErrorCode, completed: list[ValidatedFrame] | None = None) -> FeedResult:
        self._prefix.clear()
        self._payload.clear()
        self._expected = None
        self._terminal = True
        return self._result(tuple(completed or ()), code)

    def feed(self, data: bytes) -> FeedResult:
        if self._terminal:
            return self._result((), CollectionErrorCode.DECODER_CLOSED)
        if not isinstance(data, bytes):
            return self._fail(CollectionErrorCode.INTERNAL_FAILURE)
        if len(data) > self._config.max_connection_buffer_bytes:
            return self._fail(CollectionErrorCode.CONNECTION_BUFFER_FULL)
        frames: list[ValidatedFrame] = []
        index = 0
        try:
            while index < len(data):
                if self._expected is None:
                    byte = data[index]
                    index += 1
                    if byte == 32:
                        if not self._prefix:
                            return self._fail(CollectionErrorCode.INVALID_PREFIX, frames)
                        if self._prefix[0] == 48 and len(self._prefix) != 1:
                            return self._fail(CollectionErrorCode.INVALID_PREFIX, frames)
                        length = int(self._prefix)
                        if length == 0:
                            return self._fail(CollectionErrorCode.INVALID_PREFIX, frames)
                        if length > self._config.max_frame_bytes:
                            return self._fail(CollectionErrorCode.FRAME_TOO_LARGE, frames)
                        self._prefix.clear()
                        self._expected = length
                        continue
                    if byte < 48 or byte > 57:
                        return self._fail(CollectionErrorCode.INVALID_PREFIX, frames)
                    if len(self._prefix) >= self._config.max_prefix_digits:
                        return self._fail(CollectionErrorCode.PREFIX_TOO_LONG, frames)
                    if len(self._prefix) == 0 and byte == 48:
                        self._prefix.append(byte)
                    elif self._prefix and self._prefix[0] == 48:
                        return self._fail(CollectionErrorCode.INVALID_PREFIX, frames)
                    else:
                        self._prefix.append(byte)
                    if len(self._prefix) + 1 > self._config.max_connection_buffer_bytes:
                        return self._fail(CollectionErrorCode.CONNECTION_BUFFER_FULL, frames)
                else:
                    take = min(self._expected - len(self._payload), len(data) - index)
                    _append_payload(self._payload, data[index:index + take])
                    index += take
                    if len(self._payload) > self._config.max_connection_buffer_bytes:
                        return self._fail(CollectionErrorCode.CONNECTION_BUFFER_FULL, frames)
                    if len(self._payload) == self._expected:
                        raw = bytes(self._payload)
                        try:
                            text = _decode_payload(raw)
                        except UnicodeDecodeError:
                            return self._fail(CollectionErrorCode.INVALID_UTF8, frames)
                        if any(ord(char) < 32 or ord(char) == 127 for char in text):
                            return self._fail(CollectionErrorCode.FORBIDDEN_CONTROL, frames)
                        frames.append(ValidatedFrame(self._config.source_role, text, len(raw)))
                        self._payload.clear()
                        self._expected = None
            return self._result(tuple(frames), None)
        except Exception:
            return self._fail(CollectionErrorCode.INTERNAL_FAILURE, frames)

    def close(self) -> FeedResult:
        if self._close_result is not None:
            return self._close_result
        if self._terminal:
            self._close_result = self._result((), None)
        elif self._prefix or self._payload or self._expected is not None:
            self._close_result = self._fail(CollectionErrorCode.INCOMPLETE_FRAME)
        else:
            self._terminal = True
            self._close_result = self._result((), None)
        return self._close_result
