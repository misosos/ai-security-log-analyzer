"""In-memory FIFO with event-count and UTF-8 byte caps."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from app.log_collection.framing import ValidatedFrame
from app.log_collection.models import CollectionCoreError, CollectionErrorCode, TcpCollectionConfig


@dataclass(frozen=True, slots=True, repr=False)
class QueueItem:
    source_role: str
    receipt_id: int
    payload: str = field(repr=False)
    payload_byte_count: int

    def __repr__(self) -> str:
        return f"QueueItem(source_role={self.source_role!r}, receipt_id={self.receipt_id}, payload_byte_count={self.payload_byte_count})"


@dataclass(frozen=True, slots=True, repr=False)
class QueueSnapshot:
    queued_events: int
    queued_bytes: int
    event_limit: int
    byte_limit: int
    accepted_count: int
    rejected_count: int
    dequeued_count: int
    dropped_count: int
    closed: bool

    def __repr__(self) -> str:
        return f"QueueSnapshot(queued_events={self.queued_events}, queued_bytes={self.queued_bytes}, closed={self.closed})"


class BoundedEventQueue:
    __slots__ = ("_config", "_items", "_bytes", "_next_id", "_accepted", "_rejected", "_dequeued", "_dropped", "_closed")

    def __init__(self, config: TcpCollectionConfig):
        self._config = config
        self._items: deque[QueueItem] = deque()
        self._bytes = self._next_id = self._accepted = self._rejected = self._dequeued = self._dropped = 0
        self._closed = False

    def _admit_item(self, item: QueueItem) -> None:
        self._items.append(item)

    def _dequeue_head(self) -> QueueItem:
        return self._items.popleft()

    def _clear_items(self) -> None:
        self._items.clear()

    def enqueue(self, frame: ValidatedFrame) -> QueueItem:
        if self._closed:
            self._rejected += 1
            raise CollectionCoreError(CollectionErrorCode.QUEUE_CLOSED)
        original_count = len(self._items)
        rejected_counted = False
        try:
            actual = len(frame.payload.encode("utf-8", errors="strict"))
            if (frame.source_role != self._config.source_role or type(frame.payload_byte_count) is not int
                    or actual != frame.payload_byte_count or actual > self._config.max_frame_bytes
                    or not frame.payload or any(ord(ch) < 32 or ord(ch) == 127 for ch in frame.payload)):
                self._rejected += 1
                rejected_counted = True
                raise CollectionCoreError(CollectionErrorCode.INVALID_UTF8)
            if (len(self._items) + 1 > self._config.max_queue_events
                    or self._bytes + actual > self._config.max_queue_bytes):
                self._rejected += 1
                rejected_counted = True
                raise CollectionCoreError(CollectionErrorCode.QUEUE_FULL)
            item = QueueItem(frame.source_role, self._next_id + 1, frame.payload, actual)
            self._admit_item(item)
            self._next_id += 1
            self._accepted += 1
            self._bytes += actual
            return item
        except CollectionCoreError:
            self._rollback_partial_admission(original_count)
            if not rejected_counted:
                self._rejected += 1
            raise
        except Exception:
            self._rollback_partial_admission(original_count)
            self._rejected += 1
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE) from None

    def _rollback_partial_admission(self, original_count: int) -> None:
        try:
            while len(self._items) > original_count:
                self._items.pop()
        except Exception:
            self._items = deque()
            self._bytes = 0
            self._closed = True

    def dequeue(self) -> QueueItem | None:
        if not self._items:
            return None
        try:
            item = self._dequeue_head()
            self._bytes -= item.payload_byte_count
            self._dequeued += 1
            return item
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE) from None

    def snapshot(self) -> QueueSnapshot:
        try:
            return QueueSnapshot(len(self._items), self._bytes, self._config.max_queue_events,
                                 self._config.max_queue_bytes, self._accepted, self._rejected,
                                 self._dequeued, self._dropped, self._closed)
        except Exception:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE) from None

    def close(self) -> None:
        if self._closed:
            return
        pending = len(self._items)
        failed = False
        try:
            self._clear_items()
        except Exception:
            failed = True
        finally:
            self._items = deque()
            self._bytes = 0
            self._dropped += pending
            self._closed = True
        if failed:
            raise CollectionCoreError(CollectionErrorCode.INTERNAL_FAILURE) from None
