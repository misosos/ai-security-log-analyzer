"""Bounded, privacy-safe, process-local live detection publication and replay.

No SSE framing, HTTP API, filesystem, detector, or trusted raw event enters this
module. Direct publish accepts only a committed change set; worker prepare
accepts only the bound accumulator's active, prevalidated proposal.
"""

from dataclasses import dataclass, field, replace
import json

from app.live_monitoring.core import MAX_COUNTER
from app.live_monitoring.detection_accumulator import (
    LiveDetectionAccumulator, LiveDetectionChange, LiveDetectionChangeSet,
    LiveDetectionProposal,
)


MAX_PUBLICATION_ITEMS = 32
MAX_PUBLICATION_BYTES = 16_384
_NEXT_SESSION_NUMBER = 0
_CHANGE_TYPES = ("CREATED", "UPDATED", "NO_LONGER_MATCHES")
_STATES = ("ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT")
_TYPES = (
    "brute_force", "password_spraying_like", "path_traversal",
    "sql_injection_like", "xss_like", "sensitive_resource_probing_like",
    "web_scanning_like",
)
_MESSAGES = {
    "INVALID_BUFFER_ARGUMENT": "publication buffer 설정을 확인하십시오.",
    "INVALID_CHANGE_SET": "확정된 detection change 계약을 확인하십시오.",
    "UNCOMMITTED_CHANGE_SET": "확정되지 않았거나 다른 session의 change입니다.",
    "DUPLICATE_REVISION": "이미 처리한 detection revision입니다.",
    "REVISION_GAP": "detection revision 순서를 확인하십시오.",
    "EVENT_TOO_LARGE": "단일 publication event가 byte 상한을 초과했습니다.",
    "COUNTER_LIMIT": "publication 집계 상한에 도달했습니다.",
    "BUFFER_CLOSED": "닫힌 publication buffer는 게시할 수 없습니다.",
    "SERIALIZATION_FAILURE": "publication 직렬화 계약을 확인하십시오.",
    "ACTIVE_PROPOSAL": "진행 중인 publication proposal을 정산하십시오.",
    "PROPOSAL_MISMATCH": "publication proposal 소유권을 확인하십시오.",
}
_GAP_MESSAGES = {
    "BUFFER_CLOSED": "버퍼가 닫혔습니다. 새 session의 최신 snapshot부터 다시 시작하십시오.",
    "MALFORMED_EVENT_ID": "event ID가 유효하지 않습니다. 최신 snapshot부터 다시 시작하십시오.",
    "FOREIGN_SESSION": "다른 session의 event ID입니다. 최신 snapshot부터 다시 시작하십시오.",
    "FUTURE_EVENT_ID": "아직 게시되지 않은 event ID입니다. 최신 snapshot부터 다시 시작하십시오.",
    "EVICTED_EVENT_ID": "재연결 범위가 제거됐습니다. 최신 snapshot부터 다시 시작하십시오.",
    "UNKNOWN_EVENT_ID": "확인할 수 없는 event ID입니다. 최신 snapshot부터 다시 시작하십시오.",
}


class LivePublicationError(ValueError):
    """Fixed, input-free publication failure."""

    def __init__(self, code: str):
        if type(code) is not str or code not in _MESSAGES:
            code = "INVALID_BUFFER_ARGUMENT"
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LivePublicationError(code={self.code!r})"


def _add(left: int, right: int) -> int:
    if (type(left) is not int or type(right) is not int
        or not 0 <= left <= MAX_COUNTER or not 0 <= right <= MAX_COUNTER - left):
        raise LivePublicationError("COUNTER_LIMIT")
    return left + right


def _positive(value: object, maximum: int) -> bool:
    return type(value) is int and 1 <= value <= maximum


def _session_id(number: int) -> str:
    return f"LIVE-SESSION-{number:06d}"


def _event_id(session_number: int, event_number: int) -> str:
    return f"LIVE-EVENT-{session_number:06d}-{event_number:06d}"


def _parse_event_id(value: object) -> tuple[int, int] | None:
    if type(value) is not str or not value.startswith("LIVE-EVENT-"):
        return None
    fields = value[len("LIVE-EVENT-"):].split("-")
    if len(fields) != 2:
        return None
    for field in fields:
        if (not 6 <= len(field) <= 19
            or any(char not in "0123456789" for char in field)):
            return None
    session_number, event_number = (int(field) for field in fields)
    if (not 1 <= session_number <= MAX_COUNTER or not 1 <= event_number <= MAX_COUNTER
        or value != _event_id(session_number, event_number)):
        return None
    return session_number, event_number


@dataclass(frozen=True, slots=True)
class LivePublicationEvent:
    event_id: str
    session_id: str
    revision: int
    event_type: str
    created_count: int
    updated_count: int
    no_longer_matches_count: int
    active_observation_count: int
    published_observation_count: int
    observations: tuple[LiveDetectionChange, ...]

    def __post_init__(self) -> None:
        counts = (self.revision, self.created_count, self.updated_count,
                  self.no_longer_matches_count, self.active_observation_count,
                  self.published_observation_count)
        parsed = _parse_event_id(self.event_id)
        if (parsed is None or self.session_id != _session_id(parsed[0])
            or self.event_type != "DETECTION_CHANGE"
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.revision < 1 or type(self.observations) is not tuple
            or not self.observations
            or any(type(change) is not LiveDetectionChange
                   or change.accumulator_revision != self.revision
                   for change in self.observations)
            or self.published_observation_count != len(self.observations)
            or self.created_count != sum(c.change_type == "CREATED" for c in self.observations)
            or self.updated_count != sum(c.change_type == "UPDATED" for c in self.observations)
            or self.no_longer_matches_count != sum(
                c.change_type == "NO_LONGER_MATCHES" for c in self.observations)):
            raise LivePublicationError("INVALID_CHANGE_SET")


@dataclass(frozen=True, slots=True)
class LivePublicationSnapshot:
    schema_version: str
    state: str
    session_id: str
    item_count: int
    byte_count: int
    max_items: int
    max_bytes: int
    earliest_available_event_id: str | None
    latest_available_event_id: str | None
    latest_committed_detection_revision: int
    published_total: int
    evicted_total: int
    rejected_oversized_total: int
    replay_gap_total: int
    active_observation_count: int
    last_created_count: int
    last_updated_count: int
    last_no_longer_matches_count: int

    def __post_init__(self) -> None:
        counters = (self.item_count, self.byte_count,
                    self.latest_committed_detection_revision, self.published_total,
                    self.evicted_total, self.rejected_oversized_total,
                    self.replay_gap_total, self.active_observation_count,
                    self.last_created_count, self.last_updated_count,
                    self.last_no_longer_matches_count)
        if (self.schema_version != "1" or self.state not in ("OPEN", "CLOSED")
            or type(self.session_id) is not str
            or not self.session_id.startswith("LIVE-SESSION-")
            or not _positive(self.max_items, MAX_COUNTER)
            or not _positive(self.max_bytes, MAX_COUNTER)
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counters)
            or self.item_count > self.max_items or self.byte_count > self.max_bytes
            or (self.item_count == 0) != (self.earliest_available_event_id is None)
            or (self.item_count == 0) != (self.latest_available_event_id is None)
            or self.published_total < self.evicted_total + self.item_count
            or self.state == "CLOSED" and self.item_count != 0):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")


@dataclass(frozen=True, slots=True)
class LiveReplayResult:
    status: str
    snapshot: LivePublicationSnapshot
    events: tuple[LivePublicationEvent, ...]
    gap_code: str | None = None
    recovery_action: str | None = None

    def __post_init__(self) -> None:
        if (self.status not in ("INITIAL", "REPLAY", "GAP")
            or type(self.snapshot) is not LivePublicationSnapshot
            or type(self.events) is not tuple
            or any(type(event) is not LivePublicationEvent for event in self.events)
            or (self.status == "GAP") != (self.gap_code is not None)
            or (self.status == "GAP") != (self.recovery_action is not None)
            or self.status == "GAP" and self.events
            or self.gap_code is not None and self.gap_code not in _GAP_MESSAGES):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")


@dataclass(frozen=True, slots=True)
class _StoredEvent:
    event: LivePublicationEvent
    encoded: bytes


@dataclass(frozen=True, slots=True)
class _BufferState:
    records: tuple[_StoredEvent, ...]
    byte_count: int
    latest_revision: int
    last_event_number: int
    published_total: int
    evicted_total: int
    rejected_oversized_total: int
    replay_gap_total: int
    active_observation_count: int
    last_counts: tuple[int, int, int]
    closed: bool


@dataclass(frozen=True, slots=True)
class LivePublicationProposal:
    """Pre-serialized, safe candidate; only its bound buffer may settle it."""

    revision: int
    event: LivePublicationEvent | None
    _candidate: _BufferState = field(repr=False)
    _change_set: LiveDetectionChangeSet = field(repr=False)


def _json_bytes(value: dict) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise LivePublicationError("SERIALIZATION_FAILURE") from None


def _change_data(change: LiveDetectionChange) -> dict[str, str | int]:
    return {
        "observation_id": change.observation_id,
        "observation_revision": change.observation_revision,
        "change_type": change.change_type,
        "state": change.state,
        "detection_type": change.detection_type,
        "accumulator_revision": change.accumulator_revision,
    }


def serialize_live_publication_event(event: LivePublicationEvent) -> bytes:
    if type(event) is not LivePublicationEvent:
        raise LivePublicationError("INVALID_CHANGE_SET")
    return _json_bytes({
        "event_id": event.event_id, "session_id": event.session_id,
        "revision": event.revision, "event_type": event.event_type,
        "created_count": event.created_count, "updated_count": event.updated_count,
        "no_longer_matches_count": event.no_longer_matches_count,
        "active_observation_count": event.active_observation_count,
        "published_observation_count": event.published_observation_count,
        "observations": [_change_data(change) for change in event.observations],
    })


def serialize_live_publication_snapshot(snapshot: LivePublicationSnapshot) -> bytes:
    if type(snapshot) is not LivePublicationSnapshot:
        raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
    return _json_bytes({
        "schema_version": snapshot.schema_version, "state": snapshot.state,
        "session_id": snapshot.session_id, "item_count": snapshot.item_count,
        "byte_count": snapshot.byte_count, "max_items": snapshot.max_items,
        "max_bytes": snapshot.max_bytes,
        "earliest_available_event_id": snapshot.earliest_available_event_id,
        "latest_available_event_id": snapshot.latest_available_event_id,
        "latest_committed_detection_revision": snapshot.latest_committed_detection_revision,
        "published_total": snapshot.published_total,
        "evicted_total": snapshot.evicted_total,
        "rejected_oversized_total": snapshot.rejected_oversized_total,
        "replay_gap_total": snapshot.replay_gap_total,
        "active_observation_count": snapshot.active_observation_count,
        "last_created_count": snapshot.last_created_count,
        "last_updated_count": snapshot.last_updated_count,
        "last_no_longer_matches_count": snapshot.last_no_longer_matches_count,
    })


class LivePublicationBuffer:
    """Single-caller bounded replay of committed, safe detection changes."""

    __slots__ = ("_accumulator", "_session_number", "_session_id", "_max_items",
                 "_max_bytes", "_state", "_last_committed_revision", "_active")

    def __init__(self, accumulator: LiveDetectionAccumulator,
                 max_items: int = MAX_PUBLICATION_ITEMS,
                 max_bytes: int = MAX_PUBLICATION_BYTES):
        if type(accumulator) is not LiveDetectionAccumulator:
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        if not _positive(max_items, MAX_PUBLICATION_ITEMS) or not _positive(max_bytes, MAX_PUBLICATION_BYTES):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        snapshot = accumulator.snapshot()
        if (snapshot.closed or snapshot.revision != 0 or snapshot.active_proposal
            or accumulator._publication_bound):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        global _NEXT_SESSION_NUMBER
        number = _add(_NEXT_SESSION_NUMBER, 1)
        _NEXT_SESSION_NUMBER = number
        accumulator._publication_bound = True
        self._accumulator = accumulator
        self._session_number = number
        self._session_id = _session_id(number)
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._state = _BufferState((), 0, 0, 0, 0, 0, 0, 0, 0, (0, 0, 0), False)
        self._last_committed_revision = 0
        self._active: LivePublicationProposal | None = None

    def __repr__(self) -> str:
        state = "CLOSED" if self._state.closed else "OPEN"
        return (f"LivePublicationBuffer(session_id={self._session_id!r}, "
                f"item_count={len(self._state.records)}, state={state!r})")

    @property
    def session_id(self) -> str:
        return self._session_id

    def snapshot(self) -> LivePublicationSnapshot:
        state = self._state
        return LivePublicationSnapshot(
            "1", "CLOSED" if state.closed else "OPEN", self._session_id,
            len(state.records), state.byte_count, self._max_items, self._max_bytes,
            state.records[0].event.event_id if state.records else None,
            state.records[-1].event.event_id if state.records else None,
            (self._last_committed_revision if state.closed
             else self._accumulator.snapshot().revision),
            state.published_total, state.evicted_total,
            state.rejected_oversized_total, state.replay_gap_total,
            state.active_observation_count, *state.last_counts,
        )

    def publish(self, change_set: LiveDetectionChangeSet) -> LivePublicationEvent | None:
        if self._active is not None:
            raise LivePublicationError("ACTIVE_PROPOSAL")
        state = self._state
        if state.closed:
            raise LivePublicationError("BUFFER_CLOSED")
        if type(change_set) is not LiveDetectionChangeSet:
            raise LivePublicationError("INVALID_CHANGE_SET")
        if (change_set is not self._accumulator.latest_change_set()
            or self._accumulator.snapshot().revision != change_set.accumulator_revision):
            raise LivePublicationError("UNCOMMITTED_CHANGE_SET")
        revision = change_set.accumulator_revision
        if revision <= state.latest_revision:
            raise LivePublicationError("DUPLICATE_REVISION")
        if revision != state.latest_revision + 1:
            raise LivePublicationError("REVISION_GAP")
        candidate, event = self._build_candidate(change_set, self._accumulator.snapshot().active_observation_count)
        self._state = candidate
        return event

    def _build_candidate(self, change_set: LiveDetectionChangeSet,
                         active: int) -> tuple[_BufferState, LivePublicationEvent | None]:
        state = self._state
        revision = change_set.accumulator_revision
        changes = change_set.changes
        if type(changes) is not tuple or any(type(change) is not LiveDetectionChange for change in changes):
            raise LivePublicationError("INVALID_CHANGE_SET")
        # A single enormous committed change set must not first allocate an
        # unbounded list of serialization dictionaries. Stop once its safe
        # observation JSON alone exceeds the complete event byte budget.
        change_bytes = 0
        for change in changes:
            change_bytes = _add(change_bytes, len(_json_bytes(_change_data(change))))
            if change_bytes > self._max_bytes:
                self._state = replace(state, rejected_oversized_total=_add(state.rejected_oversized_total, 1))
                raise LivePublicationError("EVENT_TOO_LARGE")
        created = sum(c.change_type == "CREATED" for c in changes)
        updated = sum(c.change_type == "UPDATED" for c in changes)
        no_longer = sum(c.change_type == "NO_LONGER_MATCHES" for c in changes)
        if not changes:
            return (replace(state, latest_revision=revision,
                            active_observation_count=active, last_counts=(0, 0, 0)), None)
        next_number = _add(state.last_event_number, 1)
        event = LivePublicationEvent(
            _event_id(self._session_number, next_number), self._session_id,
            revision, "DETECTION_CHANGE", created, updated, no_longer,
            active, len(changes), changes,
        )
        encoded = serialize_live_publication_event(event)
        if len(encoded) > self._max_bytes:
            self._state = replace(state, rejected_oversized_total=_add(state.rejected_oversized_total, 1))
            raise LivePublicationError("EVENT_TOO_LARGE")
        stored = state.records + (_StoredEvent(event, encoded),)
        byte_count = _add(state.byte_count, len(encoded))
        evicted = 0
        while len(stored) > self._max_items or byte_count > self._max_bytes:
            byte_count -= len(stored[0].encoded)
            stored = stored[1:]
            evicted += 1
        candidate = _BufferState(
            stored, byte_count, revision, next_number,
            _add(state.published_total, 1), _add(state.evicted_total, evicted),
            state.rejected_oversized_total, state.replay_gap_total,
            active, (created, updated, no_longer), False,
        )
        return candidate, event

    def prepare(self, detection_proposal: LiveDetectionProposal) -> LivePublicationProposal:
        """Complete JSON serialization and eviction calculation before queue ack."""
        state = self._state
        if state.closed:
            raise LivePublicationError("BUFFER_CLOSED")
        if self._active is not None:
            raise LivePublicationError("ACTIVE_PROPOSAL")
        if (type(detection_proposal) is not LiveDetectionProposal
            or self._accumulator._active is not detection_proposal
            or detection_proposal._change_set is None):
            raise LivePublicationError("UNCOMMITTED_CHANGE_SET")
        revision = detection_proposal.proposal_revision
        if revision <= state.latest_revision:
            raise LivePublicationError("DUPLICATE_REVISION")
        if revision != state.latest_revision + 1:
            raise LivePublicationError("REVISION_GAP")
        candidate, event = self._build_candidate(
            detection_proposal._change_set, detection_proposal._active_observation_count)
        proposal = LivePublicationProposal(revision, event, candidate, detection_proposal._change_set)
        self._active = proposal
        return proposal

    def abort(self, proposal: LivePublicationProposal) -> None:
        if type(proposal) is not LivePublicationProposal or proposal is not self._active:
            raise LivePublicationError("PROPOSAL_MISMATCH")
        self._active = None

    def commit_prepared(self, proposal: LivePublicationProposal) -> LivePublicationEvent | None:
        if (type(proposal) is not LivePublicationProposal or proposal is not self._active
            or self._state.closed):
            raise LivePublicationError("PROPOSAL_MISMATCH")
        if (proposal.revision != self._state.latest_revision + 1
            or self._accumulator._revision != proposal.revision
            or self._accumulator.latest_change_set() is not proposal._change_set):
            raise LivePublicationError("PROPOSAL_MISMATCH")
        self._state = proposal._candidate
        self._active = None
        return proposal.event

    def _gap(self, code: str) -> LiveReplayResult:
        self._state = replace(self._state, replay_gap_total=_add(self._state.replay_gap_total, 1))
        return LiveReplayResult("GAP", self.snapshot(), (), code, _GAP_MESSAGES[code])

    def replay_after(self, last_event_id: str | None) -> LiveReplayResult:
        state = self._state
        if state.closed:
            return self._gap("BUFFER_CLOSED")
        if last_event_id is None:
            return LiveReplayResult("INITIAL", self.snapshot(),
                                    tuple(item.event for item in state.records))
        parsed = _parse_event_id(last_event_id)
        if parsed is None:
            return self._gap("MALFORMED_EVENT_ID")
        session_number, event_number = parsed
        if session_number != self._session_number:
            return self._gap("FOREIGN_SESSION")
        if event_number > state.last_event_number:
            return self._gap("FUTURE_EVENT_ID")
        for index, stored in enumerate(state.records):
            if stored.event.event_id == last_event_id:
                return LiveReplayResult("REPLAY", self.snapshot(),
                                        tuple(item.event for item in state.records[index + 1:]))
        if event_number <= state.last_event_number and state.evicted_total:
            return self._gap("EVICTED_EVENT_ID")
        return self._gap("UNKNOWN_EVENT_ID")

    def close(self) -> None:
        if self._state.closed:
            return
        self._active = None
        self._last_committed_revision = self._accumulator.snapshot().revision
        self._state = replace(self._state, records=(), byte_count=0, closed=True)
        self._accumulator = None
