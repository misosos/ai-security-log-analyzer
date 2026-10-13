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
from app.live_monitoring.analysis_accumulator import (
    LiveAnalysisAccumulator, LiveAnalysisProposal, LiveAnalysisChangeSet,
    LiveAnalysisSnapshot, LiveRelationSummary, LiveRiskSummary, LiveCaseSummary,
)


MAX_PUBLICATION_ITEMS = 32
MAX_PUBLICATION_BYTES = 16_384
MAX_ANALYSIS_SNAPSHOT_BYTES = 131_072  # Development cap; not a history budget.
MAX_ANALYSIS_SNAPSHOT_ITEMS = 256  # Per category; aligned with parsed-prefix item cap.
_NEXT_SESSION_NUMBER = 0
_CHANGE_TYPES = ("CREATED", "UPDATED", "NO_LONGER_MATCHES")
_STATES = ("ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT")
_TYPES = (
    "brute_force", "password_spraying_like", "path_traversal",
    "sql_injection_like", "xss_like", "sensitive_resource_probing_like",
    "web_scanning_like",
)
_RELATION_CHANGES = frozenset(("RELATION_CREATED", "RELATION_UPDATED", "RELATION_NO_LONGER_MATCHES"))
_RISK_CHANGES = frozenset(("RISK_CREATED", "RISK_UPDATED", "RISK_NO_LONGER_PRESENT"))
_CASE_CHANGES = frozenset(("CASE_CREATED", "CASE_UPDATED", "CASE_NO_LONGER_MATCHES"))
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
    "ANALYSIS_SNAPSHOT_TOO_LARGE": "안전한 분석 요약의 byte 상한을 초과했습니다.",
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
class LiveAnalysisPublicationEvent:
    """Only approved safe summaries; never trusted relation/risk/case objects."""

    event_id: str
    session_id: str
    revision: int
    event_type: str
    source_role: str
    relation_changes: tuple[tuple[str, LiveRelationSummary], ...]
    risk_changes: tuple[tuple[str, LiveRiskSummary], ...]
    case_changes: tuple[tuple[str, LiveCaseSummary], ...]
    active_relation_count: int
    active_risk_count: int
    active_case_count: int

    def __post_init__(self) -> None:
        parsed = _parse_event_id(self.event_id)
        if (parsed is None or self.session_id != _session_id(parsed[0])
            or self.event_type != "ANALYSIS_CHANGE" or self.source_role != "application"
            or type(self.revision) is not int or not 1 <= self.revision <= MAX_COUNTER
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in (
                self.active_relation_count, self.active_risk_count, self.active_case_count))
            or not (self.relation_changes or self.risk_changes or self.case_changes)
            or any(type(group) is not tuple for group in (
                self.relation_changes, self.risk_changes, self.case_changes))
            or any(type(change) is not tuple or len(change) != 2
                   for group in (self.relation_changes, self.risk_changes, self.case_changes)
                   for change in group)
            or any(category not in _RELATION_CHANGES
                   or type(item) is not LiveRelationSummary
                   or (category == "RELATION_NO_LONGER_MATCHES") !=
                      (item.state == "NO_LONGER_MATCHES_CURRENT_RESULT")
                   for category, item in self.relation_changes)
            or any(category not in _RISK_CHANGES
                   or type(item) is not LiveRiskSummary
                   or (category == "RISK_NO_LONGER_PRESENT") !=
                      (item.state == "NO_LONGER_PRESENT")
                   for category, item in self.risk_changes)
            or any(category not in _CASE_CHANGES
                   or type(item) is not LiveCaseSummary
                   or (category == "CASE_NO_LONGER_MATCHES") !=
                      (item.state == "NO_LONGER_MATCHES_CURRENT_RESULT")
                   for category, item in self.case_changes)):
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
    analysis: LiveAnalysisSnapshot | None = None

    def __post_init__(self) -> None:
        counters = (self.item_count, self.byte_count,
                    self.latest_committed_detection_revision, self.published_total,
                    self.evicted_total, self.rejected_oversized_total,
                    self.replay_gap_total, self.active_observation_count,
                    self.last_created_count, self.last_updated_count,
                    self.last_no_longer_matches_count)
        if (self.schema_version != "2" or self.state not in ("OPEN", "CLOSED")
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
        if self.analysis is not None and type(self.analysis) is not LiveAnalysisSnapshot:
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")


@dataclass(frozen=True, slots=True)
class LiveReplayResult:
    status: str
    snapshot: LivePublicationSnapshot
    events: tuple[LivePublicationEvent | LiveAnalysisPublicationEvent, ...]
    gap_code: str | None = None
    recovery_action: str | None = None

    def __post_init__(self) -> None:
        if (self.status not in ("INITIAL", "REPLAY", "GAP")
            or type(self.snapshot) is not LivePublicationSnapshot
            or type(self.events) is not tuple
            or any(type(event) not in (LivePublicationEvent, LiveAnalysisPublicationEvent)
                   for event in self.events)
            or (self.status == "GAP") != (self.gap_code is not None)
            or (self.status == "GAP") != (self.recovery_action is not None)
            or self.status == "GAP" and self.events
            or self.gap_code is not None and self.gap_code not in _GAP_MESSAGES):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")


@dataclass(frozen=True, slots=True)
class _StoredEvent:
    event: LivePublicationEvent | LiveAnalysisPublicationEvent
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
    analysis: LiveAnalysisSnapshot | None = None


@dataclass(frozen=True, slots=True)
class LivePublicationProposal:
    """Pre-serialized, safe candidate; only its bound buffer may settle it."""

    revision: int
    event: LivePublicationEvent | None
    _candidate: _BufferState = field(repr=False)
    _change_set: LiveDetectionChangeSet = field(repr=False)
    analysis_event: LiveAnalysisPublicationEvent | None = None
    _analysis_change_set: LiveAnalysisChangeSet | None = field(default=None, repr=False)


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


def _relation_data(item: LiveRelationSummary) -> dict:
    return {"relation_id": item.relation_id, "revision": item.revision,
            "relation_type": item.relation_type, "state": item.state,
            "delta_seconds": item.delta_seconds}


def _risk_data(item: LiveRiskSummary) -> dict:
    return {"risk_id": item.risk_id, "revision": item.revision,
            "state": item.state, "risk_level": item.risk_level,
            "confidence": item.confidence}


def _case_data(item: LiveCaseSummary) -> dict:
    return {"case_id": item.case_id, "revision": item.revision,
            "state": item.state, "rule_id": item.rule_id,
            "included_highest_risk": item.included_highest_risk,
            "included_highest_confidence": item.included_highest_confidence,
            "relation_count": item.relation_count,
            "observation_count": item.observation_count,
            "supporting_relation_count": item.supporting_relation_count,
            "account_reference_status": item.account_reference_status}


def analysis_snapshot_data(snapshot: LiveAnalysisSnapshot | None) -> dict:
    """Explicit public projection, including only current safe items."""
    if snapshot is None:
        return {"schema_version": "1", "analysis_available": False, "revision": None,
                "relation_count": 0, "risk_count": 0, "case_count": 0,
                "independent_observation_count": 0,
                "relations": [], "risks": [], "cases": [], "bounded_warnings": []}
    if type(snapshot) is not LiveAnalysisSnapshot:
        raise LivePublicationError("INVALID_CHANGE_SET")
    return {"schema_version": "1", "analysis_available": True,
            "revision": snapshot.revision,
            "relation_count": snapshot.relation_count,
            "risk_count": snapshot.risk_count, "case_count": snapshot.case_count,
            "independent_observation_count": snapshot.independent_observation_count,
            "relations": [_relation_data(item) for item in snapshot.relations
                          if item.state == "ACTIVE"],
            "risks": [_risk_data(item) for item in snapshot.risks
                      if item.state == "CURRENT"],
            "cases": [_case_data(item) for item in snapshot.cases
                      if item.state == "CURRENT"],
            "bounded_warnings": list(snapshot.fixed_warning_codes)}


def serialize_live_analysis_publication_event(event: LiveAnalysisPublicationEvent) -> bytes:
    if type(event) is not LiveAnalysisPublicationEvent:
        raise LivePublicationError("INVALID_CHANGE_SET")
    return _json_bytes({
        "event_id": event.event_id, "session_id": event.session_id,
        "revision": event.revision, "event_type": event.event_type,
        "source_role": event.source_role,
        "relation_changes": [dict(_relation_data(item), change_type=category)
                             for category, item in event.relation_changes],
        "risk_changes": [dict(_risk_data(item), change_type=category)
                         for category, item in event.risk_changes],
        "case_changes": [dict(_case_data(item), change_type=category)
                         for category, item in event.case_changes],
        "summary": {"relation_count": event.active_relation_count,
                    "risk_count": event.active_risk_count,
                    "case_count": event.active_case_count},
        "bounded_warnings": [],
    })


def serialize_live_publication_snapshot(snapshot: LivePublicationSnapshot) -> bytes:
    if type(snapshot) is not LivePublicationSnapshot:
        raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
    data = {
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
    }
    data["analysis"] = analysis_snapshot_data(snapshot.analysis)
    return _json_bytes(data)


class LivePublicationBuffer:
    """Single-caller bounded replay of committed, safe detection changes."""

    __slots__ = ("_accumulator", "_analysis", "_session_number", "_session_id", "_max_items",
                 "_max_bytes", "_state", "_last_committed_revision", "_active")

    def __init__(self, accumulator: LiveDetectionAccumulator,
                 max_items: int = MAX_PUBLICATION_ITEMS,
                 max_bytes: int = MAX_PUBLICATION_BYTES,
                 *, analysis_accumulator: LiveAnalysisAccumulator | None = None):
        if type(accumulator) is not LiveDetectionAccumulator:
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        if not _positive(max_items, MAX_PUBLICATION_ITEMS) or not _positive(max_bytes, MAX_PUBLICATION_BYTES):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        snapshot = accumulator.snapshot()
        if (snapshot.closed or snapshot.revision != 0 or snapshot.active_proposal
            or accumulator._publication_bound):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        if analysis_accumulator is not None and (
            type(analysis_accumulator) is not LiveAnalysisAccumulator
            or analysis_accumulator._detection is not accumulator
            or analysis_accumulator.snapshot().closed
            or analysis_accumulator.snapshot().revision != 0):
            raise LivePublicationError("INVALID_BUFFER_ARGUMENT")
        global _NEXT_SESSION_NUMBER
        number = _add(_NEXT_SESSION_NUMBER, 1)
        _NEXT_SESSION_NUMBER = number
        accumulator._publication_bound = True
        self._accumulator = accumulator
        self._analysis = analysis_accumulator
        self._session_number = number
        self._session_id = _session_id(number)
        self._max_items = max_items
        self._max_bytes = max_bytes
        self._state = _BufferState((), 0, 0, 0, 0, 0, 0, 0, 0, (0, 0, 0), False,
                                   analysis_accumulator.snapshot() if analysis_accumulator else None)
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
            "2", "CLOSED" if state.closed else "OPEN", self._session_id,
            len(state.records), state.byte_count, self._max_items, self._max_bytes,
            state.records[0].event.event_id if state.records else None,
            state.records[-1].event.event_id if state.records else None,
            (self._last_committed_revision if state.closed
             else self._accumulator.snapshot().revision),
            state.published_total, state.evicted_total,
            state.rejected_oversized_total, state.replay_gap_total,
            state.active_observation_count, *state.last_counts,
            state.analysis,
        )

    def publish(self, change_set: LiveDetectionChangeSet) -> LivePublicationEvent | None:
        if self._analysis is not None:
            raise LivePublicationError("INVALID_CHANGE_SET")
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
        if self._analysis is not None:
            raise LivePublicationError("INVALID_CHANGE_SET")
        return self._prepare_detection(detection_proposal)

    def _prepare_detection(self, detection_proposal: LiveDetectionProposal) -> LivePublicationProposal:
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

    def prepare_batch(self, detection_proposal: LiveDetectionProposal,
                      analysis_proposal: LiveAnalysisProposal) -> LivePublicationProposal:
        """Prepare both ordered events and one immutable buffer replacement pre-ack."""
        if (self._analysis is None or type(detection_proposal) is not LiveDetectionProposal
            or type(analysis_proposal) is not LiveAnalysisProposal):
            raise LivePublicationError("INVALID_CHANGE_SET")
        analysis = self._analysis
        if (analysis._active is not analysis_proposal or analysis._candidate is None
            or analysis_proposal.target_revision != detection_proposal.proposal_revision
            or analysis._candidate_detection_state is not detection_proposal._committed_state):
            raise LivePublicationError("PROPOSAL_MISMATCH")
        # Existing detection event builder/serializer is unchanged.
        proposal = self._prepare_detection(detection_proposal)
        try:
            snapshot = analysis._candidate.snapshot
            projection_size = len(_json_bytes(analysis_snapshot_data(snapshot)))
            if (projection_size > MAX_ANALYSIS_SNAPSHOT_BYTES
                or any(count > MAX_ANALYSIS_SNAPSHOT_ITEMS for count in (
                    snapshot.relation_count, snapshot.risk_count, snapshot.case_count))):
                raise LivePublicationError("ANALYSIS_SNAPSHOT_TOO_LARGE")
            changes = analysis._candidate.change_set.changes
            relation_by_id = {item.relation_id: item for item in snapshot.relations}
            risk_by_id = {item.risk_id: item for item in snapshot.risks}
            case_by_id = {item.case_id: item for item in snapshot.cases}
            relation_changes = tuple((item.category, relation_by_id[item.public_id]) for item in changes
                                     if item.category.startswith("RELATION_"))
            risk_changes = tuple((item.category, risk_by_id[item.public_id]) for item in changes
                                 if item.category.startswith("RISK_"))
            case_changes = tuple((item.category, case_by_id[item.public_id]) for item in changes
                                 if item.category.startswith("CASE_"))
            if len(relation_changes) + len(risk_changes) + len(case_changes) != len(changes):
                raise LivePublicationError("INVALID_CHANGE_SET")
            if any(len(group) > MAX_ANALYSIS_SNAPSHOT_ITEMS for group in (
                    relation_changes, risk_changes, case_changes)):
                raise LivePublicationError("ANALYSIS_SNAPSHOT_TOO_LARGE")
            candidate = proposal._candidate
            event = None
            if changes:
                next_number = _add(candidate.last_event_number, 1)
                event = LiveAnalysisPublicationEvent(
                    _event_id(self._session_number, next_number), self._session_id,
                    proposal.revision, "ANALYSIS_CHANGE", "application",
                    relation_changes, risk_changes, case_changes,
                    snapshot.relation_count, snapshot.risk_count, snapshot.case_count)
                encoded = serialize_live_analysis_publication_event(event)
                if len(encoded) > self._max_bytes:
                    raise LivePublicationError("EVENT_TOO_LARGE")
                detection_bytes = (len(serialize_live_publication_event(proposal.event))
                                   if proposal.event else 0)
                if (detection_bytes + len(encoded) > self._max_bytes
                    or (1 if proposal.event is None else 2) > self._max_items):
                    raise LivePublicationError("EVENT_TOO_LARGE")
                stored = candidate.records + (_StoredEvent(event, encoded),)
                byte_count = _add(candidate.byte_count, len(encoded))
                evicted = 0
                while len(stored) > self._max_items or byte_count > self._max_bytes:
                    byte_count -= len(stored[0].encoded)
                    stored = stored[1:]
                    evicted += 1
                candidate = replace(candidate, records=stored, byte_count=byte_count,
                                    last_event_number=next_number,
                                    published_total=_add(candidate.published_total, 1),
                                    evicted_total=_add(candidate.evicted_total, evicted))
            candidate = replace(candidate, analysis=snapshot)
            prepared = replace(proposal, _candidate=candidate, analysis_event=event,
                               _analysis_change_set=analysis._candidate.change_set)
            self._active = prepared
            return prepared
        except LivePublicationError:
            self._active = None
            raise
        except Exception:
            self._active = None
            raise LivePublicationError("INVALID_CHANGE_SET") from None

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
        if proposal._analysis_change_set is not None and (
            self._analysis is None or self._analysis._state.revision != proposal.revision
            or self._analysis._state.change_set is not proposal._analysis_change_set):
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
        self._analysis = None
