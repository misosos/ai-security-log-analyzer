"""Private v3 pair adapter with one bounded, safe public replay cursor."""

from dataclasses import dataclass, field
import json
import secrets

from app.live_monitoring.multi_source import InternalPairRuntime, ROLES
from app.live_monitoring.publication import (
    LivePublicationBuffer, LivePublicationProposal, LivePublicationEvent,
    LiveAnalysisPublicationEvent, MAX_PUBLICATION_ITEMS, MAX_PUBLICATION_BYTES,
    _event_id, _parse_event_id, _session_id, serialize_live_publication_event,
    serialize_live_analysis_publication_event,
)
from app.live_monitoring.worker import LiveWorkerState


MAX_PAIR_SNAPSHOT_BYTES = 131_072
_OBSERVATION_KEYS = frozenset((
    "event_id", "session_id", "revision", "event_type", "created_count", "updated_count",
    "no_longer_matches_count", "active_observation_count", "published_observation_count",
    "observations"))
_ANALYSIS_KEYS = frozenset((
    "event_id", "session_id", "revision", "event_type", "source_role",
    "relation_changes", "risk_changes", "case_changes", "summary", "bounded_warnings"))
_CHANGE_KEYS = frozenset(("observation_id", "observation_revision", "change_type", "state",
                          "detection_type", "accumulator_revision"))
_RELATION_KEYS = frozenset(("relation_id", "revision", "relation_type", "state",
                            "delta_seconds", "change_type"))
_RISK_KEYS = frozenset(("risk_id", "revision", "state", "risk_level", "confidence",
                        "change_type"))
_CASE_KEYS = frozenset(("case_id", "revision", "state", "rule_id", "included_highest_risk",
                        "included_highest_confidence", "relation_count", "observation_count",
                        "supporting_relation_count", "account_reference_status", "change_type"))


def _closed_projection(payload: dict, kind: str) -> None:
    keys = _OBSERVATION_KEYS if kind == "observation_changes" else _ANALYSIS_KEYS
    if type(payload) is not dict or payload.keys() != keys:
        raise PairPublicationError("PAIR_PUBLICATION_INVALID")
    groups = (("observations", _CHANGE_KEYS),) if kind == "observation_changes" else (
        ("relation_changes", _RELATION_KEYS), ("risk_changes", _RISK_KEYS),
        ("case_changes", _CASE_KEYS))
    for field, item_keys in groups:
        items = payload[field]
        if type(items) is not list or any(type(item) is not dict or item.keys() != item_keys
                                            for item in items):
            raise PairPublicationError("PAIR_PUBLICATION_INVALID")
    if kind == "analysis_changes" and (
        type(payload["summary"]) is not dict
        or payload["summary"].keys() != frozenset(("relation_count", "risk_count", "case_count"))
        or type(payload["bounded_warnings"]) is not list):
        raise PairPublicationError("PAIR_PUBLICATION_INVALID")


class PairPublicationError(ValueError):
    _CODES = frozenset(("PAIR_PUBLICATION_INVALID", "PAIR_PUBLICATION_TOO_LARGE",
                        "PAIR_PUBLICATION_FAILED", "PAIR_SNAPSHOT_TOO_LARGE"))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "PAIR_PUBLICATION_FAILED"
        super().__init__(f"{self.code}: 두 로그의 공개 결과를 준비할 수 없습니다.")

    def __repr__(self) -> str:
        return f"PairPublicationError(code={self.code!r})"


def _safe_bytes(value: dict) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise PairPublicationError("PAIR_PUBLICATION_FAILED") from None


@dataclass(frozen=True, slots=True)
class PairEvent:
    event_id: str
    source_role: str
    event_type: str
    encoded: bytes = field(repr=False)

    @property
    def payload(self) -> dict:
        return json.loads(self.encoded)


@dataclass(frozen=True, slots=True)
class PairReplay:
    status: str
    events: tuple[PairEvent, ...]
    gap_code: str | None = None
    affected_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _PairProposal:
    records: tuple[PairEvent, ...]
    byte_count: int
    last_number: int
    published_total: int
    evicted_total: int
    evicted_high: tuple[int, int]
    events: tuple[PairEvent, ...]


class PairPublicationBuffer:
    """One atomic in-memory swap per source step, with bounded global replay."""

    __slots__ = ("session_id", "_session_number", "_records", "_byte_count", "_last_number",
                 "_published_total", "_evicted_total", "_evicted_high", "_gap_total", "_active",
                 "_closed")

    def __init__(self):
        # Transport epoch is random and independent of source metadata.
        self._session_number = secrets.randbelow(1_000_000_000_000 - 1) + 1
        self.session_id = _session_id(self._session_number)
        self._records: tuple[PairEvent, ...] = ()
        self._byte_count = 0
        self._last_number = 0
        self._published_total = 0
        self._evicted_total = 0
        self._evicted_high = (0, 0)
        self._gap_total = 0
        self._active: _PairProposal | None = None
        self._closed = False

    def __repr__(self) -> str:
        return f"PairPublicationBuffer(closed={self._closed}, item_count={len(self._records)})"

    @property
    def item_count(self) -> int:
        return len(self._records)

    @property
    def byte_count(self) -> int:
        return self._byte_count

    @property
    def published_total(self) -> int:
        return self._published_total

    @property
    def evicted_total(self) -> int:
        return self._evicted_total

    @property
    def replay_gap_total(self) -> int:
        return self._gap_total

    @property
    def earliest_event_id(self) -> str | None:
        return self._records[0].event_id if self._records else None

    @property
    def latest_event_id(self) -> str | None:
        return self._records[-1].event_id if self._records else None

    def prepare(self, role: str, source: LivePublicationProposal) -> _PairProposal:
        if (self._closed or self._active is not None or role not in ROLES
            or type(source) is not LivePublicationProposal):
            raise PairPublicationError("PAIR_PUBLICATION_INVALID")
        records = self._records
        byte_count = self._byte_count
        number = self._last_number
        published = self._published_total
        evicted = self._evicted_total
        high = list(self._evicted_high)
        events = []
        for original, kind, serializer in (
            (source.event, "observation_changes", serialize_live_publication_event),
            (source.analysis_event, "analysis_changes", serialize_live_analysis_publication_event),
        ):
            if original is None:
                continue
            if (kind == "observation_changes" and type(original) is not LivePublicationEvent
                or kind == "analysis_changes" and type(original) is not LiveAnalysisPublicationEvent):
                raise PairPublicationError("PAIR_PUBLICATION_INVALID")
            try:
                payload = json.loads(serializer(original))
                _closed_projection(payload, kind)
                number += 1
                event_id = _event_id(self._session_number, number)
                payload.update(schema_version="3", event_id=event_id, session_id=self.session_id,
                               source_role=role, detection_revision=source.revision,
                               analysis_revision=source.revision)
                encoded = _safe_bytes(payload)
            except PairPublicationError:
                raise
            except Exception:
                raise PairPublicationError("PAIR_PUBLICATION_FAILED") from None
            if len(encoded) > MAX_PUBLICATION_BYTES:
                raise PairPublicationError("PAIR_PUBLICATION_TOO_LARGE")
            event = PairEvent(event_id, role, kind, encoded)
            records += (event,)
            events.append(event)
            byte_count += len(encoded)
            published += 1
        if sum(len(event.encoded) for event in events) > MAX_PUBLICATION_BYTES:
            raise PairPublicationError("PAIR_PUBLICATION_TOO_LARGE")
        while len(records) > MAX_PUBLICATION_ITEMS or byte_count > MAX_PUBLICATION_BYTES:
            oldest = records[0]
            byte_count -= len(oldest.encoded)
            records = records[1:]
            evicted += 1
            index = ROLES.index(oldest.source_role)
            high[index] = max(high[index], int(oldest.event_id.rsplit("-", 1)[1]))
        proposal = _PairProposal(records, byte_count, number, published, evicted,
                                 tuple(high), tuple(events))
        self._active = proposal
        return proposal

    def abort(self, proposal: _PairProposal) -> None:
        if proposal is not self._active:
            raise PairPublicationError("PAIR_PUBLICATION_INVALID")
        self._active = None

    def _swap(self, proposal: _PairProposal) -> None:
        self._records, self._byte_count = proposal.records, proposal.byte_count
        self._last_number, self._published_total = proposal.last_number, proposal.published_total
        self._evicted_total, self._evicted_high = proposal.evicted_total, proposal.evicted_high

    def commit(self, proposal: _PairProposal) -> None:
        if self._closed or proposal is not self._active:
            raise PairPublicationError("PAIR_PUBLICATION_INVALID")
        try:
            self._swap(proposal)
        finally:
            self._active = None

    def _gap(self, code: str, affected: tuple[str, ...] = ROLES) -> PairReplay:
        self._gap_total += 1
        return PairReplay("GAP", (), code, affected)

    def replay_after(self, cursor: str | None) -> PairReplay:
        if self._closed:
            return self._gap("BUFFER_CLOSED")
        if cursor is None:
            return PairReplay("INITIAL", self._records)
        parsed = _parse_event_id(cursor)
        if parsed is None:
            return self._gap("MALFORMED_EVENT_ID")
        session_number, number = parsed
        if session_number != self._session_number:
            return self._gap("FOREIGN_SESSION")
        if number > self._last_number:
            return self._gap("FUTURE_EVENT_ID")
        for index, event in enumerate(self._records):
            if event.event_id == cursor:
                return PairReplay("REPLAY", self._records[index + 1:])
        if self._evicted_total:
            affected = tuple(role for role, high in zip(ROLES, self._evicted_high)
                             if high >= number)
            return self._gap("EVICTED_EVENT_ID", affected or ROLES)
        return self._gap("UNKNOWN_EVENT_ID")

    def close(self) -> None:
        self._closed = True
        self._active = None
        self._records = ()
        self._byte_count = 0


class _PairPublicationAdapter:
    """Keep the existing worker's pre-ack proposal and post-ack commit boundary."""

    __slots__ = ("_source", "_pair", "_role", "_pair_proposal")

    def __init__(self, source: LivePublicationBuffer, pair: PairPublicationBuffer, role: str):
        self._source = source
        self._pair = pair
        self._role = role
        self._pair_proposal = None

    @property
    def _active(self):
        return self._source._active

    def snapshot(self):
        return self._source.snapshot()

    def prepare_batch(self, detection, analysis):
        proposal = self._source.prepare_batch(detection, analysis)
        self._pair_proposal = self._pair.prepare(self._role, proposal)
        return proposal

    def abort(self, proposal):
        if self._pair_proposal is not None:
            self._pair.abort(self._pair_proposal)
            self._pair_proposal = None
        self._source.abort(proposal)

    def commit_prepared(self, proposal):
        committed = self._source.commit_prepared(proposal)
        pair_proposal = self._pair_proposal
        self._pair_proposal = None
        if pair_proposal is None:
            raise PairPublicationError("PAIR_PUBLICATION_INVALID")
        self._pair.commit(pair_proposal)
        return committed

    def close(self):
        self._pair_proposal = None
        self._source.close()


def attach_pair_publication(runtime: InternalPairRuntime) -> PairPublicationBuffer:
    if (type(runtime) is not InternalPairRuntime or runtime.state != "READY"
        or any(worker.snapshot().state is not LiveWorkerState.READY
               or type(worker._publication) is not LivePublicationBuffer
               for worker in runtime.workers.values())):
        raise PairPublicationError("PAIR_PUBLICATION_INVALID")
    pair = PairPublicationBuffer()
    for role in ROLES:
        worker = runtime.workers[role]
        worker._publication = _PairPublicationAdapter(worker._publication, pair, role)
    return pair
