"""Bounded, transactional detection state for one trusted live source.

This module does not publish detections or settle record leases. Raw events and
detector results are trusted internal values; only summaries are privacy-safe.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math

from app.analyzer.pipeline import detect_attacks
from app.live_monitoring.config import ROLES
from app.live_monitoring.core import MAX_COUNTER
from app.live_monitoring.parser_adapter import LiveParseBatch, LiveParseOutcome
from app.models.schemas import DetectionResult, Evidence, NormalizedEvent


_SLOTS = (
    ("brute_force", "brute_force"),
    ("password_spray", "password_spraying_like"),
    ("path_traversal", "path_traversal"),
    ("sql_injection_like", "sql_injection_like"),
    ("xss_like", "xss_like"),
    ("sensitive_resource_probing_like", "sensitive_resource_probing_like"),
    ("web_scanning_like", "web_scanning_like"),
)
_FEATURES = frozenset((
    "failure_count", "target_users", "login_succeeded", "within_window",
    "window_seconds", "average_interval", "interval_variability",
    "unique_target_count",
))
_SOURCE_NAMES = {"application": "application", "ssh": "ssh", "access": "access_log"}
_REJECTIONS = {
    "application": "MALFORMED_APPLICATION_RECORD",
    "ssh": "MALFORMED_SSH_RECORD",
    "access": "MALFORMED_ACCESS_RECORD",
}
_MESSAGES = {
    "INVALID_ARGUMENT": "detection accumulator 입력 형식을 확인하십시오.",
    "UNSUPPORTED_SOURCE_ROLE": "지원하는 로그 역할을 사용하십시오.",
    "INVALID_HISTORY_LIMIT": "history 상한을 확인하십시오.",
    "INVALID_PARSE_BATCH": "parser batch 계약을 확인하십시오.",
    "SOURCE_MISMATCH": "로그 역할이 일치하지 않습니다.",
    "ACTIVE_PROPOSAL_EXISTS": "진행 중인 proposal을 먼저 정산하십시오.",
    "HISTORY_LIMIT_EXCEEDED": "history 상한에 도달했습니다. 세션을 중지하고 검토하십시오.",
    "UNEXPECTED_EVENT_TYPE": "event 형식을 확인하십시오.",
    "INVALID_RAW_FIELD": "event 원문 형식을 확인하십시오.",
    "DETECTOR_CONTRACT_FAILURE": "detector 입력 계약을 확인하십시오.",
    "DETECTION_INVARIANT_FAILURE": "detector 결과 계약을 확인하십시오.",
    "FOREIGN_PROPOSAL": "다른 accumulator의 proposal입니다.",
    "STALE_PROPOSAL": "만료된 proposal입니다.",
    "FORGED_PROPOSAL": "proposal 계약을 확인하십시오.",
    "DOUBLE_SETTLEMENT": "이미 정산된 proposal입니다.",
    "REVISION_MISMATCH": "proposal revision이 일치하지 않습니다.",
    "COUNTER_OVERFLOW": "집계 상한에 도달했습니다.",
    "UNEXPECTED_DETECTOR_FAILURE": "detector 처리가 중단됐습니다.",
    "OPERATION_AFTER_CLOSE": "닫힌 accumulator는 처리할 수 없습니다.",
    "ALREADY_OWNED": "accumulator는 이미 worker에 연결됐습니다.",
}
_NEXT_OWNER_TOKEN = 0
_CHANGE_TYPES = frozenset(("CREATED", "UPDATED", "NO_LONGER_MATCHES"))
_STATES = frozenset(("ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT"))


class LiveDetectionError(ValueError):
    """Fixed code and input-free message; no raw exception chaining."""

    def __init__(self, code: str):
        if type(code) is not str or code not in _MESSAGES:
            code = "INVALID_ARGUMENT"
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LiveDetectionError(code={self.code!r})"


def _bounded_add(left: int, right: int) -> int:
    if (type(left) is not int or type(right) is not int
        or not 0 <= left <= MAX_COUNTER or not 0 <= right <= MAX_COUNTER - left):
        raise LiveDetectionError("COUNTER_OVERFLOW")
    return left + right


def _owner_token() -> int:
    global _NEXT_OWNER_TOKEN
    _NEXT_OWNER_TOKEN = _bounded_add(_NEXT_OWNER_TOKEN, 1)
    return _NEXT_OWNER_TOKEN


def _event_bytes(event: NormalizedEvent, role: str, limit: int) -> int:
    if (type(event) is not NormalizedEvent or type(event.source) is not str
        or event.source != _SOURCE_NAMES[role]
        or type(event.timestamp) is not datetime
        or event.timestamp.tzinfo is not timezone.utc
        or type(event.event_type) not in (str, type(None))
        or type(event.src_ip) not in (str, type(None))):
        raise LiveDetectionError("UNEXPECTED_EVENT_TYPE")
    if type(event.raw) is not str:
        raise LiveDetectionError("INVALID_RAW_FIELD")
    # A Unicode code point takes at least one UTF-8 byte; avoid a larger
    # temporary encoded allocation once this event cannot fit the budget.
    if len(event.raw) > limit:
        raise LiveDetectionError("HISTORY_LIMIT_EXCEEDED")
    try:
        size = len(event.raw.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise LiveDetectionError("INVALID_RAW_FIELD") from None
    if size > MAX_COUNTER:
        raise LiveDetectionError("COUNTER_OVERFLOW")
    return size


def _validate_batch(batch: LiveParseBatch, role: str, last_sequence: int) -> tuple[NormalizedEvent, ...]:
    if type(batch) is not LiveParseBatch or type(batch.source_role) is not str:
        raise LiveDetectionError("INVALID_PARSE_BATCH")
    if batch.source_role != role:
        raise LiveDetectionError("SOURCE_MISMATCH")
    if (type(batch.outcomes) is not tuple or not batch.outcomes
        or any(type(outcome) is not LiveParseOutcome for outcome in batch.outcomes)
        or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in (
            batch.parsed_count, batch.ignored_count, batch.rejected_count))
        or batch.parsed_count + batch.ignored_count + batch.rejected_count != len(batch.outcomes)):
        raise LiveDetectionError("INVALID_PARSE_BATCH")
    parsed = []
    counts = {"PARSED": 0, "IGNORED": 0, "REJECTED": 0}
    sequence = last_sequence
    for outcome in batch.outcomes:
        if (type(outcome.sequence) is not int or not sequence < outcome.sequence <= MAX_COUNTER
            or type(outcome.status) is not str or outcome.status not in counts):
            raise LiveDetectionError("INVALID_PARSE_BATCH")
        sequence = outcome.sequence
        counts[outcome.status] += 1
        if outcome.status == "PARSED":
            if type(outcome.event) is not NormalizedEvent or outcome.fixed_reason_code is not None:
                raise LiveDetectionError("INVALID_PARSE_BATCH")
            parsed.append(outcome.event)
        elif outcome.status == "IGNORED":
            if outcome.event is not None or outcome.fixed_reason_code is not None:
                raise LiveDetectionError("INVALID_PARSE_BATCH")
        elif outcome.event is not None or outcome.fixed_reason_code != _REJECTIONS[role]:
            raise LiveDetectionError("INVALID_PARSE_BATCH")
    if (counts["PARSED"] != batch.parsed_count
        or counts["IGNORED"] != batch.ignored_count
        or counts["REJECTED"] != batch.rejected_count):
        raise LiveDetectionError("INVALID_PARSE_BATCH")
    return tuple(parsed)


def _valid_time(value: datetime) -> bool:
    return type(value) is datetime and value.tzinfo is timezone.utc


def _validate_detection(detection: DetectionResult, expected_type: str) -> None:
    if (type(detection) is not DetectionResult or type(detection.is_detected) is not bool
        or type(detection.evidence) is not list):
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    if detection.is_detected:
        if detection.detection_type != expected_type or not detection.evidence:
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    elif detection.detection_type is not None or detection.evidence:
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    for evidence in detection.evidence:
        if (type(evidence) is not Evidence or type(evidence.type) is not str
            or type(evidence.source) is not str or not evidence.type or not evidence.source
            or type(evidence.value) not in (str, int, float, bool)
            or (type(evidence.value) is float and not math.isfinite(evidence.value))
            or (evidence.timestamp is not None and not _valid_time(evidence.timestamp))
            or (evidence.time_range is not None and (
                type(evidence.time_range) is not tuple or len(evidence.time_range) != 2
                or not all(_valid_time(item) for item in evidence.time_range)
                or evidence.time_range[0] > evidence.time_range[1]))):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


def _validate_features(features: object) -> None:
    if type(features) is not dict or set(features) != _FEATURES:
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    if (type(features["failure_count"]) is not int or features["failure_count"] < 0
        or type(features["unique_target_count"]) is not int
        or features["unique_target_count"] < 0
        or type(features["target_users"]) is not list
        or any(type(user) is not str for user in features["target_users"])
        or features["unique_target_count"] != len(features["target_users"])
        or type(features["login_succeeded"]) is not bool
        or type(features["within_window"]) is not bool):
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    for name in ("window_seconds", "average_interval", "interval_variability"):
        value = features[name]
        if (type(value) not in (int, float) or value < 0
            or (type(value) is float and not math.isfinite(value))):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


def _detection_counts(result: object, history: tuple[NormalizedEvent, ...]) -> tuple[int, tuple[tuple[str, int], ...]]:
    if type(result) is not dict:
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    expected_subjects = {event.src_ip for event in history if event.src_ip is not None}
    if (any(type(subject) is not str for subject in expected_subjects)
        or set(result) != expected_subjects):
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
    counts = {kind: 0 for _, kind in _SLOTS}
    for subject_result in result.values():
        if (type(subject_result) is not dict or set(subject_result) != {"features", "detections"}
            or type(subject_result["detections"]) is not dict
            or set(subject_result["detections"]) != {slot for slot, _ in _SLOTS}):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")
        _validate_features(subject_result["features"])
        for slot, kind in _SLOTS:
            detection = subject_result["detections"][slot]
            _validate_detection(detection, kind)
            counts[kind] += detection.is_detected
    return len(result), tuple((kind, counts[kind]) for _, kind in _SLOTS)


def _safe_detection_counts(result: object, history: tuple[NormalizedEvent, ...]) -> tuple[int, tuple[tuple[str, int], ...]]:
    try:
        return _detection_counts(result, history)
    except LiveDetectionError:
        raise
    except Exception:
        raise LiveDetectionError("DETECTION_INVARIANT_FAILURE") from None


@dataclass(frozen=True, slots=True)
class LiveDetectionSummary:
    schema_version: str
    proposal_revision: int
    source_role: str
    history_record_count: int
    history_byte_count: int
    subject_count: int
    detected_type_counts: tuple[tuple[str, int], ...]
    parsed_input_count: int
    ignored_input_count: int
    rejected_input_count: int
    fixed_warning_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        counts = (self.proposal_revision, self.history_record_count, self.history_byte_count,
                  self.subject_count, self.parsed_input_count, self.ignored_input_count,
                  self.rejected_input_count)
        if (self.schema_version != "1" or type(self.source_role) is not str
            or self.source_role not in ROLES
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.proposal_revision < 1
            or type(self.detected_type_counts) is not tuple
            or any(type(pair) is not tuple or len(pair) != 2 for pair in self.detected_type_counts)
            or tuple(kind for kind, _ in self.detected_type_counts) != tuple(kind for _, kind in _SLOTS)
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER
                   for _, value in self.detected_type_counts)
            or any(value > self.subject_count for _, value in self.detected_type_counts)
            or type(self.fixed_warning_codes) is not tuple or self.fixed_warning_codes):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


@dataclass(frozen=True, slots=True)
class LiveDetectionSnapshot:
    schema_version: str
    source_role: str
    revision: int
    history_record_count: int
    history_byte_count: int
    subject_count: int
    detected_type_counts: tuple[tuple[str, int], ...]
    total_parsed: int
    total_ignored: int
    total_rejected: int
    active_proposal: bool
    active_observation_count: int = 0
    closed: bool = False

    def __post_init__(self) -> None:
        counts = (self.revision, self.history_record_count, self.history_byte_count,
                  self.subject_count, self.total_parsed, self.total_ignored, self.total_rejected)
        if (self.schema_version != "1" or type(self.source_role) is not str
            or self.source_role not in ROLES
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.history_record_count != self.total_parsed
            or type(self.active_proposal) is not bool
            or type(self.closed) is not bool
            or type(self.active_observation_count) is not int
            or not 0 <= self.active_observation_count <= MAX_COUNTER
            or type(self.detected_type_counts) is not tuple
            or any(type(pair) is not tuple or len(pair) != 2 for pair in self.detected_type_counts)
            or tuple(kind for kind, _ in self.detected_type_counts) != tuple(kind for _, kind in _SLOTS)
            or any(type(value) is not int or not 0 <= value <= self.subject_count
                   for _, value in self.detected_type_counts)):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


@dataclass(frozen=True, slots=True)
class LiveDetectionChange:
    observation_id: str
    observation_revision: int
    change_type: str
    state: str
    detection_type: str
    accumulator_revision: int

    def __post_init__(self) -> None:
        suffix = self.observation_id[9:] if type(self.observation_id) is str else ""
        if (type(self.observation_id) is not str
            or not self.observation_id.startswith("LIVE-OBS-")
            or not 6 <= len(suffix) <= 19 or any(char not in "0123456789" for char in suffix)
            or int(suffix) == 0
            or type(self.observation_revision) is not int or not 1 <= self.observation_revision <= MAX_COUNTER
            or type(self.accumulator_revision) is not int or not 1 <= self.accumulator_revision <= MAX_COUNTER
            or type(self.change_type) is not str or self.change_type not in _CHANGE_TYPES
            or type(self.state) is not str or self.state not in _STATES
            or type(self.detection_type) is not str
            or self.detection_type not in {kind for _, kind in _SLOTS}
            or (self.change_type == "NO_LONGER_MATCHES") != (
                self.state == "NO_LONGER_MATCHES_CURRENT_RESULT")):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


@dataclass(frozen=True, slots=True)
class LiveDetectionChangeSet:
    accumulator_revision: int
    changes: tuple[LiveDetectionChange, ...]
    safe_summary: LiveDetectionSummary

    def __post_init__(self) -> None:
        if (type(self.accumulator_revision) is not int
            or type(self.safe_summary) is not LiveDetectionSummary
            or self.accumulator_revision != self.safe_summary.proposal_revision
            or type(self.changes) is not tuple
            or any(type(change) is not LiveDetectionChange
                   or change.accumulator_revision != self.accumulator_revision
                   for change in self.changes)
            or len({change.observation_id for change in self.changes}) != len(self.changes)):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")


@dataclass(frozen=True, slots=True)
class _Observation:
    observation_id: str
    revision: int
    first_revision: int
    latest_revision: int
    state: str
    _subject: str = field(repr=False)
    _slot: str = field(repr=False)
    _detection: DetectionResult = field(repr=False)


def _canonical_detection(detection: DetectionResult) -> tuple:
    return (
        detection.is_detected, detection.detection_type,
        tuple((e.type, e.value, e.source, e.timestamp, e.time_range)
              for e in detection.evidence),
    )


def _prepare_observations(previous: tuple[_Observation, ...], result: dict,
                          next_id: int, revision: int,
                          summary: LiveDetectionSummary) -> tuple[tuple[_Observation, ...], int, LiveDetectionChangeSet, int]:
    old = {(item._subject, item._slot): item for item in previous}
    updated = dict(old)
    changes = []
    for subject, entry in result.items():
        for slot, kind in _SLOTS:
            detection = entry["detections"][slot]
            prior = old.get((subject, slot))
            if detection.is_detected:
                if prior is None:
                    next_id = _bounded_add(next_id, 1)
                    obs_id = f"LIVE-OBS-{next_id:06d}"
                    item = _Observation(obs_id, 1, revision, revision, "ACTIVE", subject, slot, detection)
                    change_type = "CREATED"
                elif (prior.state != "ACTIVE"
                      or _canonical_detection(prior._detection) != _canonical_detection(detection)):
                    item = _Observation(prior.observation_id, _bounded_add(prior.revision, 1),
                                        prior.first_revision, revision, "ACTIVE", subject, slot, detection)
                    change_type = "UPDATED"
                else:
                    continue
                updated[(subject, slot)] = item
            elif prior is not None and prior.state == "ACTIVE":
                item = _Observation(prior.observation_id, _bounded_add(prior.revision, 1),
                                    prior.first_revision, revision, "NO_LONGER_MATCHES_CURRENT_RESULT",
                                    subject, slot, prior._detection)
                updated[(subject, slot)] = item
                change_type = "NO_LONGER_MATCHES"
            else:
                continue
            changes.append(LiveDetectionChange(item.observation_id, item.revision, change_type,
                                               item.state, kind, revision))
    # Preserve first-allocation order; inactive slots remain available for reactivation.
    observations = tuple(sorted(updated.values(), key=lambda item: int(item.observation_id[9:])))
    active_count = sum(item.state == "ACTIVE" for item in observations)
    return observations, next_id, LiveDetectionChangeSet(revision, tuple(changes), summary), active_count


@dataclass(frozen=True, slots=True)
class _CommittedState:
    history: tuple[NormalizedEvent, ...] = field(repr=False)
    history_bytes: int
    detection: dict = field(repr=False)
    subject_count: int
    type_counts: tuple[tuple[str, int], ...]
    revision: int
    parsed: int
    ignored: int
    rejected: int
    last_sequence: int
    observations: tuple[_Observation, ...] = field(repr=False)
    next_observation_id: int
    last_change_set: LiveDetectionChangeSet | None
    active_observation_count: int


@dataclass(frozen=True, slots=True)
class LiveDetectionProposal:
    proposal_revision: int
    source_role: str
    _proposal_id: int = field(repr=False)
    _owner_token: int = field(repr=False)
    _history: tuple[NormalizedEvent, ...] = field(repr=False)
    _history_bytes: int = field(repr=False)
    _detection: dict = field(repr=False)
    _summary: LiveDetectionSummary
    _last_sequence: int = field(repr=False)
    _total_parsed: int = field(repr=False)
    _total_ignored: int = field(repr=False)
    _total_rejected: int = field(repr=False)
    _observations: tuple[_Observation, ...] = field(repr=False, default=())
    _next_observation_id: int = field(repr=False, default=0)
    _change_set: LiveDetectionChangeSet | None = field(repr=False, default=None)
    _active_observation_count: int = field(repr=False, default=0)
    _committed_snapshot: LiveDetectionSnapshot | None = field(repr=False, default=None)
    _committed_state: _CommittedState | None = field(repr=False, default=None)

    def safe_summary(self) -> LiveDetectionSummary:
        return self._summary


class LiveDetectionAccumulator:
    """Single-caller, whole-session prefix state; not a public serializer input."""

    __slots__ = ("_source_role", "_max_records", "_max_bytes", "_committed", "_owner_token",
                 "_next_proposal_id", "_active", "_last_settled_id",
                 "_worker_bound", "_publication_bound", "_closed", "_validated_proposal_id")

    def __init__(self, source_role: str, max_history_records: int, max_history_bytes: int):
        if type(source_role) is not str or source_role not in ROLES:
            raise LiveDetectionError("UNSUPPORTED_SOURCE_ROLE")
        if (type(max_history_records) is not int or not 1 <= max_history_records <= MAX_COUNTER
            or type(max_history_bytes) is not int or not 1 <= max_history_bytes <= MAX_COUNTER):
            raise LiveDetectionError("INVALID_HISTORY_LIMIT")
        self._source_role = source_role
        self._max_records = max_history_records
        self._max_bytes = max_history_bytes
        self._committed = _CommittedState((), 0, {}, 0, tuple((kind, 0) for _, kind in _SLOTS),
                                          0, 0, 0, 0, 0, (), 0, None, 0)
        self._owner_token = _owner_token()
        self._next_proposal_id = 1
        self._active: LiveDetectionProposal | None = None
        self._last_settled_id = 0
        self._worker_bound = False
        self._publication_bound = False
        self._closed = False
        self._validated_proposal_id = 0

    @property
    def _history(self) -> tuple[NormalizedEvent, ...]:
        return self._committed.history

    @property
    def _history_bytes(self) -> int:
        return self._committed.history_bytes

    @property
    def _detection(self) -> dict:
        return self._committed.detection

    @property
    def _subject_count(self) -> int:
        return self._committed.subject_count

    @property
    def _type_counts(self) -> tuple[tuple[str, int], ...]:
        return self._committed.type_counts

    @property
    def _revision(self) -> int:
        return self._committed.revision

    @property
    def _parsed(self) -> int:
        return self._committed.parsed

    @property
    def _ignored(self) -> int:
        return self._committed.ignored

    @property
    def _rejected(self) -> int:
        return self._committed.rejected

    @property
    def _last_sequence(self) -> int:
        return self._committed.last_sequence

    @property
    def _observations(self) -> tuple[_Observation, ...]:
        return self._committed.observations

    @property
    def _next_observation_id(self) -> int:
        return self._committed.next_observation_id

    @property
    def _last_change_set(self) -> LiveDetectionChangeSet | None:
        return self._committed.last_change_set

    @property
    def _active_observation_count(self) -> int:
        return self._committed.active_observation_count

    def __repr__(self) -> str:
        return ("LiveDetectionAccumulator("
                f"source_role={self._source_role!r}, revision={self._revision}, "
                f"history_record_count={len(self._history)}, history_byte_count={self._history_bytes})")

    def snapshot(self) -> LiveDetectionSnapshot:
        if type(self) is not LiveDetectionAccumulator:
            raise LiveDetectionError("INVALID_ARGUMENT")
        return LiveDetectionSnapshot(
            "1", self._source_role, self._revision, len(self._history), self._history_bytes,
            self._subject_count, self._type_counts, self._parsed, self._ignored,
            self._rejected, self._active is not None,
            self._active_observation_count, self._closed,
        )

    @property
    def source_role(self) -> str:
        return self._source_role

    def latest_change_set(self) -> LiveDetectionChangeSet | None:
        return self._last_change_set

    def prepare(self, batch: LiveParseBatch) -> LiveDetectionProposal:
        if type(self) is not LiveDetectionAccumulator:
            raise LiveDetectionError("INVALID_ARGUMENT")
        if self._closed:
            raise LiveDetectionError("OPERATION_AFTER_CLOSE")
        if self._active is not None:
            raise LiveDetectionError("ACTIVE_PROPOSAL_EXISTS")
        parsed = _validate_batch(batch, self._source_role, self._last_sequence)
        candidate_count = _bounded_add(len(self._history), len(parsed))
        if candidate_count > self._max_records:
            raise LiveDetectionError("HISTORY_LIMIT_EXCEEDED")
        added_bytes = 0
        for event in parsed:
            added_bytes = _bounded_add(added_bytes, _event_bytes(event, self._source_role, self._max_bytes))
        candidate_bytes = _bounded_add(self._history_bytes, added_bytes)
        if candidate_bytes > self._max_bytes:
            raise LiveDetectionError("HISTORY_LIMIT_EXCEEDED")
        next_revision = _bounded_add(self._revision, 1)
        next_parsed = _bounded_add(self._parsed, batch.parsed_count)
        next_ignored = _bounded_add(self._ignored, batch.ignored_count)
        next_rejected = _bounded_add(self._rejected, batch.rejected_count)
        candidate_history = self._history + parsed
        if parsed:
            try:
                candidate_detection = detect_attacks(list(candidate_history))
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                raise LiveDetectionError("DETECTOR_CONTRACT_FAILURE") from None
            except Exception:
                raise LiveDetectionError("UNEXPECTED_DETECTOR_FAILURE") from None
            subject_count, type_counts = _safe_detection_counts(candidate_detection, candidate_history)
        else:
            candidate_detection = self._detection
            subject_count, type_counts = self._subject_count, self._type_counts
        summary = LiveDetectionSummary(
            "1", next_revision, self._source_role, candidate_count, candidate_bytes,
            subject_count, type_counts, batch.parsed_count, batch.ignored_count,
            batch.rejected_count,
        )
        try:
            observations, next_observation_id, change_set, active_count = _prepare_observations(
                self._observations, candidate_detection, self._next_observation_id, next_revision, summary,
            ) if parsed else (
                self._observations, self._next_observation_id,
                LiveDetectionChangeSet(next_revision, (), summary), self._active_observation_count,
            )
        except LiveDetectionError:
            raise
        except Exception:
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE") from None
        proposal = LiveDetectionProposal(
            next_revision, self._source_role, self._next_proposal_id, self._owner_token,
            candidate_history, candidate_bytes, candidate_detection, summary,
            batch.outcomes[-1].sequence if batch.outcomes else self._last_sequence,
            next_parsed, next_ignored, next_rejected,
            observations, next_observation_id, change_set, active_count,
            LiveDetectionSnapshot("1", self._source_role, next_revision, candidate_count,
                                  candidate_bytes, subject_count, type_counts, next_parsed,
                                  next_ignored, next_rejected, False, active_count, False),
            _CommittedState(candidate_history, candidate_bytes, candidate_detection,
                            subject_count, type_counts, next_revision, next_parsed,
                            next_ignored, next_rejected,
                            batch.outcomes[-1].sequence, observations,
                            next_observation_id, change_set, active_count),
        )
        self._next_proposal_id = _bounded_add(self._next_proposal_id, 1)
        self._active = proposal
        self._validated_proposal_id = 0
        return proposal

    def _validate_proposal(self, proposal: LiveDetectionProposal) -> None:
        if type(proposal) is not LiveDetectionProposal:
            raise LiveDetectionError("FORGED_PROPOSAL")
        if (type(proposal._proposal_id) is not int or type(proposal._owner_token) is not int
            or type(proposal._summary) is not LiveDetectionSummary
            or type(proposal._total_parsed) is not int
            or type(proposal._total_ignored) is not int
            or type(proposal._total_rejected) is not int
            or type(proposal._last_sequence) is not int):
            raise LiveDetectionError("FORGED_PROPOSAL")
        if proposal._owner_token != self._owner_token:
            raise LiveDetectionError("FOREIGN_PROPOSAL")
        if self._active is None:
            code = "DOUBLE_SETTLEMENT" if proposal._proposal_id == self._last_settled_id else "STALE_PROPOSAL"
            raise LiveDetectionError(code)
        if proposal._proposal_id != self._active._proposal_id:
            raise LiveDetectionError("STALE_PROPOSAL" if proposal._proposal_id < self._active._proposal_id else "FORGED_PROPOSAL")
        if proposal.proposal_revision != self._revision + 1:
            raise LiveDetectionError("REVISION_MISMATCH")
        if proposal.source_role != self._source_role:
            raise LiveDetectionError("SOURCE_MISMATCH")
        if (type(proposal._history) is not tuple
            or len(proposal._history) > self._max_records
            or type(proposal._history_bytes) is not int
            or proposal._history_bytes > self._max_bytes
            or proposal._history_bytes != sum(_event_bytes(event, self._source_role, self._max_bytes) for event in proposal._history)
            or proposal._summary.history_record_count != len(proposal._history)
            or proposal._summary.history_byte_count != proposal._history_bytes
            or proposal._summary.proposal_revision != proposal.proposal_revision
            or proposal._summary.source_role != self._source_role
            or proposal._summary != self._active._summary
            or proposal._history != self._active._history
            or proposal._detection != self._active._detection
            or proposal._last_sequence != self._active._last_sequence
            or proposal._total_parsed != self._active._total_parsed
            or proposal._total_ignored != self._active._total_ignored
            or proposal._total_rejected != self._active._total_rejected):
            raise LiveDetectionError("FORGED_PROPOSAL")
        subject_count, type_counts = _safe_detection_counts(proposal._detection, proposal._history)
        if (proposal._summary.subject_count != subject_count
            or proposal._summary.detected_type_counts != type_counts
            or proposal._total_parsed != len(proposal._history)
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in (
                proposal._total_ignored, proposal._total_rejected, proposal._last_sequence))):
            raise LiveDetectionError("DETECTION_INVARIANT_FAILURE")

    def prevalidate(self, proposal: LiveDetectionProposal) -> None:
        if self._closed:
            raise LiveDetectionError("OPERATION_AFTER_CLOSE")
        try:
            self._validate_proposal(proposal)
            if (proposal is not self._active or proposal._change_set is None
                or proposal._change_set.accumulator_revision != proposal.proposal_revision
                or proposal._change_set.safe_summary != proposal._summary
                or type(proposal._committed_snapshot) is not LiveDetectionSnapshot
                or type(proposal._committed_state) is not _CommittedState
                or proposal._committed_state.revision != proposal.proposal_revision
                or proposal._committed_state.history is not proposal._history
                or proposal._committed_state.detection is not proposal._detection
                or proposal._committed_state.history_bytes != proposal._history_bytes
                or proposal._committed_state.last_change_set is not proposal._change_set
                or proposal._committed_state.observations is not proposal._observations
                or proposal._committed_snapshot.revision != proposal.proposal_revision
                or proposal._active_observation_count != sum(
                    item.state == "ACTIVE" for item in proposal._observations)
                or len({item.observation_id for item in proposal._observations}) != len(proposal._observations)
                or any(change.change_type not in _CHANGE_TYPES or change.state not in _STATES
                       for change in proposal._change_set.changes)):
                raise LiveDetectionError("FORGED_PROPOSAL")
        except LiveDetectionError:
            raise
        except Exception:
            raise LiveDetectionError("FORGED_PROPOSAL") from None
        self._validated_proposal_id = proposal._proposal_id

    def commit_prepared(self, proposal: LiveDetectionProposal) -> LiveDetectionSnapshot:
        if self._closed:
            raise LiveDetectionError("OPERATION_AFTER_CLOSE")
        if (type(proposal) is not LiveDetectionProposal or proposal is not self._active
            or self._validated_proposal_id != proposal._proposal_id
            or proposal.proposal_revision != self._revision + 1):
            raise LiveDetectionError("FORGED_PROPOSAL")
        # No detector, raw byte accounting, ID allocation, diff, or deep validation here.
        self._committed = proposal._committed_state
        self._active = None
        self._validated_proposal_id = 0
        self._last_settled_id = proposal._proposal_id
        return proposal._committed_snapshot

    def commit(self, proposal: LiveDetectionProposal) -> LiveDetectionSnapshot:
        if type(self) is not LiveDetectionAccumulator:
            raise LiveDetectionError("INVALID_ARGUMENT")
        self.prevalidate(proposal)
        return self.commit_prepared(proposal)

    def abort(self, proposal: LiveDetectionProposal) -> None:
        if type(self) is not LiveDetectionAccumulator:
            raise LiveDetectionError("INVALID_ARGUMENT")
        try:
            self._validate_proposal(proposal)
        except LiveDetectionError:
            raise
        except Exception:
            raise LiveDetectionError("FORGED_PROPOSAL") from None
        self._active = None
        self._validated_proposal_id = 0
        self._last_settled_id = proposal._proposal_id

    def close(self) -> None:
        if self._closed and not self._history and not self._detection:
            return
        self._active = None
        self._committed = _CommittedState((), 0, {}, 0, tuple((kind, 0) for _, kind in _SLOTS),
                                          self._revision, 0, 0, 0, self._last_sequence,
                                          (), self._next_observation_id, None, 0)
        self._validated_proposal_id = 0
        self._closed = True

    def _fail_after_ack(self, last_confirmed: _CommittedState) -> None:
        """Terminalize without claiming a possibly partial commit succeeded.

        This does not restore acknowledged queue records or make retry safe.
        """
        self._committed = last_confirmed
        self._active = None
        self._validated_proposal_id = 0
        self._closed = True
