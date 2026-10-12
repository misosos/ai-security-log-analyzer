"""Application-only, single-caller full-prefix correlation/risk/case state.

Trusted production results remain private to this process. The frozen proposal,
change set and snapshot contain only approved aggregate/ordinal values.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math

from app.analyzer.incident_case import assemble_incident_cases
from app.analyzer.incident_case_adapter import build_incident_case_subject_inputs
from app.analyzer.incident_case_projection import build_investigation_case_projection
from app.analyzer.pipeline import group_logs_by_ip, assess_risk_with_metadata
from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_post_authentication_activity,
    correlate_brute_force_to_success,
    correlate_password_spray_to_success,
)
from app.live_monitoring.core import MAX_COUNTER
from app.live_monitoring.detection_accumulator import (
    LiveDetectionAccumulator, LiveDetectionProposal,
)


MAX_HISTORY_RECORDS = 256
MAX_HISTORY_BYTES = 256 * 1024
MAX_IDENTITIES = 4096
_NEXT_OWNER_TOKEN = 0
_CORRELATIONS = (
    ("authentication", "failed_to_successful_login"),
    ("post_authentication", "successful_login_to_file_access"),
    ("brute_force_to_success", "brute_force_to_successful_login"),
    ("password_spray_to_success", "password_spray_to_successful_login"),
)
_CATEGORIES = frozenset({
    "RELATION_CREATED", "RELATION_UPDATED", "RELATION_NO_LONGER_MATCHES",
    "RISK_CREATED", "RISK_UPDATED", "RISK_NO_LONGER_PRESENT",
    "CASE_CREATED", "CASE_UPDATED", "CASE_NO_LONGER_MATCHES",
})
_RELATION_TYPES = frozenset(kind for _, kind in _CORRELATIONS)
_LEVELS = frozenset(("LOW", "MEDIUM", "HIGH"))
_RELATION_STATES = frozenset(("ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT"))
_MESSAGES = {
    "LIVE_ANALYSIS_INVALID_INPUT": "내부 분석 입력 계약을 확인하십시오.",
    "LIVE_ANALYSIS_UNSUPPORTED_SOURCE": "application 로그만 지원합니다.",
    "LIVE_ANALYSIS_REVISION_MISMATCH": "분석 revision을 확인하십시오.",
    "LIVE_ANALYSIS_CORRELATION_FAILED": "관계 계산을 완료하지 못했습니다.",
    "LIVE_ANALYSIS_RISK_FAILED": "위험도 계산을 완료하지 못했습니다.",
    "LIVE_ANALYSIS_CASE_FAILED": "조사 사례 구성을 완료하지 못했습니다.",
    "LIVE_ANALYSIS_PROJECTION_FAILED": "조사 사례 projection을 완료하지 못했습니다.",
    "LIVE_ANALYSIS_HISTORY_LIMIT": "전체 history 상한에 도달했습니다.",
    "LIVE_ANALYSIS_COMMIT_FAILED": "분석 상태를 확정하지 못했습니다.",
    "LIVE_ANALYSIS_CLOSED": "닫힌 분석 상태는 처리할 수 없습니다.",
    "LIVE_ANALYSIS_ACTIVE_PROPOSAL": "진행 중인 proposal을 먼저 정산하십시오.",
    "LIVE_ANALYSIS_PROPOSAL_MISMATCH": "proposal 소유권 또는 상태를 확인하십시오.",
    "LIVE_ANALYSIS_IDENTITY_LIMIT": "분석 identity 상한에 도달했습니다.",
}


class LiveAnalysisError(ValueError):
    def __init__(self, code: str):
        self.code = code if type(code) is str and code in _MESSAGES else "LIVE_ANALYSIS_INVALID_INPUT"
        super().__init__(f"{self.code}: {_MESSAGES[self.code]}")

    def __repr__(self) -> str:
        return f"LiveAnalysisError(code={self.code!r})"


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_COUNTER:
        raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")
    return value


def _next(value: int) -> int:
    if type(value) is not int or not 0 <= value < MAX_COUNTER:
        raise LiveAnalysisError("LIVE_ANALYSIS_IDENTITY_LIMIT")
    return value + 1


def _ordinal(prefix: str, number: int) -> str:
    return f"LIVE-{prefix}-{number:06d}"


def _valid_id(value: object, prefix: str) -> bool:
    if type(value) is not str or not value.startswith(f"LIVE-{prefix}-"):
        return False
    suffix = value[len(prefix) + 6:]
    if not (6 <= len(suffix) <= 19 and suffix.isascii() and suffix.isdecimal()):
        return False
    number = int(suffix)
    return 0 < number <= MAX_COUNTER and (len(suffix) == 6 or suffix[0] != "0")


def _owner_token() -> int:
    global _NEXT_OWNER_TOKEN
    _NEXT_OWNER_TOKEN = _next(_NEXT_OWNER_TOKEN)
    return _NEXT_OWNER_TOKEN


@dataclass(frozen=True, slots=True)
class LiveAnalysisChange:
    category: str
    public_id: str
    item_revision: int

    def __post_init__(self) -> None:
        prefix = self.category.split("_", 1)[0] if type(self.category) is str else ""
        id_prefix = {"RELATION": "REL", "RISK": "RISK", "CASE": "CASE"}.get(prefix, "")
        if (type(self.category) is not str or self.category not in _CATEGORIES
            or not _valid_id(self.public_id, id_prefix)
            or type(self.item_revision) is not int
            or not 1 <= self.item_revision <= MAX_COUNTER):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveAnalysisChangeSet:
    analysis_revision: int
    changes: tuple[LiveAnalysisChange, ...]

    def __post_init__(self) -> None:
        _integer(self.analysis_revision)
        if (type(self.changes) is not tuple
            or any(type(item) is not LiveAnalysisChange for item in self.changes)
            or len({(item.category, item.public_id) for item in self.changes}) != len(self.changes)):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveRelationSummary:
    relation_id: str
    revision: int
    relation_type: str
    state: str
    delta_seconds: int | float

    def __post_init__(self) -> None:
        if (not _valid_id(self.relation_id, "REL")
            or type(self.revision) is not int or not 1 <= self.revision <= MAX_COUNTER
            or type(self.relation_type) is not str or self.relation_type not in _RELATION_TYPES
            or type(self.state) is not str or self.state not in _RELATION_STATES
            or type(self.delta_seconds) not in (int, float)
            or not math.isfinite(self.delta_seconds) or not 0 < self.delta_seconds <= 60):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveRiskSummary:
    risk_id: str
    revision: int
    state: str
    risk_level: str
    confidence: str

    def __post_init__(self) -> None:
        if (not _valid_id(self.risk_id, "RISK")
            or type(self.revision) is not int or not 1 <= self.revision <= MAX_COUNTER
            or self.state not in ("CURRENT", "NO_LONGER_PRESENT")
            or self.risk_level not in _LEVELS or self.confidence not in _LEVELS):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveCaseSummary:
    case_id: str
    revision: int
    state: str
    rule_id: str
    included_highest_risk: str
    included_highest_confidence: str
    relation_count: int
    observation_count: int
    supporting_relation_count: int
    account_reference_status: str = "ACCOUNT_REFERENCE_UNAVAILABLE"

    def __post_init__(self) -> None:
        if (not _valid_id(self.case_id, "CASE")
            or type(self.revision) is not int or not 1 <= self.revision <= MAX_COUNTER
            or self.state not in ("CURRENT", "NO_LONGER_MATCHES_CURRENT_RESULT")
            or self.rule_id not in ("CASE-AUTH-TRANSITION-01", "CASE-BRUTE-SUCCESS-01")
            or self.included_highest_risk not in _LEVELS
            or self.included_highest_confidence not in _LEVELS
            or type(self.relation_count) is not int or not 1 <= self.relation_count <= MAX_COUNTER
            or type(self.observation_count) is not int or not 1 <= self.observation_count <= MAX_COUNTER
            or type(self.supporting_relation_count) is not int
            or not 0 <= self.supporting_relation_count < self.relation_count
            or self.account_reference_status != "ACCOUNT_REFERENCE_UNAVAILABLE"):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveAnalysisSnapshot:
    schema_version: str
    revision: int
    source_role: str
    relation_count: int
    risk_count: int
    case_count: int
    independent_observation_count: int
    relations: tuple[LiveRelationSummary, ...]
    risks: tuple[LiveRiskSummary, ...]
    cases: tuple[LiveCaseSummary, ...]
    active_proposal: bool
    closed: bool
    fixed_warning_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        counts = (self.revision, self.relation_count, self.risk_count,
                  self.case_count, self.independent_observation_count)
        if (self.schema_version != "1" or self.source_role != "application"
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or type(self.relations) is not tuple or type(self.risks) is not tuple
            or type(self.cases) is not tuple or type(self.fixed_warning_codes) is not tuple
            or self.fixed_warning_codes
            or any(type(item) is not LiveRelationSummary for item in self.relations)
            or any(type(item) is not LiveRiskSummary for item in self.risks)
            or any(type(item) is not LiveCaseSummary for item in self.cases)
            or self.relation_count != sum(item.state == "ACTIVE" for item in self.relations)
            or self.risk_count != sum(item.state == "CURRENT" for item in self.risks)
            or self.case_count != sum(item.state == "CURRENT" for item in self.cases)
            or type(self.active_proposal) is not bool or type(self.closed) is not bool):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class LiveAnalysisProposal:
    base_revision: int
    target_revision: int
    source_role: str
    _proposal_id: int = field(repr=False)
    _owner_token: int = field(repr=False)

    def __post_init__(self) -> None:
        if (type(self.base_revision) is not int or not 0 <= self.base_revision < MAX_COUNTER
            or type(self.target_revision) is not int
            or self.target_revision != self.base_revision + 1
            or self.source_role != "application"
            or type(self._proposal_id) is not int or not 1 <= self._proposal_id <= MAX_COUNTER
            or type(self._owner_token) is not int or not 1 <= self._owner_token <= MAX_COUNTER):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")


@dataclass(frozen=True, slots=True)
class _Identity:
    _anchor: tuple = field(repr=False)
    public_id: str
    revision: int
    state: str
    _meaning: object = field(repr=False)
    safe: object


@dataclass(frozen=True, slots=True)
class _State:
    revision: int
    relations: tuple[_Identity, ...] = field(repr=False)
    risks: tuple[_Identity, ...] = field(repr=False)
    cases: tuple[_Identity, ...] = field(repr=False)
    next_relation: int
    next_risk: int
    next_case: int
    snapshot: LiveAnalysisSnapshot
    change_set: LiveAnalysisChangeSet
    _results: dict = field(repr=False)
    _subjects: tuple = field(repr=False)
    _assembly: object = field(repr=False)
    _projection: object = field(repr=False)


def _relation_candidate(results: dict) -> tuple[tuple[tuple, tuple], ...]:
    candidates = []
    for subject, result in results.items():
        correlation = result["correlation"]
        if type(correlation) is not dict or set(correlation) != {slot for slot, _ in _CORRELATIONS}:
            raise LiveAnalysisError("LIVE_ANALYSIS_CORRELATION_FAILED")
        for slot, kind in _CORRELATIONS:
            value = correlation[slot]
            if type(value) is not dict or type(value.get("is_correlated")) is not bool:
                raise LiveAnalysisError("LIVE_ANALYSIS_CORRELATION_FAILED")
            if not value["is_correlated"]:
                continue
            first_key = "success_timestamp" if slot == "post_authentication" else "failure_timestamp"
            second_key = "file_access_timestamp" if slot == "post_authentication" else "success_timestamp"
            first, second = value.get(first_key), value.get(second_key)
            delta = value.get("time_delta_seconds")
            if (value.get("type") != kind or type(value.get("user")) is not str
                or type(first) is not datetime or first.tzinfo is not timezone.utc
                or type(second) is not datetime or second.tzinfo is not timezone.utc
                or type(delta) not in (int, float) or not 0 < delta <= 60
                or first >= second or (second - first).total_seconds() != delta):
                raise LiveAnalysisError("LIVE_ANALYSIS_CORRELATION_FAILED")
            anchor = (subject, kind, value["user"], first, second, delta)
            # The complete production value is trusted and compared for updates.
            candidates.append((anchor, (kind, delta, value)))
    return tuple(candidates)


def _advance(previous: tuple[_Identity, ...], candidates: tuple[tuple[tuple, object], ...],
             next_id: int, prefix: str, category: str, missing: str,
             make_safe) -> tuple[tuple[_Identity, ...], int, tuple[LiveAnalysisChange, ...]]:
    old = {item._anchor: item for item in previous}
    if len(old) != len(previous) or len({anchor for anchor, _ in candidates}) != len(candidates):
        raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")
    updated = dict(old)
    changes = []
    current = set()
    for anchor, meaning in candidates:
        current.add(anchor)
        prior = old.get(anchor)
        if prior is None:
            next_id = _next(next_id)
            public_id, revision, change = _ordinal(prefix, next_id), 1, "CREATED"
        elif prior.state != "ACTIVE" or prior._meaning != meaning:
            public_id, revision, change = prior.public_id, _next(prior.revision), "UPDATED"
        else:
            continue
        safe = make_safe(public_id, revision, "ACTIVE", meaning)
        updated[anchor] = _Identity(anchor, public_id, revision, "ACTIVE", meaning, safe)
        changes.append(LiveAnalysisChange(f"{category}_{change}", public_id, revision))
    for item in previous:
        if item._anchor not in current and item.state == "ACTIVE":
            revision = _next(item.revision)
            safe = make_safe(item.public_id, revision, "NO_LONGER_MATCHES_CURRENT_RESULT", item._meaning)
            updated[item._anchor] = _Identity(item._anchor, item.public_id, revision,
                                              "NO_LONGER_MATCHES_CURRENT_RESULT", item._meaning, safe)
            changes.append(LiveAnalysisChange(f"{category}_{missing}", item.public_id, revision))
    if len(updated) > MAX_IDENTITIES:
        raise LiveAnalysisError("LIVE_ANALYSIS_IDENTITY_LIMIT")
    return tuple(sorted(updated.values(), key=lambda item: int(item.public_id.rsplit("-", 1)[1]))), next_id, tuple(changes)


def _relation_safe(public_id: str, revision: int, state: str, meaning: tuple) -> LiveRelationSummary:
    return LiveRelationSummary(public_id, revision, meaning[0], state, meaning[1])


def _risk_safe(public_id: str, revision: int, state: str, meaning: tuple) -> LiveRiskSummary:
    value = meaning[0]
    return LiveRiskSummary(public_id, revision, "CURRENT" if state == "ACTIVE" else "NO_LONGER_PRESENT",
                           value["risk_level"], value["risk_factors"]["confidence"]["level"])


def _case_safe(public_id: str, revision: int, state: str, meaning: tuple) -> LiveCaseSummary:
    case = meaning[0]
    return LiveCaseSummary(public_id, revision, "CURRENT" if state == "ACTIVE" else state,
                           case.rule_id, case.included_highest_risk,
                           case.included_highest_confidence, len(case.relations),
                           len(case.observations), len(case.relations) - 1)


class LiveAnalysisAccumulator:
    """One application detection accumulator and an injected metadata snapshot.

    No worker, publication, parser, filesystem, or clock calls occur here.
    The caller serializes operations and supplies metadata matching its batch oracle.
    """

    __slots__ = ("_detection", "_metadata", "_state", "_active", "_candidate",
                 "_candidate_detection_state", "_owner_token", "_next_proposal_id", "_closed")

    def __init__(self, detection_accumulator: LiveDetectionAccumulator,
                 account_metadata: tuple[tuple[str, str], ...]):
        if type(detection_accumulator) is not LiveDetectionAccumulator:
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")
        if detection_accumulator.source_role != "application":
            raise LiveAnalysisError("LIVE_ANALYSIS_UNSUPPORTED_SOURCE")
        snapshot = detection_accumulator.snapshot()
        if snapshot.closed or snapshot.revision != 0 or snapshot.active_proposal:
            raise LiveAnalysisError("LIVE_ANALYSIS_REVISION_MISMATCH")
        if (type(account_metadata) is not tuple or len(account_metadata) > MAX_HISTORY_RECORDS
            or any(type(pair) is not tuple or len(pair) != 2
                   or type(pair[0]) is not str or not pair[0]
                   or type(pair[1]) is not str or not pair[1]
                   for pair in account_metadata)
            or len({pair[0] for pair in account_metadata}) != len(account_metadata)):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")
        self._detection = detection_accumulator
        self._metadata = {account: {"privilege": privilege} for account, privilege in account_metadata}
        empty_snapshot = LiveAnalysisSnapshot("1", 0, "application", 0, 0, 0, 0,
                                               (), (), (), False, False)
        self._state = _State(0, (), (), (), 0, 0, 0, empty_snapshot,
                             LiveAnalysisChangeSet(0, ()), {}, (), None, None)
        self._owner_token = _owner_token()
        self._next_proposal_id = 1
        self._active: LiveAnalysisProposal | None = None
        self._candidate: _State | None = None
        self._candidate_detection_state: object | None = None
        self._closed = False

    def __repr__(self) -> str:
        return f"LiveAnalysisAccumulator(revision={self._state.revision}, closed={self._closed})"

    def snapshot(self) -> LiveAnalysisSnapshot:
        value = self._state.snapshot
        return LiveAnalysisSnapshot(value.schema_version, value.revision, value.source_role,
                                    value.relation_count, value.risk_count, value.case_count,
                                    value.independent_observation_count, value.relations,
                                    value.risks, value.cases, self._active is not None,
                                    self._closed, value.fixed_warning_codes)

    def latest_change_set(self) -> LiveAnalysisChangeSet:
        return self._state.change_set

    def _check_open(self) -> None:
        if self._closed:
            raise LiveAnalysisError("LIVE_ANALYSIS_CLOSED")

    def prepare(self, detection_proposal: LiveDetectionProposal) -> LiveAnalysisProposal:
        self._check_open()
        if self._active is not None:
            raise LiveAnalysisError("LIVE_ANALYSIS_ACTIVE_PROPOSAL")
        detector = self._detection
        if (type(detection_proposal) is not LiveDetectionProposal
            or detector._active is not detection_proposal
            or detection_proposal.source_role != "application"):
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT")
        if (detector.snapshot().revision != self._state.revision
            or detection_proposal.proposal_revision != self._state.revision + 1):
            raise LiveAnalysisError("LIVE_ANALYSIS_REVISION_MISMATCH")
        try:
            detector.prevalidate(detection_proposal)
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT") from None
        history = detection_proposal._history
        if (type(history) is not tuple or len(history) > MAX_HISTORY_RECORDS
            or detection_proposal._history_bytes > MAX_HISTORY_BYTES):
            raise LiveAnalysisError("LIVE_ANALYSIS_HISTORY_LIMIT")
        try:
            grouped = group_logs_by_ip(history)
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_CORRELATION_FAILED") from None
        results = {}
        for subject, entry in detection_proposal._detection.items():
            ip_logs = grouped.get(subject, [])
            try:
                correlations = {
                    "authentication": correlate_authentication_transition(ip_logs),
                    "post_authentication": correlate_post_authentication_activity(ip_logs),
                    "brute_force_to_success": correlate_brute_force_to_success(
                        ip_logs, entry["detections"]["brute_force"]),
                    "password_spray_to_success": correlate_password_spray_to_success(
                        ip_logs, entry["detections"]["password_spray"]),
                }
            except Exception:
                raise LiveAnalysisError("LIVE_ANALYSIS_CORRELATION_FAILED") from None
            results[subject] = {"features": entry["features"],
                                "detections": entry["detections"], "correlation": correlations}
        try:
            assess_risk_with_metadata({"results": results, "global_correlation": {}}, self._metadata)
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_RISK_FAILED") from None
        try:
            subjects = build_incident_case_subject_inputs(results)
            assembly = assemble_incident_cases(subjects)
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_CASE_FAILED") from None
        try:
            projection = build_investigation_case_projection(assembly)
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_PROJECTION_FAILED") from None
        try:
            relation_candidates = _relation_candidate(results)
            relations, next_rel, relation_changes = _advance(
                self._state.relations, relation_candidates, self._state.next_relation,
                "REL", "RELATION", "NO_LONGER_MATCHES", _relation_safe)
            risk_candidates = tuple(
                ((subject,), ({"risk_level": value["risk_level"],
                               "risk_factors": value["risk_factors"]},))
                for subject, value in results.items()
            )
            risks, next_risk, risk_changes = _advance(
                self._state.risks, tuple(risk_candidates), self._state.next_risk,
                "RISK", "RISK", "NO_LONGER_PRESENT", _risk_safe)
            case_candidates = []
            for case in assembly.cases:
                if not case.relations or case.rule_id not in {
                    "CASE-AUTH-TRANSITION-01", "CASE-BRUTE-SUCCESS-01"
                }:
                    raise LiveAnalysisError("LIVE_ANALYSIS_CASE_FAILED")
                anchor_relation = case.relations[0]
                matching = [item for item in relations if item.state == "ACTIVE"
                            and item._anchor[0] == case.subject_ip
                            and item._anchor[1] == anchor_relation.relation_type
                            and item._anchor[3:] == (
                                anchor_relation.failure_timestamp_utc,
                                anchor_relation.success_timestamp_utc,
                                anchor_relation.time_delta_seconds)]
                if len(matching) != 1:
                    raise LiveAnalysisError("LIVE_ANALYSIS_CASE_FAILED")
                case_candidates.append(((case.rule_id, matching[0].public_id), (case,)))
            cases, next_case, case_changes = _advance(
                self._state.cases, tuple(case_candidates), self._state.next_case,
                "CASE", "CASE", "NO_LONGER_MATCHES", _case_safe)
            changes = relation_changes + risk_changes + case_changes
            change_set = LiveAnalysisChangeSet(detection_proposal.proposal_revision, changes)
            safe = LiveAnalysisSnapshot(
                "1", detection_proposal.proposal_revision, "application",
                sum(item.state == "ACTIVE" for item in relations),
                sum(item.state == "ACTIVE" for item in risks),
                sum(item.state == "ACTIVE" for item in cases),
                len(assembly.independent_observations),
                tuple(item.safe for item in relations), tuple(item.safe for item in risks),
                tuple(item.safe for item in cases), False, False,
            )
            candidate = _State(detection_proposal.proposal_revision, relations, risks, cases,
                               next_rel, next_risk, next_case, safe, change_set,
                               results, subjects, assembly, projection)
        except LiveAnalysisError:
            raise
        except Exception:
            raise LiveAnalysisError("LIVE_ANALYSIS_INVALID_INPUT") from None
        proposal = LiveAnalysisProposal(self._state.revision, candidate.revision, "application",
                                        self._next_proposal_id, self._owner_token)
        self._next_proposal_id = _next(self._next_proposal_id)
        self._candidate = candidate
        self._candidate_detection_state = detection_proposal._committed_state
        self._active = proposal
        return proposal

    def _check_proposal(self, proposal: LiveAnalysisProposal) -> None:
        self._check_open()
        if type(proposal) is not LiveAnalysisProposal or proposal is not self._active:
            raise LiveAnalysisError("LIVE_ANALYSIS_PROPOSAL_MISMATCH")
        if (proposal._owner_token != self._owner_token or proposal.base_revision != self._state.revision
            or proposal.target_revision != self._state.revision + 1
            or proposal.source_role != "application" or self._candidate is None
            or self._candidate.revision != proposal.target_revision):
            raise LiveAnalysisError("LIVE_ANALYSIS_REVISION_MISMATCH")

    def abort(self, proposal: LiveAnalysisProposal) -> None:
        self._check_proposal(proposal)
        if self._detection._revision != self._state.revision:
            # Detection is already committed; discarding analysis is an integrity gap.
            self._closed = True
            raise LiveAnalysisError("LIVE_ANALYSIS_COMMIT_FAILED")
        self._active = None
        self._candidate = None
        self._candidate_detection_state = None

    def _install_candidate(self, candidate: _State) -> None:
        # A single prevalidated reference swap; useful as a narrow fault boundary.
        self._state = candidate

    def commit(self, proposal: LiveAnalysisProposal) -> LiveAnalysisSnapshot:
        self._check_proposal(proposal)
        # The detector must have committed this exact candidate, not aborted it.
        if (self._detection._revision != proposal.target_revision
            or self._detection._committed is not self._candidate_detection_state):
            raise LiveAnalysisError("LIVE_ANALYSIS_REVISION_MISMATCH")
        committed = self._candidate
        try:
            self._install_candidate(committed)
        except Exception:
            # Whether the swap happened is not guessed; no retry or rollback.
            self._closed = True
            self._active = None
            self._candidate = None
            self._candidate_detection_state = None
            raise LiveAnalysisError("LIVE_ANALYSIS_COMMIT_FAILED") from None
        self._candidate = None
        self._candidate_detection_state = None
        self._active = None
        return committed.snapshot

    def close(self) -> None:
        if self._closed and not self._metadata and not self._state._results and self._candidate is None:
            return
        self._active = None
        self._candidate = None
        self._candidate_detection_state = None
        self._metadata = {}
        previous = self._state.snapshot
        safe = LiveAnalysisSnapshot(previous.schema_version, previous.revision,
                                    previous.source_role, previous.relation_count,
                                    previous.risk_count, previous.case_count,
                                    previous.independent_observation_count, previous.relations,
                                    previous.risks, previous.cases, False, True,
                                    previous.fixed_warning_codes)
        self._state = _State(previous.revision, (), (), (), 0, 0, 0, safe,
                             LiveAnalysisChangeSet(previous.revision, ()), {}, (), None, None)
        self._closed = True
