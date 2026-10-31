"""Isolated, evaluation-only trusted Spray Window contract prototype.

This module is intentionally not imported by the production analysis pipeline.
Its object-identity checks address accidental in-process cross-run misbinding,
not hostile Python code or process-memory tampering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Iterable

from app.models.schemas import AuthenticationContext, NormalizedEvent


POLICY_ID = "spray-window-eval-v1"
MIN_FAILURES = 4
MIN_TARGETS = 3
WINDOW = timedelta(seconds=60)
CORRELATION_WINDOW = timedelta(seconds=60)
MAX_EVENTS = 512
MAX_CONTEXTS = 128
MAX_RAW_BYTES = 8192
_CONTEXT_TOKEN = object()
_EVIDENCE_TOKEN = object()


class PrototypeValidationError(ValueError):
    """Fixed safe error code; never includes event data."""

    def __init__(self, code: str = "invalid_context") -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PrototypeValidationError(code) from None


def _utc(value: object) -> datetime:
    try:
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            _fail("invalid_timestamp")
        return value.astimezone(timezone.utc)
    except PrototypeValidationError:
        raise
    except Exception:
        _fail("invalid_timestamp")


def _bounded_text(value: object, limit: int, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not str or len(value) > limit:
        _fail("event_too_large")


def _materialize_events(events: Iterable[NormalizedEvent]) -> tuple[NormalizedEvent, ...]:
    try:
        iterator = iter(events)
        materialized = []
        for _ in range(MAX_EVENTS + 1):
            try:
                materialized.append(next(iterator))
            except StopIteration:
                return tuple(materialized)
    except Exception:
        _fail("invalid_event_set")
    _fail("invalid_event_set")


def _signature(event: NormalizedEvent) -> tuple:
    _bounded_text(event.event_type, 64)
    _bounded_text(event.source, 64)
    _bounded_text(event.user, 256, optional=True)
    _bounded_text(event.src_ip, 64, optional=True)
    _bounded_text(event.dst_ip, 64, optional=True)
    _bounded_text(event.application, 128, optional=True)
    _bounded_text(event.protocol, 64, optional=True)
    _bounded_text(event.user_agent, 1024, optional=True)
    _bounded_text(event.raw, MAX_RAW_BYTES)
    if len(event.raw.encode("utf-8", errors="surrogatepass")) > MAX_RAW_BYTES:
        _fail("event_too_large")
    auth = event.authentication
    if auth is None:
        auth_signature = None
    else:
        if type(auth) is not AuthenticationContext:
            _fail("invalid_event")
        _bounded_text(auth.outcome, 32)
        _bounded_text(auth.method, 64, optional=True)
        _bounded_text(auth.service, 128, optional=True)
        auth_signature = (
            type(auth), auth.outcome, auth.method, auth.service,
            auth.source_port, auth.invalid_user,
        )
    # A digest detects mutation without retaining or rendering raw data.
    raw_digest = sha256(event.raw.encode("utf-8", errors="surrogatepass")).digest()
    return (
        _utc(event.timestamp), event.event_type, event.source, event.user,
        event.src_ip, event.dst_ip, event.application, event.protocol,
        event.user_agent, raw_digest, auth_signature,
    )


def _selection_key(event: NormalizedEvent) -> tuple:
    return (_utc(event.timestamp), event.source, event.user or "", event.event_type)


class PrototypeSprayRunOwner:
    """One-shot strong-reference owner for one normalized synthetic run."""

    __slots__ = ("__bound", "__events", "__snapshots", "__contexts", "__evidence")

    def __init__(self) -> None:
        self.__bound = False
        self.__events: tuple[NormalizedEvent, ...] = ()
        self.__snapshots: dict[int, tuple[NormalizedEvent, tuple]] = {}
        self.__contexts: list[tuple[PrototypeSprayWindowContext, tuple]] = []
        self.__evidence: list[tuple[PrototypeSprayDetectionEvidence, tuple]] = []

    def register_events(self, events: Iterable[NormalizedEvent]) -> None:
        if self.__bound:
            _fail("owner_already_bound")
        materialized = _materialize_events(events)
        if not materialized or len(materialized) > MAX_EVENTS:
            _fail("invalid_event_set")
        if any(type(event) is not NormalizedEvent for event in materialized):
            _fail("invalid_event")
        if len({id(event) for event in materialized}) != len(materialized):
            _fail("duplicate_event_reference")
        try:
            snapshots = {id(event): (event, _signature(event)) for event in materialized}
        except (AttributeError, TypeError, UnicodeError):
            _fail("invalid_event")
        self.__events = materialized
        self.__snapshots = snapshots
        self.__bound = True

    def _owns_event(self, event: object) -> bool:
        entry = self.__snapshots.get(id(event))
        return entry is not None and entry[0] is event

    def _validate_events(self, events: Iterable[NormalizedEvent] | None = None) -> tuple[NormalizedEvent, ...]:
        if not self.__bound:
            _fail("owner_unbound")
        selected = self.__events if events is None else _materialize_events(events)
        if len(selected) > MAX_EVENTS or len({id(event) for event in selected}) != len(selected):
            _fail("invalid_event_set")
        for event in selected:
            if type(event) is not NormalizedEvent or not self._owns_event(event):
                _fail("wrong_run")
            try:
                current = _signature(event)
            except (AttributeError, TypeError, UnicodeError):
                _fail("event_mutated")
            if current != self.__snapshots[id(event)][1]:
                _fail("event_mutated")
        if len(selected) != len(self.__events) or {id(item) for item in selected} != {id(item) for item in self.__events}:
            _fail("event_set_mismatch")
        return selected

    def _context_issued(self, context: object) -> bool:
        return any(item is context for item, _ in self.__contexts)

    def _context_snapshot(self, context: object) -> tuple | None:
        return next((snapshot for item, snapshot in self.__contexts if item is context), None)

    def _issue_context(self, context: PrototypeSprayWindowContext) -> None:
        if len(self.__contexts) >= MAX_CONTEXTS:
            _fail("context_limit")
        if any(item.subject_ip == context.subject_ip for item, _ in self.__contexts):
            _fail("context_already_issued")
        self.__contexts.append((context, _context_signature(context)))

    def _evidence_issued(self, evidence: object) -> bool:
        return any(item is evidence for item, _ in self.__evidence)

    def _evidence_snapshot(self, evidence: object) -> tuple | None:
        return next((snapshot for item, snapshot in self.__evidence if item is evidence), None)

    def _issue_evidence(self, evidence: PrototypeSprayDetectionEvidence) -> None:
        if any(item._context is evidence._context for item, _ in self.__evidence):
            _fail("evidence_already_issued")
        self.__evidence.append((evidence, _evidence_signature(evidence)))

    def __repr__(self) -> str:
        return "PrototypeSprayRunOwner(<redacted>)"


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PrototypeSprayWindowContext:
    subject_ip: str
    policy_id: str
    start_utc: datetime
    end_utc: datetime
    failure_count: int
    known_target_count: int
    missing_user_count: int
    members: tuple[NormalizedEvent, ...] = field(repr=False)
    sources: tuple[str, ...]
    _owner: PrototypeSprayRunOwner = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "PrototypeSprayWindowContext(<redacted>)"

    @classmethod
    def _untrusted_copy(cls, context: "PrototypeSprayWindowContext") -> "PrototypeSprayWindowContext":
        return cls(
            context.subject_ip, context.policy_id, context.start_utc, context.end_utc,
            context.failure_count, context.known_target_count, context.missing_user_count,
            context.members, context.sources, context._owner, object(),
        )


def _context_signature(context: PrototypeSprayWindowContext) -> tuple:
    return (
        context.subject_ip, context.policy_id, context.start_utc, context.end_utc,
        context.failure_count, context.known_target_count, context.missing_user_count,
        tuple(id(event) for event in context.members), context.sources, id(context._owner),
        context._token is _CONTEXT_TOKEN,
    )


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PrototypeSprayDetectionEvidence:
    subject_ip: str
    policy_id: str
    start_utc: datetime
    end_utc: datetime
    failure_count: int
    known_target_count: int
    missing_user_count: int
    members: tuple[NormalizedEvent, ...] = field(repr=False)
    _owner: PrototypeSprayRunOwner = field(repr=False, compare=False)
    _context: PrototypeSprayWindowContext = field(repr=False, compare=False)
    _token: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "PrototypeSprayDetectionEvidence(<redacted>)"


def _evidence_signature(evidence: PrototypeSprayDetectionEvidence) -> tuple:
    return (
        evidence.subject_ip, evidence.policy_id, evidence.start_utc, evidence.end_utc,
        evidence.failure_count, evidence.known_target_count, evidence.missing_user_count,
        tuple(id(event) for event in evidence.members), id(evidence._owner),
        id(evidence._context), evidence._token is _EVIDENCE_TOKEN,
    )


def build_prototype_window(
    owner: PrototypeSprayRunOwner,
    subject_ip: str,
    *,
    events: Iterable[NormalizedEvent] | None = None,
) -> PrototypeSprayWindowContext | None:
    if type(owner) is not PrototypeSprayRunOwner or not isinstance(subject_ip, str) or not subject_ip:
        _fail("invalid_context")
    observed = owner._validate_events(events)
    failures = [event for event in observed if event.src_ip == subject_ip and event.event_type == "login_failed"]
    ordered = sorted(failures, key=_selection_key)
    end_index = 0
    while end_index < len(ordered):
        group_end = end_index
        group_timestamp = _utc(ordered[end_index].timestamp)
        while group_end + 1 < len(ordered) and _utc(ordered[group_end + 1].timestamp) == group_timestamp:
            group_end += 1
        end_event = ordered[group_end]
        end = _utc(end_event.timestamp)
        left = group_end
        while left >= 0 and end - _utc(ordered[left].timestamp) <= WINDOW:
            candidate = ordered[left:group_end + 1]
            known = {event.user for event in candidate if isinstance(event.user, str) and event.user}
            if len(candidate) >= MIN_FAILURES and len(known) >= MIN_TARGETS:
                while left < group_end:
                    shorter = ordered[left + 1:group_end + 1]
                    shorter_users = {event.user for event in shorter if isinstance(event.user, str) and event.user}
                    if len(shorter) < MIN_FAILURES or len(shorter_users) < MIN_TARGETS:
                        break
                    left += 1
                    candidate = shorter
                    known = shorter_users
                signatures = [_signature(event) for event in candidate]
                selection_keys = [_selection_key(event) for event in candidate]
                if len(set(signatures)) != len(signatures) or len(set(selection_keys)) != len(selection_keys):
                    _fail("ambiguous_selection")
                members = tuple(candidate)
                start_utc = min(_utc(event.timestamp) for event in members)
                end_utc = max(_utc(event.timestamp) for event in members)
                context = PrototypeSprayWindowContext(
                    subject_ip=subject_ip, policy_id=POLICY_ID,
                    start_utc=start_utc, end_utc=end_utc,
                    failure_count=len(members), known_target_count=len(known),
                    missing_user_count=sum(not (isinstance(item.user, str) and item.user) for item in members),
                    members=members, sources=tuple(sorted({event.source for event in members})),
                    _owner=owner, _token=_CONTEXT_TOKEN,
                )
                owner._issue_context(context)
                validate_window(owner, context)
                return context
            left -= 1
        end_index = group_end + 1
    return None


def validate_window(owner: PrototypeSprayRunOwner, context: object) -> None:
    if type(owner) is not PrototypeSprayRunOwner or type(context) is not PrototypeSprayWindowContext:
        _fail("invalid_context")
    if context._owner is not owner or context._token is not _CONTEXT_TOKEN or not owner._context_issued(context):
        _fail("unissued_context")
    owner._validate_events()
    issued = owner._context_snapshot(context)
    if issued is None:
        _fail("unissued_context")
    if _context_signature(context) != issued:
        _fail("context_mutated")
    if context.policy_id != POLICY_ID or context.failure_count != len(context.members) or not context.members:
        _fail("invalid_membership")
    if len({id(item) for item in context.members}) != len(context.members):
        _fail("invalid_membership")
    for member in context.members:
        if not owner._owns_event(member) or member.event_type != "login_failed" or member.src_ip != context.subject_ip:
            _fail("invalid_membership")
    timestamps = tuple(_utc(member.timestamp) for member in context.members)
    if min(timestamps) != context.start_utc or max(timestamps) != context.end_utc:
        _fail("invalid_membership")
    if any(context.end_utc - item > WINDOW for item in timestamps):
        _fail("invalid_membership")
    known = {item.user for item in context.members if isinstance(item.user, str) and item.user}
    missing = sum(not (isinstance(item.user, str) and item.user) for item in context.members)
    if len(known) != context.known_target_count or missing != context.missing_user_count:
        _fail("invalid_membership")
    if context.failure_count < MIN_FAILURES or len(known) < MIN_TARGETS:
        _fail("invalid_membership")
    if context.sources != tuple(sorted({item.source for item in context.members})):
        _fail("invalid_membership")
    return None


def issue_detection_evidence(
    owner: PrototypeSprayRunOwner, context: PrototypeSprayWindowContext,
) -> PrototypeSprayDetectionEvidence:
    validate_window(owner, context)
    evidence = PrototypeSprayDetectionEvidence(
        context.subject_ip, context.policy_id, context.start_utc, context.end_utc,
        context.failure_count, context.known_target_count, context.missing_user_count,
        context.members, owner, context, _EVIDENCE_TOKEN,
    )
    owner._issue_evidence(evidence)
    return evidence


def validate_detection_evidence(
    owner: PrototypeSprayRunOwner,
    context: PrototypeSprayWindowContext,
    evidence: object,
) -> None:
    validate_window(owner, context)
    if type(evidence) is not PrototypeSprayDetectionEvidence:
        _fail("invalid_evidence")
    if evidence._owner is not owner or evidence._context is not context or evidence._token is not _EVIDENCE_TOKEN:
        _fail("unissued_evidence")
    if not owner._evidence_issued(evidence):
        _fail("unissued_evidence")
    issued = owner._evidence_snapshot(evidence)
    if issued is None:
        _fail("unissued_evidence")
    if _evidence_signature(evidence) != issued:
        _fail("invalid_evidence")
    expected = (
        context.subject_ip, context.policy_id, context.start_utc, context.end_utc,
        context.failure_count, context.known_target_count, context.missing_user_count,
        tuple(id(item) for item in context.members),
    )
    actual = (
        evidence.subject_ip, evidence.policy_id, evidence.start_utc, evidence.end_utc,
        evidence.failure_count, evidence.known_target_count, evidence.missing_user_count,
        tuple(id(item) for item in evidence.members),
    )
    if actual != expected:
        _fail("invalid_evidence")


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class PrototypePairResult:
    correlated: bool
    reason: str
    failure_event: NormalizedEvent | None = field(default=None, repr=False, compare=False)
    success_event: NormalizedEvent | None = field(default=None, repr=False, compare=False)
    time_delta_seconds: float | None = None

    def __repr__(self) -> str:
        return f"PrototypePairResult(correlated={self.correlated}, reason={self.reason!r})"


def _correlate(
    owner: PrototypeSprayRunOwner,
    context: PrototypeSprayWindowContext,
    events: Iterable[NormalizedEvent],
    *, conservative: bool,
) -> PrototypePairResult:
    validate_window(owner, context)
    observed = owner._validate_events(events)
    if conservative and context.missing_user_count:
        return PrototypePairResult(False, "missing_account")
    successes = [item for item in observed if item.event_type == "user_login"]
    candidates = []
    for failure in context.members:
        if not isinstance(failure.user, str) or not failure.user:
            continue
        failure_time = _utc(failure.timestamp)
        for success in successes:
            if (success.user != failure.user or success.src_ip != context.subject_ip
                    or success.src_ip != failure.src_ip):
                continue
            success_time = _utc(success.timestamp)
            if success_time <= failure_time:
                continue
            if conservative and success_time <= context.end_utc:
                continue
            delta = success_time - failure_time
            if delta > CORRELATION_WINDOW:
                continue
            if conservative and success_time - context.end_utc > CORRELATION_WINDOW:
                continue
            candidates.append((delta, failure, success))
    if not candidates:
        return PrototypePairResult(False, "no_eligible_pair")
    minimum = min(item[0] for item in candidates)
    closest = [(failure, success) for delta, failure, success in candidates if delta == minimum]
    distinct = []
    for pair in closest:
        if not any(pair[0] is prior[0] and pair[1] is prior[1] for prior in distinct):
            distinct.append(pair)
    if len(distinct) != 1:
        return PrototypePairResult(False, "ambiguous_pair")
    failure, success = distinct[0]
    return PrototypePairResult(True, "member_bound_pair", failure, success, minimum.total_seconds())


def correlate_c1(owner, context, events) -> PrototypePairResult:
    """Candidate C1: member failure anchor, strict order, <=60s."""
    return _correlate(owner, context, events, conservative=False)


def correlate_c2(owner, context, events) -> PrototypePairResult:
    """Candidate C2: C1 plus complete member accounts and success after end."""
    return _correlate(owner, context, events, conservative=True)


def run_prototype_checks() -> dict:
    """Small deterministic smoke summary; it intentionally emits no event data."""
    base = datetime(2026, 10, 31, tzinfo=timezone.utc)
    rows = tuple(
        NormalizedEvent(base + timedelta(seconds=second), kind, "application", user, "192.0.2.77",
                        None, "synthetic-auth", None, None, "synthetic-redacted",
                        authentication=None)
        for second, kind, user in ((0, "login_failed", "spray_a"), (5, "login_failed", "spray_b"),
                                   (10, "login_failed", "spray_c"), (15, "login_failed", "spray_a"),
                                   (20, "user_login", "spray_a"))
    )
    owner = PrototypeSprayRunOwner()
    owner.register_events(rows)
    context = build_prototype_window(owner, "192.0.2.77")
    assert context is not None
    evidence = issue_detection_evidence(owner, context)
    validate_detection_evidence(owner, context, evidence)
    other = PrototypeSprayRunOwner()
    other.register_events((rows[0],))
    try:
        validate_window(other, context)
    except PrototypeValidationError as error:
        cross_run = error.code == "unissued_context"
    else:
        cross_run = False
    duplicate_rows = (
        NormalizedEvent(base, "login_failed", "application", "spray_a", "192.0.2.88",
                        None, "synthetic-auth", None, None, "synthetic-a"),
        NormalizedEvent(base + timedelta(seconds=5), "login_failed", "application", "spray_b", "192.0.2.88",
                        None, "synthetic-auth", None, None, "synthetic-b"),
        NormalizedEvent(base + timedelta(seconds=10), "login_failed", "application", "spray_c", "192.0.2.88",
                        None, "synthetic-auth", None, None, "synthetic-c"),
        NormalizedEvent(base + timedelta(seconds=15), "login_failed", "application", "spray_a", "192.0.2.88",
                        None, "synthetic-auth", None, None, "synthetic-a"),
        NormalizedEvent(base + timedelta(seconds=15), "login_failed", "application", "spray_a", "192.0.2.88",
                        None, "synthetic-auth", None, None, "synthetic-a"),
    )
    ambiguous_owner = PrototypeSprayRunOwner()
    ambiguous_owner.register_events(duplicate_rows)
    try:
        build_prototype_window(ambiguous_owner, "192.0.2.88")
    except PrototypeValidationError as error:
        ambiguous = error.code == "ambiguous_selection"
    else:
        ambiguous = False
    mutated = rows[0]
    mutated_timestamp = mutated.timestamp
    mutated.timestamp += timedelta(seconds=1)
    try:
        validate_window(owner, context)
    except PrototypeValidationError as error:
        mutation_rejected = error.code == "event_mutated"
    else:
        mutation_rejected = False
    mutated.timestamp = mutated_timestamp
    return {
        "prototype_version": "36.10B-R3-v1",
        "synthetic_scenario_count": 2,
        "owner_binding": "pass",
        "membership_validation": "pass",
        "evidence_validation": "pass",
        "correlation_c1": "pass" if correlate_c1(owner, context, rows).correlated else "fail",
        "correlation_c2": "pass" if correlate_c2(owner, context, rows).correlated else "fail",
        "cross_run_rejection": "pass" if cross_run else "fail",
        "ambiguous_selection": "fail_closed" if ambiguous else "fail",
        "mutation_rejection": "pass" if mutation_rejected else "fail",
        "production_changed": False,
        "remaining_risks": ["operational_false_alerts", "shared_egress", "live_runtime_parity"],
    }
