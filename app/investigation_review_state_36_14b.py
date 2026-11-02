"""Closed, memory-only analyst workflow state core (not wired to the app)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from threading import Lock
from typing import Final, Iterable, Mapping


SCHEMA_VERSION: Final = 1
MAX_ACTIVE_ANALYSES: Final = 1
MAX_CASES_PER_ANALYSIS: Final = 128
MAX_TOTAL_STATES: Final = 128
MAX_IDENTIFIER_LENGTH: Final = 34
MAX_REVISION: Final = (1 << 53) - 1

_ANALYSIS_REF = re.compile(r"a_[0-9a-f]{32}\Z")
_CASE_REF = re.compile(r"c_[0-9a-f]{24}\Z")


class ReviewState(str, Enum):
    UNREVIEWED = "unreviewed"
    IN_REVIEW = "in_review"
    REVIEWED = "reviewed"
    DEFERRED = "deferred"


class ReviewStateError(Exception):
    """Fixed-category failure; messages never echo input or identifiers."""

    __slots__ = ("code",)

    _MESSAGES = {
        "INVALID_INPUT": "Workflow state input is invalid.",
        "INVALID_IDENTIFIER": "Workflow state identifier is invalid.",
        "UNSUPPORTED_SCHEMA": "Workflow state schema is unsupported.",
        "UNKNOWN_ANALYSIS": "Workflow analysis is unavailable.",
        "UNKNOWN_CASE": "Workflow case is unavailable.",
        "INVALID_TRANSITION": "Workflow state transition is not allowed.",
        "STALE_REVISION": "Workflow state revision is stale.",
        "CAPACITY_EXCEEDED": "Workflow state capacity was exceeded.",
        "STORE_CLOSED": "Workflow state store is closed.",
        "ANALYSIS_ALREADY_ACTIVE": "Workflow analysis is already active.",
        "REVISION_LIMIT_REACHED": "Workflow state revision limit was reached.",
    }

    def __init__(self, code: str) -> None:
        if code not in self._MESSAGES:
            code = "INVALID_INPUT"
        self.code = code
        super().__init__(self._MESSAGES[code])

    def __repr__(self) -> str:
        return f"ReviewStateError(code={self.code!r})"


def _require_ref(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or len(value) > MAX_IDENTIFIER_LENGTH or pattern.fullmatch(value) is None:
        raise ReviewStateError("INVALID_IDENTIFIER")
    return value


def _require_revision(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_REVISION:
        raise ReviewStateError("INVALID_INPUT")
    return value


def _require_identity(value: object) -> ReviewCaseIdentity:
    if type(value) is not ReviewCaseIdentity:
        raise ReviewStateError("INVALID_INPUT")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class ReviewCaseIdentity:
    schema_version: int
    analysis_ref: str
    case_ref: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int:
            raise ReviewStateError("UNSUPPORTED_SCHEMA")
        if self.schema_version != SCHEMA_VERSION:
            raise ReviewStateError("UNSUPPORTED_SCHEMA")
        _require_ref(self.analysis_ref, _ANALYSIS_REF)
        _require_ref(self.case_ref, _CASE_REF)

    def __repr__(self) -> str:
        return "ReviewCaseIdentity(<opaque>)"

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "analysis_ref": self.analysis_ref,
            "case_ref": self.case_ref,
        }

    @classmethod
    def from_mapping(cls, value: object) -> ReviewCaseIdentity:
        expected = {"schema_version", "analysis_ref", "case_ref"}
        if type(value) is not dict or set(value) != expected:
            raise ReviewStateError("INVALID_INPUT")
        return cls(value["schema_version"], value["analysis_ref"], value["case_ref"])


@dataclass(frozen=True, slots=True, repr=False)
class ReviewStateSnapshot:
    identity: ReviewCaseIdentity
    review_state: ReviewState
    revision: int

    def __post_init__(self) -> None:
        _require_identity(self.identity)
        if type(self.review_state) is not ReviewState:
            raise ReviewStateError("INVALID_INPUT")
        _require_revision(self.revision)

    def __repr__(self) -> str:
        return f"ReviewStateSnapshot(state={self.review_state.value!r}, revision={self.revision})"

    def to_mapping(self) -> dict[str, object]:
        result = self.identity.to_mapping()
        result.update(review_state=self.review_state.value, revision=self.revision)
        return result

    @classmethod
    def from_mapping(cls, value: object) -> ReviewStateSnapshot:
        expected = {"schema_version", "analysis_ref", "case_ref", "review_state", "revision"}
        if type(value) is not dict or set(value) != expected:
            raise ReviewStateError("INVALID_INPUT")
        identity = ReviewCaseIdentity.from_mapping(
            {key: value[key] for key in ("schema_version", "analysis_ref", "case_ref")}
        )
        if type(value["review_state"]) is not str:
            raise ReviewStateError("INVALID_INPUT")
        try:
            state = ReviewState(value["review_state"])
        except (ValueError, TypeError):
            raise ReviewStateError("INVALID_INPUT") from None
        return cls(identity, state, value["revision"])


@dataclass(frozen=True, slots=True, repr=False)
class ReviewTransitionCommand:
    identity: ReviewCaseIdentity
    review_state: ReviewState
    expected_revision: int

    def __post_init__(self) -> None:
        _require_identity(self.identity)
        if type(self.review_state) is not ReviewState:
            raise ReviewStateError("INVALID_INPUT")
        _require_revision(self.expected_revision)

    def __repr__(self) -> str:
        return f"ReviewTransitionCommand(state={self.review_state.value!r}, expected_revision={self.expected_revision})"

    def to_mapping(self) -> dict[str, object]:
        result = self.identity.to_mapping()
        result.update(
            review_state=self.review_state.value,
            expected_revision=self.expected_revision,
        )
        return result

    @classmethod
    def from_mapping(cls, value: object) -> ReviewTransitionCommand:
        expected = {
            "schema_version", "analysis_ref", "case_ref", "review_state", "expected_revision"
        }
        if type(value) is not dict or set(value) != expected or type(value["review_state"]) is not str:
            raise ReviewStateError("INVALID_INPUT")
        identity = ReviewCaseIdentity.from_mapping(
            {key: value[key] for key in ("schema_version", "analysis_ref", "case_ref")}
        )
        try:
            state = ReviewState(value["review_state"])
        except (ValueError, TypeError):
            raise ReviewStateError("INVALID_INPUT") from None
        return cls(identity, state, value["expected_revision"])


@dataclass(frozen=True, slots=True, repr=False)
class ReviewResetCommand:
    identity: ReviewCaseIdentity
    expected_revision: int

    def __post_init__(self) -> None:
        _require_identity(self.identity)
        _require_revision(self.expected_revision)

    def __repr__(self) -> str:
        return f"ReviewResetCommand(expected_revision={self.expected_revision})"

    def to_mapping(self) -> dict[str, object]:
        result = self.identity.to_mapping()
        result["expected_revision"] = self.expected_revision
        return result

    @classmethod
    def from_mapping(cls, value: object) -> ReviewResetCommand:
        expected = {"schema_version", "analysis_ref", "case_ref", "expected_revision"}
        if type(value) is not dict or set(value) != expected:
            raise ReviewStateError("INVALID_INPUT")
        identity = ReviewCaseIdentity.from_mapping(
            {key: value[key] for key in ("schema_version", "analysis_ref", "case_ref")}
        )
        return cls(identity, value["expected_revision"])


_ALLOWED_TRANSITIONS: Final[dict[ReviewState, frozenset[ReviewState]]] = {
    ReviewState.UNREVIEWED: frozenset(
        {ReviewState.IN_REVIEW, ReviewState.REVIEWED, ReviewState.DEFERRED}
    ),
    ReviewState.IN_REVIEW: frozenset({ReviewState.REVIEWED, ReviewState.DEFERRED}),
    ReviewState.REVIEWED: frozenset({ReviewState.IN_REVIEW, ReviewState.DEFERRED}),
    ReviewState.DEFERRED: frozenset({ReviewState.IN_REVIEW, ReviewState.REVIEWED}),
}


class ReviewStateStore:
    """One-active-analysis bounded store; no IO and no analysis objects retained."""

    __slots__ = ("_lock", "_active_analysis", "_states", "_closed")

    def __init__(self) -> None:
        self._lock = Lock()
        self._active_analysis: str | None = None
        self._states: dict[str, ReviewStateSnapshot] = {}
        self._closed = False

    def __repr__(self) -> str:
        return "ReviewStateStore(<memory-only>)"

    def _check_open(self) -> None:
        if self._closed:
            raise ReviewStateError("STORE_CLOSED")

    def register_analysis(self, analysis_ref: str, case_refs: Iterable[str]) -> tuple[ReviewStateSnapshot, ...]:
        """Install a new generation. Input is validated and copied before replacement."""
        _require_ref(analysis_ref, _ANALYSIS_REF)
        if type(case_refs) not in (list, tuple, set, frozenset):
            raise ReviewStateError("INVALID_INPUT")
        if len(case_refs) > MAX_CASES_PER_ANALYSIS:
            raise ReviewStateError("CAPACITY_EXCEEDED")
        copied = tuple(case_refs)
        if len(copied) > MAX_TOTAL_STATES:
            raise ReviewStateError("CAPACITY_EXCEEDED")
        for case_ref in copied:
            _require_ref(case_ref, _CASE_REF)
        if len(set(copied)) != len(copied):
            raise ReviewStateError("INVALID_INPUT")
        copied = tuple(sorted(copied))
        snapshots = tuple(
            ReviewStateSnapshot(
                ReviewCaseIdentity(SCHEMA_VERSION, analysis_ref, case_ref),
                ReviewState.UNREVIEWED,
                0,
            )
            for case_ref in copied
        )
        new_states = {snapshot.identity.case_ref: snapshot for snapshot in snapshots}
        with self._lock:
            self._check_open()
            if self._active_analysis == analysis_ref:
                raise ReviewStateError("ANALYSIS_ALREADY_ACTIVE")
            if len(new_states) > MAX_TOTAL_STATES:
                raise ReviewStateError("CAPACITY_EXCEEDED")
            # A validated new generation atomically replaces the old in-memory projection.
            self._active_analysis = analysis_ref
            self._states = new_states
        return snapshots

    def get(self, identity: ReviewCaseIdentity) -> ReviewStateSnapshot:
        identity = _require_identity(identity)
        with self._lock:
            self._check_open()
            self._require_active(identity)
            snapshot = self._states.get(identity.case_ref)
            if snapshot is None:
                raise ReviewStateError("UNKNOWN_CASE")
            return snapshot

    def list_snapshots(self, analysis_ref: str) -> tuple[ReviewStateSnapshot, ...]:
        _require_ref(analysis_ref, _ANALYSIS_REF)
        with self._lock:
            self._check_open()
            if self._active_analysis != analysis_ref:
                raise ReviewStateError("UNKNOWN_ANALYSIS")
            return tuple(self._states.values())

    def transition(self, command: ReviewTransitionCommand) -> ReviewStateSnapshot:
        if type(command) is not ReviewTransitionCommand:
            raise ReviewStateError("INVALID_INPUT")
        with self._lock:
            self._check_open()
            current = self._lookup(command.identity)
            if current.revision != command.expected_revision:
                raise ReviewStateError("STALE_REVISION")
            if command.review_state not in _ALLOWED_TRANSITIONS[current.review_state]:
                raise ReviewStateError("INVALID_TRANSITION")
            return self._replace_state(current, command.review_state)

    def reset(self, command: ReviewResetCommand) -> ReviewStateSnapshot:
        if type(command) is not ReviewResetCommand:
            raise ReviewStateError("INVALID_INPUT")
        with self._lock:
            self._check_open()
            current = self._lookup(command.identity)
            if current.revision != command.expected_revision:
                raise ReviewStateError("STALE_REVISION")
            if current.review_state is ReviewState.UNREVIEWED:
                raise ReviewStateError("INVALID_TRANSITION")
            return self._replace_state(current, ReviewState.UNREVIEWED)

    def clear_analysis(self, analysis_ref: str) -> None:
        _require_ref(analysis_ref, _ANALYSIS_REF)
        with self._lock:
            self._check_open()
            if self._active_analysis != analysis_ref:
                raise ReviewStateError("UNKNOWN_ANALYSIS")
            self._active_analysis = None
            self._states = {}

    def clear_all(self) -> None:
        with self._lock:
            self._check_open()
            self._active_analysis = None
            self._states = {}

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._active_analysis = None
                self._states = {}
                self._closed = True

    def _require_active(self, identity: ReviewCaseIdentity) -> None:
        if self._active_analysis != identity.analysis_ref:
            raise ReviewStateError("UNKNOWN_ANALYSIS")

    def _lookup(self, identity: ReviewCaseIdentity) -> ReviewStateSnapshot:
        self._require_active(identity)
        snapshot = self._states.get(identity.case_ref)
        if snapshot is None:
            raise ReviewStateError("UNKNOWN_CASE")
        return snapshot

    def _replace_state(self, current: ReviewStateSnapshot, state: ReviewState) -> ReviewStateSnapshot:
        if current.revision >= MAX_REVISION:
            raise ReviewStateError("REVISION_LIMIT_REACHED")
        updated = ReviewStateSnapshot(current.identity, state, current.revision + 1)
        self._states[current.identity.case_ref] = updated
        return updated
