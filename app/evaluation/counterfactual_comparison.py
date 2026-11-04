"""Fail-closed comparison rules for ER-1B replay observations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CounterfactualReplayError(ValueError):
    _CODES = frozenset((
        "INVALID_INTERNAL_CONTRACT", "RESOURCE_LIMIT", "CORPUS_INVALID",
        "ANALYSIS_EXECUTION_FAILED", "INPUT_SCOPE_MISMATCH",
    ))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "INVALID_INTERNAL_CONTRACT"
        super().__init__(self.code)


class ParserState(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    REJECTED = "REJECTED"
    NOT_EVALUATED = "NOT_EVALUATED"


class DetectionState(str, Enum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    NOT_EVALUATED = "NOT_EVALUATED"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class ComparisonState(str, Enum):
    PRESERVED = "PRESERVED"
    LOST = "LOST"
    GAINED = "GAINED"
    UNCHANGED_ABSENT = "UNCHANGED_ABSENT"
    INCOMPARABLE = "INCOMPARABLE"
    UNDETERMINED = "UNDETERMINED"


_REASON_CODES = frozenset((
    "EVENT_COUNT_MISMATCH", "EVENT_TYPE_MISMATCH", "SUBJECT_MISMATCH",
    "REQUIRED_FIELD_MISSING", "LINE_REJECTED", "LINE_IGNORED",
    "PARSER_REJECTED", "UNSUPPORTED_SOURCE", "INPUT_LIMIT_EXCEEDED",
    "PARSER_NOT_RUN", "SOURCE_OUT_OF_SCOPE", "DETECTOR_MATCH",
    "NO_MATCH_IN_EVALUATED_SCOPE", "DETECTOR_NOT_RUN",
    "ANALYSIS_EXECUTION_FAILED", "RESOURCE_LIMIT", "INVALID_INTERNAL_CONTRACT",
    "OUTCOME_PRESERVED", "OUTCOME_LOST", "OUTCOME_GAINED",
    "OUTCOME_ABSENT_BOTH", "PARSER_PROFILE_MISMATCH",
    "DETECTOR_VERSION_MISMATCH", "POLICY_MISMATCH", "SOURCE_SCOPE_MISMATCH",
    "INPUT_SCOPE_MISMATCH", "EVIDENCE_BINDING_FAILED",
    "LABEL_PROVENANCE_MISSING", "AMBIGUOUS_OUTCOME", "EXECUTION_INCOMPLETE",
))


@dataclass(frozen=True, slots=True, repr=False)
class RunObservation:
    detector_id: str
    policy_id: str
    source: str
    parser_profile: str
    parser_state: str
    detection_state: str
    comparison_scope: str
    subject_present: bool
    label_provenance: bool
    evidence_bound: bool
    execution_complete: bool
    target_subject: str = field(default="192.0.2.10", repr=False)

    def __repr__(self) -> str:
        return "RunObservation(<synthetic run metadata redacted>)"


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    state: ComparisonState
    reason_codes: tuple[str, ...]


def _validate_run(run: object) -> None:
    if type(run) is not RunObservation:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    string_fields = (
        run.detector_id, run.policy_id, run.source, run.parser_profile,
        run.parser_state, run.detection_state, run.comparison_scope,
        run.target_subject,
    )
    if any(type(value) is not str or not value for value in string_fields):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.parser_state not in ParserState._value2member_map_:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.detection_state not in DetectionState._value2member_map_:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if any(type(value) is not bool for value in (
        run.subject_present, run.label_provenance, run.evidence_bound,
        run.execution_complete,
    )):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.parser_state == ParserState.REJECTED.value and run.detection_state != DetectionState.NOT_EVALUATED.value:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.parser_state == ParserState.NOT_EVALUATED.value and run.detection_state != DetectionState.NOT_EVALUATED.value:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.detection_state == DetectionState.EXECUTION_FAILED.value and run.execution_complete:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    if run.detection_state in (DetectionState.DETECTED.value, DetectionState.NOT_DETECTED.value) and not run.execution_complete:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")


def compare_runs(baseline: RunObservation, variant: RunObservation) -> ComparisonResult:
    """Compare only verified, complete, bound runs with matching proposition scope."""
    _validate_run(baseline)
    _validate_run(variant)

    mismatches = []
    if baseline.detector_id != variant.detector_id:
        mismatches.append("DETECTOR_VERSION_MISMATCH")
    if baseline.policy_id != variant.policy_id:
        mismatches.append("POLICY_MISMATCH")
    if baseline.source != variant.source:
        mismatches.append("SOURCE_SCOPE_MISMATCH")
    if baseline.parser_profile != variant.parser_profile:
        mismatches.append("PARSER_PROFILE_MISMATCH")
    if baseline.comparison_scope != variant.comparison_scope:
        mismatches.append("INPUT_SCOPE_MISMATCH")
    if baseline.target_subject != variant.target_subject:
        mismatches.append("SUBJECT_MISMATCH")
    if mismatches:
        return ComparisonResult(ComparisonState.INCOMPARABLE, tuple(sorted(set(mismatches))))

    states = (baseline.parser_state, variant.parser_state)
    if ParserState.REJECTED.value in states:
        return ComparisonResult(ComparisonState.INCOMPARABLE, ("PARSER_REJECTED",))
    if ParserState.NOT_EVALUATED.value in states:
        return ComparisonResult(ComparisonState.INCOMPARABLE, ("PARSER_NOT_RUN",))

    if not baseline.subject_present or not variant.subject_present:
        return ComparisonResult(ComparisonState.INCOMPARABLE, ("SUBJECT_MISMATCH",))
    if not baseline.label_provenance or not variant.label_provenance:
        return ComparisonResult(ComparisonState.UNDETERMINED, ("LABEL_PROVENANCE_MISSING",))
    if not baseline.evidence_bound or not variant.evidence_bound:
        return ComparisonResult(ComparisonState.UNDETERMINED, ("EVIDENCE_BINDING_FAILED",))

    if states != (ParserState.VERIFIED.value, ParserState.VERIFIED.value):
        if states[0] != states[1]:
            return ComparisonResult(ComparisonState.INCOMPARABLE, ("INPUT_SCOPE_MISMATCH",))
        return ComparisonResult(ComparisonState.UNDETERMINED, ("AMBIGUOUS_OUTCOME",))

    detection_states = (baseline.detection_state, variant.detection_state)
    if DetectionState.EXECUTION_FAILED.value in detection_states or DetectionState.NOT_EVALUATED.value in detection_states:
        return ComparisonResult(ComparisonState.UNDETERMINED, ("EXECUTION_INCOMPLETE",))
    mapping = {
        (DetectionState.DETECTED.value, DetectionState.DETECTED.value):
            (ComparisonState.PRESERVED, "OUTCOME_PRESERVED"),
        (DetectionState.DETECTED.value, DetectionState.NOT_DETECTED.value):
            (ComparisonState.LOST, "OUTCOME_LOST"),
        (DetectionState.NOT_DETECTED.value, DetectionState.DETECTED.value):
            (ComparisonState.GAINED, "OUTCOME_GAINED"),
        (DetectionState.NOT_DETECTED.value, DetectionState.NOT_DETECTED.value):
            (ComparisonState.UNCHANGED_ABSENT, "OUTCOME_ABSENT_BOTH"),
    }
    state, reason = mapping[detection_states]
    return ComparisonResult(state, (reason,))


def validate_reason_codes(values: object) -> tuple[str, ...]:
    if type(values) not in (tuple, list) or any(
        type(value) is not str or value not in _REASON_CODES for value in values
    ):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    return tuple(sorted(set(values)))
