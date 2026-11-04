"""Offline ER-1B replay through the existing Production analysis entrypoint."""

from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_network
import io
import json
from pathlib import Path
import tempfile
from types import MappingProxyType
from typing import Any

from app.detector.brute_force import (
    AnalysisRunOwner,
    brute_evidence_matches_context,
    brute_window_context_owner,
)
from app.evaluation.counterfactual_comparison import (
    ComparisonState,
    CounterfactualReplayError,
    DetectionState,
    ParserState,
    RunObservation,
    compare_runs,
    validate_reason_codes,
)
from app.evaluation.counterfactual_corpus import (
    CounterfactualScenario,
    PreparedScenario,
    _thaw,
    load_corpus,
    load_fixture,
    prepare_scenario,
)
from app.evaluation.counterfactual_mutation import (
    CounterfactualCorpusError,
    apply_mutation,
)
from app.main import analyze_with_source_role_snapshot
from app.models.schemas import DetectionResult, Evidence


SCHEMA_VERSION = 1
MAX_CANONICAL_OUTPUT_BYTES = 64 * 1024
_DETECTOR_KEYS = {
    "brute_force": "brute_force",
    "password_spraying_like": "password_spray",
}
_PARSER_PROFILES = {
    "application": "application_auth_v1",
    "ssh": "rfc5424_openssh_restricted_v1",
}
_REASONS = frozenset((
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
_LABEL_STATES = frozenset(("MATCH", "MISMATCH", "NOT_EVALUATED"))
_DOC_NETWORKS = tuple(ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
))


@dataclass(frozen=True, slots=True)
class SafeFacts:
    event_count: int
    login_failed_count: int
    known_account_count: int
    source_ip_count: int
    target_failure_count: int
    target_known_account_count: int
    target_failure_span_seconds: int | float | None

    @classmethod
    def from_pairs(cls, pairs):
        values = dict(pairs)
        return cls(**values)

    def to_mapping(self) -> dict[str, int | float | None]:
        return {
            "event_count": self.event_count,
            "login_failed_count": self.login_failed_count,
            "known_account_count": self.known_account_count,
            "source_ip_count": self.source_ip_count,
            "target_failure_count": self.target_failure_count,
            "target_known_account_count": self.target_known_account_count,
            "target_failure_span_seconds": self.target_failure_span_seconds,
        }


@dataclass(frozen=True, slots=True)
class ReplayScenarioResult:
    scenario_id: str
    detector_id: str
    policy_id: str
    parser_profile: str
    baseline_parser_state: str
    variant_parser_state: str
    baseline_detection_state: str
    variant_detection_state: str
    comparison_state: str
    reason_codes: tuple[str, ...]
    baseline_pattern_label: str
    variant_pattern_label: str
    label_validation_baseline: str
    label_validation_variant: str
    baseline_facts: SafeFacts | None
    variant_facts: SafeFacts | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "detector_id": self.detector_id,
            "policy_id": self.policy_id,
            "parser_profile": self.parser_profile,
            "parser": {
                "baseline": self.baseline_parser_state,
                "variant": self.variant_parser_state,
            },
            "detection": {
                "baseline": self.baseline_detection_state,
                "variant": self.variant_detection_state,
            },
            "comparison": self.comparison_state,
            "reason_codes": list(self.reason_codes),
            "independent_pattern": {
                "baseline": self.baseline_pattern_label,
                "variant": self.variant_pattern_label,
            },
            "label_validation": {
                "baseline": self.label_validation_baseline,
                "variant": self.label_validation_variant,
            },
            "facts": {
                "baseline": None if self.baseline_facts is None else self.baseline_facts.to_mapping(),
                "variant": None if self.variant_facts is None else self.variant_facts.to_mapping(),
            },
        }


@dataclass(frozen=True, slots=True)
class ReplayReport:
    schema_version: int
    scenario_count: int
    counts: Any = field(repr=False)
    results: tuple[ReplayScenarioResult, ...]

    def __repr__(self) -> str:
        return f"ReplayReport(schema_version={self.schema_version}, scenario_count={self.scenario_count})"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scenario_count": self.scenario_count,
            "counts": {key: dict(value) for key, value in self.counts.items()},
            "results": [row.to_mapping() for row in self.results],
        }


@dataclass(frozen=True, slots=True, repr=False)
class _Execution:
    parser_state: str
    detection_state: str
    facts: SafeFacts | None
    subject_present: bool
    evidence_bound: bool
    execution_complete: bool
    reason_codes: tuple[str, ...]
    owner: AnalysisRunOwner | None = field(default=None, repr=False, compare=False)


def _fixed_reasons(values) -> tuple[str, ...]:
    try:
        return validate_reason_codes(tuple(values))
    except CounterfactualReplayError:
        raise


def _safe_facts(pairs) -> SafeFacts:
    try:
        result = SafeFacts.from_pairs(pairs)
    except (TypeError, ValueError):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT") from None
    for value in result.to_mapping().values():
        if value is not None and (type(value) not in (int, float) or value < 0):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    return result


def _label_validation(parser_state: str, detection_state: str, label: str) -> str:
    if parser_state != ParserState.VERIFIED.value or detection_state not in (
        DetectionState.DETECTED.value, DetectionState.NOT_DETECTED.value,
    ) or label == "PATTERN_UNDETERMINED":
        return "NOT_EVALUATED"
    expected_detected = label == "PATTERN_PRESENT"
    return "MATCH" if (detection_state == "DETECTED") is expected_detected else "MISMATCH"


def _verify_spray_evidence(detection: DetectionResult, features: dict) -> bool:
    if detection.is_detected is not True:
        return detection.detection_type is None and detection.evidence == []
    if detection.detection_type != "password_spraying_like" or type(detection.evidence) is not list:
        return False
    evidence = {item.type: item for item in detection.evidence if type(item) is Evidence}
    expected_types = {
        "multiple_login_failures", "multiple_target_users", "failures_within_short_window",
    }
    if len(evidence) != 3 or set(evidence) != expected_types:
        return False
    if any(item.source != "password_spray_detector" for item in evidence.values()):
        return False
    if (
        evidence["multiple_login_failures"].value != features.get("failure_count")
        or evidence["multiple_target_users"].value != features.get("unique_target_count")
        or evidence["failures_within_short_window"].value != features.get("window_seconds")
    ):
        return False
    time_range = evidence["multiple_login_failures"].time_range
    return (
        type(time_range) is tuple and len(time_range) == 2
        and all(isinstance(item, datetime) and item.tzinfo is not None for item in time_range)
        and (time_range[1] - time_range[0]).total_seconds() == features.get("window_seconds")
    )


def _execute_production(
    scenario: CounterfactualScenario,
    input_bytes: bytes,
    parser_state: str,
    facts: SafeFacts | None,
    *,
    label_provenance: bool,
    run_role: str,
) -> tuple[_Execution, RunObservation]:
    if parser_state == ParserState.REJECTED.value:
        execution = _Execution(
            parser_state, DetectionState.NOT_EVALUATED.value, None,
            False, True, True, ("PARSER_REJECTED", "DETECTOR_NOT_RUN"),
        )
        return execution, RunObservation(
            scenario.detector_id, scenario.policy_id, scenario.source,
            _PARSER_PROFILES[scenario.source], parser_state,
            DetectionState.NOT_EVALUATED.value, scenario.comparison_scope,
            False, label_provenance, True, True, scenario.target_subject,
        )

    try:
        if parser_state not in (ParserState.VERIFIED.value, ParserState.PARTIAL.value):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        if run_role not in ("baseline", "variant"):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        with tempfile.TemporaryDirectory(prefix=f"er1b-{run_role}-") as directory:
            path = Path(directory) / "synthetic.log"
            path.write_bytes(input_bytes)
            if path.read_bytes() != input_bytes:
                raise CounterfactualReplayError("INPUT_SCOPE_MISMATCH")
            capture_out = io.StringIO()
            capture_err = io.StringIO()
            with redirect_stdout(capture_out), redirect_stderr(capture_err):
                bundle = analyze_with_source_role_snapshot([
                    {"source": scenario.source, "path": str(path)},
                ])

        if (
            bundle.run_owner is None
            or type(bundle.run_owner) is not AnalysisRunOwner
            or not bundle.run_owner.is_bound_to(bundle.analysis)
            or not bundle.source_roles.is_bound_to(bundle.analysis)
        ):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        analysis = bundle.analysis
        if type(analysis) is not dict and not isinstance(analysis, dict):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        results = analysis.get("results")
        if type(results) is not dict:
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        subject = results.get(scenario.target_subject)
        if subject is None:
            execution = _Execution(
                parser_state, DetectionState.NOT_EVALUATED.value, facts,
                False, True, True, ("SUBJECT_MISMATCH", "DETECTOR_NOT_RUN"), bundle.run_owner,
            )
            observation = RunObservation(
                scenario.detector_id, scenario.policy_id, scenario.source,
                _PARSER_PROFILES[scenario.source], parser_state,
                DetectionState.NOT_EVALUATED.value, scenario.comparison_scope,
                False, label_provenance, True, True, scenario.target_subject,
            )
            return execution, observation
        if type(subject) is not dict or type(subject.get("features")) is not dict or type(subject.get("detections")) is not dict:
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        detector_key = _DETECTOR_KEYS[scenario.detector_id]
        detection = subject["detections"].get(detector_key)
        if type(detection) is not DetectionResult or type(detection.is_detected) is not bool:
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        if detection.is_detected:
            if detection.detection_type != scenario.detector_id:
                raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        elif detection.detection_type is not None or detection.evidence != []:
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")

        if scenario.detector_id == "brute_force":
            context = bundle.brute_window_contexts.get(scenario.target_subject)
            if detection.is_detected:
                if (
                    context is None
                    or brute_window_context_owner(context) is not bundle.run_owner
                    or not brute_evidence_matches_context(
                        detection, context, subject_ip=scenario.target_subject,
                    )
                ):
                    raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
            elif context is not None:
                raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
        elif not _verify_spray_evidence(detection, subject["features"]):
            raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")

        detected = detection.is_detected
        state = DetectionState.DETECTED.value if detected else DetectionState.NOT_DETECTED.value
        reasons = ["DETECTOR_MATCH" if detected else "NO_MATCH_IN_EVALUATED_SCOPE"]
        if parser_state == ParserState.PARTIAL.value:
            reasons.append("REQUIRED_FIELD_MISSING")
        execution = _Execution(
            parser_state, state, facts, True, True, True,
            tuple(reasons),
            bundle.run_owner,
        )
        observation = RunObservation(
            scenario.detector_id, scenario.policy_id, scenario.source,
            _PARSER_PROFILES[scenario.source], parser_state, state,
            scenario.comparison_scope, True, label_provenance, True, True,
            scenario.target_subject,
        )
        return execution, observation
    except CounterfactualReplayError as error:
        if error.code not in ("INVALID_INTERNAL_CONTRACT", "INPUT_SCOPE_MISMATCH"):
            raise
        reason = "EVIDENCE_BINDING_FAILED" if error.code == "INVALID_INTERNAL_CONTRACT" else "INPUT_SCOPE_MISMATCH"
        execution = _Execution(
            parser_state, DetectionState.EXECUTION_FAILED.value, facts,
            facts is not None and facts.target_failure_count > 0, False, False,
            (reason, "EXECUTION_INCOMPLETE"),
        )
        observation = RunObservation(
            scenario.detector_id, scenario.policy_id, scenario.source,
            _PARSER_PROFILES[scenario.source], parser_state,
            DetectionState.EXECUTION_FAILED.value, scenario.comparison_scope,
            execution.subject_present, label_provenance, False, False,
            scenario.target_subject,
        )
        return execution, observation
    except Exception:
        execution = _Execution(
            parser_state, DetectionState.EXECUTION_FAILED.value, facts,
            facts is not None and facts.target_failure_count > 0, False, False,
            ("ANALYSIS_EXECUTION_FAILED",),
        )
        observation = RunObservation(
            scenario.detector_id, scenario.policy_id, scenario.source,
            _PARSER_PROFILES[scenario.source], parser_state,
            DetectionState.EXECUTION_FAILED.value, scenario.comparison_scope,
            execution.subject_present, label_provenance, False, False,
            scenario.target_subject,
        )
        return execution, observation


def _result_counts(results: tuple[ReplayScenarioResult, ...]):
    state_values = {
        "parser_baseline": tuple(item.baseline_parser_state for item in results),
        "parser_variant": tuple(item.variant_parser_state for item in results),
        "detector_baseline": tuple(item.baseline_detection_state for item in results),
        "detector_variant": tuple(item.variant_detection_state for item in results),
        "comparison": tuple(item.comparison_state for item in results),
        "label_baseline": tuple(item.label_validation_baseline for item in results),
        "label_variant": tuple(item.label_validation_variant for item in results),
    }
    allowed = {
        "parser_baseline": tuple(item.value for item in ParserState),
        "parser_variant": tuple(item.value for item in ParserState),
        "detector_baseline": tuple(item.value for item in DetectionState),
        "detector_variant": tuple(item.value for item in DetectionState),
        "comparison": tuple(item.value for item in ComparisonState),
        "label_baseline": tuple(_LABEL_STATES),
        "label_variant": tuple(_LABEL_STATES),
    }
    counts = {
        key: MappingProxyType({state: values.count(state) for state in allowed[key]})
        for key, values in state_values.items()
    }
    counts["excluded_comparisons"] = MappingProxyType({
        "count": sum(
            item.comparison_state in (
                ComparisonState.INCOMPARABLE.value,
                ComparisonState.UNDETERMINED.value,
            )
            for item in results
        ),
    })
    counts["reason_codes"] = MappingProxyType({
        code: sum(code in item.reason_codes for item in results)
        for code in sorted(_REASONS)
    })
    return MappingProxyType(counts)


def _failed_result(scenario: CounterfactualScenario, reason: str) -> ReplayScenarioResult:
    return ReplayScenarioResult(
        scenario.scenario_id, scenario.detector_id, scenario.policy_id,
        _PARSER_PROFILES[scenario.source],
        ParserState.NOT_EVALUATED.value, ParserState.NOT_EVALUATED.value,
        DetectionState.NOT_EVALUATED.value, DetectionState.NOT_EVALUATED.value,
        ComparisonState.UNDETERMINED.value, _fixed_reasons((reason, "EXECUTION_INCOMPLETE")),
        scenario.baseline_expected_behavioral_pattern,
        scenario.expected_behavioral_pattern,
        "NOT_EVALUATED", "NOT_EVALUATED", None, None,
    )


def run_scenario(scenario: CounterfactualScenario) -> ReplayScenarioResult:
    if type(scenario) is not CounterfactualScenario:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    try:
        prepared = prepare_scenario(scenario)
        baseline_bytes = load_fixture(scenario.baseline_fixture_id)
        variant_bytes = apply_mutation(
            baseline_bytes,
            source=scenario.source,
            mutation_type=scenario.mutation_type,
            mutation_target=scenario.mutation_target,
            mutation_parameters=_thaw(scenario.mutation_parameters),
        )
    except CounterfactualCorpusError as error:
        if error.code == "parser_execution_failed":
            return _failed_result(scenario, "ANALYSIS_EXECUTION_FAILED")
        raise CounterfactualReplayError("CORPUS_INVALID") from None

    return _replay_prevalidated_scenario(scenario, baseline_bytes, variant_bytes, prepared)


def _replay_prevalidated_scenario(
    scenario: CounterfactualScenario,
    baseline_bytes: bytes,
    variant_bytes: bytes,
    prepared,
) -> ReplayScenarioResult:
    """Run independently validated bytes through two fresh Production runs."""
    if (
        type(scenario) is not CounterfactualScenario
        or type(baseline_bytes) is not bytes
        or type(variant_bytes) is not bytes
        or type(prepared) is not PreparedScenario
        or prepared.scenario_id != scenario.scenario_id
        or prepared.detector_id != scenario.detector_id
        or not prepared.label_validated
    ):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")

    baseline_facts = _safe_facts(prepared.baseline_event_facts)
    variant_facts = None if prepared.event_facts is None else _safe_facts(prepared.event_facts)
    baseline, baseline_observation = _execute_production(
        scenario, baseline_bytes, prepared.baseline_parser_disposition,
        baseline_facts, label_provenance=prepared.label_validated, run_role="baseline",
    )
    variant, variant_observation = _execute_production(
        scenario, variant_bytes, prepared.parser_disposition,
        variant_facts, label_provenance=prepared.label_validated, run_role="variant",
    )
    if baseline.owner is not None and variant.owner is not None and baseline.owner is variant.owner:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")

    comparison = compare_runs(baseline_observation, variant_observation)
    reasons = set(baseline.reason_codes) | set(variant.reason_codes) | set(comparison.reason_codes)
    return ReplayScenarioResult(
        scenario_id=scenario.scenario_id,
        detector_id=scenario.detector_id,
        policy_id=scenario.policy_id,
        parser_profile=_PARSER_PROFILES[scenario.source],
        baseline_parser_state=baseline.parser_state,
        variant_parser_state=variant.parser_state,
        baseline_detection_state=baseline.detection_state,
        variant_detection_state=variant.detection_state,
        comparison_state=comparison.state.value,
        reason_codes=_fixed_reasons(reasons),
        baseline_pattern_label=scenario.baseline_expected_behavioral_pattern,
        variant_pattern_label=scenario.expected_behavioral_pattern,
        label_validation_baseline=_label_validation(
            baseline.parser_state, baseline.detection_state,
            scenario.baseline_expected_behavioral_pattern,
        ),
        label_validation_variant=_label_validation(
            variant.parser_state, variant.detection_state,
            scenario.expected_behavioral_pattern,
        ),
        baseline_facts=baseline.facts,
        variant_facts=variant.facts,
    )


def run_corpus() -> ReplayReport:
    try:
        scenarios = tuple(sorted(load_corpus(), key=lambda item: item.scenario_id))
        if not 1 <= len(scenarios) <= 32:
            raise CounterfactualReplayError("RESOURCE_LIMIT")
        results = tuple(run_scenario(item) for item in scenarios)
    except CounterfactualCorpusError:
        raise CounterfactualReplayError("CORPUS_INVALID") from None
    report = ReplayReport(SCHEMA_VERSION, len(results), _result_counts(results), results)
    if len(canonical_json(report)) > MAX_CANONICAL_OUTPUT_BYTES:
        raise CounterfactualReplayError("RESOURCE_LIMIT")
    return report


def canonical_json(report: ReplayReport) -> bytes:
    if type(report) is not ReplayReport or report.schema_version != SCHEMA_VERSION:
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT")
    try:
        encoded = (
            json.dumps(
                report.to_mapping(), sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise CounterfactualReplayError("INVALID_INTERNAL_CONTRACT") from None
    if len(encoded) > MAX_CANONICAL_OUTPUT_BYTES:
        raise CounterfactualReplayError("RESOURCE_LIMIT")
    return encoded
