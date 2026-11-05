"""Read-only Markdown projection for the fixed ER-1B/ER-1C replay results."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any

from app.evaluation.counterfactual_comparison import (
    ComparisonState,
    CounterfactualReplayError,
    DetectionState,
    ParserState,
    _REASON_CODES,
    validate_reason_codes,
)
from app.evaluation.counterfactual_corpus import CounterfactualCorpusError, load_corpus
from app.evaluation.counterfactual_holdout import (
    AUTOMATED_AUDIT,
    HUMAN_REVIEW_PENDING,
    HoldoutError,
    load_holdout,
)
from app.evaluation.counterfactual_replay import ReplayReport, ReplayScenarioResult
from app.evaluation.counterfactual_holdout import HoldoutReplayReport


SCHEMA_VERSION = 1
MAX_MARKDOWN_BYTES = 128 * 1024
_SCENARIO_ID = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
_DETECTORS = frozenset(("brute_force", "password_spraying_like"))
_POLICIES = {
    "brute_force": "brute_force_production_v1",
    "password_spraying_like": "password_spray_whole_span_production_v1",
}
_MUTATIONS = frozenset((
    "remove_failure_row", "add_failure_row", "change_timestamp", "change_account",
    "change_source_ip", "reorder_rows", "damage_format",
))
_LABEL_VALIDATION = frozenset(("MATCH", "MISMATCH", "NOT_EVALUATED"))
_COMPARISON_LABELS = {
    "PRESERVED": "탐지 유지",
    "LOST": "탐지 소멸",
    "GAINED": "새로 탐지",
    "UNCHANGED_ABSENT": "양쪽 미탐지",
    "INCOMPARABLE": "비교 불가",
    "UNDETERMINED": "판정 불확정",
}


class AnalystReportError(ValueError):
    """Fixed-category report validation error without input reflection."""

    _CODES = frozenset(("INVALID_REPORT_INPUT", "RESOURCE_LIMIT"))

    def __init__(self, code: str = "INVALID_REPORT_INPUT") -> None:
        self.code = code if code in self._CODES else "INVALID_REPORT_INPUT"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"AnalystReportError({self.code})"


@dataclass(frozen=True, slots=True)
class ScenarioProjection:
    corpus_id: str
    scenario_id: str
    detector_id: str
    mutation_type: str
    baseline_parser_state: str
    variant_parser_state: str
    baseline_detection_state: str
    variant_detection_state: str
    comparison_state: str
    reason_codes: tuple[str, ...]
    # Kept only for count reconciliation; never rendered in Markdown.
    label_validation_baseline: str
    label_validation_variant: str


@dataclass(frozen=True, slots=True)
class CorpusProjection:
    corpus_id: str
    denominator: int
    parser_baseline: Mapping[str, int]
    parser_variant: Mapping[str, int]
    detection_baseline: Mapping[str, int]
    detection_variant: Mapping[str, int]
    comparison_counts: Mapping[str, int]
    label_baseline: Mapping[str, int]
    label_variant: Mapping[str, int]
    excluded_comparisons: int
    reason_code_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class AnalystReport:
    schema_version: int
    development: CorpusProjection
    holdout: CorpusProjection
    scenarios: tuple[ScenarioProjection, ...]

    @property
    def scenario_count(self) -> int:
        return len(self.scenarios)


def _invalid() -> AnalystReportError:
    return AnalystReportError("INVALID_REPORT_INPUT")


def _closed_state(value: object, enum_type) -> str:
    if type(value) is not str or value not in {item.value for item in enum_type}:
        raise _invalid()
    return value


def _count_mapping(value: object, allowed: tuple[str, ...], *, denominator: int) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or set(value) != set(allowed):
        raise _invalid()
    result = {}
    for key in allowed:
        count = value[key]
        if type(count) is not int or count < 0 or count > denominator:
            raise _invalid()
        result[key] = count
    if sum(result.values()) != denominator:
        raise _invalid()
    return MappingProxyType(result)


def _reason_codes(value: object) -> tuple[str, ...]:
    try:
        normalized = validate_reason_codes(value)
    except CounterfactualReplayError:
        raise _invalid() from None
    if tuple(value) != normalized:
        raise _invalid()
    return normalized


def _validate_outcome(parser_baseline: str, parser_variant: str,
                      detector_baseline: str, detector_variant: str,
                      comparison: str, reasons: tuple[str, ...]) -> None:
    """Check public result invariants; private provenance stays with the producer."""
    outcomes = {
        "PRESERVED": (("DETECTED", "DETECTED"), "OUTCOME_PRESERVED"),
        "LOST": (("DETECTED", "NOT_DETECTED"), "OUTCOME_LOST"),
        "GAINED": (("NOT_DETECTED", "DETECTED"), "OUTCOME_GAINED"),
        "UNCHANGED_ABSENT": (("NOT_DETECTED", "NOT_DETECTED"), "OUTCOME_ABSENT_BOTH"),
    }
    for parser, detection in ((parser_baseline, detector_baseline), (parser_variant, detector_variant)):
        if parser in ("REJECTED", "NOT_EVALUATED") and detection != "NOT_EVALUATED":
            raise _invalid()
    if comparison not in outcomes:
        return
    expected_states, expected_reason = outcomes[comparison]
    outcome_reasons = {reason for reason in reasons if reason in {item[1] for item in outcomes.values()}}
    if (
        (parser_baseline, parser_variant) != ("VERIFIED", "VERIFIED")
        or (detector_baseline, detector_variant) != expected_states
        or outcome_reasons != {expected_reason}
    ):
        raise _invalid()


def _validate_row(row: object, *, metadata: Mapping[str, tuple[str, str]], corpus_id: str) -> ScenarioProjection:
    if type(row) is not ReplayScenarioResult:
        raise _invalid()
    if (
        type(row.scenario_id) is not str
        or _SCENARIO_ID.fullmatch(row.scenario_id) is None
        or row.scenario_id not in metadata
    ):
        raise _invalid()
    detector, mutation = metadata[row.scenario_id]
    if (
        type(row.detector_id) is not str
        or type(row.policy_id) is not str
        or type(row.parser_profile) is not str
        or row.detector_id not in _DETECTORS
        or row.detector_id != detector
        or row.policy_id != _POLICIES[detector]
        or mutation not in _MUTATIONS
        or row.parser_profile not in ("application_auth_v1", "rfc5424_openssh_restricted_v1")
    ):
        raise _invalid()
    parser_baseline = _closed_state(row.baseline_parser_state, ParserState)
    parser_variant = _closed_state(row.variant_parser_state, ParserState)
    detector_baseline = _closed_state(row.baseline_detection_state, DetectionState)
    detector_variant = _closed_state(row.variant_detection_state, DetectionState)
    comparison = _closed_state(row.comparison_state, ComparisonState)
    label_baseline = row.label_validation_baseline
    label_variant = row.label_validation_variant
    if type(label_baseline) is not str or type(label_variant) is not str or label_baseline not in _LABEL_VALIDATION or label_variant not in _LABEL_VALIDATION:
        raise _invalid()
    for parser_state, detection_state in (
        (parser_baseline, detector_baseline),
        (parser_variant, detector_variant),
    ):
        if parser_state in (ParserState.REJECTED.value, ParserState.NOT_EVALUATED.value) and detection_state != DetectionState.NOT_EVALUATED.value:
            raise _invalid()
        if detection_state == DetectionState.EXECUTION_FAILED.value and comparison in {
            ComparisonState.PRESERVED.value,
            ComparisonState.LOST.value,
            ComparisonState.GAINED.value,
            ComparisonState.UNCHANGED_ABSENT.value,
        }:
            raise _invalid()
    if type(row.reason_codes) is not tuple:
        raise _invalid()
    reasons = _reason_codes(row.reason_codes)
    _validate_outcome(parser_baseline, parser_variant, detector_baseline, detector_variant, comparison, reasons)
    outcome_comparisons = {
        ComparisonState.PRESERVED.value,
        ComparisonState.LOST.value,
        ComparisonState.GAINED.value,
        ComparisonState.UNCHANGED_ABSENT.value,
    }
    if comparison in outcome_comparisons and (
        parser_baseline != ParserState.VERIFIED.value
        or parser_variant != ParserState.VERIFIED.value
        or detector_baseline not in (DetectionState.DETECTED.value, DetectionState.NOT_DETECTED.value)
        or detector_variant not in (DetectionState.DETECTED.value, DetectionState.NOT_DETECTED.value)
    ):
        raise _invalid()
    for parser_state, detection_state, label_state in (
        (parser_baseline, detector_baseline, label_baseline),
        (parser_variant, detector_variant, label_variant),
    ):
        if parser_state != ParserState.VERIFIED.value or detection_state in (
            DetectionState.NOT_EVALUATED.value, DetectionState.EXECUTION_FAILED.value,
        ):
            if label_state != "NOT_EVALUATED":
                raise _invalid()
    return ScenarioProjection(
        corpus_id=corpus_id,
        scenario_id=row.scenario_id,
        detector_id=detector,
        mutation_type=mutation,
        baseline_parser_state=parser_baseline,
        variant_parser_state=parser_variant,
        baseline_detection_state=detector_baseline,
        variant_detection_state=detector_variant,
        comparison_state=comparison,
        reason_codes=reasons,
        label_validation_baseline=label_baseline,
        label_validation_variant=label_variant,
    )


def _summarize(
    rows: tuple[ScenarioProjection, ...],
    *,
    corpus_id: str,
    source_counts: object,
    holdout: bool,
) -> CorpusProjection:
    denominator = len(rows)
    if denominator < 1:
        raise _invalid()

    def count(attribute: str, allowed: tuple[str, ...]) -> Mapping[str, int]:
        return MappingProxyType({
            state: sum(getattr(row, attribute) == state for row in rows)
            for state in allowed
        })

    parser_values = tuple(item.value for item in ParserState)
    detection_values = tuple(item.value for item in DetectionState)
    comparison_values = tuple(item.value for item in ComparisonState)
    label_values = tuple(sorted(_LABEL_VALIDATION))
    parser_baseline = count("baseline_parser_state", parser_values)
    parser_variant = count("variant_parser_state", parser_values)
    detection_baseline = count("baseline_detection_state", detection_values)
    detection_variant = count("variant_detection_state", detection_values)
    comparisons = count("comparison_state", comparison_values)
    label_baseline = count("label_validation_baseline", label_values)
    label_variant = count("label_validation_variant", label_values)
    excluded = comparisons[ComparisonState.INCOMPARABLE.value] + comparisons[ComparisonState.UNDETERMINED.value]
    reason_counts = MappingProxyType({
        reason: sum(reason in row.reason_codes for row in rows)
        for reason in sorted(_REASON_CODES)
    })

    expected = {
        "parser_baseline": parser_baseline,
        "parser_variant": parser_variant,
        "detector_baseline": detection_baseline,
        "detector_variant": detection_variant,
        "comparison": comparisons,
    }
    if holdout:
        if not isinstance(source_counts, Mapping):
            raise _invalid()
        for key, expected_value in expected.items():
            _assert_count_mapping(source_counts.get(key), expected_value, denominator)
        labels = source_counts.get("label_validation")
        if not isinstance(labels, Mapping):
            raise _invalid()
        _assert_count_mapping(labels.get("baseline"), label_baseline, denominator)
        _assert_count_mapping(labels.get("variant"), label_variant, denominator)
        if labels.get("mismatch_total") != label_baseline["MISMATCH"] + label_variant["MISMATCH"]:
            raise _invalid()
        if labels.get("not_evaluated_total") != label_baseline["NOT_EVALUATED"] + label_variant["NOT_EVALUATED"]:
            raise _invalid()
        excluded_counts = source_counts.get("excluded_comparisons")
        if not isinstance(excluded_counts, Mapping) or excluded_counts.get("count") != excluded:
            raise _invalid()
        if source_counts.get("execution_failures") != detection_baseline["EXECUTION_FAILED"] + detection_variant["EXECUTION_FAILED"]:
            raise _invalid()
    else:
        if not isinstance(source_counts, Mapping):
            raise _invalid()
        for key, expected_value in expected.items():
            _assert_count_mapping(source_counts.get(key), expected_value, denominator)
        _assert_count_mapping(source_counts.get("label_baseline"), label_baseline, denominator)
        _assert_count_mapping(source_counts.get("label_variant"), label_variant, denominator)
        excluded_counts = source_counts.get("excluded_comparisons")
        if not isinstance(excluded_counts, Mapping) or excluded_counts.get("count") != excluded:
            raise _invalid()

    _assert_count_mapping(source_counts.get("reason_codes"), reason_counts, denominator)
    return CorpusProjection(
        corpus_id=corpus_id,
        denominator=denominator,
        parser_baseline=parser_baseline,
        parser_variant=parser_variant,
        detection_baseline=detection_baseline,
        detection_variant=detection_variant,
        comparison_counts=comparisons,
        label_baseline=label_baseline,
        label_variant=label_variant,
        excluded_comparisons=excluded,
        reason_code_counts=reason_counts,
    )


def _assert_count_mapping(actual: object, expected: Mapping[str, int], denominator: int) -> None:
    if not isinstance(actual, Mapping) or set(actual) != set(expected):
        raise _invalid()
    for key, expected_count in expected.items():
        value = actual[key]
        if type(value) is not int or value < 0 or value > denominator or value != expected_count:
            raise _invalid()


def build_report(development: ReplayReport, holdout: HoldoutReplayReport) -> AnalystReport:
    """Validate replay DTOs against both fixed inventories and project safe fields."""
    if type(development) is not ReplayReport or type(holdout) is not HoldoutReplayReport:
        raise _invalid()
    if development.schema_version != 1 or holdout.schema_version != SCHEMA_VERSION:
        raise _invalid()
    if holdout.human_review_status != HUMAN_REVIEW_PENDING or holdout.label_audit_status != AUTOMATED_AUDIT:
        raise _invalid()
    try:
        development_scenarios = load_corpus()
        holdout_corpus = load_holdout()
    except (CounterfactualCorpusError, HoldoutError):
        raise _invalid() from None
    development_metadata = {
        item.scenario_id: (item.detector_id, item.mutation_type)
        for item in development_scenarios
    }
    holdout_metadata = {
        item.scenario_id: (item.detector_id, item.mutation_type)
        for item in holdout_corpus.scenarios
    }
    if (
        development.scenario_count != len(development_metadata)
        or len(development.results) != len(development_metadata)
        or holdout.scenario_count != len(holdout_metadata)
        or len(holdout.results) != len(holdout_metadata)
        or holdout.corpus_id != holdout_corpus.corpus_id
        or set(holdout.fixture_hashes) != {item.baseline_fixture_id for item in holdout_corpus.scenarios}
    ):
        raise _invalid()
    dev_ids = [item.scenario_id for item in development.results]
    hold_ids = [item.scenario_id for item in holdout.results]
    if set(dev_ids) != set(development_metadata) or len(set(dev_ids)) != len(dev_ids):
        raise _invalid()
    if set(hold_ids) != set(holdout_metadata) or len(set(hold_ids)) != len(hold_ids):
        raise _invalid()
    if set(dev_ids) & set(hold_ids):
        raise _invalid()

    dev_rows = tuple(sorted(
        (_validate_row(row, metadata=development_metadata, corpus_id="er1a_development") for row in development.results),
        key=lambda item: item.scenario_id,
    ))
    hold_rows = tuple(sorted(
        (_validate_row(row, metadata=holdout_metadata, corpus_id=holdout.corpus_id) for row in holdout.results),
        key=lambda item: item.scenario_id,
    ))
    _validate_holdout_audit(holdout)
    dev_summary = _summarize(
        dev_rows, corpus_id="er1a_development", source_counts=development.counts, holdout=False,
    )
    hold_summary = _summarize(
        hold_rows, corpus_id=holdout.corpus_id, source_counts=holdout.counts, holdout=True,
    )
    report = AnalystReport(SCHEMA_VERSION, dev_summary, hold_summary, (*dev_rows, *hold_rows))
    _validate_projection(report)
    if len(render_markdown(report).encode("utf-8")) > MAX_MARKDOWN_BYTES:
        raise AnalystReportError("RESOURCE_LIMIT")
    return report


def _validate_holdout_audit(report: HoldoutReplayReport) -> None:
    audit_rows = report.audit_rows
    if len(audit_rows) != report.scenario_count:
        raise _invalid()
    ids = []
    for item in audit_rows:
        if item.status != AUTOMATED_AUDIT:
            raise _invalid()
        ids.append(item.scenario_id)
        _reason_codes(item.reason_codes)
    if len(set(ids)) != len(ids) or set(ids) != {item.scenario_id for item in report.results}:
        raise _invalid()
    audit = report.development_audit
    if audit.status != AUTOMATED_AUDIT or audit.human_review_status != HUMAN_REVIEW_PENDING:
        raise _invalid()
    if audit.scenario_count < 1 or audit.input_validation_failures != 0 or audit.label_mismatches != 0:
        raise _invalid()


def _validate_projection(report: AnalystReport) -> None:
    if type(report) is not AnalystReport or report.schema_version != SCHEMA_VERSION:
        raise _invalid()
    if report.scenario_count < 1 or report.scenario_count > 32:
        raise _invalid()
    if type(report.development) is not CorpusProjection or type(report.holdout) is not CorpusProjection:
        raise _invalid()
    if report.development.corpus_id != "er1a_development" or report.holdout.corpus_id != "er1c_independent_holdout_v1":
        raise _invalid()
    seen = set()
    for item in report.scenarios:
        if type(item) is not ScenarioProjection or type(item.scenario_id) is not str or _SCENARIO_ID.fullmatch(item.scenario_id) is None:
            raise _invalid()
        if (
            item.scenario_id in seen
            or item.corpus_id not in ("er1a_development", "er1c_independent_holdout_v1")
            or type(item.detector_id) is not str
            or item.detector_id not in _DETECTORS
            or type(item.mutation_type) is not str
            or item.mutation_type not in _MUTATIONS
        ):
            raise _invalid()
        seen.add(item.scenario_id)
        _closed_state(item.baseline_parser_state, ParserState)
        _closed_state(item.variant_parser_state, ParserState)
        _closed_state(item.baseline_detection_state, DetectionState)
        _closed_state(item.variant_detection_state, DetectionState)
        _closed_state(item.comparison_state, ComparisonState)
        reasons = _reason_codes(item.reason_codes)
        _validate_outcome(item.baseline_parser_state, item.variant_parser_state,
                          item.baseline_detection_state, item.variant_detection_state,
                          item.comparison_state, reasons)
        if (
            type(item.label_validation_baseline) is not str
            or type(item.label_validation_variant) is not str
            or item.label_validation_baseline not in _LABEL_VALIDATION
            or item.label_validation_variant not in _LABEL_VALIDATION
        ):
            raise _invalid()
    if seen != {item.scenario_id for item in report.scenarios}:
        raise _invalid()
    for corpus_id, corpus in (
        ("er1a_development", report.development),
        ("er1c_independent_holdout_v1", report.holdout),
    ):
        rows = tuple(item for item in report.scenarios if item.corpus_id == corpus_id)
        denominator = len(rows)
        if denominator < 1 or corpus.denominator != denominator:
            raise _invalid()
        expected_maps = (
            (corpus.parser_baseline, {state.value: sum(row.baseline_parser_state == state.value for row in rows) for state in ParserState}, tuple(item.value for item in ParserState)),
            (corpus.parser_variant, {state.value: sum(row.variant_parser_state == state.value for row in rows) for state in ParserState}, tuple(item.value for item in ParserState)),
            (corpus.detection_baseline, {state.value: sum(row.baseline_detection_state == state.value for row in rows) for state in DetectionState}, tuple(item.value for item in DetectionState)),
            (corpus.detection_variant, {state.value: sum(row.variant_detection_state == state.value for row in rows) for state in DetectionState}, tuple(item.value for item in DetectionState)),
            (corpus.comparison_counts, {state.value: sum(row.comparison_state == state.value for row in rows) for state in ComparisonState}, tuple(item.value for item in ComparisonState)),
            (corpus.label_baseline, {state: sum(row.label_validation_baseline == state for row in rows) for state in _LABEL_VALIDATION}, tuple(sorted(_LABEL_VALIDATION))),
            (corpus.label_variant, {state: sum(row.label_validation_variant == state for row in rows) for state in _LABEL_VALIDATION}, tuple(sorted(_LABEL_VALIDATION))),
            (corpus.reason_code_counts, {reason: sum(reason in row.reason_codes for row in rows) for reason in sorted(_REASON_CODES)}, tuple(sorted(_REASON_CODES))),
        )
        for actual, expected, allowed in expected_maps:
            _assert_count_mapping(actual, expected, denominator)
        expected_excluded = corpus.comparison_counts[ComparisonState.INCOMPARABLE.value] + corpus.comparison_counts[ComparisonState.UNDETERMINED.value]
        if type(corpus.excluded_comparisons) is not int or corpus.excluded_comparisons != expected_excluded:
            raise _invalid()


def _cell(value: str) -> str:
    if type(value) is not str or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
        raise _invalid()
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _state_table(title: str, baseline: Mapping[str, int], variant: Mapping[str, int], denominator: int) -> list[str]:
    lines = [f"| {title} | Baseline ({denominator}) | Variant ({denominator}) |", "|---|---:|---:|"]
    for state in sorted(baseline):
        lines.append(f"| {_cell(state)} | {baseline[state]}/{denominator} | {variant[state]}/{denominator} |")
    return lines


def render_markdown(report: AnalystReport) -> str:
    _validate_projection(report)
    total = report.scenario_count
    combined_comparisons = {
        state: report.development.comparison_counts[state] + report.holdout.comparison_counts[state]
        for state in (item.value for item in ComparisonState)
    }
    lines = [
        "# ER-2A — 오프라인 합성 보안 근거 검토 보고서",
        "",
        "## Executive Summary",
        "",
        "| 항목 | 값 |",
        "|---|---|",
        "| Evaluation Scope | SYNTHETIC_ONLY |",
        f"| Development Corpus | {report.development.denominator}건 |",
        f"| Holdout Corpus | {report.holdout.denominator}건 |",
        f"| 총 시나리오 | {total}건 |",
        "| Human Review | PENDING |",
        "| Operational Validation | NOT_APPROVED |",
        "",
        "총계는 두 개별 Corpus의 결과를 단순 합산한 값이며, 별도 통합 replay나 독립 검증 점수가 아닙니다.",
        "",
        "## Corpus별 결과",
        "",
        "### Development Corpus — er1a_development",
        "",
        *_state_table("Parser", report.development.parser_baseline, report.development.parser_variant, report.development.denominator),
        "",
        *_state_table("Detection", report.development.detection_baseline, report.development.detection_variant, report.development.denominator),
        "",
        "| Comparison | 건수 / 분모 |",
        "|---|---:|",
    ]
    for state in (item.value for item in ComparisonState):
        lines.append(f"| {_cell(state)} | {report.development.comparison_counts[state]}/{report.development.denominator} |")
    lines.extend([
        "",
        *_state_table("Label Validation", report.development.label_baseline, report.development.label_variant, report.development.denominator),
        "",
        f"비교 제외(INCOMPARABLE + UNDETERMINED): {report.development.excluded_comparisons}/{report.development.denominator}",
        "",
        f"### Holdout Corpus — {_cell(report.holdout.corpus_id)}",
        "",
        *_state_table("Parser", report.holdout.parser_baseline, report.holdout.parser_variant, report.holdout.denominator),
        "",
        *_state_table("Detection", report.holdout.detection_baseline, report.holdout.detection_variant, report.holdout.denominator),
        "",
        "| Comparison | 건수 / 분모 |",
        "|---|---:|",
    ])
    for state in (item.value for item in ComparisonState):
        lines.append(f"| {_cell(state)} | {report.holdout.comparison_counts[state]}/{report.holdout.denominator} |")
    lines.extend([
        "",
        *_state_table("Label Validation", report.holdout.label_baseline, report.holdout.label_variant, report.holdout.denominator),
        "",
        f"비교 제외(INCOMPARABLE + UNDETERMINED): {report.holdout.excluded_comparisons}/{report.holdout.denominator}",
        "",
        "각 corpus 집계의 분모는 해당 corpus의 시나리오 수입니다. Parser와 Detection은 Baseline/Variant를 각각 집계했습니다.",
        "",
        "## Comparison Summary",
        "",
        "전체 count는 corpus별 수치를 단순 합산하며, 각 상태의 분모는 30개 Scenario입니다.",
        "",
        "| 원본 상태 | 표시 | 건수 / 분모 | 해석 제한 |",
        "|---|---|---:|---|",
    ])
    restrictions = {
        "PRESERVED": "합성 비교 범위에서 양쪽 탐지",
        "LOST": "공격 회피 성공을 뜻하지 않음",
        "GAINED": "새 공격의 발견을 단정하지 않음",
        "UNCHANGED_ABSENT": "안전을 뜻하지 않음",
        "INCOMPARABLE": "동일 범위 비교가 성립하지 않음",
        "UNDETERMINED": "근거가 부족해 판정 보류",
    }
    for state in (item.value for item in ComparisonState):
        lines.append(f"| {state} | {_COMPARISON_LABELS[state]} | {combined_comparisons[state]}/{total} | {restrictions[state]} |")
    lines.extend([
        "",
        "## Scenario Review Table",
        "",
        "이 표는 읽기 전용 결과 요약입니다. Expected Label과 Label Basis는 포함하지 않으며 Label-Blind reviewer packet을 대체하지 않습니다.",
        "",
        "| Corpus ID | Scenario ID | Detector ID | Mutation Type | Baseline Parser | Variant Parser | Baseline Detection | Variant Detection | Comparison | Reason Codes |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ])
    for item in sorted(report.scenarios, key=lambda value: (value.corpus_id, value.scenario_id)):
        reasons = ", ".join(item.reason_codes) if item.reason_codes else "—"
        lines.append(
            "| " + " | ".join(_cell(value) for value in (
                item.corpus_id, item.scenario_id, item.detector_id, item.mutation_type,
                item.baseline_parser_state, item.variant_parser_state,
                item.baseline_detection_state, item.variant_detection_state,
                item.comparison_state, reasons,
            )) + " |"
        )
    lines.extend([
        "",
        "## Incomparable and Undetermined Handling",
        "",
        "`INCOMPARABLE`과 `UNDETERMINED`는 별도 상태로 유지합니다. 각 scenario의 기존 closed Reason Code를 그대로 표시하며 별도 원인 설명이나 새 Reason Code를 생성하지 않습니다.",
        "Parser 불완전성은 미탐지가 아니며, 실행 실패는 `EXECUTION_FAILED`로 보존합니다.",
        "",
        "## Security and Privacy",
        "",
        "- 합성 corpus의 검증된 replay DTO에서 허용된 식별자·enum·reason·count만 출력합니다.",
        "- Raw Log, IP, 계정명, timestamp, 로컬 경로, Evidence 객체, Run Owner 및 예외 원문은 출력하지 않습니다.",
        "- Expected Label과 Label Basis는 scenario table 및 본 보고서에서 제외합니다.",
        "- 외부 네트워크, LLM, 원격 서비스, 자동 대응을 호출하지 않습니다.",
        "",
        "## Review Limitations",
        "",
        "- 이 결과는 합성 자료에 한정됩니다.",
        "- 독립 사람 검토는 미완료입니다.",
        "- 실제 운영 정확도는 검증되지 않았습니다.",
        "- 공격 의도와 침해 여부를 판정하지 않습니다.",
        "- Parser 불완전성은 미탐지와 다릅니다.",
        "- 입력 변형과 결과 변화 사이의 유일한 원인은 확정되지 않았습니다.",
        "- 자동 대응 기능이 아닙니다.",
        "",
        "Human Review: `INDEPENDENT_HUMAN_REVIEW_PENDING` · Manual Approval: `REQUIRED` · ER-1D Implementation: `HOLD`.",
        "실제 사용자 자료·조직 운영·자동 대응은 `NO_GO`입니다.",
        "",
    ])
    rendered = "\n".join(lines)
    encoded = rendered.encode("utf-8")
    if len(encoded) > MAX_MARKDOWN_BYTES:
        raise AnalystReportError("RESOURCE_LIMIT")
    return rendered
