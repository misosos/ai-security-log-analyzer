"""Read-only evaluation of fixed synthetic fixtures against reviewed labels."""

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.evaluation.corpus import (
    CASE_RULES, DETECTION_TYPES, FIXTURE_ROOT, LEVELS, RELATION_TYPES,
    EvaluationScenario, ExpectedCase, ExpectedDetection, ExpectedParser,
    ExpectedRelation, ExpectedRisk, SCENARIOS,
)
from app.main import analyze
from app.parser.registry import get_parser, get_timezone
from app.parser.time_utils import normalize_to_utc


NOTICES = (
    "합성·경계 시나리오 평가이며 실제 운영환경 성능을 의미하지 않습니다.",
    "탐지는 침해 확정이 아니며 상관관계는 인과관계가 아닙니다.",
    "precision/recall은 포함된 라벨 범위에서만 유효합니다.",
    "작은 support는 일반화할 수 없고 같은 fixture로 규칙 조정과 평가를 반복하면 과적합됩니다.",
)
_RELATION_SLOTS = (
    ("authentication", "failed_to_successful_login"),
    ("brute_force_to_success", "brute_force_to_successful_login"),
    ("password_spray_to_success", "password_spray_to_successful_login"),
)
_DETECTION_SLOTS = (
    ("brute_force", "brute_force"),
    ("password_spray", "password_spraying_like"),
    ("path_traversal", "path_traversal"),
)


class EvaluationError(ValueError):
    """Bounded failure; private input and underlying exceptions stay internal."""

    def __init__(self, code: Literal["invalid_label", "fixture_unavailable", "analysis_failed", "unknown_scenario"]):
        self.code = code if code in {
            "invalid_label", "fixture_unavailable", "analysis_failed", "unknown_scenario"
        } else "invalid_label"
        super().__init__(f"Evaluation failed: {self.code}.")


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, expected: bool, actual: bool) -> "Confusion":
        return Confusion(
            self.tp + int(expected and actual),
            self.fp + int(not expected and actual),
            self.fn + int(expected and not actual),
            self.tn + int(not expected and not actual),
        )


def ratio(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "not_applicable"
    return f"{numerator / denominator:.6f}"


@dataclass(frozen=True)
class DetectionMetric:
    detection_type: str
    tp: int
    fp: int
    fn: int
    tn: int
    support: int
    precision: str
    recall: str
    f1: str


@dataclass(frozen=True)
class CorrelationMetric:
    relation_type: str
    tp: int
    fp: int
    fn: int
    precision: str
    recall: str
    f1: str


@dataclass(frozen=True)
class ParserSummary:
    input_lines: int
    parsed: int
    ignored: int
    failed: int
    matched_scenarios: int
    unexpected_parse_count: int
    unexpected_rejection_count: int


@dataclass(frozen=True)
class LayerSummary:
    matched_scenarios: int
    failed_scenarios: int
    applicable_scenarios: int


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    passed: bool
    failed_layers: tuple[str, ...]


@dataclass(frozen=True)
class EvaluationSummary:
    schema_version: str
    corpus_kind: str
    scenario_count: int
    ssh_scenario_count: int
    excluded_ambiguous_scenarios: int
    excluded_reasons: tuple[str, ...]
    passed_scenarios: int
    failed_scenarios: int
    parser_summary: ParserSummary
    detection_metrics: tuple[DetectionMetric, ...]
    correlation_metrics: tuple[CorrelationMetric, ...]
    risk_summary: LayerSummary
    case_summary: LayerSummary
    invariant_failures: tuple[str, ...]
    scenarios: tuple[ScenarioResult, ...]
    interpretation_notices: tuple[str, ...]


def _validated_corpus(scenarios: tuple[EvaluationScenario, ...]) -> None:
    if type(scenarios) is not tuple or not scenarios:
        raise EvaluationError("invalid_label")
    ids: set[str] = set()
    for item in scenarios:
        if type(item) is not EvaluationScenario or type(item.id) is not str or not item.id.isascii() or not item.id.replace("_", "").isalnum() or item.id in ids:
            raise EvaluationError("invalid_label")
        ids.add(item.id)
        if (
            type(item.parser) is not ExpectedParser
            or type(item.detections) is not tuple
            or type(item.relations) is not tuple
            or type(item.risks) is not tuple
            or type(item.cases) is not tuple
            or any(type(d) is not ExpectedDetection for d in item.detections)
            or any(type(r) is not ExpectedRelation for r in item.relations)
            or any(type(r) is not ExpectedRisk for r in item.risks)
            or any(type(c) is not ExpectedCase for c in item.cases)
            or any(type(value) is not tuple for value in (
                item.parser.event_types, item.parser.account_present,
                item.parser.http_methods, item.parser.http_statuses,
                item.parser.line_dispositions,
            ))
        ):
            raise EvaluationError("invalid_label")
        if item.label_scope not in ("labeled", "parser_only", "ambiguous_operational"):
            raise EvaluationError("invalid_label")
        if item.label_scope == "ambiguous_operational":
            if item.exclusion_reason not in ("authorization_context_unavailable",):
                raise EvaluationError("invalid_label")
        elif item.exclusion_reason is not None:
            raise EvaluationError("invalid_label")
        if item.label_scope == "parser_only" and (
            item.detections or item.relations or item.risks or item.cases or item.independent_count
        ):
            raise EvaluationError("invalid_label")
        if (type(item.fixture) is not str or type(item.source) is not str
                or item.source not in ("application", "ssh", "access")
                or Path(item.fixture).name != item.fixture or not item.fixture.endswith(".log")):
            raise EvaluationError("invalid_label")
        if any(d.detection_type not in DETECTION_TYPES for d in item.detections):
            raise EvaluationError("invalid_label")
        if any(r.relation_type not in RELATION_TYPES for r in item.relations):
            raise EvaluationError("invalid_label")
        if any(r.level not in LEVELS or r.confidence not in LEVELS for r in item.risks):
            raise EvaluationError("invalid_label")
        if any(c.rule not in CASE_RULES or c.risk not in LEVELS for c in item.cases):
            raise EvaluationError("invalid_label")
        if len({(d.detection_type, d.subject) for d in item.detections}) != len(item.detections):
            raise EvaluationError("invalid_label")
        if len({(r.relation_type, r.subject) for r in item.relations}) != len(item.relations):
            raise EvaluationError("invalid_label")
        if len({r.subject for r in item.risks}) != len(item.risks):
            raise EvaluationError("invalid_label")
        if any(
            type(d.start) is not datetime or type(d.end) is not datetime
            or d.start.tzinfo is not timezone.utc or d.end.tzinfo is not timezone.utc
            or d.start > d.end
            or (
                d.detection_type != "path_traversal"
                and (
                    type(d.failure_count) is not int or d.failure_count < 0
                    or type(d.target_count) is not int or d.target_count < 0
                    or type(d.window_seconds) is not int or d.window_seconds < 0
                )
            )
            for d in item.detections
        ):
            raise EvaluationError("invalid_label")
        if any(
            type(r.failure_timestamp) is not datetime or type(r.success_timestamp) is not datetime
            or r.failure_timestamp.tzinfo is not timezone.utc
            or r.success_timestamp.tzinfo is not timezone.utc
            or r.failure_timestamp >= r.success_timestamp
            for r in item.relations
        ):
            raise EvaluationError("invalid_label")
        if any(
            type(c.supporting_relations) is not int or c.supporting_relations < 0
            or type(c.observation_count) is not int or c.observation_count < 1
            for c in item.cases
        ):
            raise EvaluationError("invalid_label")
        timestamps = tuple(t for t in (item.parser.first_timestamp, item.parser.last_timestamp) if t is not None) + tuple(
            timestamp for d in item.detections for timestamp in (d.start, d.end) if timestamp is not None
        ) + tuple(
            timestamp for r in item.relations for timestamp in (r.failure_timestamp, r.success_timestamp)
        )
        if any(type(t) is not datetime or t.tzinfo is not timezone.utc for t in timestamps):
            raise EvaluationError("invalid_label")
        try:
            parser_subject = () if item.label_scope == "parser_only" or item.parser.subject is None else (item.parser.subject,)
            subjects = parser_subject + tuple(d.subject for d in item.detections) + tuple(
                r.subject for r in item.relations
            ) + tuple(r.subject for r in item.risks)
            if any(type(subject) is not str or str(ip_address(subject)) != subject for subject in subjects):
                raise EvaluationError("invalid_label")
        except ValueError:
            raise EvaluationError("invalid_label") from None
        if item.independent_count < 0 or item.parser.lines < 0 or item.parser.lines != item.parser.parsed + item.parser.ignored + item.parser.failed:
            raise EvaluationError("invalid_label")
        if (
            len(item.parser.event_types) != item.parser.parsed
            or len(item.parser.account_present) != item.parser.parsed
            or len(item.parser.http_methods) != item.parser.parsed
            or len(item.parser.http_statuses) != item.parser.parsed
            or len(item.parser.line_dispositions) != item.parser.lines
            or item.parser.line_dispositions.count("parsed") != item.parser.parsed
            or item.parser.line_dispositions.count("ignored") != item.parser.ignored
            or item.parser.line_dispositions.count("rejected") != item.parser.failed
            or any(value not in ("parsed", "ignored", "rejected") for value in item.parser.line_dispositions)
            or any(type(value) is not bool for value in item.parser.account_present)
        ):
            raise EvaluationError("invalid_label")
        if item.parser.parsed == 0 and (item.parser.first_timestamp is not None or item.parser.last_timestamp is not None):
            raise EvaluationError("invalid_label")
        if item.parser.parsed > 0 and (item.parser.first_timestamp is None or item.parser.last_timestamp is None):
            raise EvaluationError("invalid_label")


def _fixture(item: EvaluationScenario) -> Path:
    path = FIXTURE_ROOT / item.fixture
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            raise EvaluationError("fixture_unavailable")
    except OSError:
        raise EvaluationError("fixture_unavailable") from None
    return path


def _parser_matches(item: EvaluationScenario, path: Path) -> tuple[bool, tuple[int, int, int, int], int, int]:
    parser = get_parser(item.source)
    zone = get_timezone(item.source)
    parsed = []
    dispositions = []
    ignored = failed = lines = 0
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                lines += 1
                try:
                    event = parser(line, zone)
                    if event is not None:
                        event.timestamp = normalize_to_utc(event.timestamp)
                except (ValueError, IndexError, TypeError):
                    failed += 1
                    dispositions.append("rejected")
                    continue
                if event is None:
                    ignored += 1
                    dispositions.append("ignored")
                else:
                    parsed.append(event)
                    dispositions.append("parsed")
    except (OSError, UnicodeError):
        raise EvaluationError("fixture_unavailable") from None
    observed = (lines, len(parsed), ignored, failed)
    expected = item.parser
    match = observed == (expected.lines, expected.parsed, expected.ignored, expected.failed)
    match &= tuple(dispositions) == expected.line_dispositions
    match &= tuple(event.event_type for event in parsed) == expected.event_types
    match &= all(event.src_ip == expected.subject for event in parsed)
    if parsed:
        match &= parsed[0].timestamp == expected.first_timestamp and parsed[-1].timestamp == expected.last_timestamp
    match &= tuple(bool(event.user) for event in parsed) == expected.account_present
    match &= tuple(event.http.method if event.http is not None else None for event in parsed) == expected.http_methods
    match &= tuple(event.http.status_code if event.http is not None else None for event in parsed) == expected.http_statuses
    unexpected_parse = sum(
        actual == "parsed" and labeled != "parsed"
        for actual, labeled in zip(dispositions, expected.line_dispositions)
    )
    unexpected_rejection = sum(
        actual != "parsed" and labeled == "parsed"
        for actual, labeled in zip(dispositions, expected.line_dispositions)
    )
    return match, observed, unexpected_parse, unexpected_rejection


def _detection_match(item: EvaluationScenario, results: dict) -> tuple[bool, dict[str, bool]]:
    expected_types = {d.detection_type for d in item.detections}
    actual: dict[str, bool] = {kind: False for kind in DETECTION_TYPES}
    exact = True
    for subject, subject_result in results.items():
        for slot, kind in _DETECTION_SLOTS:
            detected = subject_result["detections"][slot]
            if detected.is_detected:
                actual[kind] = True
                labels = [d for d in item.detections if d.detection_type == kind and d.subject == subject]
                if len(labels) != 1 or detected.detection_type != kind:
                    exact = False
                elif kind != "path_traversal":
                    label = labels[0]
                    evidence = {e.type: e for e in detected.evidence}
                    exact &= (
                        evidence["multiple_login_failures"].value == label.failure_count
                        and evidence["multiple_login_failures"].time_range == (label.start, label.end)
                        and evidence["failures_within_short_window"].value == label.window_seconds
                    )
                    target_type = "single_target_user" if kind == "brute_force" else "multiple_target_users"
                    exact &= evidence[target_type].value == label.target_count
                else:
                    exact &= any(e.type == "path_pattern" and e.value in ("../", "..\\") for e in detected.evidence)
    return exact and all(actual[k] == (k in expected_types) for k in DETECTION_TYPES), actual


def _relations(item: EvaluationScenario, results: dict) -> tuple[bool, dict[str, bool]]:
    actual: dict[str, bool] = {kind: False for kind in RELATION_TYPES}
    exact = True
    for subject, value in results.items():
        for slot, kind in _RELATION_SLOTS:
            relation = value["correlation"][slot]
            if relation["is_correlated"]:
                actual[kind] = True
                labels = [r for r in item.relations if r.relation_type == kind and r.subject == subject]
                exact &= len(labels) == 1 and relation["type"] == kind
                if len(labels) == 1:
                    exact &= (relation["failure_timestamp"], relation["success_timestamp"]) == (
                        labels[0].failure_timestamp, labels[0].success_timestamp
                    )
    return exact and all(actual[k] == any(r.relation_type == k for r in item.relations) for k in RELATION_TYPES), actual


def _risk_matches(item: EvaluationScenario, results: dict) -> bool:
    if set(results) != {r.subject for r in item.risks}:
        return False
    for label in item.risks:
        value = results[label.subject]
        factors = value["risk_factors"]
        if value["risk_level"] != label.level or factors["confidence"]["level"] != label.confidence:
            return False
        if any(not factors[key]["rationale"] for key in ("likelihood", "impact", "confidence")):
            return False
        if "evidence" not in factors:
            return False
    return True


def _case_matches(item: EvaluationScenario, projection) -> bool:
    if projection.summary.case_count != len(item.cases) or projection.summary.independent_observation_count != item.independent_count:
        return False
    if projection.summary.spray_no_go_observation_count and not any(
        i.display_type == "Password Spraying-like" for i in projection.independent_observations
    ):
        return False
    if any(
        case.row.observation_count != (
            len(case.timeline_entries) + len(case.timeline_entries_without_time)
            - case.row.supporting_relation_count
        )
        for case in projection.cases
    ):
        return False
    if any(
        case.row.supporting_relation_count != sum(
            entry.category == "SUPPORTED_RELATION"
            for entry in case.timeline_entries + case.timeline_entries_without_time
        )
        for case in projection.cases
    ):
        return False
    return all(
        case.rule_code == label.rule
        and case.row.included_highest_risk == label.risk
        and case.row.supporting_relation_count == label.supporting_relations
        and case.row.observation_count == label.observation_count
        and case.row.review_order == index
        for index, (case, label) in enumerate(zip(projection.cases, item.cases), 1)
    )


def _metric(kind: str, count: Confusion) -> DetectionMetric:
    return DetectionMetric(kind, count.tp, count.fp, count.fn, count.tn, count.tp + count.fn,
                           ratio(count.tp, count.tp + count.fp), ratio(count.tp, count.tp + count.fn),
                           ratio(2 * count.tp, 2 * count.tp + count.fp + count.fn))


def evaluate(scenarios: tuple[EvaluationScenario, ...] = SCENARIOS) -> EvaluationSummary:
    _validated_corpus(scenarios)
    parser_totals = [0, 0, 0, 0]
    parser_passes = risk_passes = case_passes = 0
    risk_applicable = case_applicable = 0
    unexpected_parse_total = unexpected_rejection_total = 0
    detection_counts = {kind: Confusion() for kind in DETECTION_TYPES}
    relation_counts = {kind: Confusion() for kind in RELATION_TYPES}
    outcomes = []
    for item in scenarios:
        path = _fixture(item)
        parser_ok, observed, unexpected_parse, unexpected_rejection = _parser_matches(item, path)
        parser_totals = [old + new for old, new in zip(parser_totals, observed)]
        unexpected_parse_total += unexpected_parse
        unexpected_rejection_total += unexpected_rejection
        if item.label_scope == "parser_only":
            parser_passes += int(parser_ok)
            failed = () if parser_ok else ("parser",)
            outcomes.append(ScenarioResult(item.id, parser_ok, failed))
            continue
        try:
            analysis = analyze([{"source": item.source, "path": str(path)}])
            projection = project_investigation_cases_from_analysis(analysis)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError):
            raise EvaluationError("analysis_failed") from None
        results = analysis["results"]
        try:
            detection_ok, detections = _detection_match(item, results)
            relation_ok, relations = _relations(item, results)
            risk_ok = _risk_matches(item, results)
            case_ok = _case_matches(item, projection)
        except (KeyError, IndexError, TypeError, AttributeError):
            raise EvaluationError("analysis_failed") from None
        if item.label_scope == "labeled":
            for kind in DETECTION_TYPES:
                detection_counts[kind] = detection_counts[kind].add(
                    any(d.detection_type == kind for d in item.detections), detections[kind]
                )
            for kind in RELATION_TYPES:
                relation_counts[kind] = relation_counts[kind].add(
                    any(r.relation_type == kind for r in item.relations), relations[kind]
                )
        parser_passes += int(parser_ok)
        risk_applicable += 1
        case_applicable += 1
        risk_passes += int(risk_ok)
        case_passes += int(case_ok)
        failed = tuple(name for name, ok in (
            ("parser", parser_ok), ("detection", detection_ok), ("correlation", relation_ok),
            ("risk", risk_ok), ("case", case_ok)
        ) if not ok)
        outcomes.append(ScenarioResult(item.id, not failed, failed))
    relation_metrics = tuple(
        CorrelationMetric(kind, count.tp, count.fp, count.fn,
                          ratio(count.tp, count.tp + count.fp), ratio(count.tp, count.tp + count.fn),
                          ratio(2 * count.tp, 2 * count.tp + count.fp + count.fn))
        for kind, count in relation_counts.items()
    )
    failures = tuple(f"{outcome.scenario_id}:{layer}" for outcome in outcomes for layer in outcome.failed_layers)
    exclusions = tuple(
        f"{item.id}:{item.exclusion_reason}" for item in scenarios
        if item.label_scope == "ambiguous_operational"
    )
    return EvaluationSummary(
        "1", "synthetic_boundary_corpus", len(scenarios),
        sum(item.source == "ssh" for item in scenarios), len(exclusions), exclusions,
        sum(o.passed for o in outcomes),
        sum(not o.passed for o in outcomes),
        ParserSummary(*parser_totals, parser_passes, unexpected_parse_total, unexpected_rejection_total),
        tuple(_metric(kind, count) for kind, count in detection_counts.items()), relation_metrics,
        LayerSummary(risk_passes, risk_applicable - risk_passes, risk_applicable),
        LayerSummary(case_passes, case_applicable - case_passes, case_applicable),
        failures, tuple(outcomes), NOTICES,
    )
