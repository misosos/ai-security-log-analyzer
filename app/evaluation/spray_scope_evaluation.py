"""Bounded, offline comparison of Password Spray-like scope policies."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from time import perf_counter_ns
import tracemalloc
from typing import Any

from app.main import analyze
from app.parser.registry import get_parser, get_timezone
from app.parser.time_utils import normalize_to_utc
from app.evaluation.spray_scope_policy import (
    evaluate_known_account_window,
    evaluate_sliding_ip_window,
)


CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "spray_scope_evaluation"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SCENARIOS = 128
MAX_FIXTURE_BYTES = 8 * 1024
MAX_INPUTS_PER_SCENARIO = 4
MAX_LINES_PER_INPUT = 128
MAX_EVENTS_PER_SCENARIO = 512
MAX_TOTAL_FIXTURE_LINES = 4096
SPRAY_FAILURES = 4
SPRAY_TARGETS = 3
SPRAY_WINDOW_SECONDS = 60

POLICIES = ("current_whole_span", "sliding_ip_window", "known_account_window")
PATTERN_LABELS = frozenset(("PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"))
CONTEXT_LABELS = frozenset(("KNOWN_BENIGN", "CONTEXT_UNKNOWN", "NOT_LABELED", "SIMULATED_ATTACK"))
PARSER_STATUSES = frozenset(("VERIFIED", "PARTIAL", "REJECTED", "IGNORED"))
UNDETERMINED_REASONS = frozenset((
    "account_identity_incomplete", "parser_observation_insufficient", "actor_attribution_unavailable",
))
ALLOWED_SOURCES = frozenset(("application", "ssh", "access"))
DOCUMENTATION_NETWORKS = (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)
ID_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
USER_RE = re.compile(r"spray_[a-z0-9_]{1,24}\Z", re.ASCII)
ROOT_KEYS = {"schema_version", "data_scope", "scenarios"}
SCENARIO_KEYS = {
    "id", "inputs", "subjects", "expected_event_count", "expected_failure_count",
    "behavioral_pattern", "operational_context", "expected_parser_status",
    "expected_parser_counts", "undetermined_reason", "label_basis", "context_basis",
}
INPUT_KEYS = {"source", "fixture"}
COUNT_KEYS = {"input_lines", "parsed", "ignored", "rejected"}


class SprayScopeEvaluationError(ValueError):
    def __init__(self, code: str = "invalid_manifest"):
        self.code = code if code in {
            "invalid_manifest", "fixture_unavailable", "parser_contract_mismatch", "evaluation_failed",
        } else "invalid_manifest"
        super().__init__(self.code)


@dataclass(frozen=True)
class _ParsedScenario:
    events: tuple[Any, ...]
    counts: dict[str, int]
    status: str
    failure_count: int
    known_target_count: int
    time_range: tuple[str, str] | None
    reason: str


def _json_load(raw: bytes) -> dict[str, Any]:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise SprayScopeEvaluationError("invalid_manifest") from None
    if type(value) is not dict or set(value) != ROOT_KEYS:
        raise SprayScopeEvaluationError("invalid_manifest")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise SprayScopeEvaluationError("invalid_manifest")
    if value["data_scope"] != "synthetic-only" or type(value["scenarios"]) is not list:
        raise SprayScopeEvaluationError("invalid_manifest")
    return value


def _is_documentation_ip(value: object) -> bool:
    from ipaddress import ip_address, ip_network

    if type(value) is not str:
        return False
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return str(parsed) == value and any(parsed in ip_network(network) for network in DOCUMENTATION_NETWORKS)


def load_scenarios(manifest_path: Path = MANIFEST_PATH) -> tuple[dict[str, Any], ...]:
    root = manifest_path.parent
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise SprayScopeEvaluationError("invalid_manifest")
        root_real = root.resolve(strict=True)
        manifest_path.resolve(strict=True).relative_to(root_real)
        raw = manifest_path.read_bytes()
    except SprayScopeEvaluationError:
        raise
    except (OSError, ValueError):
        raise SprayScopeEvaluationError("fixture_unavailable") from None

    scenarios = _json_load(raw)["scenarios"]
    if not 1 <= len(scenarios) <= MAX_SCENARIOS:
        raise SprayScopeEvaluationError()
    ids: set[str] = set()
    fixtures: set[str] = set()
    accepted = []
    total_lines = 0
    for item in scenarios:
        if type(item) is not dict or set(item) != SCENARIO_KEYS:
            raise SprayScopeEvaluationError()
        if (
            type(item["id"]) is not str or ID_RE.fullmatch(item["id"]) is None or item["id"] in ids
            or type(item["inputs"]) is not list or not 1 <= len(item["inputs"]) <= MAX_INPUTS_PER_SCENARIO
            or type(item["subjects"]) is not list or len(item["subjects"]) > 8
            or any(not _is_documentation_ip(subject) for subject in item["subjects"])
            or len(set(item["subjects"])) != len(item["subjects"])
            or type(item["expected_event_count"]) is not int or not 0 <= item["expected_event_count"] <= MAX_EVENTS_PER_SCENARIO
            or type(item["expected_failure_count"]) is not int or not 0 <= item["expected_failure_count"] <= item["expected_event_count"]
            or type(item["behavioral_pattern"]) is not str or item["behavioral_pattern"] not in PATTERN_LABELS
            or type(item["operational_context"]) is not str or item["operational_context"] not in CONTEXT_LABELS
            or type(item["expected_parser_status"]) is not str or item["expected_parser_status"] not in PARSER_STATUSES
            or type(item["expected_parser_counts"]) is not dict or set(item["expected_parser_counts"]) != COUNT_KEYS
            or any(type(value) is not int or value < 0 for value in item["expected_parser_counts"].values())
            or sum(item["expected_parser_counts"][key] for key in ("parsed", "ignored", "rejected"))
                != item["expected_parser_counts"]["input_lines"]
            or type(item["undetermined_reason"]) not in (str, type(None))
            or (item["behavioral_pattern"] == "PATTERN_UNDETERMINED")
                != (item["undetermined_reason"] in UNDETERMINED_REASONS)
            or type(item["label_basis"]) is not str or not 1 <= len(item["label_basis"]) <= 300
            or type(item["context_basis"]) is not str or not 1 <= len(item["context_basis"]) <= 300
        ):
            raise SprayScopeEvaluationError()
        counts = item["expected_parser_counts"]
        if (
            counts["parsed"] != item["expected_event_count"]
            or item["expected_failure_count"] > counts["parsed"]
            or counts["input_lines"] == 0
            or counts["input_lines"] > MAX_LINES_PER_INPUT * len(item["inputs"])
        ):
            raise SprayScopeEvaluationError()
        if item["expected_parser_status"] == "VERIFIED" and (
            counts["parsed"] != counts["input_lines"] or counts["ignored"] or counts["rejected"]
        ):
            raise SprayScopeEvaluationError()
        if item["expected_parser_status"] == "REJECTED" and (counts["parsed"] or counts["ignored"] or not counts["rejected"]):
            raise SprayScopeEvaluationError()
        if item["expected_parser_status"] == "IGNORED" and (counts["parsed"] or counts["rejected"] or not counts["ignored"]):
            raise SprayScopeEvaluationError()
        seen_sources = set()
        for source_input in item["inputs"]:
            if type(source_input) is not dict or set(source_input) != INPUT_KEYS:
                raise SprayScopeEvaluationError()
            source = source_input["source"]
            fixture_name = source_input["fixture"]
            if type(source) is not str or source not in ALLOWED_SOURCES or source in seen_sources:
                raise SprayScopeEvaluationError()
            if type(fixture_name) is not str:
                raise SprayScopeEvaluationError()
            fixture = Path(fixture_name)
            if (
                fixture.is_absolute() or len(fixture.parts) != 1 or fixture.suffix != ".log"
                or fixture.name != fixture_name or fixture_name in fixtures
            ):
                raise SprayScopeEvaluationError()
            path = root_real / fixture
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FIXTURE_BYTES:
                    raise SprayScopeEvaluationError("fixture_unavailable")
                path.resolve(strict=True).relative_to(root_real)
                raw_lines = path.read_bytes().splitlines()
            except SprayScopeEvaluationError:
                raise
            except (OSError, ValueError):
                raise SprayScopeEvaluationError("fixture_unavailable") from None
            nonempty = sum(bool(line.strip()) for line in raw_lines)
            if not 0 < nonempty <= MAX_LINES_PER_INPUT:
                raise SprayScopeEvaluationError()
            total_lines += nonempty
            fixtures.add(fixture_name)
            seen_sources.add(source)
        if len(fixtures) > MAX_SCENARIOS * MAX_INPUTS_PER_SCENARIO or total_lines > MAX_TOTAL_FIXTURE_LINES:
            raise SprayScopeEvaluationError()
        ids.add(item["id"])
        accepted.append(item)

    actual_files = {path.name for path in root_real.glob("*.log") if path.is_file() and not path.is_symlink()}
    if actual_files != fixtures:
        raise SprayScopeEvaluationError()
    return tuple(sorted(accepted, key=lambda row: row["id"]))


def _scenario_sources(scenario: dict[str, Any], root: Path) -> list[dict[str, str]]:
    return [{"source": item["source"], "path": str(root / item["fixture"])} for item in scenario["inputs"]]


def _parser_status(events: list[Any], counts: dict[str, int]) -> str:
    if counts["parsed"] == 0 and counts["rejected"] > 0 and counts["ignored"] == 0:
        return "REJECTED"
    if counts["parsed"] == 0 and counts["ignored"] > 0 and counts["rejected"] == 0:
        return "IGNORED"
    incomplete_fields = any(
        event.src_ip is None
        or (event.event_type in {"login_failed", "user_login"} and event.authentication is None)
        or (event.event_type == "login_failed" and not event.user)
        for event in events
    )
    if counts["rejected"] or counts["ignored"] or incomplete_fields:
        return "PARTIAL"
    return "VERIFIED"


def _parser_reason(events: list[Any], counts: dict[str, int]) -> str:
    if counts["parsed"] == 0 and counts["rejected"] > 0 and counts["ignored"] == 0:
        return "ALL_INPUT_RECORDS_REJECTED"
    if counts["parsed"] == 0 and counts["ignored"] > 0 and counts["rejected"] == 0:
        return "ALL_INPUT_RECORDS_IGNORED"
    if counts["rejected"]:
        return "PARSER_REJECTED_RECORDS_PRESENT"
    if counts["ignored"]:
        return "PARSER_IGNORED_RECORDS_PRESENT"
    if any(event.src_ip is None for event in events):
        return "SOURCE_IP_MISSING"
    if any(event.event_type == "login_failed" and not event.user for event in events):
        return "ACCOUNT_MISSING"
    return "NONE"


def _parse_scenario(scenario: dict[str, Any], root: Path) -> _ParsedScenario:
    events = []
    counts = {"input_lines": 0, "parsed": 0, "ignored": 0, "rejected": 0}
    try:
        for item in scenario["inputs"]:
            path = root / item["fixture"]
            try:
                text = path.read_bytes().decode("utf-8", errors="strict")
            except UnicodeError:
                lines = [line for line in path.read_bytes().splitlines() if line.strip()]
                counts["input_lines"] += len(lines)
                counts["rejected"] += len(lines)
                continue
            parser = get_parser(item["source"])
            timezone_name = get_timezone(item["source"])
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                counts["input_lines"] += 1
                try:
                    event = parser(line, timezone_name)
                    if event is None:
                        counts["ignored"] += 1
                        continue
                    event.timestamp = normalize_to_utc(event.timestamp)
                except (UnicodeError, ValueError, TypeError, KeyError, IndexError, OverflowError):
                    counts["rejected"] += 1
                    continue
                counts["parsed"] += 1
                events.append(event)
    except (OSError, UnicodeError):
        raise SprayScopeEvaluationError("fixture_unavailable") from None

    status = _parser_status(events, counts)
    failures = [event for event in events if event.event_type == "login_failed"]
    times = sorted(event.timestamp for event in failures)
    start_end = None if not times else (
        times[0].isoformat().replace("+00:00", "Z"),
        times[-1].isoformat().replace("+00:00", "Z"),
    )
    known_targets = len({event.user for event in failures if event.user})
    actual_counts = {
        **counts,
        "failure_count": len(failures),
        "known_target_count": known_targets,
    }
    expected = scenario["expected_parser_counts"]
    if status != scenario["expected_parser_status"] or any(counts[key] != expected[key] for key in COUNT_KEYS):
        raise SprayScopeEvaluationError("parser_contract_mismatch")
    if len(events) != scenario["expected_event_count"] or len(failures) != scenario["expected_failure_count"]:
        raise SprayScopeEvaluationError("parser_contract_mismatch")
    for event in events:
        if event.src_ip is not None and not _is_documentation_ip(event.src_ip):
            raise SprayScopeEvaluationError("parser_contract_mismatch")
        if event.user and USER_RE.fullmatch(event.user) is None:
            raise SprayScopeEvaluationError("parser_contract_mismatch")
        if event.src_ip is not None and event.src_ip not in scenario["subjects"]:
            raise SprayScopeEvaluationError("parser_contract_mismatch")
    return _ParsedScenario(
        tuple(events), actual_counts, status, len(failures), known_targets, start_end,
        _parser_reason(events, counts),
    )


def _ratio(numerator: int, denominator: int) -> str:
    return "not_applicable" if denominator == 0 else f"{numerator / denominator:.6f}"


def _metric(name: str, values: list[tuple[bool, bool]], excluded_undetermined: int,
            excluded_parser: int, benign_candidates: list[str]) -> dict[str, Any]:
    tp = sum(expected and actual for expected, actual in values)
    fp = sum(not expected and actual for expected, actual in values)
    fn = sum(expected and not actual for expected, actual in values)
    tn = sum(not expected and not actual for expected, actual in values)
    precision_denominator = tp + fp
    recall_denominator = tp + fn
    return {
        "policy": name,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "positive_support": recall_denominator,
        "negative_support": fp + tn,
        "precision": _ratio(tp, precision_denominator),
        "recall": _ratio(tp, recall_denominator),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "excluded_undetermined": excluded_undetermined,
        "excluded_parser": excluded_parser,
        "operational_false_alert_candidate_count": len(benign_candidates),
        "operational_false_alert_candidate_scenarios": sorted(benign_candidates),
    }


def _production_decisions(scenario: dict[str, Any], root: Path) -> tuple[dict[str, bool], dict[str, Any]]:
    analysis = analyze(_scenario_sources(scenario, root))
    result_map = analysis.get("results")
    if type(result_map) is not dict:
        raise SprayScopeEvaluationError("evaluation_failed")
    decisions = {}
    features_out = {}
    for subject in scenario["subjects"]:
        entry = result_map.get(subject)
        if type(entry) is not dict:
            decisions[subject] = False
            continue
        features = entry.get("features")
        detections = entry.get("detections")
        if type(features) is not dict or type(detections) is not dict:
            raise SprayScopeEvaluationError("evaluation_failed")
        detection = detections.get("password_spray")
        if not hasattr(detection, "is_detected") or type(detection.is_detected) is not bool:
            raise SprayScopeEvaluationError("evaluation_failed")
        failures = features.get("failure_count")
        targets = features.get("unique_target_count")
        within = features.get("within_window")
        seconds = features.get("window_seconds")
        if type(failures) is not int or type(targets) is not int or type(within) is not bool or type(seconds) not in (int, float):
            raise SprayScopeEvaluationError("evaluation_failed")
        expected = failures >= SPRAY_FAILURES and targets >= SPRAY_TARGETS and within
        if detection.is_detected != expected:
            raise SprayScopeEvaluationError("evaluation_failed")
        decisions[subject] = detection.is_detected
        features_out[subject] = {
            "failure_count": failures,
            "known_target_count": targets,
            "within_window": within,
            "whole_span_seconds": seconds,
        }
    return decisions, features_out


def _candidate_decisions(events: list[Any], subjects: tuple[str, ...]) -> tuple[dict[str, bool], dict[str, bool], dict[str, Any]]:
    sliding = evaluate_sliding_ip_window(events, subjects)
    known = evaluate_known_account_window(events, subjects)
    return (
        {subject: sliding[subject].detected for subject in subjects},
        {subject: known[subject].detected for subject in subjects},
        {
            "sliding_ip_window": {
                subject: asdict(sliding[subject].window) if sliding[subject].window else None
                for subject in subjects
            },
            "known_account_window": {
                subject: asdict(known[subject].window) if known[subject].window else None
                for subject in subjects
            },
        },
    )


def evaluate(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    scenarios = load_scenarios(manifest_path)
    root = manifest_path.parent
    scenario_records = []
    parser_records = []
    context_counts: Counter[str] = Counter()
    pattern_counts: Counter[str] = Counter()
    parser_counts: Counter[str] = Counter()
    exclusion_reason_counts: Counter[str] = Counter()
    metric_values: dict[str, list[tuple[bool, bool]]] = {name: [] for name in POLICIES}
    excluded_undetermined = {name: 0 for name in POLICIES}
    excluded_parser = {name: 0 for name in POLICIES}
    benign_candidates: dict[str, list[str]] = {name: [] for name in POLICIES}
    policy_times_ns = {name: 0 for name in POLICIES}
    tracemalloc.start()

    for scenario in scenarios:
        context_counts[scenario["operational_context"]] += 1
        pattern_counts[scenario["behavioral_pattern"]] += 1
        parsed = _parse_scenario(scenario, root)
        parser_counts[parsed.status] += 1
        parser_records.append({
            "scenario_id": scenario["id"], "status": parsed.status,
            "reason": parsed.reason,
            "input_lines": parsed.counts["input_lines"], "parsed": parsed.counts["parsed"],
            "ignored": parsed.counts["ignored"], "rejected": parsed.counts["rejected"],
            "failure_count": parsed.failure_count, "known_target_count": parsed.known_target_count,
            "failure_time_range_utc": parsed.time_range,
            "event_type_counts": dict(sorted(Counter(event.event_type for event in parsed.events).items())),
            "source_counts": dict(sorted(Counter(event.source for event in parsed.events).items())),
            "authentication_outcome_counts": dict(sorted(Counter(
                event.authentication.outcome for event in parsed.events if event.authentication is not None
            ).items())),
            "missing_account_failure_count": sum(
                event.event_type == "login_failed" and not event.user for event in parsed.events
            ),
            "missing_source_ip_count": sum(event.src_ip is None for event in parsed.events),
            "normalized_timestamp_range_utc": None if not parsed.events else (
                min(event.timestamp for event in parsed.events).isoformat().replace("+00:00", "Z"),
                max(event.timestamp for event in parsed.events).isoformat().replace("+00:00", "Z"),
            ),
        })
        if scenario["behavioral_pattern"] == "PATTERN_UNDETERMINED":
            exclusion_reason_counts[scenario["undetermined_reason"]] += 1

        decisions_by_policy: dict[str, dict[str, bool] | None] = {}
        features = {}
        windows = {}
        if parsed.status not in {"REJECTED", "IGNORED"} and parsed.counts["rejected"] == 0:
            started = perf_counter_ns()
            decisions_by_policy["current_whole_span"], features = _production_decisions(scenario, root)
            policy_times_ns["current_whole_span"] += perf_counter_ns() - started
            started = perf_counter_ns()
            sliding, known, windows = _candidate_decisions(list(parsed.events), tuple(scenario["subjects"]))
            policy_times_ns["sliding_ip_window"] += perf_counter_ns() - started
            decisions_by_policy["sliding_ip_window"] = sliding
            decisions_by_policy["known_account_window"] = known
        else:
            decisions_by_policy = {name: None for name in POLICIES}

        scenario_decisions = {
            name: (None if decisions_by_policy[name] is None else any(decisions_by_policy[name].values()))
            for name in POLICIES
        }
        for policy in POLICIES:
            if scenario_decisions[policy] is None:
                excluded_parser[policy] += 1
            elif scenario["behavioral_pattern"] == "PATTERN_UNDETERMINED":
                excluded_undetermined[policy] += 1
            else:
                metric_values[policy].append((
                    scenario["behavioral_pattern"] == "PATTERN_PRESENT",
                    scenario_decisions[policy],
                ))
            if scenario["operational_context"] == "KNOWN_BENIGN" and scenario_decisions[policy] is True:
                benign_candidates[policy].append(scenario["id"])

        scenario_records.append({
            "scenario_id": scenario["id"],
            "behavioral_pattern": scenario["behavioral_pattern"],
            "operational_context": scenario["operational_context"],
            "parser_status": parsed.status,
            "undetermined_reason": scenario["undetermined_reason"],
            "production_features_by_subject": features,
            "detected_by_policy": scenario_decisions,
            "candidate_windows_by_subject": windows,
            "metric_disposition": (
                "EXCLUDED_PARSER" if scenario_decisions["current_whole_span"] is None
                else "EXCLUDED_UNDETERMINED" if scenario["behavioral_pattern"] == "PATTERN_UNDETERMINED"
                else "SCORED"
            ),
            "label_basis": scenario["label_basis"],
            "context_basis": scenario["context_basis"],
        })

    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    metrics = []
    for policy in POLICIES:
        metrics.append(_metric(
            policy, metric_values[policy], excluded_undetermined[policy], excluded_parser[policy],
            benign_candidates[policy],
        ))
    differences = []
    for row in scenario_records:
        values = row["detected_by_policy"]
        if len({value for value in values.values()}) > 1:
            differences.append({
                "scenario_id": row["scenario_id"],
                "behavioral_pattern": row["behavioral_pattern"],
                "operational_context": row["operational_context"],
                "parser_status": row["parser_status"],
                "detected_by_policy": values,
                "candidate_windows_by_subject": row["candidate_windows_by_subject"],
            })
    policy_performance = {
        "current_whole_span_end_to_end_ms": round(policy_times_ns["current_whole_span"] / 1_000_000, 3),
        "candidate_sliding_and_known_account_ms_combined": round(policy_times_ns["sliding_ip_window"] / 1_000_000, 3),
        "peak_tracked_python_bytes": peak_bytes,
        "scenario_count": len(scenarios),
        "timing_note": "단일 로컬 실행의 관측값이며 정책 간 공정한 benchmark 또는 자원 상한이 아닙니다.",
    }
    return {
        "schema_version": "1",
        "evaluation": "password_spray_scope_policy_comparison",
        "data_scope": "synthetic-only",
        "evaluation_unit": "scenario; multi-IP scenario is detected if any per-IP pipeline result detects",
        "scenario_count": len(scenarios),
        "policy_parameters": {
            "minimum_failures": SPRAY_FAILURES,
            "minimum_known_targets": SPRAY_TARGETS,
            "inclusive_window_seconds": SPRAY_WINDOW_SECONDS,
            "current_policy_source": "app.analyzer.pipeline.detect_attacks_with_context -> app.detector.password_spray.detect_password_spray",
            "threshold_basis": "프로젝트 평가 휴리스틱이며 표준/벤더 권고 임계값이 아닙니다.",
        },
        "label_counts": {
            "behavioral_pattern": {label: pattern_counts[label] for label in sorted(PATTERN_LABELS)},
            "operational_context": {label: context_counts[label] for label in sorted(CONTEXT_LABELS)},
            "parser_status": {label: parser_counts[label] for label in sorted(PARSER_STATUSES)},
            "undetermined_reason": {label: exclusion_reason_counts[label] for label in sorted(UNDETERMINED_REASONS)},
        },
        "parser_summary": {
            "input_lines": sum(row["input_lines"] for row in parser_records),
            "parsed": sum(row["parsed"] for row in parser_records),
            "ignored": sum(row["ignored"] for row in parser_records),
            "rejected": sum(row["rejected"] for row in parser_records),
            "scenario_observations": parser_records,
        },
        "metrics": metrics,
        "policy_differences": differences,
        "performance": policy_performance,
        "scenario_results": scenario_records,
        "notices": [
            "합성 데이터 결과이며 실환경 Precision/Recall 또는 오탐률을 의미하지 않습니다.",
            "Behavioral pattern 라벨과 운영 맥락 라벨은 별도입니다. KNOWN_BENIGN 탐지는 Pattern FP와 별개인 운영상 경보 후보입니다.",
            "실패 관측은 동일 비밀번호, 공격 의도, 단일 행위자, 계정 침해를 증명하지 않습니다.",
            "분산 IP 시나리오 라벨은 통제된 합성 fixture의 생성 설명을 사용하며 관측 로그는 행위자 공통성을 증명하지 않습니다.",
            "비밀번호와 원문 로그는 CLI 결과에 포함하지 않습니다.",
        ],
    }


def render_text(summary: dict[str, Any]) -> str:
    labels = summary["label_counts"]
    lines = [
        f"spray_scope_evaluation: scenarios={summary['scenario_count']} unit={summary['evaluation_unit']}",
        "pattern_labels: " + ", ".join(
            f"{key}={value}" for key, value in labels["behavioral_pattern"].items()
        ),
        "operational_context_labels: " + ", ".join(
            f"{key}={value}" for key, value in labels["operational_context"].items()
        ),
        "parser_status_counts: " + ", ".join(
            f"{key}={value}" for key, value in labels["parser_status"].items()
        ),
        "parser_observations: " + ", ".join(
            f"{key}={summary['parser_summary'][key]}" for key in ("input_lines", "parsed", "ignored", "rejected")
        ),
        "policy tp fp fn tn precision recall f1 positive_support negative_support excluded_undetermined excluded_parser operational_false_alert_candidates",
    ]
    for row in summary["metrics"]:
        lines.append(
            f"{row['policy']} {row['tp']} {row['fp']} {row['fn']} {row['tn']} {row['precision']} {row['recall']} {row['f1']} "
            f"{row['positive_support']} {row['negative_support']} {row['excluded_undetermined']} {row['excluded_parser']} "
            f"{row['operational_false_alert_candidate_count']}"
        )
    lines.append("operational_false_alert_candidate_ids:")
    for row in summary["metrics"]:
        lines.append(f"  {row['policy']}: {', '.join(row['operational_false_alert_candidate_scenarios']) or 'none'}")
    lines.append("policy_differences:")
    for row in summary["policy_differences"]:
        detected = ", ".join(f"{key}={value}" for key, value in row["detected_by_policy"].items())
        lines.append(f"  {row['scenario_id']} pattern={row['behavioral_pattern']} context={row['operational_context']} {detected}")
    if not summary["policy_differences"]:
        lines.append("  none")
    parser_reason = {
        row["scenario_id"]: row["reason"] for row in summary["parser_summary"]["scenario_observations"]
    }
    lines.append("excluded_scenarios:")
    excluded = [row for row in summary["scenario_results"] if row["metric_disposition"] != "SCORED"]
    for row in excluded:
        reason = (
            row["undetermined_reason"]
            if row["metric_disposition"] == "EXCLUDED_UNDETERMINED"
            else parser_reason.get(row["scenario_id"], "PARSER_OBSERVATION_INSUFFICIENT")
        )
        lines.append(f"  {row['scenario_id']}: {row['metric_disposition']} ({reason})")
    if not excluded:
        lines.append("  none")
    performance = summary["performance"]
    lines.extend((
        f"performance_ms: production_end_to_end={performance['current_whole_span_end_to_end_ms']} "
        f"candidate_pair={performance['candidate_sliding_and_known_account_ms_combined']}",
        f"peak_tracked_python_bytes: {performance['peak_tracked_python_bytes']}",
        "production_mutation: none; candidate policies remain evaluation-only",
    ))
    lines.extend(summary["notices"])
    return "\n".join(lines)
