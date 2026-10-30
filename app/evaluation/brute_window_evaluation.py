"""고정 합성 인증 fixture에서 whole-span과 평가 후보 창을 비교한다."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
import re
from typing import Any

from app.analyzer.pipeline import load_normalized_logs
from app.evaluation.brute_window_policy import (
    POLICY_NAMES, PolicyDecision, decision_dict, evaluate_candidate_policies,
    evaluate_whole_span,
)


CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "brute_window_evaluation"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_FIXTURE_BYTES = 16 * 1024
MAX_SCENARIOS = 64
MAX_EVENTS_PER_SCENARIO = 512
ALLOWED_SOURCES = frozenset(("application", "ssh"))
PATTERN_LABELS = frozenset(("PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"))
CONTEXT_LABELS = frozenset(("SIMULATED_ATTACK", "KNOWN_BENIGN", "AMBIGUOUS", "UNVERIFIED"))
NETWORKS = tuple(ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
ID_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
SYNTHETIC_USER_RE = re.compile(r"synthetic_user_[a-z0-9_]{1,32}\Z", re.ASCII)
ROOT_KEYS = {"schema_version", "data_scope", "scenarios"}
SCENARIO_KEYS = {
    "id", "source", "fixture", "subject", "expected_event_count", "expected_failure_count",
    "timestamp_contract", "behavioral_pattern", "operational_context", "label_basis",
    "context_basis", "current_policy_expectation", "candidate_policy_expectation",
    "ambiguity", "expected_exclusion", "evidence_selection_expectation",
}
CANDIDATE_KEYS = {"global_single_account", "window_single_account", "per_account"}
PUBLIC_POLICIES = {"whole_span": "current_whole_span", "sliding_global": "candidate_global_account", "sliding_window": "candidate_window_account", "per_account": "candidate_ip_account"}


class BruteWindowEvaluationError(ValueError):
    """오류 문구는 고정 코드이며 fixture 원문/경로를 포함하지 않는다."""

    def __init__(self, code: str = "invalid_manifest"):
        self.code = code if code in {"invalid_manifest", "fixture_unavailable", "parser_contract_mismatch", "evaluation_failed"} else "invalid_manifest"
        super().__init__(self.code)


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int
    positive_support: int
    negative_support: int
    precision: str
    recall: str
    f1: str
    excluded_undetermined: int


def _ratio(numerator: int, denominator: int) -> str:
    return "not_applicable" if denominator == 0 else f"{numerator / denominator:.6f}"


def score_confusion(pairs: list[tuple[bool, bool]]) -> Confusion:
    tp = sum(expected and actual for expected, actual in pairs)
    fp = sum(not expected and actual for expected, actual in pairs)
    fn = sum(expected and not actual for expected, actual in pairs)
    tn = sum(not expected and not actual for expected, actual in pairs)
    return Confusion(
        tp=tp, fp=fp, fn=fn, tn=tn,
        positive_support=tp + fn, negative_support=fp + tn,
        precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn),
        f1=_ratio(2 * tp, 2 * tp + fp + fn), excluded_undetermined=0,
    )


def _pairs_metric(pairs: list[tuple[bool, bool]], excluded: int) -> Confusion:
    item = score_confusion(pairs)
    return Confusion(**{**asdict(item), "excluded_undetermined": excluded})


def _json_load(raw: bytes) -> dict[str, Any]:
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise BruteWindowEvaluationError() from None
    if type(value) is not dict or set(value) != ROOT_KEYS or type(value.get("schema_version")) is not int or value["schema_version"] != 1 or value.get("data_scope") != "synthetic-only" or type(value.get("scenarios")) is not list:
        raise BruteWindowEvaluationError()
    return value


def load_manifest(manifest_path: Path = MANIFEST_PATH) -> tuple[dict[str, Any], ...]:
    root = manifest_path.parent
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise BruteWindowEvaluationError()
        root_real = root.resolve(strict=True)
        manifest_path.resolve(strict=True).relative_to(root_real)
        data = _json_load(manifest_path.read_bytes())
    except BruteWindowEvaluationError:
        raise
    except (OSError, ValueError):
        raise BruteWindowEvaluationError("fixture_unavailable") from None
    scenarios = data["scenarios"]
    if not scenarios or len(scenarios) > MAX_SCENARIOS:
        raise BruteWindowEvaluationError()
    ids, fixtures, accepted = set(), set(), []
    for item in scenarios:
        if type(item) is not dict or set(item) != SCENARIO_KEYS:
            raise BruteWindowEvaluationError()
        if (type(item["id"]) is not str or ID_RE.fullmatch(item["id"]) is None or item["id"] in ids
            or type(item["source"]) is not str or item["source"] not in ALLOWED_SOURCES
            or type(item["subject"]) is not str or type(item["fixture"]) is not str
            or type(item["expected_event_count"]) is not int or not 0 < item["expected_event_count"] <= MAX_EVENTS_PER_SCENARIO
            or type(item["expected_failure_count"]) is not int or not 0 <= item["expected_failure_count"] <= item["expected_event_count"]
            or type(item["timestamp_contract"]) is not str or item["timestamp_contract"] != "parser_aware_localized_then_candidate_utc"
            or type(item["behavioral_pattern"]) is not str or item["behavioral_pattern"] not in PATTERN_LABELS
            or type(item["operational_context"]) is not str or item["operational_context"] not in CONTEXT_LABELS
            or type(item["label_basis"]) is not str or not item["label_basis"]
            or type(item["context_basis"]) is not str or not item["context_basis"]
            or type(item["current_policy_expectation"]) is not bool
            or type(item["candidate_policy_expectation"]) is not dict or set(item["candidate_policy_expectation"]) != CANDIDATE_KEYS
            or any(type(value) is not bool for value in item["candidate_policy_expectation"].values())
            or type(item["ambiguity"]) is not list or any(type(value) is not str for value in item["ambiguity"])
            or type(item["expected_exclusion"]) is not bool
            or item["expected_exclusion"] != (item["behavioral_pattern"] == "PATTERN_UNDETERMINED")
            or (item["evidence_selection_expectation"] is not None and (
                type(item["evidence_selection_expectation"]) is not dict
                or set(item["evidence_selection_expectation"]) not in ({"window_offsets_seconds"}, {"window_offsets_seconds", "policy"})
                or type(item["evidence_selection_expectation"].get("window_offsets_seconds")) is not list
                or len(item["evidence_selection_expectation"]["window_offsets_seconds"]) != 2
                or any(type(value) not in (int, float) or value < 0 for value in item["evidence_selection_expectation"]["window_offsets_seconds"])
                or ("policy" in item["evidence_selection_expectation"] and (
                    type(item["evidence_selection_expectation"]["policy"]) is not str
                    or item["evidence_selection_expectation"]["policy"] not in {"sliding_global", "sliding_window", "per_account"}
                ))
            ))):
            raise BruteWindowEvaluationError()
        try:
            subject = ip_address(item["subject"])
        except ValueError:
            raise BruteWindowEvaluationError() from None
        if str(subject) != item["subject"] or not any(subject in network for network in NETWORKS):
            raise BruteWindowEvaluationError()
        fixture = Path(item["fixture"])
        if fixture.is_absolute() or len(fixture.parts) != 1 or fixture.suffix != ".log" or fixture.name in {".", ".."} or item["fixture"] in fixtures:
            raise BruteWindowEvaluationError()
        path = root_real / fixture
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FIXTURE_BYTES:
                raise BruteWindowEvaluationError("fixture_unavailable")
            path.resolve(strict=True).relative_to(root_real)
        except (OSError, ValueError):
            raise BruteWindowEvaluationError("fixture_unavailable") from None
        ids.add(item["id"]); fixtures.add(item["fixture"]); accepted.append(item)
    actual = {path.name for path in root_real.glob("*.log") if path.is_file() and not path.is_symlink()}
    if actual != fixtures:
        raise BruteWindowEvaluationError()
    return tuple(sorted(accepted, key=lambda item: item["id"]))


def _parse_scenario(item: dict[str, Any], root: Path):
    path = root / item["fixture"]
    try:
        events = load_normalized_logs([{"source": item["source"], "path": str(path)}])
    except Exception:
        raise BruteWindowEvaluationError("parser_contract_mismatch") from None
    failures = [event for event in events if event.event_type == "login_failed"]
    if len(events) != item["expected_event_count"] or len(failures) != item["expected_failure_count"]:
        raise BruteWindowEvaluationError("parser_contract_mismatch")
    if any(event.source != item["source"] or event.timestamp.tzinfo is None for event in events):
        raise BruteWindowEvaluationError("parser_contract_mismatch")
    for event in events:
        if event.src_ip is not None:
            try:
                address = ip_address(event.src_ip)
            except ValueError:
                raise BruteWindowEvaluationError("parser_contract_mismatch") from None
            if not any(address in network for network in NETWORKS):
                raise BruteWindowEvaluationError("parser_contract_mismatch")
        if event.user and SYNTHETIC_USER_RE.fullmatch(event.user) is None:
            raise BruteWindowEvaluationError("parser_contract_mismatch")
    return events


def _public_decision(decision: PolicyDecision) -> dict[str, Any]:
    value = decision_dict(decision)
    if value["window"] is not None:
        value["window"].pop("target_account", None)
    if value.get("selection_comparison") is not None:
        for window in value["selection_comparison"].values():
            if window is not None:
                window.pop("target_account", None)
    return value


def evaluate_corpus(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    scenarios = load_manifest(manifest_path)
    policy_pairs: dict[str, list[tuple[bool, bool]]] = {name: [] for name in POLICY_NAMES}
    exclusions = 0
    operational_candidates: dict[str, list[str]] = {name: [] for name in POLICY_NAMES}
    rows = []
    for scenario in scenarios:
        events = _parse_scenario(scenario, manifest_path.parent)
        current = evaluate_whole_span(events, scenario["subject"])
        candidates = evaluate_candidate_policies(events, scenario["subject"])
        decisions = {"whole_span": current, **candidates}
        expected = {"whole_span": scenario["current_policy_expectation"],
                    "sliding_global": scenario["candidate_policy_expectation"]["global_single_account"],
                    "sliding_window": scenario["candidate_policy_expectation"]["window_single_account"],
                    "per_account": scenario["candidate_policy_expectation"]["per_account"]}
        if any(decisions[name].detected != value for name, value in expected.items()):
            raise BruteWindowEvaluationError("evaluation_failed")
        evidence_expectation = scenario["evidence_selection_expectation"]
        if evidence_expectation is not None:
            evidence_policy = evidence_expectation.get("policy", "sliding_window")
            policy_map = {"sliding_global": "sliding_global", "sliding_window": "sliding_window", "per_account": "per_account"}
            selected = candidates[policy_map.get(evidence_policy, "")].window if evidence_policy in policy_map else None
            failures = [event for event in events if event.event_type == "login_failed" and event.src_ip == scenario["subject"]]
            if selected is None or not failures or set(evidence_expectation) not in ({"window_offsets_seconds"}, {"window_offsets_seconds", "policy"}):
                raise BruteWindowEvaluationError("evaluation_failed")
            origin = min(event.timestamp for event in failures)
            actual_offsets = [
                (datetime.fromisoformat(value.replace("Z", "+00:00")) - origin.astimezone(timezone.utc)).total_seconds()
                for value in (selected.start_time, selected.end_time)
            ]
            if actual_offsets != evidence_expectation["window_offsets_seconds"]:
                raise BruteWindowEvaluationError("evaluation_failed")
        label = scenario["behavioral_pattern"]
        if label == "PATTERN_UNDETERMINED":
            exclusions += 1
        else:
            positive = label == "PATTERN_PRESENT"
            for name, decision in decisions.items():
                policy_pairs[name].append((positive, decision.detected))
        for name, decision in decisions.items():
            if scenario["operational_context"] == "KNOWN_BENIGN" and decision.detected:
                operational_candidates[name].append(scenario["id"])
        rows.append({
            "scenario_id": scenario["id"], "source": scenario["source"],
            "parser_status": "PARSER_VERIFIED", "normalized_event_count": len(events),
            "failure_event_count": sum(event.event_type == "login_failed" for event in events),
            "behavioral_pattern": label, "operational_context": scenario["operational_context"],
            "ambiguity_count": len(scenario["ambiguity"]),
            "policies": {PUBLIC_POLICIES[name]: _public_decision(decisions[name]) for name in POLICY_NAMES},
        })
    metrics = {PUBLIC_POLICIES[name]: asdict(_pairs_metric(pairs, exclusions)) for name, pairs in policy_pairs.items()}
    context_counts = {label: sum(item["operational_context"] == label for item in scenarios) for label in sorted(CONTEXT_LABELS)}
    pattern_counts = {label: sum(item["behavioral_pattern"] == label for item in scenarios) for label in sorted(PATTERN_LABELS)}
    return {
        "schema_version": 1,
        "scope_notice": "고정 합성 시간창 비교이며 운영 탐지 정확도를 의미하지 않습니다.",
        "scenario_count": len(scenarios),
        "behavioral_label_counts": pattern_counts,
        "operational_context_counts": context_counts,
        "metrics": metrics,
        "operational_false_alert_candidates": {PUBLIC_POLICIES[name]: sorted(ids) for name, ids in operational_candidates.items()},
        "operational_ambiguous_scenarios": [item["id"] for item in scenarios if item["operational_context"] == "AMBIGUOUS"],
        "undetermined_scenarios": [item["id"] for item in scenarios if item["behavioral_pattern"] == "PATTERN_UNDETERMINED"],
        "scenario_results": rows,
    }


def render_text(summary: dict[str, Any]) -> str:
    lines = [summary["scope_notice"], f"scenario_count: {summary['scenario_count']}"]
    for name, metric in summary["metrics"].items():
        lines.append(f"{name}: TP={metric['tp']} FP={metric['fp']} FN={metric['fn']} TN={metric['tn']} P={metric['precision']} R={metric['recall']} F1={metric['f1']}")
    for name, values in summary["operational_false_alert_candidates"].items():
        lines.append(f"{name}_operational_false_alert_candidates: {len(values)}")
    return "\n".join(lines)
