"""Offline detector-pattern evaluation against independently reviewed labels."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
import re
from typing import Any

from app.analyzer.pipeline import load_normalized_logs
from app.main import analyze


CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "detector_accuracy"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SCENARIOS = 128
MAX_FIXTURE_BYTES = 8192
DETECTORS = (
    "brute_force", "password_spraying_like", "path_traversal",
    "sql_injection_like", "xss_like", "sensitive_resource_probing_like",
    "web_scanning_like",
)
AUTH_DETECTORS = frozenset(("brute_force", "password_spraying_like"))
PATTERN_LABELS = frozenset(("PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"))
CONTEXT_LABELS = frozenset(("SIMULATED_ATTACK", "KNOWN_BENIGN", "AMBIGUOUS", "UNVERIFIED"))
FIELD_PATHS = frozenset((
    "timestamp", "src_ip", "user", "authentication.outcome",
    "authentication.method", "http.method", "http.path", "http.query",
    "http.status_code",
))
DETECTION_SLOTS = {
    "brute_force": "brute_force",
    "password_spraying_like": "password_spray",
    "path_traversal": "path_traversal",
    "sql_injection_like": "sql_injection_like",
    "xss_like": "xss_like",
    "sensitive_resource_probing_like": "sensitive_resource_probing_like",
    "web_scanning_like": "web_scanning_like",
}
DOCUMENTATION_NETWORKS = tuple(ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
_ID = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
_ROOT_KEYS = {"schema_version", "data_scope", "scenarios"}
_SCENARIO_KEYS = {
    "id", "detector", "source", "fixture", "subject", "expected_event_types", "expected_event_subjects",
    "required_fields", "behavioral_pattern", "operational_context",
    "label_basis", "context_basis",
}


class DetectorAccuracyError(ValueError):
    """Public, bounded evaluation error that never includes input text or paths."""

    def __init__(self, code: str):
        self.code = code if code in {
            "invalid_manifest", "fixture_unavailable", "analysis_failed",
        } else "invalid_manifest"
        super().__init__(self.code)


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


@dataclass(frozen=True)
class DetectorMetric:
    detector: str
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
    excluded_parser: int


def _ratio(numerator: int, denominator: int) -> str:
    return "not_applicable" if denominator == 0 else f"{numerator / denominator:.6f}"


def _decode_manifest(raw: bytes) -> dict[str, Any]:
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
        raise DetectorAccuracyError("invalid_manifest") from None
    if type(value) is not dict or set(value) != _ROOT_KEYS:
        raise DetectorAccuracyError("invalid_manifest")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise DetectorAccuracyError("invalid_manifest")
    if value["data_scope"] != "synthetic-only" or type(value["scenarios"]) is not list:
        raise DetectorAccuracyError("invalid_manifest")
    return value


def _validate_scenarios(scenarios: list[dict[str, Any]], root: Path) -> tuple[dict[str, Any], ...]:
    if not scenarios or len(scenarios) > MAX_SCENARIOS:
        raise DetectorAccuracyError("invalid_manifest")
    ids: set[str] = set()
    fixtures: set[str] = set()
    validated = []
    for item in scenarios:
        if type(item) is not dict or set(item) != _SCENARIO_KEYS:
            raise DetectorAccuracyError("invalid_manifest")
        if (
            type(item["id"]) is not str or _ID.fullmatch(item["id"]) is None
            or item["id"] in ids
            or type(item["detector"]) is not str or item["detector"] not in DETECTORS
            or type(item["source"]) is not str or item["source"] not in ("application", "ssh", "access")
            or (item["detector"] in AUTH_DETECTORS) != (item["source"] in ("application", "ssh"))
            or type(item["subject"]) is not str
            or type(item["fixture"]) is not str
            or type(item["expected_event_types"]) is not list
            or not item["expected_event_types"]
            or any(type(event_type) is not str for event_type in item["expected_event_types"])
            or type(item["expected_event_subjects"]) is not list
            or len(item["expected_event_subjects"]) != len(item["expected_event_types"])
            or any(type(subject) is not str for subject in item["expected_event_subjects"])
            or type(item["required_fields"]) is not list
            or any(type(field) is not str or field not in FIELD_PATHS for field in item["required_fields"])
            or type(item["behavioral_pattern"]) is not str
            or item["behavioral_pattern"] not in PATTERN_LABELS
            or type(item["operational_context"]) is not str
            or item["operational_context"] not in CONTEXT_LABELS
            or type(item["label_basis"]) is not str or not 1 <= len(item["label_basis"]) <= 240
            or type(item["context_basis"]) is not str or not 1 <= len(item["context_basis"]) <= 240
        ):
            raise DetectorAccuracyError("invalid_manifest")
        expected_event_types = set(item["expected_event_types"])
        allowed_event_types = (
            {"login_failed", "user_login"}
            if item["source"] in ("application", "ssh")
            else {"http_request"}
        )
        if not expected_event_types or not expected_event_types <= allowed_event_types:
            raise DetectorAccuracyError("invalid_manifest")
        try:
            address = ip_address(item["subject"])
            event_addresses = [ip_address(subject) for subject in item["expected_event_subjects"]]
        except ValueError:
            raise DetectorAccuracyError("invalid_manifest") from None
        if str(address) != item["subject"] or not any(address in network for network in DOCUMENTATION_NETWORKS):
            raise DetectorAccuracyError("invalid_manifest")
        if any(str(value) != text or not any(value in network for network in DOCUMENTATION_NETWORKS)
               for text, value in zip(item["expected_event_subjects"], event_addresses)):
            raise DetectorAccuracyError("invalid_manifest")
        fixture = Path(item["fixture"])
        if (
            fixture.is_absolute() or fixture.suffix != ".log"
            or any(part in ("", ".", "..") for part in fixture.parts)
            or len(fixture.parts) != 1
            or item["fixture"] in fixtures
        ):
            raise DetectorAccuracyError("invalid_manifest")
        path = root / fixture
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FIXTURE_BYTES:
                raise DetectorAccuracyError("fixture_unavailable")
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, ValueError):
            raise DetectorAccuracyError("fixture_unavailable") from None
        if item["detector"] in AUTH_DETECTORS:
            if not set(("timestamp", "src_ip", "authentication.outcome")).issubset(item["required_fields"]):
                raise DetectorAccuracyError("invalid_manifest")
            if item["behavioral_pattern"] != "PATTERN_UNDETERMINED" and "user" not in item["required_fields"]:
                raise DetectorAccuracyError("invalid_manifest")
        elif not set(("timestamp", "src_ip", "http.method", "http.path", "http.status_code")).issubset(item["required_fields"]):
            raise DetectorAccuracyError("invalid_manifest")
        if item["detector"] in {"sql_injection_like", "xss_like"} and "http.query" not in item["required_fields"]:
            raise DetectorAccuracyError("invalid_manifest")
        ids.add(item["id"])
        fixtures.add(item["fixture"])
        validated.append(item)
    actual_fixtures = {path.name for path in root.glob("*.log") if path.is_file() and not path.is_symlink()}
    if actual_fixtures != fixtures:
        raise DetectorAccuracyError("invalid_manifest")
    return tuple(validated)


def load_corpus(manifest_path: Path = MANIFEST_PATH) -> tuple[dict[str, Any], ...]:
    root = manifest_path.parent
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise DetectorAccuracyError("invalid_manifest")
        root_real = root.resolve(strict=True)
        manifest_path.resolve(strict=True).relative_to(root_real)
        raw = manifest_path.read_bytes()
    except DetectorAccuracyError:
        raise
    except (OSError, ValueError):
        raise DetectorAccuracyError("fixture_unavailable") from None
    data = _decode_manifest(raw)
    return _validate_scenarios(data["scenarios"], root_real)


def _field(event, name: str):
    value = event
    for part in name.split("."):
        value = getattr(value, part, None)
        if value is None:
            return None
    return value


def _parse_disposition(scenario: dict[str, Any], path: Path) -> tuple[str, str | None]:
    try:
        events = load_normalized_logs([{"source": scenario["source"], "path": str(path)}])
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError):
        return "PARSER_REJECTED", "PARSER_REJECTED"
    expected_types = tuple(scenario["expected_event_types"])
    if len(events) != len(expected_types):
        return "PARSER_PARTIAL", "EVENT_COUNT_MISMATCH"
    if tuple(event.event_type for event in events) != expected_types:
        return "PARSER_PARTIAL", "EVENT_TYPE_MISMATCH"
    if tuple(event.src_ip for event in events) != tuple(scenario["expected_event_subjects"]):
        return "PARSER_PARTIAL", "SUBJECT_MISMATCH"
    if any(any(_field(event, name) is None for name in scenario["required_fields"]) for event in events):
        return "PARSER_PARTIAL", "REQUIRED_FIELD_MISSING"
    return "PARSER_VERIFIED", None


def _observed(scenario: dict[str, Any], path: Path) -> bool:
    try:
        analysis = analyze([{"source": scenario["source"], "path": str(path)}])
        result = analysis["results"].get(scenario["subject"])
        if result is None:
            raise DetectorAccuracyError("analysis_failed")
        detection = result["detections"][DETECTION_SLOTS[scenario["detector"]]]
        return detection.is_detected is True
    except DetectorAccuracyError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise DetectorAccuracyError("analysis_failed") from None


def _metric(detector: str, confusion: Confusion, undetermined: int, parser_excluded: int) -> DetectorMetric:
    return DetectorMetric(
        detector, confusion.tp, confusion.fp, confusion.fn, confusion.tn,
        confusion.tp + confusion.fn, confusion.fp + confusion.tn,
        _ratio(confusion.tp, confusion.tp + confusion.fp),
        _ratio(confusion.tp, confusion.tp + confusion.fn),
        _ratio(2 * confusion.tp, 2 * confusion.tp + confusion.fp + confusion.fn),
        undetermined, parser_excluded,
    )


def evaluate(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    scenarios = load_corpus(manifest_path)
    counts = {kind: Confusion() for kind in DETECTORS}
    undetermined = {kind: 0 for kind in DETECTORS}
    parser_excluded = {kind: 0 for kind in DETECTORS}
    records = []
    operational_candidates = []
    parser_findings = []
    context_counts = {label: 0 for label in sorted(CONTEXT_LABELS)}
    pattern_counts = {label: 0 for label in sorted(PATTERN_LABELS)}
    for scenario in scenarios:
        context_counts[scenario["operational_context"]] += 1
        pattern_counts[scenario["behavioral_pattern"]] += 1
        path = manifest_path.parent / scenario["fixture"]
        disposition, parser_reason = _parse_disposition(scenario, path)
        actual = None
        metric_disposition = "PARSER_EXCLUDED"
        if disposition == "PARSER_VERIFIED":
            actual = _observed(scenario, path)
            label = scenario["behavioral_pattern"]
            if label == "PATTERN_UNDETERMINED":
                undetermined[scenario["detector"]] += 1
                metric_disposition = "LABEL_UNDETERMINED"
            else:
                expected = label == "PATTERN_PRESENT"
                counts[scenario["detector"]] = counts[scenario["detector"]].add(expected, actual)
                metric_disposition = "SCORED"
                if expected and not actual:
                    finding = "DETECTOR_FALSE_NEGATIVE"
                elif not expected and actual:
                    finding = "DETECTOR_FALSE_POSITIVE"
                else:
                    finding = None
                if finding:
                    records.append({"scenario_id": scenario["id"], "detector": scenario["detector"],
                                    "finding": finding})
            if scenario["operational_context"] == "KNOWN_BENIGN" and actual:
                operational_candidates.append({"scenario_id": scenario["id"], "detector": scenario["detector"],
                                                "finding": "OPERATIONAL_FALSE_ALERT_CANDIDATE"})
        else:
            parser_excluded[scenario["detector"]] += 1
            parser_findings.append({"scenario_id": scenario["id"], "detector": scenario["detector"],
                                    "finding": "PARSER_CONTRIBUTION", "reason": parser_reason})
        records.append({
            "scenario_id": scenario["id"], "detector": scenario["detector"],
            "behavioral_pattern": scenario["behavioral_pattern"],
            "operational_context": scenario["operational_context"],
            "parser_disposition": disposition, "metric_disposition": metric_disposition,
            "detected": actual,
        })
    records.sort(key=lambda row: (row["scenario_id"], row.get("finding", "scenario")))
    operational_candidates.sort(key=lambda row: (row["scenario_id"], row["detector"]))
    parser_findings.sort(key=lambda row: (row["scenario_id"], row["detector"]))
    return {
        "schema_version": "1",
        "evaluation": "synthetic_detector_pattern_accuracy",
        "evaluation_unit": "scenario × subject × detector",
        "scenario_count": len(scenarios),
        "label_counts": {"behavioral_pattern": pattern_counts, "operational_context": context_counts},
        "metrics": [asdict(_metric(kind, counts[kind], undetermined[kind], parser_excluded[kind]))
                    for kind in DETECTORS],
        "operational_false_alert_candidates": operational_candidates,
        "parser_contributions": parser_findings,
        "scenario_results": records,
        "notices": [
            "합성 시나리오 결과이며 실제 환경 정확도를 의미하지 않습니다.",
            "Behavioral pattern은 악의성 또는 침해 성공을 뜻하지 않습니다.",
            "Operational false alert 후보는 합성 맥락 라벨에 기반하며 실제 조직 맥락을 대변하지 않습니다.",
            "작은 독립 corpus의 metric은 실제 운영 환경으로 일반화할 수 없습니다.",
        ],
    }


def render_text(summary: dict[str, Any]) -> str:
    lines = [
        f"evaluation_complete: scenarios={summary['scenario_count']} unit={summary['evaluation_unit']}",
        "detector tp fp fn tn precision recall f1 positive_support negative_support excluded_undetermined excluded_parser",
    ]
    for metric in summary["metrics"]:
        lines.append(
            f"{metric['detector']} {metric['tp']} {metric['fp']} {metric['fn']} {metric['tn']} "
            f"{metric['precision']} {metric['recall']} {metric['f1']} {metric['positive_support']} "
            f"{metric['negative_support']} {metric['excluded_undetermined']} {metric['excluded_parser']}"
        )
    lines.append(f"operational_false_alert_candidates: {len(summary['operational_false_alert_candidates'])}")
    lines.append(f"parser_contributions: {len(summary['parser_contributions'])}")
    for notice in summary["notices"]:
        lines.append(notice)
    return "\n".join(lines)
