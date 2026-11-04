"""Closed, synthetic-only ER-1A corpus and Parser prevalidation harness.

This module intentionally does not execute a detector or make a comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
import tempfile
from types import MappingProxyType
from typing import Any

from app.analyzer.pipeline import load_normalized_logs
from app.evaluation.counterfactual_mutation import (
    CounterfactualCorpusError,
    MAX_FIXTURE_BYTES,
    MAX_FIXTURE_LINES,
    apply_mutation,
)


CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "counterfactual"
MANIFEST_PATH = "manifest.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_SCENARIOS = 32
MAX_LABEL_BASIS_LENGTH = 240
_ID = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
_SOURCES = frozenset(("application", "ssh"))
_DETECTORS = frozenset(("brute_force", "password_spraying_like"))
_POLICY_IDS = {
    "brute_force": "brute_force_production_v1",
    "password_spraying_like": "password_spray_whole_span_production_v1",
}
_PATTERN_LABELS = frozenset(("PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"))
_OPERATIONAL_CONTEXTS = frozenset(("SIMULATED_ATTACK", "KNOWN_BENIGN", "AMBIGUOUS", "UNVERIFIED"))
_PARSER_STATES = frozenset(("VERIFIED", "PARTIAL", "REJECTED", "NOT_EVALUATED"))
_ROOT_KEYS = frozenset(("schema_version", "data_scope", "scenarios"))
_SCENARIO_KEYS = frozenset((
    "scenario_id", "detector_id", "source", "baseline_fixture_id",
    "mutation_type", "mutation_target", "mutation_parameters",
    "expected_parser_disposition", "expected_event_facts",
    "expected_behavioral_pattern", "operational_context", "label_basis",
    "policy_id", "comparison_scope", "target_subject",
    "baseline_expected_event_facts", "baseline_expected_behavioral_pattern",
))
_FACT_KEYS = frozenset((
    "event_count", "login_failed_count", "known_account_count",
    "source_ip_count", "target_failure_count", "target_known_account_count",
    "target_failure_span_seconds",
))
_DOCUMENTATION_NETWORKS = tuple(ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
))


@dataclass(frozen=True, slots=True, repr=False)
class CounterfactualScenario:
    scenario_id: str
    detector_id: str
    source: str
    baseline_fixture_id: str
    mutation_type: str
    mutation_target: str
    mutation_parameters: Any = field(repr=False)
    expected_parser_disposition: str
    expected_event_facts: Any = field(repr=False)
    expected_behavioral_pattern: str
    operational_context: str
    label_basis: str = field(repr=False)
    policy_id: str
    comparison_scope: str
    target_subject: str = field(repr=False)
    baseline_expected_event_facts: Any = field(repr=False)
    baseline_expected_behavioral_pattern: str

    def __repr__(self) -> str:
        return f"CounterfactualScenario({self.scenario_id!r}, <synthetic fields redacted>)"


@dataclass(frozen=True, slots=True)
class PreparedScenario:
    scenario_id: str
    detector_id: str
    baseline_parser_disposition: str
    parser_disposition: str
    baseline_event_facts: tuple[tuple[str, int | float | None], ...]
    event_facts: tuple[tuple[str, int | float | None], ...] | None
    expected_behavioral_pattern: str
    label_validated: bool
    detector_execution: str = "NOT_EVALUATED"
    comparison_status: str = "NOT_EVALUATED"


def _invalid_manifest() -> CounterfactualCorpusError:
    return CounterfactualCorpusError("invalid_manifest")


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def decode_manifest(raw: bytes) -> dict[str, Any]:
    """Decode version 1 JSON while rejecting duplicate keys and non-JSON numbers."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise _invalid_manifest()

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
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise _invalid_manifest() from None
    if (
        type(value) is not dict
        or set(value) != _ROOT_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("data_scope") != "synthetic-only"
        or type(value.get("scenarios")) is not list
        or not 1 <= len(value["scenarios"]) <= MAX_SCENARIOS
    ):
        raise _invalid_manifest()
    return value


def _validate_facts(value: object, *, allow_none: bool = False) -> dict[str, Any] | None:
    if value is None and allow_none:
        return None
    if type(value) is not dict or set(value) != _FACT_KEYS:
        raise _invalid_manifest()
    for key in _FACT_KEYS - {"target_failure_span_seconds"}:
        if type(value[key]) is not int or value[key] < 0:
            raise _invalid_manifest()
    span = value["target_failure_span_seconds"]
    if span is not None and (type(span) not in (int, float) or span < 0 or span > 1_000_000):
        raise _invalid_manifest()
    if type(span) is float and span != span:  # defensive NaN check after JSON validation
        raise _invalid_manifest()
    if value["target_failure_count"] == 0 and span is not None:
        raise _invalid_manifest()
    if value["target_failure_count"] > 0 and span is None:
        raise _invalid_manifest()
    if (
        value["event_count"] != value["login_failed_count"]
        or value["known_account_count"] > value["login_failed_count"]
        or value["source_ip_count"] > value["login_failed_count"]
        or value["target_failure_count"] > value["login_failed_count"]
        or value["target_known_account_count"] > value["target_failure_count"]
        or value["target_known_account_count"] > value["known_account_count"]
        or value["target_failure_count"] > value["event_count"]
    ):
        raise _invalid_manifest()
    return dict(value)


def _validate_scenario(item: object) -> CounterfactualScenario:
    if type(item) is not dict or set(item) != _SCENARIO_KEYS:
        raise _invalid_manifest()
    if (
        type(item["scenario_id"]) is not str or _ID.fullmatch(item["scenario_id"]) is None
        or type(item["detector_id"]) is not str or item["detector_id"] not in _DETECTORS
        or type(item["source"]) is not str or item["source"] not in _SOURCES
        or type(item["baseline_fixture_id"]) is not str
        or _ID.fullmatch(item["baseline_fixture_id"]) is None
        or type(item["mutation_type"]) is not str
        or type(item["mutation_target"]) is not str
        or type(item["mutation_parameters"]) is not dict
        or type(item["expected_parser_disposition"]) is not str
        or item["expected_parser_disposition"] not in _PARSER_STATES - {"NOT_EVALUATED"}
        or type(item["expected_behavioral_pattern"]) is not str
        or item["expected_behavioral_pattern"] not in _PATTERN_LABELS
        or type(item["baseline_expected_behavioral_pattern"]) is not str
        or item["baseline_expected_behavioral_pattern"] not in _PATTERN_LABELS
        or type(item["operational_context"]) is not str
        or item["operational_context"] not in _OPERATIONAL_CONTEXTS
        or type(item["label_basis"]) is not str
        or not 1 <= len(item["label_basis"]) <= MAX_LABEL_BASIS_LENGTH
        or type(item["policy_id"]) is not str
        or item["policy_id"] != _POLICY_IDS[item["detector_id"]]
        or type(item["comparison_scope"]) is not str
        or item["comparison_scope"] != "target_source_ip"
        or type(item["target_subject"]) is not str
    ):
        raise _invalid_manifest()
    try:
        target_address = ip_address(item["target_subject"])
    except ValueError:
        raise _invalid_manifest() from None
    if (
        str(target_address) != item["target_subject"]
        or not any(target_address in network for network in _DOCUMENTATION_NETWORKS)
    ):
        raise _invalid_manifest()
    if (item["detector_id"] in _DETECTORS) and item["source"] not in ("application", "ssh"):
        raise _invalid_manifest()

    baseline_facts = _validate_facts(item["baseline_expected_event_facts"])
    expected_facts = _validate_facts(
        item["expected_event_facts"], allow_none=item["expected_parser_disposition"] == "REJECTED",
    )
    if item["expected_parser_disposition"] == "REJECTED":
        if expected_facts is not None or item["expected_behavioral_pattern"] != "PATTERN_UNDETERMINED":
            raise _invalid_manifest()
    elif expected_facts is None:
        raise _invalid_manifest()
    if item["baseline_expected_behavioral_pattern"] == "PATTERN_UNDETERMINED":
        raise _invalid_manifest()
    if item["detector_id"] == "brute_force" and item["policy_id"] != "brute_force_production_v1":
        raise _invalid_manifest()
    if item["detector_id"] == "password_spraying_like" and item["policy_id"] != "password_spray_whole_span_production_v1":
        raise _invalid_manifest()

    return CounterfactualScenario(
        scenario_id=item["scenario_id"], detector_id=item["detector_id"],
        source=item["source"], baseline_fixture_id=item["baseline_fixture_id"],
        mutation_type=item["mutation_type"], mutation_target=item["mutation_target"],
        mutation_parameters=_freeze(item["mutation_parameters"]),
        expected_parser_disposition=item["expected_parser_disposition"],
        expected_event_facts=None if expected_facts is None else _freeze(expected_facts),
        expected_behavioral_pattern=item["expected_behavioral_pattern"],
        operational_context=item["operational_context"], label_basis=item["label_basis"],
        policy_id=item["policy_id"], comparison_scope=item["comparison_scope"],
        target_subject=item["target_subject"], baseline_expected_event_facts=_freeze(baseline_facts),
        baseline_expected_behavioral_pattern=item["baseline_expected_behavioral_pattern"],
    )


def load_fixture(fixture_id: str) -> bytes:
    if type(fixture_id) is not str or _ID.fullmatch(fixture_id) is None:
        raise _invalid_manifest()
    root = CORPUS_ROOT
    path = root / f"{fixture_id}.log"
    try:
        root_real = root.resolve(strict=True)
        if root.is_symlink() or path.is_symlink() or not path.is_file():
            raise CounterfactualCorpusError("fixture_unavailable")
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise CounterfactualCorpusError("fixture_unavailable")
        path.resolve(strict=True).relative_to(root_real)
        raw = path.read_bytes()
    except CounterfactualCorpusError:
        raise
    except (OSError, ValueError):
        raise CounterfactualCorpusError("fixture_unavailable") from None
    if not raw or len(raw) > MAX_FIXTURE_BYTES:
        raise CounterfactualCorpusError("fixture_unavailable")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise CounterfactualCorpusError("invalid_utf8") from None
    if "\r" in text or not text.endswith("\n") or len(text[:-1].split("\n")) > MAX_FIXTURE_LINES:
        raise CounterfactualCorpusError("fixture_unavailable")
    return raw


def load_corpus() -> tuple[CounterfactualScenario, ...]:
    root = CORPUS_ROOT
    manifest = root / MANIFEST_PATH
    try:
        if root.is_symlink() or manifest.is_symlink() or not manifest.is_file():
            raise _invalid_manifest()
        if manifest.stat().st_size > MAX_MANIFEST_BYTES:
            raise _invalid_manifest()
        raw = manifest.read_bytes()
    except CounterfactualCorpusError:
        raise
    except OSError:
        raise _invalid_manifest() from None
    decoded = decode_manifest(raw)
    try:
        scenarios = tuple(_validate_scenario(item) for item in decoded["scenarios"])
    except CounterfactualCorpusError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError):
        raise _invalid_manifest() from None
    if len({item.scenario_id for item in scenarios}) != len(scenarios):
        raise _invalid_manifest()
    fixture_ids = {item.baseline_fixture_id for item in scenarios}
    try:
        actual_paths = list(root.iterdir())
    except OSError:
        raise _invalid_manifest() from None
    if any(path.is_symlink() for path in actual_paths):
        raise _invalid_manifest()
    actual_names = {path.name for path in actual_paths}
    if actual_names != {MANIFEST_PATH, *(f"{fixture_id}.log" for fixture_id in fixture_ids)}:
        raise _invalid_manifest()
    for fixture_id in sorted(fixture_ids):
        load_fixture(fixture_id)
    for scenario in scenarios:
        try:
            apply_mutation(
                load_fixture(scenario.baseline_fixture_id),
                source=scenario.source,
                mutation_type=scenario.mutation_type,
                mutation_target=scenario.mutation_target,
                mutation_parameters=_thaw(scenario.mutation_parameters),
            )
        except CounterfactualCorpusError:
            raise _invalid_manifest() from None
    return scenarios


def _event_facts(events, target_subject: str) -> dict[str, int | float | None]:
    failures = [event for event in events if event.event_type == "login_failed"]
    target = [event for event in failures if event.src_ip == target_subject]
    timestamps = [event.timestamp.astimezone(timezone.utc) for event in target]
    span = None if not timestamps else (max(timestamps) - min(timestamps)).total_seconds()
    return {
        "event_count": len(events),
        "login_failed_count": len(failures),
        "known_account_count": len({event.user for event in failures if event.user}),
        "source_ip_count": len({event.src_ip for event in failures if event.src_ip}),
        "target_failure_count": len(target),
        "target_known_account_count": len({event.user for event in target if event.user}),
        "target_failure_span_seconds": span,
    }


def _parser_disposition(events, expected_line_count: int, source: str) -> str:
    if not events:
        return "REJECTED"
    if len(events) != expected_line_count:
        return "PARTIAL"
    for event in events:
        if (
            event.source != source
            or event.event_type != "login_failed"
            or not event.user
            or not event.src_ip
            or event.timestamp.tzinfo is None
            or event.timestamp.utcoffset() is None
        ):
            return "PARTIAL"
        try:
            address = ip_address(event.src_ip)
        except ValueError:
            return "PARTIAL"
        if str(address) != event.src_ip or not any(address in network for network in _DOCUMENTATION_NETWORKS):
            return "PARTIAL"
    return "VERIFIED"


def _parse_fixture(source: str, fixture_bytes: bytes):
    """Run the existing Loader/Parser against a private temporary byte copy."""
    try:
        with tempfile.TemporaryDirectory(prefix="er1a-") as directory:
            path = Path(directory) / "synthetic.log"
            path.write_bytes(fixture_bytes)
            events = load_normalized_logs([{"source": source, "path": str(path)}])
            expected_lines = len(fixture_bytes.decode("utf-8", errors="strict").splitlines())
            disposition = _parser_disposition(events, expected_lines, source)
            return disposition, tuple(events)
    except CounterfactualCorpusError:
        raise
    except ValueError:
        # The supported parser contract rejects malformed records with ValueError.
        return "REJECTED", ()
    except Exception:
        # Unexpected execution failures are not parser rejection or no-detection.
        raise CounterfactualCorpusError("parser_execution_failed") from None


def _independent_pattern(scenario: CounterfactualScenario, events) -> str:
    failures = [
        event for event in events
        if event.event_type == "login_failed" and event.src_ip == scenario.target_subject
    ]
    if scenario.detector_id == "brute_force":
        by_account: dict[str, list[datetime]] = {}
        for event in failures:
            if event.user:
                by_account.setdefault(event.user, []).append(event.timestamp.astimezone(timezone.utc))
        for timestamps in by_account.values():
            ordered = sorted(timestamps)
            for start in range(len(ordered)):
                for end in range(start + 4, len(ordered)):
                    if (ordered[end] - ordered[start]).total_seconds() <= 60:
                        return "PATTERN_PRESENT"
        return "PATTERN_ABSENT"
    accounts = {event.user for event in failures if event.user}
    if (
        len(failures) >= 4
        and len(accounts) >= 3
        and failures
        and (max(event.timestamp for event in failures) - min(event.timestamp for event in failures)).total_seconds() <= 60
    ):
        return "PATTERN_PRESENT"
    return "PATTERN_ABSENT"


def _facts_tuple(facts: dict[str, int | float | None]) -> tuple[tuple[str, int | float | None], ...]:
    return tuple((key, facts[key]) for key in sorted(facts))


def _verify_facts(actual: dict[str, int | float | None], expected: dict[str, Any]) -> None:
    if actual != expected:
        raise CounterfactualCorpusError("event_facts_mismatch")


def prepare_scenario(scenario: CounterfactualScenario) -> PreparedScenario:
    if type(scenario) is not CounterfactualScenario:
        raise _invalid_manifest()
    baseline_bytes = load_fixture(scenario.baseline_fixture_id)
    baseline_state, baseline_events = _parse_fixture(scenario.source, baseline_bytes)
    if baseline_state != "VERIFIED":
        raise CounterfactualCorpusError("parser_rejected")
    baseline_facts = _event_facts(baseline_events, scenario.target_subject)
    _verify_facts(baseline_facts, scenario.baseline_expected_event_facts)
    if _independent_pattern(scenario, baseline_events) != scenario.baseline_expected_behavioral_pattern:
        raise CounterfactualCorpusError("label_mismatch")

    variant_bytes = apply_mutation(
        baseline_bytes,
        source=scenario.source,
        mutation_type=scenario.mutation_type,
        mutation_target=scenario.mutation_target,
        mutation_parameters=_thaw(scenario.mutation_parameters),
    )
    disposition, events = _parse_fixture(scenario.source, variant_bytes)
    if disposition != scenario.expected_parser_disposition:
        raise CounterfactualCorpusError("event_facts_mismatch")

    facts = None
    if disposition in ("VERIFIED", "PARTIAL"):
        facts = _event_facts(events, scenario.target_subject)
        _verify_facts(facts, scenario.expected_event_facts)
    if disposition == "VERIFIED":
        pattern = _independent_pattern(scenario, events)
    else:
        pattern = "PATTERN_UNDETERMINED"
    if pattern != scenario.expected_behavioral_pattern:
        raise CounterfactualCorpusError("label_mismatch")
    return PreparedScenario(
        scenario_id=scenario.scenario_id,
        detector_id=scenario.detector_id,
        baseline_parser_disposition=baseline_state,
        parser_disposition=disposition,
        baseline_event_facts=_facts_tuple(baseline_facts),
        event_facts=None if facts is None else _facts_tuple(facts),
        expected_behavioral_pattern=pattern,
        label_validated=True,
    )


def prepare_corpus() -> tuple[PreparedScenario, ...]:
    return tuple(prepare_scenario(scenario) for scenario in load_corpus())
