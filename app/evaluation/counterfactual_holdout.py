"""Fixed, synthetic ER-1C holdout audit and Production replay."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from app.evaluation.counterfactual_comparison import ComparisonState, validate_reason_codes
from app.evaluation.counterfactual_corpus import (
    CORPUS_ROOT,
    MAX_FIXTURE_BYTES,
    MAX_FIXTURE_LINES,
    MAX_MANIFEST_BYTES,
    MAX_SCENARIOS,
    CounterfactualScenario,
    PreparedScenario,
    _event_facts,
    _independent_pattern,
    _parse_fixture,
    prepare_corpus,
    _thaw,
    _validate_scenario,
    _verify_facts,
    load_corpus,
)
from app.evaluation.counterfactual_mutation import CounterfactualCorpusError, apply_mutation
from app.evaluation.counterfactual_replay import (
    MAX_CANONICAL_OUTPUT_BYTES,
    ReplayScenarioResult,
    SafeFacts,
    _replay_prevalidated_scenario,
    _result_counts,
)


HOLDOUT_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "counterfactual_holdout"
CORPUS_ID = "er1c_independent_holdout_v1"
AUTOMATED_AUDIT = "AUTOMATED_CONTRACT_VALIDATED"
HUMAN_REVIEW_PENDING = "INDEPENDENT_HUMAN_REVIEW_PENDING"
_MAX_HASHES_BYTES = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MUTATION_COVERAGE = frozenset((
    "remove_failure_row", "add_failure_row", "change_timestamp", "change_account",
    "change_source_ip", "reorder_rows", "damage_format",
))
_PARSER_PROFILE = {
    "application": "application_auth_v1",
    "ssh": "rfc5424_openssh_restricted_v1",
}


class HoldoutError(ValueError):
    """Fixed-category failure without input or path reflection."""

    _CODES = frozenset((
        "INVALID_MANIFEST", "HASH_MISMATCH", "INVALID_CORPUS", "LABEL_AUDIT_FAILED",
        "RESOURCE_LIMIT", "INVALID_INTERNAL_CONTRACT",
    ))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "INVALID_INTERNAL_CONTRACT"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"HoldoutError({self.code})"


@dataclass(frozen=True, slots=True)
class AuditRow:
    scenario_id: str
    detector_id: str
    source: str
    parser_profile: str
    policy_id: str
    comparison_scope: str
    mutation_type: str
    label_basis: str = field(repr=False)
    baseline_parser_state: str
    expected_variant_parser_state: str
    actual_variant_parser_state: str
    expected_baseline_pattern: str
    actual_baseline_pattern: str
    expected_variant_pattern: str
    actual_variant_pattern: str
    baseline_input_facts_match: bool
    variant_input_facts_match: bool
    label_basis_status: str
    operational_context: str
    reason_codes: tuple[str, ...]
    baseline_facts: SafeFacts | None = field(repr=False)
    variant_facts: SafeFacts | None = field(repr=False)

    @property
    def input_facts_match(self) -> bool:
        return self.baseline_input_facts_match and self.variant_input_facts_match

    @property
    def pattern_label_match(self) -> bool:
        return (
            self.expected_baseline_pattern == self.actual_baseline_pattern
            and self.expected_variant_pattern == self.actual_variant_pattern
        )

    @property
    def status(self) -> str:
        if not self.input_facts_match:
            return "INPUT_FACTS_MISMATCH"
        if not self.pattern_label_match:
            return "LABEL_MISMATCH"
        if "ANALYSIS_EXECUTION_FAILED" in self.reason_codes:
            return "PARSER_EXECUTION_FAILED"
        if self.reason_codes:
            return "INPUT_OR_LABEL_CONTRACT_MISMATCH"
        return "AUTOMATED_CONTRACT_VALIDATED"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "detector_id": self.detector_id,
            "source": self.source,
            "parser_profile": self.parser_profile,
            "policy_id": self.policy_id,
            "comparison_scope": self.comparison_scope,
            "mutation_type": self.mutation_type,
            "parser": {
                "baseline": self.baseline_parser_state,
                "expected_variant": self.expected_variant_parser_state,
                "actual_variant": self.actual_variant_parser_state,
            },
            "independent_pattern": {
                "expected_baseline": self.expected_baseline_pattern,
                "input_oracle_baseline": self.actual_baseline_pattern,
                "expected_variant": self.expected_variant_pattern,
                "input_oracle_variant": self.actual_variant_pattern,
            },
            "input_facts_match": {
                "baseline": self.baseline_input_facts_match,
                "variant": self.variant_input_facts_match,
            },
            "label_basis_status": self.label_basis_status,
            "operational_context": self.operational_context,
            "reason_codes": list(self.reason_codes),
            "safe_facts": {
                "baseline": None if self.baseline_facts is None else self.baseline_facts.to_mapping(),
                "variant": None if self.variant_facts is None else self.variant_facts.to_mapping(),
            },
            "audit_status": self.status,
        }


@dataclass(frozen=True, slots=True)
class AuditReport:
    status: str
    scenario_count: int
    input_validation_failures: int
    label_mismatches: int
    rows: tuple[AuditRow, ...]


@dataclass(frozen=True, slots=True)
class DevelopmentAuditSummary:
    status: str
    scenario_count: int
    input_validation_failures: int
    label_mismatches: int
    human_review_status: str
    parser_baseline_counts: Any
    parser_variant_counts: Any


@dataclass(frozen=True, slots=True)
class HoldoutCorpus:
    corpus_id: str
    human_review_status: str
    label_provenance: str
    scenarios: tuple[CounterfactualScenario, ...]
    raw_manifest: bytes = field(repr=False)
    fixture_bytes: Any = field(repr=False)
    variant_bytes: Any = field(repr=False)
    hashes: Any = field(repr=False)
    audit: AuditReport


@dataclass(frozen=True, slots=True)
class HoldoutReplayReport:
    schema_version: int
    corpus_id: str
    scenario_count: int
    human_review_status: str
    label_audit_status: str
    label_provenance: str
    manifest_sha256: str
    fixture_hashes: Any = field(repr=False)
    counts: Any = field(repr=False)
    development_audit: DevelopmentAuditSummary
    audit_rows: tuple[AuditRow, ...]
    results: tuple[ReplayScenarioResult, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "corpus_kind": "holdout",
            "corpus_id": self.corpus_id,
            "scenario_count": self.scenario_count,
            "independent_human_review_status": self.human_review_status,
            "label_audit_status": self.label_audit_status,
            "label_provenance": self.label_provenance,
            "provenance_hashes": {
                "manifest_sha256": self.manifest_sha256,
                "fixture_sha256": dict(self.fixture_hashes),
                "hashes_file_self_hash_excluded": True,
            },
            "development_corpus_audit": {
                "corpus_kind": "development",
                "status": self.development_audit.status,
                "scenario_count": self.development_audit.scenario_count,
                "input_validation_failures": self.development_audit.input_validation_failures,
                "label_mismatches": self.development_audit.label_mismatches,
                "independent_human_review_status": self.development_audit.human_review_status,
                "parser_baseline": _plain(self.development_audit.parser_baseline_counts),
                "parser_variant": _plain(self.development_audit.parser_variant_counts),
            },
            "counts": {key: _plain(value) for key, value in self.counts.items()},
            "label_audit": [row.to_mapping() for row in self.audit_rows],
            "results": [row.to_mapping() for row in self.results],
        }


def _plain(value):
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) is dict:
        return {key: _plain(item) for key, item in value.items()}
    return value


def _decode_strict(raw: bytes, *, limit: int, code: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise HoldoutError(code)

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
        raise HoldoutError(code) from None
    if type(value) is not dict:
        raise HoldoutError(code)
    return value


def decode_holdout_manifest(raw: bytes) -> dict[str, Any]:
    manifest = _decode_strict(raw, limit=MAX_MANIFEST_BYTES, code="INVALID_MANIFEST")
    if set(manifest) != {
        "schema_version", "data_scope", "corpus_id", "label_provenance",
        "human_review_status", "scenarios",
    }:
        raise HoldoutError("INVALID_MANIFEST")
    scenarios = manifest.get("scenarios")
    if (
        type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
        or manifest.get("data_scope") != "synthetic-only"
        or manifest.get("corpus_id") != CORPUS_ID
        or manifest.get("label_provenance") != "INDEPENDENT_INPUT_FACTS_AND_POLICY_TABLE"
        or manifest.get("human_review_status") != HUMAN_REVIEW_PENDING
        or type(scenarios) is not list or not 12 <= len(scenarios) <= MAX_SCENARIOS
    ):
        raise HoldoutError("INVALID_MANIFEST")
    try:
        parsed = tuple(_validate_scenario(item) for item in scenarios)
    except (CounterfactualCorpusError, KeyError, TypeError, ValueError, OverflowError):
        raise HoldoutError("INVALID_MANIFEST") from None
    if len({item.scenario_id for item in parsed}) != len(parsed):
        raise HoldoutError("INVALID_MANIFEST")
    if len({item.baseline_fixture_id for item in parsed}) != len(parsed):
        raise HoldoutError("INVALID_MANIFEST")
    counts = {
        detector: sum(item.detector_id == detector for item in parsed)
        for detector in ("brute_force", "password_spraying_like")
    }
    if min(counts.values()) < 6 or sum(item.source == "ssh" for item in parsed) < 4:
        raise HoldoutError("INVALID_MANIFEST")
    if {item.source for item in parsed} != {"application", "ssh"}:
        raise HoldoutError("INVALID_MANIFEST")
    if {item.expected_parser_disposition for item in parsed} < {"VERIFIED", "PARTIAL", "REJECTED"}:
        raise HoldoutError("INVALID_MANIFEST")
    if not _MUTATION_COVERAGE.issubset({item.mutation_type for item in parsed}):
        raise HoldoutError("INVALID_MANIFEST")
    return manifest


def _read_manifest_and_fixtures() -> tuple[bytes, dict[str, bytes], dict[str, Any]]:
    root = HOLDOUT_ROOT
    try:
        if root.is_symlink() or not root.is_dir():
            raise HoldoutError("INVALID_CORPUS")
        root_real = root.resolve(strict=True)
        children = tuple(root.iterdir())
        if any(item.is_symlink() for item in children):
            raise HoldoutError("INVALID_CORPUS")
        manifest_path = root / "manifest.json"
        hashes_path = root / "hashes.json"
        if not manifest_path.is_file() or not hashes_path.is_file():
            raise HoldoutError("INVALID_CORPUS")
        manifest_path.resolve(strict=True).relative_to(root_real)
        hashes_path.resolve(strict=True).relative_to(root_real)
        raw = manifest_path.read_bytes()
        hashes_raw = hashes_path.read_bytes()
        fixture_bytes = {}
        for item in children:
            if item.suffix != ".log":
                continue
            item.resolve(strict=True).relative_to(root_real)
            content = item.read_bytes()
            if not content or len(content) > MAX_FIXTURE_BYTES:
                raise HoldoutError("INVALID_CORPUS")
            text = content.decode("utf-8", errors="strict")
            if "\r" in text or not text.endswith("\n") or len(text[:-1].split("\n")) > MAX_FIXTURE_LINES:
                raise HoldoutError("INVALID_CORPUS")
            fixture_bytes[item.stem] = content
    except HoldoutError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise HoldoutError("INVALID_CORPUS") from None
    hashes = _decode_strict(hashes_raw, limit=_MAX_HASHES_BYTES, code="INVALID_CORPUS")
    return raw, fixture_bytes, hashes


def _safe_facts(values) -> SafeFacts:
    try:
        return SafeFacts(**values)
    except (TypeError, ValueError):
        raise HoldoutError("INVALID_CORPUS") from None


def audit_scenario(
    scenario: CounterfactualScenario,
    baseline_bytes: bytes,
    variant_bytes: bytes,
) -> AuditRow:
    """Audit input facts and policy labels without reading Detector outputs."""
    if type(scenario) is not CounterfactualScenario or type(baseline_bytes) is not bytes or type(variant_bytes) is not bytes:
        raise HoldoutError("INVALID_INTERNAL_CONTRACT")
    reasons: set[str] = set()
    baseline_facts = variant_facts = None
    baseline_state = variant_state = "NOT_EVALUATED"
    baseline_pattern = variant_pattern = "PATTERN_UNDETERMINED"
    baseline_match = variant_match = False
    try:
        baseline_state, baseline_events = _parse_fixture(scenario.source, baseline_bytes)
        if baseline_state == "VERIFIED":
            baseline_values = _event_facts(baseline_events, scenario.target_subject)
            baseline_facts = _safe_facts(baseline_values)
            try:
                _verify_facts(baseline_values, dict(scenario.baseline_expected_event_facts))
                baseline_match = True
            except CounterfactualCorpusError:
                reasons.add("EVENT_COUNT_MISMATCH")
            baseline_pattern = _independent_pattern(scenario, baseline_events)
        else:
            reasons.add("LINE_REJECTED")

        variant_state, variant_events = _parse_fixture(scenario.source, variant_bytes)
        if variant_state != scenario.expected_parser_disposition:
            reasons.add("AMBIGUOUS_OUTCOME")
        if variant_state in ("VERIFIED", "PARTIAL"):
            variant_values = _event_facts(variant_events, scenario.target_subject)
            variant_facts = _safe_facts(variant_values)
            try:
                _verify_facts(variant_values, dict(scenario.expected_event_facts))
                variant_match = True
            except CounterfactualCorpusError:
                reasons.add("EVENT_COUNT_MISMATCH")
            if variant_state == "VERIFIED":
                variant_pattern = _independent_pattern(scenario, variant_events)
            if variant_state == "PARTIAL":
                variant_pattern = "PATTERN_UNDETERMINED"
                if scenario.expected_behavioral_pattern != "PATTERN_UNDETERMINED":
                    reasons.add("AMBIGUOUS_OUTCOME")
        elif variant_state == "REJECTED":
            variant_pattern = "PATTERN_UNDETERMINED"
            variant_match = scenario.expected_event_facts is None
        else:
            reasons.add("PARSER_NOT_RUN")
    except CounterfactualCorpusError as error:
        if error.code == "parser_execution_failed":
            reasons.add("ANALYSIS_EXECUTION_FAILED")
        else:
            reasons.add("LINE_REJECTED")

    if baseline_pattern != scenario.baseline_expected_behavioral_pattern:
        reasons.add("AMBIGUOUS_OUTCOME")
    if variant_pattern != scenario.expected_behavioral_pattern:
        reasons.add("AMBIGUOUS_OUTCOME")
    codes = tuple(sorted(reasons))
    codes = validate_reason_codes(codes)
    return AuditRow(
        scenario_id=scenario.scenario_id,
        detector_id=scenario.detector_id,
        source=scenario.source,
        parser_profile=_PARSER_PROFILE[scenario.source],
        policy_id=scenario.policy_id,
        comparison_scope=scenario.comparison_scope,
        mutation_type=scenario.mutation_type,
        label_basis=scenario.label_basis,
        baseline_parser_state=baseline_state,
        expected_variant_parser_state=scenario.expected_parser_disposition,
        actual_variant_parser_state=variant_state,
        expected_baseline_pattern=scenario.baseline_expected_behavioral_pattern,
        actual_baseline_pattern=baseline_pattern,
        expected_variant_pattern=scenario.expected_behavioral_pattern,
        actual_variant_pattern=variant_pattern,
        baseline_input_facts_match=baseline_match,
        variant_input_facts_match=variant_match,
        label_basis_status=AUTOMATED_AUDIT if baseline_match and variant_match and not codes else "LABEL_AUDIT_FAILED",
        operational_context=scenario.operational_context,
        reason_codes=codes,
        baseline_facts=baseline_facts,
        variant_facts=variant_facts,
    )


def load_holdout() -> HoldoutCorpus:
    raw, fixture_bytes, hashes = _read_manifest_and_fixtures()
    manifest = decode_holdout_manifest(raw)
    scenarios = tuple(_validate_scenario(item) for item in manifest["scenarios"])
    expected_names = {item.baseline_fixture_id for item in scenarios}
    if set(fixture_bytes) != expected_names:
        raise HoldoutError("INVALID_CORPUS")
    try:
        inventory = tuple(HOLDOUT_ROOT.iterdir())
        expected_files = {"manifest.json", "hashes.json", *(f"{name}.log" for name in expected_names)}
        if (
            any(item.is_symlink() or not item.is_file() for item in inventory)
            or {item.name for item in inventory} != expected_files
        ):
            raise HoldoutError("INVALID_CORPUS")
    except HoldoutError:
        raise
    except OSError:
        raise HoldoutError("INVALID_CORPUS") from None
    if (
        set(hashes) != {"schema_version", "manifest_sha256", "fixtures"}
        or type(hashes.get("schema_version")) is not int or hashes["schema_version"] != 1
        or type(hashes.get("manifest_sha256")) is not str or _SHA256.fullmatch(hashes["manifest_sha256"]) is None
        or type(hashes.get("fixtures")) is not dict or set(hashes["fixtures"]) != expected_names
    ):
        raise HoldoutError("INVALID_CORPUS")
    if hashlib.sha256(raw).hexdigest() != hashes["manifest_sha256"]:
        raise HoldoutError("HASH_MISMATCH")
    fixture_hashes = {}
    for fixture_id, value in fixture_bytes.items():
        expected = hashes["fixtures"].get(fixture_id)
        if type(expected) is not str or _SHA256.fullmatch(expected) is None:
            raise HoldoutError("INVALID_CORPUS")
        actual = hashlib.sha256(value).hexdigest()
        if actual != expected:
            raise HoldoutError("HASH_MISMATCH")
        fixture_hashes[fixture_id] = actual

    # A holdout fixture must not be an ER-1A fixture or byte-for-byte copy.
    development = load_corpus()
    development_ids = {item.baseline_fixture_id for item in development}
    development_hashes = {
        hashlib.sha256((CORPUS_ROOT / f"{item.baseline_fixture_id}.log").read_bytes()).hexdigest()
        for item in development
    }
    if expected_names & development_ids or set(fixture_hashes.values()) & development_hashes:
        raise HoldoutError("INVALID_CORPUS")

    variant_bytes = {}
    audits = []
    for scenario in scenarios:
        baseline = fixture_bytes[scenario.baseline_fixture_id]
        try:
            variant = apply_mutation(
                baseline,
                source=scenario.source,
                mutation_type=scenario.mutation_type,
                mutation_target=scenario.mutation_target,
                mutation_parameters=_thaw(scenario.mutation_parameters),
            )
        except CounterfactualCorpusError:
            raise HoldoutError("INVALID_CORPUS") from None
        if variant == baseline:
            raise HoldoutError("INVALID_CORPUS")
        variant_bytes[scenario.scenario_id] = variant
        audits.append(audit_scenario(scenario, baseline, variant))
    rows = tuple(audits)
    audit = AuditReport(
        status=AUTOMATED_AUDIT if all(row.status == AUTOMATED_AUDIT for row in rows) else "LABEL_AUDIT_FAILED",
        scenario_count=len(rows),
        input_validation_failures=sum(not row.input_facts_match for row in rows),
        label_mismatches=sum(not row.pattern_label_match for row in rows),
        rows=rows,
    )
    return HoldoutCorpus(
        corpus_id=CORPUS_ID,
        human_review_status=HUMAN_REVIEW_PENDING,
        label_provenance=manifest["label_provenance"],
        scenarios=scenarios,
        raw_manifest=raw,
        fixture_bytes=MappingProxyType(dict(fixture_bytes)),
        variant_bytes=MappingProxyType(dict(variant_bytes)),
        hashes=MappingProxyType({
            "manifest_sha256": hashes["manifest_sha256"],
            "fixtures": MappingProxyType(dict(fixture_hashes)),
        }),
        audit=audit,
    )


def audit_development_corpus() -> DevelopmentAuditSummary:
    """Re-run ER-1A input-fact and policy oracle checks without detector output."""
    try:
        prepared = prepare_corpus()
    except CounterfactualCorpusError:
        raise HoldoutError("INVALID_CORPUS") from None
    if not prepared:
        raise HoldoutError("INVALID_CORPUS")
    valid = all(item.label_validated for item in prepared)
    baseline_counts = {
        state: sum(item.baseline_parser_disposition == state for item in prepared)
        for state in ("VERIFIED", "PARTIAL", "REJECTED", "NOT_EVALUATED")
    }
    variant_counts = {
        state: sum(item.parser_disposition == state for item in prepared)
        for state in ("VERIFIED", "PARTIAL", "REJECTED", "NOT_EVALUATED")
    }
    return DevelopmentAuditSummary(
        status=AUTOMATED_AUDIT if valid else "LABEL_AUDIT_FAILED",
        scenario_count=len(prepared),
        input_validation_failures=0 if valid else sum(not item.label_validated for item in prepared),
        label_mismatches=0 if valid else sum(not item.label_validated for item in prepared),
        human_review_status=HUMAN_REVIEW_PENDING,
        parser_baseline_counts=MappingProxyType(baseline_counts),
        parser_variant_counts=MappingProxyType(variant_counts),
    )


def _facts_pairs(facts: SafeFacts | None):
    return None if facts is None else tuple(sorted(facts.to_mapping().items()))


def _holdout_counts(results: tuple[ReplayScenarioResult, ...], audit: AuditReport):
    counts = dict(_result_counts(results))
    core = counts.pop("label_baseline"), counts.pop("label_variant")
    counts["label_validation"] = {
        "baseline": core[0],
        "variant": core[1],
        "mismatch_total": core[0]["MISMATCH"] + core[1]["MISMATCH"],
        "not_evaluated_total": core[0]["NOT_EVALUATED"] + core[1]["NOT_EVALUATED"],
        "input_label_audit_failures": audit.label_mismatches,
    }
    detector_counts = counts["detector_baseline"], counts["detector_variant"]
    counts["execution_failures"] = sum(
        item["EXECUTION_FAILED"] for item in detector_counts
    )
    counts["input_validation_failures"] = audit.input_validation_failures
    counts["label_audit_failures"] = audit.label_mismatches
    return MappingProxyType({key: value for key, value in counts.items()})


def run_holdout() -> HoldoutReplayReport:
    corpus = load_holdout()
    if corpus.audit.status != AUTOMATED_AUDIT:
        raise HoldoutError("LABEL_AUDIT_FAILED")
    development_audit = audit_development_corpus()
    if development_audit.status != AUTOMATED_AUDIT:
        raise HoldoutError("LABEL_AUDIT_FAILED")
    results = []
    for scenario, audit in zip(corpus.scenarios, corpus.audit.rows, strict=True):
        if audit.status != AUTOMATED_AUDIT:
            raise HoldoutError("LABEL_AUDIT_FAILED")
        baseline = corpus.fixture_bytes[scenario.baseline_fixture_id]
        variant = corpus.variant_bytes[scenario.scenario_id]
        prepared = PreparedScenario(
            scenario_id=scenario.scenario_id,
            detector_id=scenario.detector_id,
            baseline_parser_disposition=audit.baseline_parser_state,
            parser_disposition=audit.actual_variant_parser_state,
            baseline_event_facts=_facts_pairs(audit.baseline_facts) or (),
            event_facts=_facts_pairs(audit.variant_facts),
            expected_behavioral_pattern=scenario.expected_behavioral_pattern,
            label_validated=True,
        )
        results.append(_replay_prevalidated_scenario(scenario, baseline, variant, prepared))
    result_rows = tuple(results)
    replay_counts = _holdout_counts(result_rows, corpus.audit)
    return HoldoutReplayReport(
        schema_version=1,
        corpus_id=corpus.corpus_id,
        scenario_count=len(result_rows),
        human_review_status=corpus.human_review_status,
        label_audit_status=corpus.audit.status,
        label_provenance=corpus.label_provenance,
        manifest_sha256=corpus.hashes["manifest_sha256"],
        fixture_hashes=corpus.hashes["fixtures"],
        counts=replay_counts,
        development_audit=development_audit,
        audit_rows=corpus.audit.rows,
        results=result_rows,
    )


def canonical_holdout_json(report: HoldoutReplayReport) -> bytes:
    if type(report) is not HoldoutReplayReport or report.schema_version != 1:
        raise HoldoutError("INVALID_INTERNAL_CONTRACT")
    try:
        encoded = (
            json.dumps(
                report.to_mapping(), sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise HoldoutError("INVALID_INTERNAL_CONTRACT") from None
    if len(encoded) > MAX_CANONICAL_OUTPUT_BYTES:
        raise HoldoutError("RESOURCE_LIMIT")
    return encoded
