"""Label-blind review packet and manual-submission adjudication for ER-1C-R."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from app.evaluation import counterfactual_corpus as development
from app.evaluation import counterfactual_holdout as holdout
from app.evaluation.counterfactual_mutation import CounterfactualCorpusError, apply_mutation


MAX_PACKET_BYTES = 512 * 1024
MAX_SUBMISSION_BYTES = 128 * 1024
_PACKET_SCHEMA_VERSION = 1
_SUBMISSION_SCHEMA_VERSION = 1
_SCENARIO_ID = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
_REVIEWER_REF = re.compile(r"reviewer_[A-Za-z0-9_-]{1,32}\Z", re.ASCII)
_PATTERN_LABELS = frozenset(("PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"))
_REVIEW_STATES = frozenset(("REVIEWED", "NEEDS_CLARIFICATION", "DISAGREEMENT", "INSUFFICIENT_EVIDENCE", "NOT_REVIEWED"))
_PARSER_SCOPE = frozenset(("SUFFICIENT", "PARTIAL", "REJECTED", "UNDETERMINED"))
_INDEPENDENCE_CLAIMS = frozenset(("DECLARED_INDEPENDENT", "DECLARED_NOT_INDEPENDENT", "UNKNOWN"))
_OUTCOME_CATEGORIES = ("MATCH", "DISAGREEMENT", "NEEDS_CLARIFICATION", "INSUFFICIENT_EVIDENCE", "NOT_REVIEWED")
_SOURCE_PROFILE = {"application": "application_auth_v1", "ssh": "rfc5424_openssh_restricted_v1"}
_POLICY_TEXT = {
    "brute_force": (
        "같은 Source IP와 동일한 알려진 계정의 인증 실패를 선택 sliding window에서 봅니다. "
        "현재 Production 조건은 5회 이상, 시간 폭 60초 이하입니다. 전체 IP Feature는 선택 계정 window와 다른 범위입니다."
    ),
    "password_spraying_like": (
        "같은 Source IP의 전체 인증 실패를 봅니다. 현재 Production 조건은 4회 이상, "
        "알려진 계정 3개 이상, 전체 실패 시간 폭 60초 이하입니다. Production은 sliding window가 아닙니다."
    ),
}
_MUTATIONS = frozenset((
    "remove_failure_row", "add_failure_row", "change_timestamp", "change_account",
    "change_source_ip", "reorder_rows", "damage_format",
))


class ReviewPacketError(ValueError):
    _CODES = frozenset((
        "INVALID_CORPUS", "PARSER_EXECUTION_FAILED", "PACKET_LIMIT_EXCEEDED",
        "INVALID_PACKET", "INVALID_SUBMISSION", "PACKET_DIGEST_MISMATCH",
    ))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "INVALID_PACKET"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"ReviewPacketError({self.code})"


class ReviewSubmissionError(ValueError):
    _CODES = frozenset(("INVALID_SUBMISSION", "PACKET_DIGEST_MISMATCH", "PACKET_LIMIT_EXCEEDED"))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "INVALID_SUBMISSION"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"ReviewSubmissionError({self.code})"


@dataclass(frozen=True, slots=True)
class BlindScenarioInput:
    """Allowlisted inputs only: expected labels and replay outputs cannot enter packet building."""

    corpus_id: str
    scenario_id: str
    detector_id: str
    source: str
    baseline_fixture_id: str
    mutation_type: str
    baseline_bytes: bytes = field(repr=False)
    variant_bytes: bytes = field(repr=False)
    baseline_sha256: str
    variant_sha256: str


@dataclass(frozen=True, slots=True)
class BlindCorpusInput:
    corpus_id: str
    manifest_sha256: str
    fixture_sha256: Any = field(repr=False)
    scenarios: tuple[BlindScenarioInput, ...]


@dataclass(frozen=True, slots=True)
class ReviewPacket:
    packet_sha256: str
    source_corpora: Any = field(repr=False)
    scenarios: tuple[Any, ...] = field(repr=False)

    def to_mapping(self) -> dict[str, Any]:
        body = {
            "schema_version": _PACKET_SCHEMA_VERSION,
            "packet_type": "label_blind_counterfactual_review",
            "data_scope": "synthetic-only",
            "review_status": "INDEPENDENT_HUMAN_REVIEW_PENDING",
            "blindness_limit": "Public repository labels exist; the procedure cannot prove a reviewer did not view them.",
            "digest_scope": "canonical payload excluding packet_sha256",
            "source_corpora": _plain(self.source_corpora),
            "scenarios": _plain(self.scenarios),
        }
        body["packet_sha256"] = self.packet_sha256
        return body


@dataclass(frozen=True, slots=True)
class ReviewAdjudication:
    packet_sha256: str
    scenario_count: int
    response_count: int
    review_status: str
    independence_claim: str
    has_viewed_existing_labels_or_replay: bool
    independence_verification: str
    approval_status: str
    counts: Any = field(repr=False)
    scenarios: tuple[Any, ...] = field(repr=False)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "result_type": "manual_review_comparison",
            "packet_sha256": self.packet_sha256,
            "scenario_count": self.scenario_count,
            "response_count": self.response_count,
            "review_status": self.review_status,
            "independence_claim": self.independence_claim,
            "has_viewed_existing_labels_or_replay": self.has_viewed_existing_labels_or_replay,
            "independence_verification": self.independence_verification,
            "approval_status": self.approval_status,
            "counts": _plain(self.counts),
            "scenarios": _plain(self.scenarios),
        }


def _plain(value):
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    if type(value) is dict:
        return {key: _plain(item) for key, item in value.items()}
    return value


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _canonical(value: Any, *, limit: int, error_type, limit_code: str) -> bytes:
    try:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError):
        raise error_type("INVALID_PACKET") from None
    if len(encoded) > limit:
        raise error_type(limit_code)
    return encoded


def _strict_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_SUBMISSION_BYTES:
        raise ReviewSubmissionError("PACKET_LIMIT_EXCEEDED")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise ReviewSubmissionError("INVALID_SUBMISSION") from None
    if type(value) is not dict:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    return value


def _blind_scenario(corpus_id: str, scenario: dict[str, Any], baseline: bytes, variant: bytes) -> BlindScenarioInput:
    if scenario["mutation_type"] not in _MUTATIONS:
        raise ReviewPacketError("INVALID_CORPUS")
    return BlindScenarioInput(
        corpus_id=corpus_id,
        scenario_id=scenario["scenario_id"],
        detector_id=scenario["detector_id"],
        source=scenario["source"],
        baseline_fixture_id=scenario["baseline_fixture_id"],
        mutation_type=scenario["mutation_type"],
        baseline_bytes=baseline,
        variant_bytes=variant,
        baseline_sha256=hashlib.sha256(baseline).hexdigest(),
        variant_sha256=hashlib.sha256(variant).hexdigest(),
    )


def _load_development_inputs() -> BlindCorpusInput:
    try:
        root = development.CORPUS_ROOT
        manifest = (root / development.MANIFEST_PATH).read_bytes()
        manifest_value = development.decode_manifest(manifest)
        scenario_specs = manifest_value["scenarios"]
        if len(scenario_specs) != 16:
            raise ReviewPacketError("INVALID_CORPUS")
        fixture_hashes = {}
        blind = []
        seen_ids = set()
        for item in scenario_specs:
            # Validate the closed manifest shape, then read only fields needed to
            # load and mutate bytes. Label values are never materialized as DTOs.
            if type(item) is not dict or set(item) != development._SCENARIO_KEYS:
                raise ReviewPacketError("INVALID_CORPUS")
            scenario = {
                key: item[key] for key in (
                    "scenario_id", "detector_id", "source", "baseline_fixture_id",
                    "mutation_type", "mutation_target", "mutation_parameters",
                )
            }
            if (
                type(scenario["scenario_id"]) is not str
                or development._ID.fullmatch(scenario["scenario_id"]) is None
                or scenario["scenario_id"] in seen_ids
                or scenario["detector_id"] not in development._DETECTORS
                or scenario["source"] not in _SOURCE_PROFILE
                or type(scenario["baseline_fixture_id"]) is not str
                or development._ID.fullmatch(scenario["baseline_fixture_id"]) is None
                or type(scenario["mutation_type"]) is not str
                or scenario["mutation_type"] not in _MUTATIONS
                or type(scenario["mutation_target"]) is not str
                or type(scenario["mutation_parameters"]) is not dict
            ):
                raise ReviewPacketError("INVALID_CORPUS")
            seen_ids.add(scenario["scenario_id"])
            baseline = development.load_fixture(scenario["baseline_fixture_id"])
            variant = apply_mutation(
                baseline,
                source=scenario["source"],
                mutation_type=scenario["mutation_type"],
                mutation_target=scenario["mutation_target"],
                mutation_parameters=scenario["mutation_parameters"],
            )
            fixture_hashes[scenario["baseline_fixture_id"]] = hashlib.sha256(baseline).hexdigest()
            blind.append(_blind_scenario("er1a_development", scenario, baseline, variant))
    except (OSError, CounterfactualCorpusError, KeyError, TypeError, ValueError):
        raise ReviewPacketError("INVALID_CORPUS") from None
    return BlindCorpusInput(
        corpus_id="er1a_development",
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        fixture_sha256=MappingProxyType(dict(sorted(fixture_hashes.items()))),
        scenarios=tuple(blind),
    )


def _load_holdout_inputs(development_input: BlindCorpusInput) -> BlindCorpusInput:
    try:
        raw, fixture_bytes, hashes = holdout._read_manifest_and_fixtures()
        manifest = holdout._decode_strict(raw, limit=holdout.MAX_MANIFEST_BYTES, code="INVALID_MANIFEST")
        if (
            set(manifest) != {"schema_version", "data_scope", "corpus_id", "label_provenance", "human_review_status", "scenarios"}
            or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
            or manifest.get("data_scope") != "synthetic-only"
            or manifest.get("corpus_id") != holdout.CORPUS_ID
            or manifest.get("label_provenance") != "INDEPENDENT_INPUT_FACTS_AND_POLICY_TABLE"
            or manifest.get("human_review_status") != holdout.HUMAN_REVIEW_PENDING
            or type(manifest.get("scenarios")) is not list or len(manifest["scenarios"]) != 14
        ):
            raise ReviewPacketError("INVALID_CORPUS")
        scenarios = []
        seen_ids = set()
        for item in manifest["scenarios"]:
            if type(item) is not dict or set(item) != development._SCENARIO_KEYS:
                raise ReviewPacketError("INVALID_CORPUS")
            scenario = {
                key: item[key] for key in (
                    "scenario_id", "detector_id", "source", "baseline_fixture_id",
                    "mutation_type", "mutation_target", "mutation_parameters",
                )
            }
            if (
                type(scenario["scenario_id"]) is not str
                or development._ID.fullmatch(scenario["scenario_id"]) is None
                or scenario["scenario_id"] in seen_ids
                or type(scenario["detector_id"]) is not str or scenario["detector_id"] not in development._DETECTORS
                or type(scenario["source"]) is not str or scenario["source"] not in _SOURCE_PROFILE
                or type(scenario["baseline_fixture_id"]) is not str
                or development._ID.fullmatch(scenario["baseline_fixture_id"]) is None
                or type(scenario["mutation_type"]) is not str or scenario["mutation_type"] not in _MUTATIONS
                or type(scenario["mutation_target"]) is not str
                or type(scenario["mutation_parameters"]) is not dict
            ):
                raise ReviewPacketError("INVALID_CORPUS")
            seen_ids.add(scenario["scenario_id"])
            scenarios.append(scenario)
        expected_ids = {item["baseline_fixture_id"] for item in scenarios}
        expected_files = {"manifest.json", "hashes.json", *(f"{name}.log" for name in expected_ids)}
        root = holdout.HOLDOUT_ROOT
        if {item.name for item in root.iterdir()} != expected_files or set(fixture_bytes) != expected_ids:
            raise ReviewPacketError("INVALID_CORPUS")
        if (
            set(hashes) != {"schema_version", "manifest_sha256", "fixtures"}
            or type(hashes.get("schema_version")) is not int
            or hashes["schema_version"] != 1
            or hashes.get("manifest_sha256") != hashlib.sha256(raw).hexdigest()
            or type(hashes.get("fixtures")) is not dict
            or set(hashes["fixtures"]) != expected_ids
        ):
            raise ReviewPacketError("INVALID_CORPUS")
        if expected_ids & set(development_input.fixture_sha256):
            raise ReviewPacketError("INVALID_CORPUS")
        development_hashes = set(development_input.fixture_sha256.values())
        actual_hashes = {key: hashlib.sha256(value).hexdigest() for key, value in fixture_bytes.items()}
        if any(actual_hashes[key] != hashes["fixtures"].get(key) for key in expected_ids):
            raise ReviewPacketError("INVALID_CORPUS")
        if development_hashes & set(actual_hashes.values()):
            raise ReviewPacketError("INVALID_CORPUS")
        blind = []
        for scenario in scenarios:
            baseline = fixture_bytes[scenario["baseline_fixture_id"]]
            variant = apply_mutation(
                baseline,
                source=scenario["source"],
                mutation_type=scenario["mutation_type"],
                mutation_target=scenario["mutation_target"],
                mutation_parameters=scenario["mutation_parameters"],
            )
            blind.append(_blind_scenario(holdout.CORPUS_ID, scenario, baseline, variant))
    except ReviewPacketError:
        raise
    except (OSError, CounterfactualCorpusError, KeyError, TypeError, ValueError):
        raise ReviewPacketError("INVALID_CORPUS") from None
    return BlindCorpusInput(
        corpus_id=holdout.CORPUS_ID,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        fixture_sha256=MappingProxyType(dict(sorted(actual_hashes.items()))),
        scenarios=tuple(blind),
    )


def _load_source_corpora() -> tuple[BlindCorpusInput, ...]:
    development_input = _load_development_inputs()
    holdout_input = _load_holdout_inputs(development_input)
    all_scenarios = development_input.scenarios + holdout_input.scenarios
    ids = [(item.corpus_id, item.scenario_id) for item in all_scenarios]
    scenario_ids = [item.scenario_id for item in all_scenarios]
    if len(ids) != 30 or len(set(ids)) != 30 or len(set(scenario_ids)) != 30:
        raise ReviewPacketError("INVALID_CORPUS")
    return development_input, holdout_input


def _alpha_label(index: int) -> str:
    result = ""
    value = index + 1
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(ord("A") + remainder) + result
    return result


def _parse_input(source: str, data: bytes) -> tuple[str, tuple[Any, ...], int]:
    try:
        state, events = development._parse_fixture(source, data)
        line_count = len(data.decode("utf-8", errors="strict").splitlines())
    except CounterfactualCorpusError as error:
        if error.code == "parser_execution_failed":
            raise ReviewPacketError("PARSER_EXECUTION_FAILED") from None
        raise ReviewPacketError("INVALID_CORPUS") from None
    except (UnicodeError, ValueError):
        raise ReviewPacketError("INVALID_CORPUS") from None
    return state, tuple(events), line_count


def _review_side(source: str, data: bytes, events: tuple[Any, ...], state: str, line_count: int, anchor: datetime | None, source_groups: dict[str, str], account_groups: dict[str, str]) -> dict[str, Any]:
    chronological = sorted(range(len(events)), key=lambda index: (events[index].timestamp, index))
    chronological_order = {index: rank for rank, index in enumerate(chronological)}
    rows = []
    for index, event in enumerate(events):
        timestamp = event.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ReviewPacketError("PARSER_EXECUTION_FAILED")
        source_group = None
        if type(event.src_ip) is str and event.src_ip:
            source_group = source_groups[event.src_ip]
        account_group = None
        if type(event.user) is str and event.user:
            account_group = account_groups[event.user]
        outcome = "unknown"
        if event.authentication is not None and event.authentication.outcome in ("failure", "success"):
            outcome = event.authentication.outcome
        event_type = event.event_type if event.event_type in ("login_failed", "login_success") else "other"
        relative = None if anchor is None else (timestamp - anchor).total_seconds()
        if relative is not None and not math.isfinite(relative):
            raise ReviewPacketError("PARSER_EXECUTION_FAILED")
        rows.append({
            "input_order": index,
            "chronological_order": chronological_order[index],
            "relative_seconds": relative,
            "event_type": event_type,
            "authentication_outcome": outcome,
            "source_group": source_group,
            "account_group": account_group,
        })
    if state not in ("VERIFIED", "PARTIAL", "REJECTED"):
        raise ReviewPacketError("PARSER_EXECUTION_FAILED")
    if state == "VERIFIED":
        limitation = "Fixture 행이 현재 지원 Parser profile로 정규화되었습니다. 실세계 수집 완전성이나 진실성을 뜻하지 않습니다."
    elif state == "PARTIAL":
        limitation = "일부 입력 또는 필드만 정규화되었습니다. 전체 입력에 대한 확정적 판정을 요구하지 않습니다."
    else:
        limitation = "현재 Parser가 입력을 정규화하지 못했습니다. 원문을 이벤트로 추정하지 않습니다."
    unmapped = max(line_count - len(events), 0)
    return {
        "parser_disposition": state,
        "input_line_count": line_count,
        "normalized_event_count": len(events),
        "unmapped_input_line_count": unmapped,
        "input_order_basis": "one_normalized_event_per_input_line" if unmapped == 0 and line_count == len(events) else "parser_output_order_only",
        "interpretation_limit": limitation,
        "events": rows,
    }


def _derived_observations(baseline: dict[str, Any], variant: dict[str, Any]) -> list[str]:
    left, right = baseline["events"], variant["events"]
    observed = []
    if baseline["parser_disposition"] != variant["parser_disposition"]:
        observed.append("parser_disposition_changed")
    if len(left) != len(right):
        observed.append("normalized_event_count_changed")
    left_times = sorted(item["relative_seconds"] for item in left)
    right_times = sorted(item["relative_seconds"] for item in right)
    if left_times != right_times:
        observed.append("relative_timestamp_set_changed")
    if [item["source_group"] for item in left] != [item["source_group"] for item in right]:
        observed.append("source_group_sequence_changed")
    if [item["account_group"] for item in left] != [item["account_group"] for item in right]:
        observed.append("account_group_sequence_changed")
    left_accounts = {item["account_group"] for item in left if item["account_group"] is not None}
    right_accounts = {item["account_group"] for item in right if item["account_group"] is not None}
    if len(left_accounts) != len(right_accounts):
        observed.append("target_account_cardinality_changed")
    if [item["event_type"] for item in left] != [item["event_type"] for item in right]:
        observed.append("event_type_sequence_changed")
    left_semantics = [(item["relative_seconds"], item["event_type"], item["authentication_outcome"], item["source_group"], item["account_group"]) for item in left]
    right_semantics = [(item["relative_seconds"], item["event_type"], item["authentication_outcome"], item["source_group"], item["account_group"]) for item in right]
    if left_semantics != right_semantics:
        observed.append("normalized_event_order_or_content_changed")
    return observed


def _render_scenario(scenario: BlindScenarioInput) -> dict[str, Any]:
    baseline_state, baseline_events, baseline_lines = _parse_input(scenario.source, scenario.baseline_bytes)
    variant_state, variant_events, variant_lines = _parse_input(scenario.source, scenario.variant_bytes)
    if baseline_state == "VERIFIED" and not baseline_events:
        raise ReviewPacketError("INVALID_CORPUS")
    anchor = min((event.timestamp for event in baseline_events), default=None)
    source_groups: dict[str, str] = {}
    account_groups: dict[str, str] = {}
    for event in (*baseline_events, *variant_events):
        if type(event.src_ip) is str and event.src_ip and event.src_ip not in source_groups:
            source_groups[event.src_ip] = f"Source Group {_alpha_label(len(source_groups))}"
        if type(event.user) is str and event.user and event.user not in account_groups:
            account_groups[event.user] = f"Account Group {len(account_groups) + 1}"
    baseline = _review_side(scenario.source, scenario.baseline_bytes, baseline_events, baseline_state, baseline_lines, anchor, source_groups, account_groups)
    variant = _review_side(scenario.source, scenario.variant_bytes, variant_events, variant_state, variant_lines, anchor, source_groups, account_groups)
    return {
        "corpus_id": scenario.corpus_id,
        "scenario_id": scenario.scenario_id,
        "detector_id": scenario.detector_id,
        "source_profile": _SOURCE_PROFILE[scenario.source],
        "mutation_type": scenario.mutation_type,
        "baseline_fixture_id": scenario.baseline_fixture_id,
        "input_sha256": {"baseline": scenario.baseline_sha256, "variant": scenario.variant_sha256},
        "policy_summary": _POLICY_TEXT[scenario.detector_id],
        "baseline": baseline,
        "variant": variant,
        "direct_change": {"kind": scenario.mutation_type},
        "derived_observations": _derived_observations(baseline, variant),
    }


def _packet_body(source_corpora: tuple[BlindCorpusInput, ...], scenarios: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    corpora = {}
    for item in source_corpora:
        corpora[item.corpus_id] = {
            "manifest_sha256": item.manifest_sha256,
            "fixture_sha256": _plain(item.fixture_sha256),
        }
    return {
        "schema_version": _PACKET_SCHEMA_VERSION,
        "packet_type": "label_blind_counterfactual_review",
        "data_scope": "synthetic-only",
        "review_status": "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "blindness_limit": "Public repository labels exist; the procedure cannot prove a reviewer did not view them.",
        "digest_scope": "canonical payload excluding packet_sha256",
        "source_corpora": corpora,
        "scenarios": list(scenarios),
    }


def build_review_packet() -> ReviewPacket:
    corpora = _load_source_corpora()
    scenarios = tuple(
        _render_scenario(item)
        for corpus in corpora
        for item in sorted(corpus.scenarios, key=lambda value: value.scenario_id)
    )
    if len(scenarios) != 30:
        raise ReviewPacketError("INVALID_CORPUS")
    body = _packet_body(corpora, scenarios)
    digest_bytes = _canonical(body, limit=MAX_PACKET_BYTES, error_type=ReviewPacketError, limit_code="PACKET_LIMIT_EXCEEDED")
    return ReviewPacket(
        packet_sha256=hashlib.sha256(digest_bytes).hexdigest(),
        source_corpora=_freeze(body["source_corpora"]),
        scenarios=tuple(_freeze(item) for item in scenarios),
    )


def canonical_review_packet_json(packet: ReviewPacket) -> bytes:
    if type(packet) is not ReviewPacket or len(packet.scenarios) != 30:
        raise ReviewPacketError("INVALID_PACKET")
    encoded = _canonical(packet.to_mapping(), limit=MAX_PACKET_BYTES, error_type=ReviewPacketError, limit_code="PACKET_LIMIT_EXCEEDED")
    body = packet.to_mapping()
    claimed = body.pop("packet_sha256")
    digest_bytes = _canonical(body, limit=MAX_PACKET_BYTES, error_type=ReviewPacketError, limit_code="PACKET_LIMIT_EXCEEDED")
    if hashlib.sha256(digest_bytes).hexdigest() != claimed:
        raise ReviewPacketError("INVALID_PACKET")
    return encoded


def _scenario_labels() -> dict[tuple[str, str], tuple[str, str]]:
    labels = {}
    for scenario in development.load_corpus():
        labels[("er1a_development", scenario.scenario_id)] = (
            scenario.baseline_expected_behavioral_pattern,
            scenario.expected_behavioral_pattern,
        )
    for scenario in holdout.load_holdout().scenarios:
        labels[(holdout.CORPUS_ID, scenario.scenario_id)] = (
            scenario.baseline_expected_behavioral_pattern,
            scenario.expected_behavioral_pattern,
        )
    return labels


def decode_review_submission(raw: bytes, packet: ReviewPacket) -> dict[str, Any]:
    if type(packet) is not ReviewPacket:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    try:
        canonical_review_packet_json(packet)
    except ReviewPacketError:
        raise ReviewSubmissionError("INVALID_SUBMISSION") from None
    value = _strict_json(raw)
    if set(value) != {"schema_version", "packet_sha256", "reviewer", "responses"}:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    if type(value.get("schema_version")) is not int or value["schema_version"] != _SUBMISSION_SCHEMA_VERSION:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    if value.get("packet_sha256") != packet.packet_sha256:
        raise ReviewSubmissionError("PACKET_DIGEST_MISMATCH")
    reviewer = value.get("reviewer")
    if type(reviewer) is not dict or set(reviewer) != {
        "reviewer_ref", "independence_claim", "has_viewed_existing_labels_or_replay",
    }:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    if (
        type(reviewer.get("reviewer_ref")) is not str
        or _REVIEWER_REF.fullmatch(reviewer["reviewer_ref"]) is None
        or type(reviewer.get("independence_claim")) is not str
        or reviewer["independence_claim"] not in _INDEPENDENCE_CLAIMS
        or type(reviewer.get("has_viewed_existing_labels_or_replay")) is not bool
    ):
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    responses = value.get("responses")
    if type(responses) is not list or len(responses) > 30:
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    packet_ids = {item["scenario_id"] for item in packet.scenarios}
    response_by_id = {}
    required = {"scenario_id", "review_status", "baseline_label", "variant_label", "parser_scope", "review_opinion"}
    for response in responses:
        if type(response) is not dict or set(response) != required:
            raise ReviewSubmissionError("INVALID_SUBMISSION")
        scenario_id = response.get("scenario_id")
        status = response.get("review_status")
        baseline_label = response.get("baseline_label")
        variant_label = response.get("variant_label")
        scope = response.get("parser_scope")
        opinion = response.get("review_opinion")
        try:
            opinion_size = len(opinion.encode("utf-8", errors="strict")) if type(opinion) is str else MAX_SUBMISSION_BYTES + 1
        except UnicodeError:
            opinion_size = MAX_SUBMISSION_BYTES + 1
        if (
            type(scenario_id) is not str or scenario_id not in packet_ids or scenario_id in response_by_id
            or type(status) is not str or status not in _REVIEW_STATES
            or type(scope) is not str or scope not in _PARSER_SCOPE
            or (baseline_label is not None and (type(baseline_label) is not str or baseline_label not in _PATTERN_LABELS))
            or (variant_label is not None and (type(variant_label) is not str or variant_label not in _PATTERN_LABELS))
            or type(opinion) is not str or opinion_size > 2000
            or any(ord(char) < 32 and char not in "\t\n" for char in opinion)
        ):
            raise ReviewSubmissionError("INVALID_SUBMISSION")
        if status in ("REVIEWED", "DISAGREEMENT"):
            if baseline_label not in _PATTERN_LABELS or variant_label not in _PATTERN_LABELS:
                raise ReviewSubmissionError("INVALID_SUBMISSION")
        elif baseline_label is not None or variant_label is not None:
            raise ReviewSubmissionError("INVALID_SUBMISSION")
        response_by_id[scenario_id] = {
            "review_status": status,
            "baseline_label": baseline_label,
            "variant_label": variant_label,
            "parser_scope": scope,
        }
    return {
        "reviewer": {
            "independence_claim": reviewer["independence_claim"],
            "has_viewed_existing_labels_or_replay": reviewer["has_viewed_existing_labels_or_replay"],
        },
        "responses": response_by_id,
    }


def compare_review_submission(raw: bytes) -> ReviewAdjudication:
    packet = build_review_packet()
    submission = decode_review_submission(raw, packet)
    responses = submission["responses"]
    # Expected labels are consulted only after an actual, packet-bound submission exists.
    expected = _scenario_labels() if any(
        row["review_status"] in ("REVIEWED", "DISAGREEMENT") for row in responses.values()
    ) else {}
    packet_scenarios = packet.to_mapping()["scenarios"]
    counts = {key: 0 for key in _OUTCOME_CATEGORIES}
    rows = []
    for scenario in packet_scenarios:
        key = (scenario["corpus_id"], scenario["scenario_id"])
        response = responses.get(scenario["scenario_id"])
        if response is None or response["review_status"] == "NOT_REVIEWED":
            category = "NOT_REVIEWED"
        elif response["review_status"] == "NEEDS_CLARIFICATION":
            category = "NEEDS_CLARIFICATION"
        elif response["review_status"] == "INSUFFICIENT_EVIDENCE":
            category = "INSUFFICIENT_EVIDENCE"
        else:
            expected_pair = expected.get(key)
            if expected_pair is None:
                raise ReviewSubmissionError("INVALID_SUBMISSION")
            parser_verified = (
                scenario["baseline"]["parser_disposition"] == "VERIFIED"
                and scenario["variant"]["parser_disposition"] == "VERIFIED"
            )
            if response["parser_scope"] != "SUFFICIENT" or not parser_verified:
                category = "INSUFFICIENT_EVIDENCE"
            else:
                category = "MATCH" if (response["baseline_label"], response["variant_label"]) == expected_pair else "DISAGREEMENT"
        counts[category] += 1
        rows.append({
            "corpus_id": scenario["corpus_id"],
            "scenario_id": scenario["scenario_id"],
            "comparison": category,
            "parser_scope": "UNDETERMINED" if response is None else response["parser_scope"],
        })
    reviewer = submission["reviewer"]
    return ReviewAdjudication(
        packet_sha256=packet.packet_sha256,
        scenario_count=30,
        response_count=len(responses),
        review_status="INDEPENDENT_HUMAN_REVIEW_PENDING",
        independence_claim=reviewer["independence_claim"],
        has_viewed_existing_labels_or_replay=submission["reviewer"]["has_viewed_existing_labels_or_replay"],
        independence_verification="SELF_REPORTED_NOT_VERIFIED",
        approval_status="MANUAL_APPROVAL_REQUIRED",
        counts=MappingProxyType(counts),
        scenarios=tuple(MappingProxyType(item) for item in rows),
    )


def canonical_review_adjudication_json(report: ReviewAdjudication) -> bytes:
    if type(report) is not ReviewAdjudication or report.review_status != "INDEPENDENT_HUMAN_REVIEW_PENDING":
        raise ReviewSubmissionError("INVALID_SUBMISSION")
    return _canonical(report.to_mapping(), limit=MAX_SUBMISSION_BYTES, error_type=ReviewSubmissionError, limit_code="PACKET_LIMIT_EXCEEDED")
