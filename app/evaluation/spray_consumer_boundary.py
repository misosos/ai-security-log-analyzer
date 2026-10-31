"""Evaluation-only validation of Password Spray consumer boundaries.

Nothing in this module is imported by the production analysis pipeline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any

from app.main import analyze
from app.models.schemas import NormalizedEvent


CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "spray_consumer_boundary_evaluation"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
_ROOT_KEYS = {"schema_version", "data_scope", "scenarios"}
_ROW_KEYS = {
    "id", "fixture", "source", "secondary_fixture", "secondary_source",
    "behavioral_pattern", "operational_context", "parser_status",
    "correlation_eligibility", "underlying_attempt_count", "oracle_duplicate_delivery",
    "label_basis", "context_basis",
}
_LABELS = {
    "behavioral_pattern": {"PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"},
    "operational_context": {"KNOWN_BENIGN", "SIMULATED_ATTACK", "CONTEXT_UNKNOWN", "NOT_LABELED"},
    "parser_status": {"VERIFIED", "PARTIAL", "REJECTED", "IGNORED"},
    "correlation_eligibility": {"PAIR_ELIGIBLE", "PAIR_NOT_ELIGIBLE", "PAIR_AMBIGUOUS", "NOT_APPLICABLE"},
}
_ID = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
_USER = re.compile(r"spray_[a-z0-9_]{1,24}\Z", re.ASCII)
_DOC_IPS = {"192.0.2.44", "192.0.2.45", "198.51.100.44", "203.0.113.44"}
_BASE = datetime(2026, 10, 31, tzinfo=timezone.utc)


class BoundaryValidationError(ValueError):
    """Stable safe error for invalid evaluation-only inputs."""

    def __init__(self, code: str = "invalid_context"):
        self.code = code
        super().__init__(code)


class EvaluationRun:
    """Opaque identity token; not a production provenance primitive."""

    def __init__(self) -> None:
        self._issued: dict[int, object] = {}

    def _bind(self, context: SprayWindowContext) -> None:
        self._issued[id(context)] = context

    def _owns(self, context: object) -> bool:
        return id(context) in self._issued


@dataclass(frozen=True)
class SprayWindowContext:
    owner: EvaluationRun = field(repr=False, compare=False)
    subject_ip: str
    start_utc: datetime
    end_utc: datetime
    failure_count: int
    known_target_count: int
    missing_user_count: int
    policy_id: str
    member_events: tuple[NormalizedEvent, ...] = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "SprayWindowContext(<evaluation-only>)"


@dataclass(frozen=True)
class PairResult:
    correlated: bool
    reason: str
    failure_event: NormalizedEvent | None = field(default=None, repr=False, compare=False)
    success_event: NormalizedEvent | None = field(default=None, repr=False, compare=False)


def _strict_json(path: Path) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
            raise BoundaryValidationError("invalid_manifest")
        raw = path.read_bytes().decode("utf-8", errors="strict")
        doc = json.loads(raw, object_pairs_hook=pairs,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))
    except BoundaryValidationError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise BoundaryValidationError("invalid_manifest") from None
    if type(doc) is not dict or set(doc) != _ROOT_KEYS or type(doc["schema_version"]) is not int or doc["schema_version"] != 1 or doc["data_scope"] != "synthetic-only" or type(doc["scenarios"]) is not list:
        raise BoundaryValidationError("invalid_manifest")
    return doc


def load_scenarios(manifest_path: Path = MANIFEST_PATH) -> tuple[dict[str, Any], ...]:
    root = manifest_path.parent.resolve()
    doc = _strict_json(manifest_path)
    rows = doc["scenarios"]
    if not 1 <= len(rows) <= 128:
        raise BoundaryValidationError("scenario_limit")
    ids: set[str] = set()
    fixtures: set[str] = set()
    total_lines = 0
    for row in rows:
        if type(row) is not dict or set(row) != _ROW_KEYS:
            raise BoundaryValidationError("invalid_manifest")
        if type(row["source"]) is not str or row["source"] not in {"application", "ssh"}:
            raise BoundaryValidationError("invalid_manifest")
        if type(row["id"]) is not str or not _ID.fullmatch(row["id"]) or row["id"] in ids:
            raise BoundaryValidationError("invalid_manifest")
        if any(type(row[key]) is not str or row[key] not in _LABELS[key] for key in _LABELS):
            raise BoundaryValidationError("invalid_manifest")
        if (type(row["underlying_attempt_count"]) is not int or not 0 <= row["underlying_attempt_count"] <= 512
                or type(row["oracle_duplicate_delivery"]) is not bool
                or type(row["label_basis"]) is not str or not row["label_basis"]
                or type(row["context_basis"]) is not str or not row["context_basis"]):
            raise BoundaryValidationError("invalid_manifest")
        name = row["fixture"]
        if type(name) is not str or Path(name).name != name or not name.endswith(".log") or name in fixtures:
            raise BoundaryValidationError("invalid_manifest")
        path = root / name
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
                raise BoundaryValidationError("fixture_boundary")
            path.resolve(strict=True).relative_to(root)
            text = path.read_bytes().decode("utf-8", errors="strict")
        except BoundaryValidationError:
            raise
        except (OSError, UnicodeError, ValueError):
            raise BoundaryValidationError("fixture_boundary") from None
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines or len(lines) > 128:
            raise BoundaryValidationError("fixture_limit")
        total_lines += len(lines)
        if total_lines > 4096:
            raise BoundaryValidationError("fixture_limit")
        if row["parser_status"] not in {"VERIFIED", "PARTIAL"}:
            raise BoundaryValidationError("parser_contract_unsupported")
        if any(ip not in text for ip in _DOC_IPS) and row["behavioral_pattern"] != "PATTERN_UNDETERMINED":
            # Actual parsed source addresses are checked again by the parser observation below.
            pass
        ids.add(row["id"])
        fixtures.add(name)
        secondary_name = row["secondary_fixture"]
        secondary_source = row["secondary_source"]
        if (secondary_name is None) != (secondary_source is None):
            raise BoundaryValidationError("invalid_manifest")
        if secondary_name is not None:
            if (type(secondary_name) is not str or Path(secondary_name).name != secondary_name
                    or not secondary_name.endswith(".log") or secondary_name in fixtures
                    or type(secondary_source) is not str or secondary_source not in {"application", "ssh"}):
                raise BoundaryValidationError("invalid_manifest")
            secondary_path = root / secondary_name
            try:
                if secondary_path.is_symlink() or not secondary_path.is_file() or secondary_path.stat().st_size > 8192:
                    raise BoundaryValidationError("fixture_boundary")
                secondary_path.resolve(strict=True).relative_to(root)
                secondary_lines = [line for line in secondary_path.read_bytes().decode("utf-8", errors="strict").splitlines() if line.strip()]
            except BoundaryValidationError:
                raise
            except (OSError, UnicodeError, ValueError):
                raise BoundaryValidationError("fixture_boundary") from None
            if not secondary_lines or len(secondary_lines) > 128:
                raise BoundaryValidationError("fixture_limit")
            total_lines += len(secondary_lines)
            if total_lines > 4096:
                raise BoundaryValidationError("fixture_limit")
            fixtures.add(secondary_name)
    actual = {p.name for p in root.glob("*.log") if p.is_file() and not p.is_symlink()}
    if actual != fixtures:
        raise BoundaryValidationError("fixture_set_mismatch")
    return tuple(sorted(rows, key=lambda item: item["id"]))


def validate_spray_window(context: object, events: list[NormalizedEvent], owner: EvaluationRun) -> None:
    if (type(context) is not SprayWindowContext or type(owner) is not EvaluationRun
            or context.owner is not owner or not owner._owns(context)):
        raise BoundaryValidationError("run_or_context_mismatch")
    members = context.member_events
    if not members or len({id(event) for event in members}) != len(members):
        raise BoundaryValidationError("membership_invalid")
    available = {id(event) for event in events if type(event) is NormalizedEvent}
    if any(id(event) not in available for event in members):
        raise BoundaryValidationError("run_membership_mismatch")
    if any(type(event) is not NormalizedEvent or event.event_type != "login_failed" or event.src_ip != context.subject_ip for event in members):
        raise BoundaryValidationError("member_scope_mismatch")
    times = [event.timestamp for event in members]
    if any(t.tzinfo is None or t.utcoffset() is None or t.utcoffset() != timedelta(0) for t in times):
        raise BoundaryValidationError("timestamp_invalid")
    if context.start_utc != min(times) or context.end_utc != max(times):
        raise BoundaryValidationError("timestamp_membership_mismatch")
    users = {event.user for event in members if isinstance(event.user, str) and event.user}
    missing = sum(not (isinstance(event.user, str) and event.user) for event in members)
    if context.failure_count != len(members) or context.known_target_count != len(users) or context.missing_user_count != missing:
        raise BoundaryValidationError("count_mismatch")
    if context.policy_id not in {"sliding_ip_window", "known_account_window"}:
        raise BoundaryValidationError("policy_mismatch")
    if not isinstance(context.subject_ip, str) or context.subject_ip not in _DOC_IPS:
        raise BoundaryValidationError("subject_invalid")


def build_selected_window(events: list[NormalizedEvent], subject_ip: str, owner: EvaluationRun) -> SprayWindowContext:
    if type(owner) is not EvaluationRun or subject_ip not in _DOC_IPS:
        raise BoundaryValidationError("invalid_context")
    failures = [e for e in events if type(e) is NormalizedEvent and e.event_type == "login_failed" and e.src_ip == subject_ip]
    failures.sort(key=lambda e: (e.timestamp.astimezone(timezone.utc), e.source, e.user or "", e.raw))
    selected: tuple[NormalizedEvent, ...] | None = None
    left = 0
    for right, event in enumerate(failures):
        while left <= right and (event.timestamp - failures[left].timestamp).total_seconds() > 60:
            left += 1
        window = failures[left:right + 1]
        if len(window) >= 4 and len({e.user for e in window if e.user}) >= 3:
            while len(window) > 4 and len({e.user for e in window[1:] if e.user}) >= 3:
                window = window[1:]
            selected = tuple(window)
            break
    if selected is None:
        selected = tuple(failures)
    if not selected:
        raise BoundaryValidationError("empty_window")
    context = SprayWindowContext(
        owner, subject_ip, min(e.timestamp for e in selected), max(e.timestamp for e in selected),
        len(selected), len({e.user for e in selected if e.user}),
        sum(not e.user for e in selected), "sliding_ip_window", selected,
    )
    owner._bind(context)
    validate_spray_window(context, events, owner)
    return context


def _pair_candidates(context: SprayWindowContext, events: list[NormalizedEvent], owner: EvaluationRun,
                     *, conservative: bool) -> PairResult:
    try:
        validate_spray_window(context, events, owner)
    except BoundaryValidationError:
        return PairResult(False, "context_validation_failure")
    members = context.member_events
    if conservative and any(not event.user for event in members):
        return PairResult(False, "missing_account")
    successes = [e for e in events if type(e) is NormalizedEvent and e.event_type == "user_login"
                 and e.src_ip == context.subject_ip and e.user]
    candidates = []
    for success in successes:
        if conservative and success.timestamp <= context.end_utc:
            continue
        for failure in members:
            if failure.user != success.user or failure.timestamp >= success.timestamp:
                continue
            delta = (success.timestamp - failure.timestamp).total_seconds()
            if delta <= 60:
                candidates.append((delta, failure, success))
    if not candidates:
        if any(e.event_type == "user_login" and e.src_ip != context.subject_ip for e in events):
            return PairResult(False, "cross_ip_mismatch")
        if any(e.event_type == "user_login" and e.src_ip == context.subject_ip and e.user and e.user not in {m.user for m in members} for e in events):
            return PairResult(False, "cross_account_mismatch")
        return PairResult(False, "no_member_pair")
    min_delta = min(row[0] for row in candidates)
    best = [(f, s) for d, f, s in candidates if d == min_delta]
    # Exact duplicate-looking member facts remain ambiguous; identity is preserved.
    if len(best) != 1:
        return PairResult(False, "ambiguous_pair")
    failure, success = best[0]
    return PairResult(True, "member_pair", failure, success)


def correlate_member_bound(context: SprayWindowContext, events: list[NormalizedEvent], owner: EvaluationRun) -> PairResult:
    return _pair_candidates(context, events, owner, conservative=False)


def correlate_conservative(context: SprayWindowContext, events: list[NormalizedEvent], owner: EvaluationRun) -> PairResult:
    return _pair_candidates(context, events, owner, conservative=True)


def _parse_fixture(path: Path, source: str) -> tuple[list[NormalizedEvent], int, int, int, int]:
    from app.parser.registry import get_parser, get_timezone
    from app.parser.time_utils import normalize_to_utc
    parser = get_parser(source)
    events = []
    parsed = ignored = rejected = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            item = parser(raw.strip(), get_timezone(source))
            if item is None:
                ignored += 1
            else:
                item.timestamp = normalize_to_utc(item.timestamp)
                if item.src_ip is not None and item.src_ip not in _DOC_IPS:
                    raise BoundaryValidationError("non_synthetic_ip")
                if item.user and not _USER.fullmatch(item.user):
                    raise BoundaryValidationError("non_synthetic_user")
                events.append(item)
                parsed += 1
        except BoundaryValidationError:
            raise
        except (ValueError, TypeError, KeyError, IndexError, OverflowError):
            rejected += 1
    return events, parsed + ignored + rejected, parsed, ignored, rejected


def _correlate_c0(events: list[NormalizedEvent], detected: bool) -> dict[str, Any]:
    from app.correlation.attack_chain import correlate_password_spray_to_success
    from app.models.schemas import DetectionResult
    result = correlate_password_spray_to_success(events, DetectionResult(detected, "password_spraying_like" if detected else None, []))
    origin = min((event.timestamp for event in events if event.event_type == "login_failed"), default=_BASE)
    return {"correlated": bool(result.get("is_correlated")),
            "failure_offset_seconds": None if not result.get("is_correlated") else int((result["failure_timestamp"] - origin).total_seconds()),
            "success_offset_seconds": None if not result.get("is_correlated") else int((result["success_timestamp"] - origin).total_seconds())}


def evaluate(manifest_path: Path = MANIFEST_PATH) -> dict[str, Any]:
    rows = load_scenarios(manifest_path)
    root = manifest_path.parent
    results = []
    pattern_counts = Counter(row["behavioral_pattern"] for row in rows)
    context_counts = Counter(row["operational_context"] for row in rows)
    parser_counts = Counter()
    eligibility_counts = Counter(row["correlation_eligibility"] for row in rows)
    for row in rows:
        events, lines, parsed, ignored, rejected = _parse_fixture(root / row["fixture"], row["source"])
        inputs = [{"source": row["source"], "path": str(root / row["fixture"])}]
        if row["secondary_fixture"] is not None:
            extra = _parse_fixture(root / row["secondary_fixture"], row["secondary_source"])
            events.extend(extra[0])
            lines += extra[1]
            parsed += extra[2]
            ignored += extra[3]
            rejected += extra[4]
            inputs.append({"source": row["secondary_source"], "path": str(root / row["secondary_fixture"] )})
        status = "PARTIAL" if rejected or ignored or any(not e.user for e in events if e.event_type == "login_failed") else "VERIFIED"
        if status != row["parser_status"]:
            raise BoundaryValidationError("parser_observation_mismatch")
        parser_counts[status] += 1
        by_ip = {ip: [e for e in events if e.src_ip == ip] for ip in sorted({e.src_ip for e in events if e.src_ip})}
        production = False
        prod_features = {}
        # Actual production pipeline is the authority for the current result.
        analysis = analyze(inputs)
        for ip in by_ip:
            entry = analysis.get("results", {}).get(ip)
            if entry:
                detection = entry["detections"]["password_spray"]
                production = production or detection.is_detected
                features = entry["features"]
                prod_features[ip] = {"failure_count": features.get("failure_count"),
                                     "target_count": features.get("unique_target_count"),
                                     "whole_span_seconds": features.get("window_seconds"),
                                     "within_window": features.get("within_window")}
        prod_corr = {"correlated": False, "failure_offset_seconds": None, "success_offset_seconds": None}
        gate_open_corr = {"correlated": False, "failure_offset_seconds": None, "success_offset_seconds": None}
        for ip, ip_events in by_ip.items():
            entry = analysis.get("results", {}).get(ip)
            if entry:
                current = entry["correlation"]["password_spray_to_success"]
                if current.get("is_correlated") and not prod_corr["correlated"]:
                    origin = min((e.timestamp for e in ip_events if e.event_type == "login_failed"), default=_BASE)
                    prod_corr = {"correlated": True,
                                 "failure_offset_seconds": int((current["failure_timestamp"] - origin).total_seconds()),
                                 "success_offset_seconds": int((current["success_timestamp"] - origin).total_seconds())}
            candidate = _correlate_c0(ip_events, True)
            if candidate["correlated"] and not gate_open_corr["correlated"]:
                gate_open_corr = candidate
        context = None
        owner = EvaluationRun()
        candidates = []
        for ip in sorted(by_ip):
            failures = [e for e in by_ip[ip] if e.event_type == "login_failed"]
            if len(failures) >= 4:
                try:
                    context = build_selected_window(events, ip, owner)
                    candidates.append((context, correlate_member_bound(context, events, owner), correlate_conservative(context, events, owner)))
                except BoundaryValidationError:
                    continue
        selected = candidates[0] if candidates else None
        event_origin = min((e.timestamp for e in events if e.event_type == "login_failed"), default=_BASE)
        def pair_json(pair):
            return {"correlated": pair.correlated, "reason": pair.reason,
                    "failure_offset_seconds": None if pair.failure_event is None else int((pair.failure_event.timestamp - event_origin).total_seconds()),
                    "success_offset_seconds": None if pair.success_event is None else int((pair.success_event.timestamp - event_origin).total_seconds())}
        benign = row["operational_context"] == "KNOWN_BENIGN" and production
        gate_open_outside = False
        if selected and gate_open_corr["correlated"]:
            gate_time = event_origin + timedelta(seconds=gate_open_corr["failure_offset_seconds"])
            gate_open_outside = all(gate_time != member.timestamp for member in selected[0].member_events)
        prefix_sequence = None
        if row["id"] == "late_noise_changes_full_input_result":
            from app.detector.password_spray import detect_password_spray
            failures = [e for e in events if e.event_type == "login_failed"]
            prefix_sequence = []
            for count in (1, 4, 5):
                sample = failures[:count]
                span = 0 if not sample else (max(e.timestamp for e in sample) - min(e.timestamp for e in sample)).total_seconds()
                features = {"failure_count": len(sample), "unique_target_count": len({e.user for e in sample if e.user}),
                            "within_window": span <= 60, "window_seconds": span}
                prefix_sequence.append(detect_password_spray(features, sample).is_detected)
        results.append({
            "scenario_id": row["id"], "behavioral_pattern": row["behavioral_pattern"],
            "operational_context": row["operational_context"], "parser_status": status,
            "correlation_eligibility": row["correlation_eligibility"],
            "input_lines": lines, "parsed": parsed, "ignored": ignored, "rejected": rejected,
            "prefix_detection_sequence": prefix_sequence,
            "observed_event_rows": len(events), "observed_failure_rows": sum(e.event_type == "login_failed" for e in events),
            "underlying_attempt_count": row["underlying_attempt_count"],
            "oracle_duplicate_delivery": row["oracle_duplicate_delivery"],
            "oracle_dedup_counterfactual": row["underlying_attempt_count"] >= 4 and len({e.user for e in events if e.event_type == "login_failed" and e.user}) >= 3,
            "production_detection": production, "production_features": prod_features,
            "production_correlation": prod_corr["correlated"], "production_pair": prod_corr,
            "production_gate_open_correlation": gate_open_corr,
            "gate_open_endpoint_outside_window": gate_open_outside,
            "member_bound_correlation": pair_json(selected[1]) if selected else {"correlated": False, "reason": "no_selected_window"},
            "conservative_correlation": pair_json(selected[2]) if selected else {"correlated": False, "reason": "no_selected_window"},
            "window_member_count": 0 if selected is None else selected[0].failure_count,
            "window_membership_valid": selected is not None,
            "operational_false_alert_candidate": benign,
            "case_adapter_boundary": "current_whole_span_contract_only",
            "report_projection_window_membership": "not_expressible_in_current_scalar_projection",
        })
    scored = [r for r in results if r["behavioral_pattern"] != "PATTERN_UNDETERMINED" and r["parser_status"] != "REJECTED"]
    tp = sum(r["behavioral_pattern"] == "PATTERN_PRESENT" and r["production_detection"] for r in scored)
    fp = sum(r["behavioral_pattern"] == "PATTERN_ABSENT" and r["production_detection"] for r in scored)
    fn = sum(r["behavioral_pattern"] == "PATTERN_PRESENT" and not r["production_detection"] for r in scored)
    tn = sum(r["behavioral_pattern"] == "PATTERN_ABSENT" and not r["production_detection"] for r in scored)
    return {
        "schema_version": "1", "evaluation": "spray_consumer_boundary_independent_validation",
        "data_scope": "synthetic-only", "scenario_count": len(rows),
        "label_counts": {"behavioral_pattern": dict(sorted(pattern_counts.items())),
                          "operational_context": dict(sorted(context_counts.items())),
                          "parser_status": dict(sorted(parser_counts.items())),
                          "correlation_eligibility": dict(sorted(eligibility_counts.items()))},
        "parser_summary": {"input_lines": sum(x["input_lines"] for x in results), "parsed": sum(x["parsed"] for x in results),
                           "ignored": sum(x["ignored"] for x in results), "rejected": sum(x["rejected"] for x in results)},
        "correlation_summary": {"production_correlated": sum(x["production_correlation"] for x in results),
                                "member_bound_correlated": sum(x["member_bound_correlation"]["correlated"] for x in results),
                                "conservative_correlated": sum(x["conservative_correlation"]["correlated"] for x in results),
                                "operational_false_alert_candidates": sum(x["operational_false_alert_candidate"] for x in results),
                                "pair_eligible_scenarios": eligibility_counts["PAIR_ELIGIBLE"],
                                "pair_not_eligible_scenarios": eligibility_counts["PAIR_NOT_ELIGIBLE"],
                                "pair_ambiguous_scenarios": eligibility_counts["PAIR_AMBIGUOUS"],
                                "no_relation_scenarios_c2": sum(not x["conservative_correlation"]["correlated"] for x in results),
                                "gate_open_out_of_window_endpoint_scenarios": sum(x["gate_open_endpoint_outside_window"] for x in results),
                                "member_bound_tie_rejections": sum(x["member_bound_correlation"]["reason"] == "ambiguous_pair" for x in results),
                                "conservative_tie_rejections": sum(x["conservative_correlation"]["reason"] == "ambiguous_pair" for x in results),
                                "conservative_missing_account_rejections": sum(x["conservative_correlation"]["reason"] == "missing_account" for x in results),
                                "context_validation_failures_in_corpus": sum(x["member_bound_correlation"]["reason"] == "context_validation_failure" for x in results)},
        "pattern_metrics_current_production": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                                "excluded_undetermined": sum(r["behavioral_pattern"] == "PATTERN_UNDETERMINED" for r in results),
                                                "excluded_parser": sum(r["parser_status"] == "REJECTED" for r in results),
                                                "note": "고정 합성 corpus 기술 통계이며 운영 precision/recall 추정치가 아닙니다."},
        "live_runtime_integrated": False, "static_live_claim": "same-prefix-simulation-only",
        "production_mutation": "none", "policy_recommendation": "MORE_EVIDENCE_REQUIRED",
        "scenario_results": results,
        "limitations": ["합성 시나리오이며 실환경 정확도 또는 경보율을 추정하지 않습니다.",
                        "Oracle attempt/delivery 라벨은 평가 Manifest에만 있으며 Runtime 정책 입력이 아닙니다.",
                        "EvaluationRun은 테스트용 객체이며 Production provenance 보장이 아닙니다.",
                        "prefix simulation은 Collector, checkpoint, rotation을 실행하지 않습니다."],
    }


def render_text(summary: dict[str, Any]) -> str:
    lines = [f"spray_consumer_boundary: scenarios={summary['scenario_count']} scope=synthetic-only",
             f"labels: {json.dumps(summary['label_counts'], sort_keys=True, ensure_ascii=False)}",
             f"parser: {json.dumps(summary['parser_summary'], sort_keys=True)}",
             f"correlation: {json.dumps(summary['correlation_summary'], sort_keys=True)}",
             "production_mutation: none", "policy_recommendation: MORE_EVIDENCE_REQUIRED"]
    for row in summary["scenario_results"]:
        lines.append(f"{row['scenario_id']}: detection={row['production_detection']} current_pair={row['production_correlation']} member={row['member_bound_correlation']['correlated']} conservative={row['conservative_correlation']['correlated']}")
    return "\n".join(lines)
