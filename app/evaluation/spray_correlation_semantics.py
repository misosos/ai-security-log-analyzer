"""Bounded synthetic evaluation of Spray correlation semantics (not production policy)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

from app.analyzer.pipeline import detect_attacks
from app.correlation.attack_chain import (
    correlate_authentication_transition,
    correlate_password_spray_to_success,
)
from app.evaluation.spray_trusted_context_prototype import (
    PrototypeSprayRunOwner, PrototypeValidationError, build_prototype_window,
    correlate_c1, correlate_c2,
)
from app.models.schemas import DetectionResult
from app.parser.registry import get_parser, get_timezone
from app.parser.time_utils import normalize_to_utc

CORPUS_ROOT = Path(__file__).resolve().parents[2] / "sample_logs" / "spray_correlation_semantics"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
MAX_MANIFEST = 128 * 1024
MAX_FIXTURE = 8 * 1024
MAX_SCENARIOS = 128
MAX_LINES = 128
MAX_TOTAL_LINES = 4096
DOC_NETWORKS = tuple(ipaddress.ip_network(x) for x in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
ID_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z", re.ASCII)
USER_RE = re.compile(r"spray_[a-z0-9_]{1,24}\Z", re.ASCII)
ROOT_KEYS = {"data_scope", "schema_version", "scenarios"}
ROW_KEYS = {"ambiguity", "behavioral_pattern", "category", "context_basis", "event_count_expected", "fixtures", "id", "label_basis", "operational_context", "parser_status", "relationship_interpretation", "success_account_relation", "success_timing"}
FIXTURE_KEYS = {"line_count", "path", "source"}
LABELS = {
    "behavioral_pattern": {"PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED"},
    "operational_context": {"KNOWN_BENIGN", "CONTEXT_UNKNOWN", "NOT_LABELED", "SIMULATED_ATTACK"},
    "parser_status": {"VERIFIED", "PARTIAL", "REJECTED", "IGNORED"},
    "success_timing": {"AT_WINDOW_END", "BEFORE_ALL_FAILURES", "END_PLUS_60S", "END_PLUS_60S_PLUS_1US", "END_PLUS_61S", "LATE_NOISE", "MULTIPLE_SUCCESS", "NO_SUCCESS", "POST_COMPLETION", "POST_COMPLETION_BEFORE_LATE_NOISE", "PRE_COMPLETION", "SAME_TIMESTAMP"},
    "success_account_relation": {"MEMBER_KNOWN", "MISSING", "MULTIPLE_MEMBER_KNOWN", "NON_MEMBER"},
    "relationship_interpretation": {"ACCOUNT_ATTRIBUTION_UNAVAILABLE", "ACCOUNT_SCOPED_MEMBER_PAIR", "AMBIGUOUS_EQUAL_DELTA_PAIR", "BRUTE_AND_SPRAY_OVERLAP", "CLOSEST_PAIR_NOT_EARLIEST_SUCCESS", "CROSS_IP_NO_PAIR", "CROSS_SOURCE_IDENTITY_UNVERIFIED", "CURRENT_PAIR_OUTSIDE_SELECTED_WINDOW", "END_ANCHOR_PASS_MEMBER_DELTA_FAIL", "KNOWN_PAIR_WITH_INCOMPLETE_WINDOW", "LATE_NONMEMBER_PAIR", "MEMBERSHIP_AMBIGUOUS", "MEMBER_PAIR_DESPITE_LATE_NOISE", "MULTIPLE_MEMBER_PAIRS", "NO_FAILURE_BEFORE_SUCCESS", "NO_MEMBER_PAIR", "NO_STRICT_FAILURE_BEFORE_SUCCESS", "OUTSIDE_C2_END_WINDOW", "PATTERN_ACCOUNT_SCOPE_UNDETERMINED", "WINDOW_MEMBER_AT_END_PAIR", "WINDOW_MEMBER_POST_COMPLETION_PAIR", "WINDOW_MEMBER_PRE_COMPLETION_PAIR"},
    "ambiguity": {"CROSS_SOURCE_IDENTITY", "MEMBER_SELECTION", "MISSING_ACCOUNT", "NONE", "PAIR_TIE"},
}


class SemanticEvaluationError(ValueError):
    def __init__(self, code="invalid_manifest"):
        self.code = code if code in {"invalid_manifest", "fixture_unavailable", "parser_mismatch", "evaluation_failed"} else "invalid_manifest"
        super().__init__(self.code)


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate")
        result[k] = v
    return result


def _json(raw):
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise SemanticEvaluationError() from None
    if type(data) is not dict or set(data) != ROOT_KEYS or type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["data_scope"] != "synthetic-only" or type(data["scenarios"]) is not list:
        raise SemanticEvaluationError()
    return data


def _doc_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return str(ip) == value and any(ip in net for net in DOC_NETWORKS)
    except (ValueError, TypeError):
        return False


def load_scenarios(manifest_path: Path = MANIFEST_PATH):
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file() or manifest_path.stat().st_size > MAX_MANIFEST:
            raise SemanticEvaluationError()
        root = manifest_path.parent.resolve(strict=True)
        manifest_path.resolve(strict=True).relative_to(root)
        data = _json(manifest_path.read_bytes())
    except SemanticEvaluationError:
        raise
    except (OSError, ValueError):
        raise SemanticEvaluationError("fixture_unavailable") from None
    rows = data["scenarios"]
    if not 1 <= len(rows) <= MAX_SCENARIOS:
        raise SemanticEvaluationError()
    ids, fixture_names, total = set(), set(), 0
    accepted = []
    for row in rows:
        if type(row) is not dict or not (set(row) == ROW_KEYS or set(row) == ROW_KEYS | {"timestamp_adjustment"}) or type(row["id"]) is not str or not ID_RE.fullmatch(row["id"]) or row["id"] in ids:
            raise SemanticEvaluationError()
        if "timestamp_adjustment" in row:
            adjustment = row["timestamp_adjustment"]
            if (type(adjustment) is not dict or set(adjustment) != {"event_index", "microseconds"}
                    or type(adjustment["event_index"]) is not int or adjustment["event_index"] != 4
                    or type(adjustment["microseconds"]) is not int or adjustment["microseconds"] != 1):
                raise SemanticEvaluationError()
        ids.add(row["id"])
        if any(type(row[k]) is not str or row[k] not in vals for k, vals in LABELS.items()):
            raise SemanticEvaluationError()
        if (type(row["label_basis"]) is not str or type(row["context_basis"]) is not str
                or not (1 <= len(row["label_basis"]) <= 300 and 1 <= len(row["context_basis"]) <= 300)
                or type(row["category"]) is not str or not ID_RE.fullmatch(row["category"])):
            raise SemanticEvaluationError()
        if type(row["event_count_expected"]) is not int or not 0 <= row["event_count_expected"] <= 512 or type(row["fixtures"]) is not list or not row["fixtures"]:
            raise SemanticEvaluationError()
        fixture_rows = []
        for fixture in row["fixtures"]:
            if (type(fixture) is not dict or set(fixture) != FIXTURE_KEYS
                    or type(fixture["source"]) is not str or fixture["source"] not in {"application", "ssh"}):
                raise SemanticEvaluationError()
            path_text = fixture["path"]
            if type(path_text) is not str or Path(path_text).name != path_text or path_text in fixture_names:
                raise SemanticEvaluationError()
            fixture_names.add(path_text)
            path = manifest_path.parent / path_text
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FIXTURE:
                    raise SemanticEvaluationError("fixture_unavailable")
                path.resolve(strict=True).relative_to(root)
                content = path.read_bytes().decode("utf-8", "strict")
            except SemanticEvaluationError:
                raise
            except (OSError, UnicodeError, ValueError):
                raise SemanticEvaluationError("fixture_unavailable") from None
            lines = content.splitlines()
            if not 1 <= len(lines) <= MAX_LINES or type(fixture["line_count"]) is not int or len(lines) != fixture["line_count"]:
                raise SemanticEvaluationError()
            total += len(lines)
            fixture_rows.append((fixture["source"], lines))
        if total > MAX_TOTAL_LINES:
            raise SemanticEvaluationError()
        public_row = dict(row)
        public_row["fixture"] = row["fixtures"][0]["path"]
        public_row["_fixture_rows"] = tuple(fixture_rows)
        accepted.append(public_row)
    return tuple(accepted)


def _parse(row, fixture_rows):
    events, sources, rejected = [], set(), 0
    for source, lines in fixture_rows:
        parser = get_parser(source)
        sources.add(source)
        for line in lines:
            try:
                event = parser(line, get_timezone(source))
            except Exception:
                raise SemanticEvaluationError("parser_mismatch") from None
            if event is None:
                rejected += 1
            else:
                try:
                    event.timestamp = normalize_to_utc(event.timestamp)
                except Exception:
                    raise SemanticEvaluationError("parser_mismatch") from None
                if event.src_ip is not None and not _doc_ip(event.src_ip):
                    raise SemanticEvaluationError("parser_mismatch")
                if event.user is not None and (type(event.user) is not str or not USER_RE.fullmatch(event.user)):
                    raise SemanticEvaluationError("parser_mismatch")
                events.append(event)
    if len(events) != row["event_count_expected"]:
        raise SemanticEvaluationError("parser_mismatch")
    status = "PARTIAL" if rejected or any(not e.user for e in events if e.event_type == "login_failed") else "VERIFIED"
    expected = row["parser_status"]
    if status != expected:
        raise SemanticEvaluationError("parser_mismatch")
    # The one microsecond fixture is an explicit post-parser arithmetic boundary, not parser precision.
    if "timestamp_adjustment" in row:
        adjustment = row["timestamp_adjustment"]
        index = adjustment["event_index"]
        if type(index) is not int or index >= len(events) or events[index].event_type != "user_login":
            raise SemanticEvaluationError("parser_mismatch")
        events[index].timestamp += timedelta(microseconds=adjustment["microseconds"])
    return events, sources, rejected


def _offset(event, base):
    return (event.timestamp.astimezone(timezone.utc) - base).total_seconds()


def _brief(result, context=None):
    row = {"correlated": bool(result.correlated), "reason": result.reason}
    if result.correlated:
        row["failure_offset_seconds"] = _offset(result.failure_event, context.start_utc) if context else None
        row["success_offset_seconds"] = _offset(result.success_event, context.start_utc) if context else None
        row["failure_is_window_member"] = any(result.failure_event is m for m in context.members) if context else False
    return row


def _c0(result, base):
    output = {"correlated": bool(result.get("is_correlated"))}
    if output["correlated"]:
        output["failure_offset_seconds"] = (result["failure_timestamp"] - base).total_seconds()
        output["success_offset_seconds"] = (result["success_timestamp"] - base).total_seconds()
    return output


def evaluate():
    scenarios, results = load_scenarios(), []
    counts = {key: Counter() for key in LABELS}
    for row in scenarios:
        fixtures = row["_fixture_rows"]
        for key in LABELS:
            counts[key][row[key]] += 1
        events, sources, rejected = _parse(row, fixtures)
        ips = sorted({e.src_ip for e in events if e.src_ip})
        owner = PrototypeSprayRunOwner()
        owner.register_events(events)
        contexts, c1_rows, c2_rows, selection_reasons = {}, {}, {}, {}
        for ip in ips:
            try:
                context = build_prototype_window(owner, ip)
            except PrototypeValidationError as error:
                context = None
                selection_reason = error.code
            else:
                selection_reason = "no_window" if context is None else "selected"
            selection_reasons[ip] = selection_reason
            if context is not None:
                contexts[ip] = context
                c1_rows[ip] = correlate_c1(owner, context, events)
                c2_rows[ip] = correlate_c2(owner, context, events)
        detected = detect_attacks(events)
        actual_by_ip = {ip: bool(v.get("detections", {}).get("password_spray", DetectionResult(False, None, [])).is_detected) for ip, v in detected.items()}
        actual_detected = any(actual_by_ip.values())
        c0_actual, c0_open, gate_outside_member = {}, {}, False
        base = min((e.timestamp for e in events), default=datetime(1970, 1, 1, tzinfo=timezone.utc))
        for ip in ips:
            ip_events = [e for e in events if e.src_ip == ip]
            det = detected.get(ip, {}).get("detections", {}).get("password_spray")
            if det is None:
                det = DetectionResult(is_detected=False, detection_type=None, evidence=[])
            actual_pair = correlate_password_spray_to_success(ip_events, det)
            c0_actual[ip] = _c0(actual_pair, base)
            forced = DetectionResult(is_detected=True, detection_type="password_spraying_like", evidence=[])
            open_pair = correlate_password_spray_to_success(ip_events, forced)
            c0_open[ip] = _c0(open_pair, base)
            context_for_ip = contexts.get(ip)
            if open_pair.get("is_correlated") and context_for_ip is not None:
                endpoint_matches = [event for event in ip_events
                                    if event.event_type == "login_failed"
                                    and event.user == open_pair.get("user")
                                    and event.timestamp == open_pair.get("failure_timestamp")]
                if len(endpoint_matches) == 1:
                    gate_outside_member = gate_outside_member or all(endpoint_matches[0] is not member for member in context_for_ip.members)
        generic = {ip: correlate_authentication_transition([e for e in events if e.src_ip == ip]) for ip in ips}
        context = contexts.get(ips[0]) if len(ips) == 1 else None
        c1 = next((c1_rows[ip] for ip in ips if ip in c1_rows), None)
        c2 = next((c2_rows[ip] for ip in ips if ip in c2_rows), None)
        selected = context
        gen = next((value for value in generic.values() if value.get("is_correlated")), None)
        window_users = {e.user for e in selected.members if e.user} if selected else set()
        gate_pair = next((value for value in c0_open.values() if value.get("correlated")), None)
        result = {
            "scenario_id": row["id"], "label_source": "manifest", "policy_result_used_for_label": False,
            **{key: row[key] for key in LABELS},
            "labels": {key: row[key] for key in LABELS}, "parser": {"parsed": len(events), "rejected": rejected, "sources": len(sources)},
            "c0_actual": {"detection_gate": actual_by_ip.get(ips[0], False) if len(ips) == 1 else actual_detected, "correlated": any(x["correlated"] for x in c0_actual.values()), "endpoints": list(c0_actual.values())},
            "c0_gate_open": {"correlated": any(x["correlated"] for x in c0_open.values()), "endpoints": list(c0_open.values()),
                             **({k: gate_pair[k] for k in ("failure_offset_seconds", "success_offset_seconds")} if gate_pair else {})},
            "c1": _brief(c1, next((contexts[ip] for ip in ips if ip in contexts and c1_rows[ip] is c1), None)) if c1 else {"correlated": False, "reason": "no_eligible_pair"},
            "c2": _brief(c2, next((contexts[ip] for ip in ips if ip in contexts and c2_rows[ip] is c2), None)) if c2 else {"correlated": False, "reason": "no_eligible_pair"},
            "generic_auth_transition": {"correlated": bool(gen), "type": gen.get("type") if gen else None},
            "c3": {"pattern_observed": actual_detected, "generic_transition_observed": gen is not None, "pattern_success_association": False},
            "semantic_flags": {
                "pre_completion_association": bool(c1 and c1.correlated and context and c1.success_event.timestamp < context.end_utc),
                "at_completion_association": bool(c1 and c1.correlated and context and c1.success_event.timestamp == context.end_utc),
                "post_completion_association": bool(c2 and c2.correlated),
                "out_of_window_endpoint": gate_outside_member,
                "cross_source_identity_unverified": len(sources) > 1,
                "multiple_member_accounts": len(window_users) > 1,
                "selection_ambiguous": "ambiguous_selection" in selection_reasons.values(),
            },
            "selection": "ambiguous" if "ambiguous_selection" in selection_reasons.values() else ("selected" if selected else "no_window"),
        }
        results.append(result)
    label_counts = {k: dict(sorted(v.items())) for k, v in counts.items()}
    pre = sum(x["semantic_flags"]["pre_completion_association"] for x in results)
    at = sum(x["semantic_flags"]["at_completion_association"] for x in results)
    post = sum(x["semantic_flags"]["post_completion_association"] for x in results)
    outside = sum(x["semantic_flags"]["out_of_window_endpoint"] for x in results)
    c0_actual_count = sum(item["c0_actual"]["correlated"] for item in results)
    c0_gate_open_count = sum(item["c0_gate_open"]["correlated"] for item in results)
    c1_count = sum(item["c1"]["correlated"] for item in results)
    c2_count = sum(item["c2"]["correlated"] for item in results)
    c3_transition_count = sum(item["c3"]["generic_transition_observed"] for item in results)
    ambiguity_count = sum(item["c1"]["reason"] == "ambiguous_pair" for item in results)
    return {
        "corpus": {"scenario_count": len(results), "parser_events": sum(x["parser"]["parsed"] for x in results), "rejected_lines": sum(x["parser"]["rejected"] for x in results)},
        "policy_results": {"c0_production_actual": c0_actual_count, "c0_gate_open_characterization": c0_gate_open_count, "c1_member_failure_anchor": c1_count, "c2_window_end_anchor": c2_count, "c3_generic_transition_observations": c3_transition_count},
        "label_counts": label_counts, "scenarios": results,
        "label_dimensions": ["behavioral_pattern", "operational_context", "parser_status", "relationship", "ambiguity"],
        "semantic_metrics": {"pre_completion_association": pre, "at_completion_association": at, "post_completion_association": post, "out_of_window_endpoint": outside, "ambiguous_c1_pair": ambiguity_count, "precision_recall": "not_calculated_without_policy-independent_eligibility_denominator"},
        "time_anchor_analysis": {
            "definitions": {"C1": "t_f < t_success and 0 < t_success - t_f <= 60s", "C2": "t_e < t_success and 0 < t_success - t_e <= 60s plus C1 member constraint"},
            "end_pass_member_failure_fail_possible": True,
            "member_failure_pass_end_fail_possible": False,
            "failure_before_success_implies_end_not_later": True,
            "end_60_seconds_plus_microsecond": "rejected",
            "60_second_threshold_source": "project evaluation heuristic, not a universal standard",
        },
        "consumer_impact": {"risk_policy_changed": False, "case_rule_activated": False, "public_report_changed": False},
        "production_changed": False, "network_used": False,
        "recommendation": "C3_SEPARATE_OBSERVATION_RECOMMENDED",
        "correlation_anchor_status": "SEMANTIC_DESIGN_RECOMMENDED / PRODUCTION_CORRELATION_APPROVED=False",
    }


def render_json(result):
    return json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_text(result):
    lines = ["Spray Correlation Semantics (synthetic only)",
             f"Scenarios: {result['corpus']['scenario_count']}; parsed: {result['corpus']['parser_events']}; rejected: {result['corpus']['rejected_lines']}"]
    lines.append(f"Policy scenarios: C0 actual={result['policy_results']['c0_production_actual']}; C0 gate-open={result['policy_results']['c0_gate_open_characterization']}; C1={result['policy_results']['c1_member_failure_anchor']}; C2={result['policy_results']['c2_window_end_anchor']}; C3 generic observations={result['policy_results']['c3_generic_transition_observations']}")
    lines.append("Label counts: " + "; ".join(
        f"{key}=" + ",".join(f"{label}:{count}" for label, count in values.items())
        for key, values in result["label_counts"].items()
    ))
    lines.append(f"C1 pre/end/post: {result['semantic_metrics']['pre_completion_association']}/{result['semantic_metrics']['at_completion_association']}/{result['semantic_metrics']['post_completion_association']}; C0 gate-open out-of-window endpoint: {result['semantic_metrics']['out_of_window_endpoint']}; ambiguous C1 pair: {result['semantic_metrics']['ambiguous_c1_pair']}")
    lines.append("C0 actual/gate-open are separate; C1/C2 use R3 prototype; C3 preserves independent observations.")
    lines.append(f"Recommendation: {result['recommendation']}; Production changed: {result['production_changed']}")
    lines.append("No operational accuracy claim; no raw event, account, IP, or owner data is emitted.")
    return "\n".join(lines)
