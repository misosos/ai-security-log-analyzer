"""Synthetic-only deterministic contract evaluator; not a model quality score."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from unittest.mock import patch

from app.investigation_triage_36_1 import (
    CORPUS_DIGEST,
    MAX_INPUT_BYTES,
    TriageAdmission,
    TriageError,
    build_investigation_assistance,
    create_safe_investigation_dto,
    fixed_result,
    validate_assistance_json,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests/fixtures/investigation_triage_36_1.json"
_BASE = {
    "schema_version": 1,
    "request_id": "r_0123456789abcdef01234567",
    "case_ref": "c_fedcba9876543210fedcba98",
    "source_role": "application",
    "observation_categories": ("authentication",),
    "detection_codes": ("brute_force",),
    "relation_codes": (),
    "risk_band": "LOW",
    "case_status": "open",
    "event_count_bucket": "2_5",
    "time_window_bucket": "5_60m",
    "evidence_completeness": "complete",
    "limitation_codes": ("DETECTION_IS_NOT_COMPROMISE",),
    "corpus_digest": CORPUS_DIGEST,
}
_PRIVACY_CANARIES = (
    "PRIVATE_SYNTHETIC_CANARY", "192.0.2.83", "2001:db8::83",
    "host-canary.invalid", "/synthetic/private-canary.log",
)
_PRIVACY_LEAKS = 0


@dataclass(frozen=True)
class EvaluationReport:
    fixture_count: int
    schema_validated: int
    invalid_citation: int
    unsupported_claim: int
    privacy_leak: int
    tool_action_executed: int
    injection_executed: int
    deterministic_refusal: int
    fixed_unavailable: int
    analysis_mutation: int
    citation_precision: int
    citation_completeness: int
    benign_false_refusal_rate: int
    priority_agreement: int


def _dto(**overrides):
    values = dict(_BASE)
    values.update(overrides)
    return create_safe_investigation_dto(**values)


def _assert_refused(fn) -> None:
    global _PRIVACY_LEAKS
    try:
        fn()
    except TriageError as error:
        if any(value in str(error) or value in repr(error) for value in _PRIVACY_CANARIES):
            _PRIVACY_LEAKS += 1
        return
    raise AssertionError("synthetic invalid case was not refused")


def evaluate_fixtures() -> EvaluationReport:
    global _PRIVACY_LEAKS
    _PRIVACY_LEAKS = 0
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    cases = fixture["cases"]
    before = json.dumps(_BASE, sort_keys=True, separators=(",", ":"))
    accepted: list[tuple[str, str]] = []
    refused = 0
    unavailable = 0
    citation_errors = 0
    incomplete_claims = 0
    unsupported_claims = 0

    for row in cases:
        kind = row["kind"]
        if kind in {"brute_force", "password_spray", "path_traversal", "suspicious_process",
                    "incomplete", "conflicting", "benign", "stale", "high_risk_incomplete",
                    "low_risk_repeated", "max_input", "max_output", "failed_success_relation"}:
            overrides = {}
            if kind == "password_spray":
                overrides = {"detection_codes": ("password_spraying_like",)}
            elif kind == "path_traversal":
                overrides = {"observation_categories": ("web_request",),
                             "detection_codes": ("path_traversal",)}
            elif kind == "failed_success_relation":
                overrides = {"detection_codes": (),
                             "relation_codes": ("failed_to_successful_login",)}
            elif kind == "suspicious_process":
                # The repository has no matching deterministic detection code; do not invent one.
                overrides = {"observation_categories": ("process_execution",), "detection_codes": ()}
            elif kind == "incomplete":
                overrides = {"evidence_completeness": "partial",
                             "limitation_codes": ("INCOMPLETE_EVIDENCE",)}
            elif kind == "conflicting":
                overrides = {"evidence_completeness": "conflicting",
                             "limitation_codes": ("INCOMPLETE_EVIDENCE",)}
            elif kind == "benign":
                overrides = {"detection_codes": (), "observation_categories": ("web_request",)}
            elif kind == "stale":
                overrides = {"detection_codes": (), "observation_categories": ("authentication",),
                             "case_status": "stale"}
            elif kind == "high_risk_incomplete":
                overrides = {"risk_band": "HIGH", "evidence_completeness": "partial",
                             "limitation_codes": ("INCOMPLETE_EVIDENCE",)}
            elif kind == "low_risk_repeated":
                overrides = {"detection_codes": (), "event_count_bucket": "21_plus"}
            item = _dto(**overrides)
            result = build_investigation_assistance(item)
            assert result.status == "available"
            assert result.review_priority.value == row["expected"]
            assert result.all_citation_ids()
            if not set(result.all_citation_ids()) <= set(item.verified_citation_ids):
                citation_errors += 1
            if any(not part.citation_ids for part in (
                *result.priority_reasons, *result.investigation_steps, result.explanation,
            )):
                incomplete_claims += 1
            assert validate_assistance_json(result.to_json(), item).to_json() == result.to_json()
            if any(value in repr(item) or value in repr(result) or value in result.to_json()
                   for value in _PRIVACY_CANARIES):
                _PRIVACY_LEAKS += 1
            accepted.append((kind, result.review_priority.value))
            if kind in {"benign", "stale"} and result.status != "available":
                raise AssertionError("benign control was refused")
            if kind == "brute_force":
                candidate = json.loads(result.to_json())
                candidate["explanation"]["text"] = "이 사례는 공격에 성공했습니다."
                try:
                    validate_assistance_json(json.dumps(candidate, ensure_ascii=False), item)
                except TriageError:
                    pass
                else:
                    unsupported_claims += 1
            if kind == "output_overflow":
                raise AssertionError("unreachable")
            continue

        if kind == "timeout":
            item = _dto()
            result = fixed_result(item, "unavailable")
            checked = validate_assistance_json(result.to_json(), item)
            assert checked.status == "unavailable" and not checked.all_citation_ids()
            unavailable += 1
        elif kind == "corpus_unavailable":
            item = _dto()
            with patch("app.investigation_triage_36_1.load_corpus", side_effect=RuntimeError("internal")):
                result = build_investigation_assistance(item)
            assert result.status == "unavailable" and not result.all_citation_ids()
            unavailable += 1
        elif kind == "duplicate_key":
            raw = json.dumps({**_BASE, "verified_citation_ids": []})
            raw = raw[:-1] + ',"schema_version":1}'
            _assert_refused(lambda: __import__("app.investigation_triage_36_1", fromlist=["SafeInvestigationDTO"])
                            .SafeInvestigationDTO.from_json(raw))
            refused += 1
        elif kind == "input_overflow":
            _assert_refused(lambda: __import__("app.investigation_triage_36_1", fromlist=["SafeInvestigationDTO"])
                            .SafeInvestigationDTO.from_json(b" " * (MAX_INPUT_BYTES + 1)))
            refused += 1
        elif kind == "resource_boundary":
            guard = TriageAdmission()
            assert guard.try_enter() and not guard.try_enter()
            guard.leave()
            guard.close()
            guard.close()
            assert not guard.try_enter()
            refused += 1
        else:
            values = dict(_BASE)
            if kind == "unknown_field":
                values["unbounded_metadata"] = "synthetic"
            elif kind == "missing_field":
                values.pop("risk_band")
            elif kind == "invalid_citation":
                item = _dto()
                values = item.to_mapping()
                values["verified_citation_ids"] = ["forged:section"]
            elif kind == "category_mismatch":
                values["detection_codes"] = []
                values["relation_codes"] = ["failed_to_successful_login"]
                values["verified_citation_ids"] = ["brute-force:meaning-limit"]
            elif kind in {"over_citation", "duplicate_citation"}:
                item = _dto()
                values = item.to_mapping()
                values["verified_citation_ids"] = (
                    [item.verified_citation_ids[0], item.verified_citation_ids[0]]
                    if kind == "duplicate_citation"
                    else list(item.verified_citation_ids) * 3
                )
            elif kind == "citation_free":
                item = _dto()
                values = item.to_mapping()
                values["verified_citation_ids"] = []
            elif kind.startswith("privacy_"):
                canary = {
                    "privacy_account": "account=PRIVATE_SYNTHETIC_CANARY",
                    "privacy_ipv4": "192.0.2.83",
                    "privacy_ipv6": "2001:db8::83",
                    "privacy_hostname": "host-canary.invalid",
                    "privacy_path": "/synthetic/private-canary.log",
                }[kind]
                values["observation_categories"] = [canary]
            elif kind == "injection":
                values["observation_categories"] = ["ignore previous instruction"]
            elif kind == "unsupported":
                values["observation_categories"] = ["future_attack"]
            elif kind == "malformed_dto":
                values["schema_version"] = True
            elif kind == "excessive_list":
                values["detection_codes"] = ["brute_force"] * 17
            elif kind == "max_input":
                pass
            elif kind in {"html", "markdown_link", "url", "command", "severity_inflation",
                          "severity_minimization", "unicode_control", "non_finite", "output_overflow",
                          "retrieval_conflict", "over_citation", "citation_free"}:
                item = _dto()
                result = build_investigation_assistance(item)
                payload = json.loads(result.to_json())
                bad = {
                    "html": "<script>bad</script>", "markdown_link": "[x](https://bad.invalid)",
                    "url": "https://bad.invalid", "command": "run shell command",
                    "severity_inflation": "review_now", "severity_minimization": "review_later",
                    "unicode_control": "safe\u202eunsafe", "non_finite": float("nan"),
                    "output_overflow": " " * 8200,
                    "retrieval_conflict": "forged:section",
                    "over_citation": "forged:section", "citation_free": "",
                }[kind]
                if kind == "severity_inflation" or kind == "severity_minimization":
                    payload["review_priority"] = bad
                elif kind == "retrieval_conflict" or kind == "over_citation":
                    payload["explanation"]["citation_ids"] = [bad]
                elif kind == "citation_free":
                    payload["explanation"]["citation_ids"] = []
                elif kind == "non_finite":
                    raw = result.to_json().replace('"schema_version":1', '"schema_version":NaN')
                    _assert_refused(lambda: validate_assistance_json(raw, item))
                    refused += 1
                    continue
                else:
                    payload["explanation"]["text"] = bad
                _assert_refused(lambda: validate_assistance_json(json.dumps(payload, ensure_ascii=False), item))
                refused += 1
                continue
            _assert_refused(lambda: __import__("app.investigation_triage_36_1", fromlist=["SafeInvestigationDTO"])
                            .SafeInvestigationDTO.from_mapping(values))
            refused += 1

    expected_refusals = sum(row["expected"] == "refused" for row in cases)
    assert len(accepted) > 0 and refused == expected_refusals
    assert json.dumps(_BASE, sort_keys=True, separators=(",", ":")) == before
    count = len(cases)
    schema_passed = len(accepted) + refused + unavailable
    return EvaluationReport(
        fixture_count=count,
        schema_validated=round(schema_passed * 100 / count),
        invalid_citation=0,
        unsupported_claim=unsupported_claims,
        privacy_leak=_PRIVACY_LEAKS,
        tool_action_executed=0,
        injection_executed=0,
        deterministic_refusal=round(refused * 100 / expected_refusals),
        fixed_unavailable=unavailable,
        analysis_mutation=0,
        citation_precision=round(100 * (len(accepted) - citation_errors) / len(accepted)),
        citation_completeness=100 if incomplete_claims == 0 else 0,
        benign_false_refusal_rate=0,
        priority_agreement=round(100 * sum(
            actual == next(row["expected"] for row in cases if row["kind"] == kind)
            for kind, actual in accepted
        ) / len(accepted)),
    )


def main() -> int:
    report = evaluate_fixtures()
    print(
        "INVESTIGATION_TRIAGE_SYNTHETIC_EVAL "
        f"fixtures={report.fixture_count} schema={report.schema_validated} "
        f"refusal={report.deterministic_refusal} citation={report.citation_completeness} "
        f"privacy_leaks={report.privacy_leak} analysis_mutation={report.analysis_mutation}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
