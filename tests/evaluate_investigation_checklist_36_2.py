"""Evaluate manually labeled synthetic citation relevance and fixed refusals."""

from __future__ import annotations

import json
from pathlib import Path

from app.investigation_checklist_36_2 import (
    ChecklistError,
    build_investigation_checklist,
    validate_checklist_json,
)
from app.investigation_triage_36_1 import CORPUS_DIGEST, create_safe_investigation_dto

ROOT = Path(__file__).resolve().parents[1]


def _dto(kind: str):
    data = {
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
    if kind == "password_spray":
        data["detection_codes"] = ("password_spraying_like",)
    elif kind == "failed_success_relation":
        data.update(detection_codes=(), relation_codes=("failed_to_successful_login",),
                    limitation_codes=("CORRELATION_IS_NOT_CAUSATION",))
    elif kind == "incomplete":
        data.update(detection_codes=(), evidence_completeness="partial",
                    limitation_codes=("INCOMPLETE_EVIDENCE",))
    elif kind == "conflicting":
        data.update(detection_codes=(), evidence_completeness="conflicting",
                    limitation_codes=("INCOMPLETE_EVIDENCE",))
    elif kind == "benign":
        data.update(detection_codes=(), observation_categories=("authentication",),
                    limitation_codes=("NO_FINDING_IS_NOT_SAFE",))
    elif kind == "path_traversal":
        data["detection_codes"] = ("path_traversal",)
    elif kind == "suspicious_process_execution":
        data.update(detection_codes=(), observation_categories=("process_execution",))
    elif kind == "stale":
        data.update(detection_codes=(), case_status="stale", evidence_completeness="partial",
                    limitation_codes=("INCOMPLETE_EVIDENCE",))
    elif kind == "maximum_valid_combination":
        data.update(
            detection_codes=("brute_force", "password_spraying_like"),
            relation_codes=("failed_to_successful_login",),
            evidence_completeness="partial",
            limitation_codes=("INCOMPLETE_EVIDENCE", "CORRELATION_IS_NOT_CAUSATION",
                              "DETECTION_IS_NOT_COMPROMISE"),
        )
    return create_safe_investigation_dto(**data)


def _tampered(raw: str, mode: str) -> str:
    parsed = json.loads(raw)
    if mode == "irrelevant_citation_tamper":
        parsed["steps"][0]["citation_ids"] = ["no-finding:no-detection"]
    elif mode == "overcitation_tamper":
        parsed["steps"][0]["citation_ids"].append("relation-gone:not-resolved")
    elif mode == "missing_required_citation_tamper":
        parsed["steps"][0]["citation_ids"] = []
    elif mode == "command_output_tamper":
        parsed["steps"][0]["text"] = "Run this command now."
    elif mode == "output_cap_tamper":
        return " " * 8_193
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))


def evaluate(fixture: dict) -> dict:
    if (type(fixture) is not dict or fixture.get("synthetic_only") is not True
            or fixture.get("semantic_labels_are_manual") is not True
            or type(fixture.get("cases")) is not list):
        raise ValueError("fixture contract invalid")
    mismatch_ids = []
    counts = {
        "required": 0, "required_hit": 0, "cited": 0, "supported": 0,
        "forbidden_citation_count": 0, "invalid_citation_count": 0,
        "unsupported_claim_count": 0, "benign_false_refusal_count": 0,
        "status_matches": 0,
    }
    for case in fixture["cases"]:
        kind = case["input"]
        if kind in {"prompt_injection_invalid_input", "privacy_invalid_input"}:
            try:
                create_safe_investigation_dto({"synthetic_invalid_field": "synthetic invalid"})
            except Exception:
                status = "refused"
            else:
                status = "available"
            result = None
        elif kind in {
            "irrelevant_citation_tamper", "overcitation_tamper", "missing_required_citation_tamper",
            "command_output_tamper", "output_cap_tamper",
        }:
            item = _dto("brute_force")
            original = build_investigation_checklist(item).to_json()
            try:
                validate_checklist_json(_tampered(original, kind), item)
            except ChecklistError:
                status = "refused"
            else:
                status = "available"
            result = None
        elif kind in {"digest_mismatch", "retrieval_refusal"}:
            from app import investigation_checklist_36_2 as module
            if kind == "digest_mismatch":
                previous = module.load_corpus
                module.load_corpus = lambda: type(previous())(
                    "0" * 64, previous().sections, previous().total_bytes,
                )
                try:
                    result = build_investigation_checklist(_dto("brute_force"))
                finally:
                    module.load_corpus = previous
            else:
                from app.local_retrieval_33_1 import RetrievalResult, ResultStatus
                previous = module.retrieve
                module.retrieve = lambda _q, category, _e, *, corpus, index, top_k: RetrievalResult(
                    query_category=category, corpus_digest=corpus.digest,
                    status=ResultStatus.REFUSED, citations=(),
                    refusal_code="NO_SUPPORTING_CITATION",
                )
                try:
                    result = build_investigation_checklist(_dto("brute_force"))
                finally:
                    module.retrieve = previous
            status = result.status
        else:
            result = build_investigation_checklist(_dto(kind))
            status = result.status
        if status == case["status"]:
            counts["status_matches"] += 1
        else:
            mismatch_ids.append(case["id"])
        valid_input = kind not in {
            "path_traversal", "suspicious_process_execution", "irrelevant_citation_tamper",
            "overcitation_tamper", "missing_required_citation_tamper", "prompt_injection_invalid_input",
            "privacy_invalid_input", "command_output_tamper", "output_cap_tamper",
            "digest_mismatch", "retrieval_refusal",
        }
        if valid_input and case["status"] == "available" and status != "available":
            counts["benign_false_refusal_count"] += 1
        if result is not None and result.status == "available":
            citations = {citation for step in result.steps for citation in step.citation_ids}
            required, optional = set(case["required"]), set(case["optional"])
            counts["required"] += len(required)
            counts["required_hit"] += len(citations.intersection(required))
            counts["cited"] += len(citations)
            counts["supported"] += len(citations.intersection(required | optional))
            counts["forbidden_citation_count"] += len(citations.intersection(case["forbidden"]))
            counts["invalid_citation_count"] += len(citations - required - optional)
            actual_templates = {step.template_code for step in result.steps}
            if actual_templates != set(case["templates"]):
                counts["unsupported_claim_count"] += 1
    total = len(fixture["cases"])
    required_rate = counts["required_hit"] / counts["required"] if counts["required"] else 1.0
    precision = counts["supported"] / counts["cited"] if counts["cited"] else 0.0
    return {
        "fixture_count": total,
        "status_match": counts["status_matches"] / total if total else 0.0,
        "required_citation_completeness": required_rate,
        "semantic_support_precision": precision,
        "semantic_support_completeness": required_rate,
        "forbidden_citation_count": counts["forbidden_citation_count"],
        "invalid_citation_count": counts["invalid_citation_count"],
        "unsupported_claim_count": counts["unsupported_claim_count"],
        "benign_false_refusal_count": counts["benign_false_refusal_count"],
        "meaningful_available_cases": sum(
            1 for case in fixture["cases"] if case["status"] == "available"
        ),
        "status_mismatch_ids": mismatch_ids,
    }


def main() -> None:
    fixture = json.loads((ROOT / "tests/fixtures/investigation_checklist_36_2.json").read_text())
    result = evaluate(fixture)
    print("INVESTIGATION_CHECKLIST_SYNTHETIC_EVAL " + " ".join(
        f"{key}={value}" for key, value in result.items()
    ))


if __name__ == "__main__":
    main()
