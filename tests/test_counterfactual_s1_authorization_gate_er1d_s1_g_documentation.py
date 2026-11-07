from pathlib import Path
import re


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_s1_implementation_authorization_gate_er1d_s1_g.md"


def test_authorization_packet_has_complete_implementation_contract():
    text = DOC.read_text(encoding="utf-8")
    headings = (
        "Executive Summary", "Exact Start Gate", "Previous Phase Evidence",
        "Option B Decision Scope", "R1–R6 Policy Adoption Preconditions",
        "S1 Minimal Implementation Scope", "File Change Allowlist",
        "Runtime Dependency Allowlist", "Restricted Adapter Execution Contract",
        "Safe Aggregate DTO", "Brute/Spray Scope Preservation",
        "Privacy and Isolation Requirements", "Negative Test Acceptance Matrix",
        "Stop/Rollback Contract", "Node Timeout Observation", "Technical Readiness",
        "Governance Readiness", "Owner Approval Decision Text", "Remaining Blockers",
        "Final Decision",
    )
    for number, heading in enumerate(headings, 1):
        assert f"## {number}. {heading}\n" in text


def test_authorization_packet_distinguishes_direction_policy_and_implementation():
    text = DOC.read_text(encoding="utf-8")
    for term in (
        "APPROVED_IN_CONVERSATION", "CONDITIONAL_USER_STATEMENT",
        "NOT_INDEPENDENTLY_VERIFIED", "NOT_ADOPTED", "NOT_GRANTED",
        "SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING", "ER_1D_S1_IMPLEMENTATION_HOLD",
        "S1_TECHNICAL_READY", "S1_POLICY_EFFECTIVENESS_PENDING",
        "S1_IMPLEMENTATION_APPROVAL_PENDING", "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED", "ER_1D_IMPLEMENTATION_HOLD",
        "ER_2F_USER_ACCEPTANCE_PENDING", "NO_GO",
        "ER_1D_S1_G_AUTHORIZATION_PACKET_LOCAL_CONDITIONAL_GO",
        "미채택 승인문", "승인 날짜·서명은 생성하지 않는다",
    ):
        assert term in text
    for number in range(1, 7):
        assert f"| R{number} |" in text


def test_authorization_packet_freezes_files_bounds_and_all_negative_acceptance_rows():
    text = DOC.read_text(encoding="utf-8")
    for term in (
        "app/evaluation/research_er1d/__init__.py",
        "app/evaluation/research_er1d/safe_aggregate.py",
        "tests/test_counterfactual_research_safe_aggregate.py",
        "docs/counterfactual_research_safe_aggregate_er1d_s1.md",
        "data/account_metadata.json", "_analyze_normalized_logs_with_context",
        "brute_evidence_matches_context", "validate_brute_window_context",
        "object identity", "multiplicity", "8192 bytes", "64행", "4096 bytes",
        "5–64", "0–60", "allow_nan=False", "null", "NOT_EVALUATED",
        "selected-window", "whole-span", "타입", "임의 파일", "영구 저장",
    ):
        assert term in text
    assert re.findall(r"^\| N(\d{2}) \|", text, re.MULTILINE) == [
        f"{number:02}" for number in range(1, 23)
    ]
    schema = text.split("<!-- S1_SCHEMA_START -->", 1)[1].split("<!-- S1_SCHEMA_END -->", 1)[0]
    assert re.findall(r"^\| `([a-z_]+)` \|", schema, re.MULTILINE) == [
        "schema_version", "corpus_id", "scenario_id", "run_role", "detector_id",
        "policy_version", "scope_type", "parser_disposition", "detection_state",
        "evaluation_status", "evidence_validation_status", "failure_count",
        "window_span_seconds", "reason_code",
    ]


def test_authorization_packet_is_indexed_and_links_existing_evidence():
    text = DOC.read_text(encoding="utf-8")
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((counterfactual_[^)]+\.md)\)", text):
        assert (ROOT / "docs" / target).is_file(), target
