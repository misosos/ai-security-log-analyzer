from pathlib import Path


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_research_input_scope_governance_er1d_s0_g2.md"


def test_input_scope_document_has_required_sections_and_gates():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Executive Summary", "Exact Start Gate", "사용성 한계", "입력 Tier 0–3",
        "사용자 정의 합성 로그 계약", "로컬 로그 지원 조건", "Existing Input API",
        "Research/Production 격리", "Mutation 및 Provenance", "네 계층 Explanation",
        "Restricted Adapter Feasibility", "Privacy 및 Security Threat Model", "Governance 충돌",
        "정책 개정 제안", "G3/S1–S6", "사용자 승인 필요사항", "검증 및 한계", "최종 판정",
        "SOLO_RESEARCH_POLICY_PROPOSED", "PROPOSED_NOT_APPROVED", "SOLO_RESEARCH_AUTHORIZATION_PENDING",
        "INDEPENDENT_HUMAN_REVIEW_PENDING", "MANUAL_APPROVAL_REQUIRED", "ER_1D_IMPLEMENTATION_HOLD",
        "ER_2F_USER_ACCEPTANCE_PENDING", "NO_GO", "FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER",
    ):
        assert phrase in text


def test_input_scope_document_identifies_boundaries_and_negative_cases():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "32 KiB", "80 KiB", "96 KiB", "2048", "512", "duplicate", "UTF-8",
        "application", "ssh", "access", "Label provenance", "selected-window", "whole-span",
        "Run Owner", "Evidence Membership", "PARTIAL", "REJECTED", "Unknown Source",
        "Invalid Mutation Target", "Policy Version", "canary", "고정 Corpus 변조",
        "사용자 정의 입력의 Label 오염", "외부 네트워크", "S1 착수 HOLD",
    ):
        assert phrase in text


def test_input_scope_document_is_indexed():
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
