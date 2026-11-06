from pathlib import Path


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_solo_research_governance_er1d_s0_g1.md"


def test_governance_document_has_decision_boundary_and_sections():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Executive Summary", "Exact Start Gate", "기존 HOLD와 정책 충돌", "권한 및 한계",
        "Option A/B/C", "추천 Governance 경로", "연구용 격리 경계", "S1 기술적 Feasibility",
        "정책 변경 초안", "명시적 승인 절차", "S1 진입 Gate", "위협·실패·반증",
        "독립 검토 Gate 보존", "남은 미결정 사항", "최종 판정",
        "SOLO_RESEARCH_POLICY_PROPOSED", "PROPOSED_NOT_APPROVED",
        "SOLO_RESEARCH_AUTHORIZATION_PENDING", "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED", "ER_1D_IMPLEMENTATION_HOLD", "ER_2F_USER_ACCEPTANCE_PENDING",
        "NO_GO", "FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER",
    ):
        assert phrase in text


def test_governance_document_preserves_security_requirements():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Run Owner", "Evidence Membership", "selected-window", "whole-span", "PARTIAL", "REJECTED",
        "Missing Account", "Timestamp", "Policy Version", "Empty Evidence", "Source Provenance",
        "Raw Log", "IP/Account", "Private Context", "네트워크", "Production 결과",
        "기준 Commit SHA", "만료", "롤백", "별도 승인", "S1 착수 HOLD",
    ):
        assert phrase in text


def test_governance_document_is_indexed():
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
