from pathlib import Path


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_explanation_readiness_audit_er1d_g0.md"
INDEX = ROOT / "docs/index.md"


def test_readiness_audit_has_required_evidence_and_gate_sections():
    document = DOC.read_text(encoding="utf-8")
    for heading in (
        "Start Gate",
        "기존 ER-1D-P 계약",
        "4계층 Evidence Matrix",
        "현재 코드 근거",
        "Missing Evidence",
        "Privacy Boundary",
        "Human Review Gate",
        "Implementation Blockers",
        "차별화 가능성",
        "최소 구현 순서",
        "승인 전 금지사항",
        "최종 판정",
    ):
        assert heading in document


def test_readiness_audit_classifies_evidence_and_preserves_approval_holds():
    document = DOC.read_text(encoding="utf-8")
    for state in (
        "IMPLEMENTED_AND_VERIFIED",
        "IMPLEMENTED_NOT_VERIFIED",
        "DESIGN_ONLY",
        "MISSING_EVIDENCE",
        "BLOCKED_BY_HUMAN_REVIEW",
    ):
        assert state in document

    for contract in (
        "BruteWindowContext",
        "AnalysisRunOwner",
        "Evidence membership",
        "selected-window",
        "whole-span",
        "INCOMPARABLE",
        "UNDETERMINED",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD",
        "ER_2F_USER_ACCEPTANCE_PENDING",
        "NO_GO",
    ):
        assert contract in document


def test_readiness_audit_is_indexed():
    assert DOC.name in INDEX.read_text(encoding="utf-8")
