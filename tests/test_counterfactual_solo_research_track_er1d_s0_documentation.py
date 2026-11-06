from pathlib import Path


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_solo_research_track_er1d_s0.md"


def test_research_protocol_covers_scope_and_governance():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "Executive Summary", "Start Gate", "기존 Governance", "격리 설계",
        "네 계층 Evidence Contract", "자기 검증과 독립 검증", "실패·반증 테스트",
        "HOLD와의 충돌 분석", "S1~S4", "남은 차단 조건", "위험과 한계", "최종 판정",
        "ER_1D_S0_SOLO_RESEARCH_DESIGN_LOCAL_CONDITIONAL_GO",
        "INDEPENDENT_HUMAN_REVIEW_PENDING", "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD", "ER_2F_USER_ACCEPTANCE_PENDING", "NO_GO",
        "S1 착수 HOLD", "별도 명시적 승인",
    ):
        assert phrase in text


def test_research_protocol_covers_security_failures_and_review_states():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "AUTOMATED_VERIFIED", "SELF_REVIEWED", "NOT_VERIFIED", "INDEPENDENT_REVIEW_PENDING",
        "REJECTED", "PARTIAL", "Execution Failure", "Policy Version Mismatch",
        "Detector Version Mismatch", "Missing Evidence", "Evidence Membership", "Run Owner",
        "selected-window", "whole-span", "Label Leakage", "Mutation provenance",
        "Unknown Account", "INCOMPARABLE", "UNDETERMINED", "NOT_EVALUATED",
        "ER-1C-R", "ER-1C-H0", "S1", "S2", "S3", "S4",
    ):
        assert phrase in text


def test_research_protocol_is_indexed():
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
