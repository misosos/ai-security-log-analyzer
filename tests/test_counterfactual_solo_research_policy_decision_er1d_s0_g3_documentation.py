from pathlib import Path


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_solo_research_policy_decision_er1d_s0_g3.md"


def test_policy_decision_has_all_required_sections():
    text = DOC.read_text(encoding="utf-8")
    headings = (
        "Executive Summary", "Start Gate", "User Decision Record",
        "Authorization Authority and Conditions", "Governance Conflict Resolution",
        "Revised Solo Research Policy", "Effective Scope and Pending Preconditions",
        "Tier 0–3 Input Authorization Matrix", "Research/Production Isolation Contract",
        "Restricted Adapter Constraints", "S1 Separate Implementation Gate",
        "Security Negative Tests", "Stop/Rollback Conditions",
        "Independent Human Review Preservation", "Policy Reassessment Conditions",
        "Open Authorization Issues", "Final Decision",
    )
    for number, heading in enumerate(headings, start=1):
        assert f"## {number}. {heading}\n" in text


def test_policy_records_actual_direction_without_inventing_authority_or_approval():
    text = DOC.read_text(encoding="utf-8")
    assert (
        "내가 결정 권한을 가진 내부 개발 정책이라는 전제하에 Option B 연구 전용 정책 개정 방향을 승인해. "
        "단, S1 구현 자체는 별도 Gate 통과 후 승인하고 독립 검토 및 운영 HOLD는 유지해."
    ) in text
    for row in (
        "| direction_approval | APPROVED_IN_CONVERSATION |",
        "| authority_verification | CONDITIONAL_USER_STATEMENT |",
        "| external_obligations_verification | NOT_INDEPENDENTLY_VERIFIED |",
        "| approval_date | NOT_PROVIDED |",
        "| signature | NOT_PROVIDED |",
        "| policy_effectiveness | SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING |",
        "| s1_implementation_approval | NOT_GRANTED |",
        "| policy_validity_period | UNDECIDED |",
    ):
        assert row in text


def test_policy_preserves_separate_implementation_and_security_gates():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "ER_1D_S0_G3_POLICY_DECISION_RECORDED_LOCAL_CONDITIONAL_GO",
        "ER_1D_S1_IMPLEMENTATION_HOLD", "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED", "ER_1D_IMPLEMENTATION_HOLD",
        "ER_2F_USER_ACCEPTANCE_PENDING", "NO_GO", "S5", "Tier 2", "Tier 3",
        "FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER", "AnalysisRunOwner", "BruteWindowContext",
        "Evidence Membership", "selected-window", "whole-span", "Cross-run",
        "Privacy Canary", "PARTIAL", "REJECTED", "NOT_DETECTED", "UNDETERMINED",
        "SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING", "기존 Replay 공개 DTO",
        "외부 네트워크", "Source IP", "Account", "롤백", "소급 승인하지 않는다",
    ):
        assert phrase in text


def test_policy_decision_is_indexed():
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
