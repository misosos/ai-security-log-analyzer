from pathlib import Path
import re


ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs/counterfactual_restricted_adapter_preflight_er1d_s1_p.md"


def test_preflight_has_required_audit_sections():
    text = DOC.read_text(encoding="utf-8")
    headings = (
        "Executive Summary", "Start SHA / Exact CI", "실제 분석 실행 데이터 흐름",
        "Run Owner 및 Context Lifetime", "Evidence Membership 검증 경로",
        "Adapter 방식 A/B/C 비교", "Brute selected-window 계약", "Spray whole-span 계약",
        "Safe Aggregate 후보 DTO", "Privacy 및 Security Boundary", "Negative Test Matrix",
        "Production/Replay 수정 필요 여부", "Tier 0과 Tier 1 적용 차이",
        "기술적 Feasibility 판정", "정책 효력 및 S1 승인 조건",
        "구현 전 해결할 차단 조건", "Final Decision",
    )
    for number, heading in enumerate(headings, start=1):
        assert f"## {number}. {heading}\n" in text


def test_preflight_bounds_identity_scope_and_implementation_claims():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "FEASIBLE_ONLY_WITH_RESTRICTED_ADAPTER", "_analyze_normalized_logs_with_context",
        "analyze_with_source_role_snapshot", "AnalysisRunOwner", "BruteWindowContext",
        "brute_evidence_matches_context", "validate_brute_window_context", "is_bound_to",
        "object identity", "같은 필드값", "독립 재계산", "신규 보안 테스트는 구현하지 않았다",
        "NOT_EVALUATED", "INCOMPARABLE", "UNDETERMINED", "null", "자동 직렬화",
        "SOLO_RESEARCH_POLICY_EFFECTIVENESS_PENDING", "ER_1D_S1_IMPLEMENTATION_HOLD",
        "INDEPENDENT_HUMAN_REVIEW_PENDING", "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD", "ER_2F_USER_ACCEPTANCE_PENDING", "NO_GO",
    ):
        assert phrase in text


def test_preflight_covers_all_candidate_fields_and_negative_test_plans():
    text = DOC.read_text(encoding="utf-8")
    for field in (
        "detector_id", "policy_version", "scope_type", "parser_disposition",
        "evidence_validation_status", "selected_window_failure_count",
        "selected_window_span_seconds", "whole_span_failure_count",
        "whole_span_account_count", "whole_span_seconds", "evaluation_status", "reason_codes",
    ):
        assert f"`{field}`" in text
    assert re.findall(r"^\| N(\d{2}) \|", text, re.MULTILINE) == [
        f"{number:02}" for number in range(1, 23)
    ]


def test_preflight_is_indexed():
    assert DOC.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
