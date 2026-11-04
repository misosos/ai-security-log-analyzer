from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_evidence_review_ui_design_er2b.md"
INDEX = ROOT / "docs" / "index.md"


def test_er2b_design_document_has_required_architecture_and_security_contract():
    text = DOC.read_text(encoding="utf-8")
    for heading in (
        "## 1. Executive Summary",
        "## 2. Start SHA / CI",
        "## 3. Existing UI Architecture",
        "## 4. ER-2A Report Data Contract",
        "## 5. UI Integration Options",
        "## 6. Recommended Architecture",
        "## 7. Information Architecture",
        "## 8. Data Boundary",
        "## 9. Synthetic/Production Isolation",
        "## 10. Threat Model",
        "## 11. Accessibility & Responsive Design",
        "## 12. Failure States",
        "## 13. Rollback Strategy",
        "## 14. ER-2C/D/E Roadmap",
        "## 15. Human Review Gate",
        "## 16. Limitations",
        "## 17. Test Results",
        "## 18. Final Decision",
    ):
        assert heading in text

    for contract in (
        "Option A",
        "Option B",
        "Option C",
        "별도 Evaluation Workspace",
        "SYNTHETIC_ONLY",
        "합성 평가 전용 · 실제 보안 사건 아님",
        "PRESERVED",
        "LOST",
        "GAINED",
        "UNCHANGED_ABSENT",
        "INCOMPARABLE",
        "UNDETERMINED",
        "Markdown을 직접 파싱하지 않는다",
        "구조화 DTO",
        "Raw Log",
        "Prototype Pollution",
        "Reviewer Blindness",
        "1920",
        "1440",
        "1024",
        "768",
        "390",
        "320",
        "200%",
        "ER-2C",
        "ER-2D",
        "ER-2E",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD",
        "NO_GO",
        "ER_2B_EVIDENCE_REVIEW_UI_DESIGN_LOCAL_CONDITIONAL_GO",
    ):
        assert contract in text


def test_er2b_design_does_not_claim_implementation_or_human_approval():
    text = DOC.read_text(encoding="utf-8")
    assert "실제 UI 구현: 완료" not in text
    assert "INDEPENDENT_HUMAN_REVIEW_COMPLETED" not in text
    assert "운영 연결 승인: 완료" not in text
    assert "ER-2A Markdown을 HTML로 변환" not in text


def test_er2b_design_is_linked_from_docs_index():
    assert "counterfactual_evidence_review_ui_design_er2b.md" in INDEX.read_text(encoding="utf-8")
