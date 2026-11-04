from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "evidence_research_er0.md"


def test_er0_contract_document_exists_and_freezes_required_boundaries():
    text = DOC.read_text(encoding="utf-8")

    for heading in (
        "## 1. Executive Summary",
        "## 2. Start Gate",
        "## 3. Current Production Architecture",
        "## 4. Existing Evidence Model",
        "## 5. Observation / Evidence / Claim / Uncertainty Contract",
        "## 6. Parser / Detection / Comparison State Model",
        "## 7. Brute Force and Password Spray Policy Boundary",
        "## 8. Counterfactual Input Transformation Contract",
        "## 9. Independent Labeling and Evaluation",
        "## 10. Privacy and Security Boundary",
        "## 11. Research Basis",
        "## 12. ER-1A Implementation Requirements",
        "## 13. Unresolved Questions / HOLD Conditions",
        "## 14. Test Results",
        "## 15. Final Decision",
    ):
        assert heading in text

    for contract in (
        "Detection ≠ Confirmed Compromise",
        "Correlation ≠ Causation",
        "No Detection ≠ Safe",
        "Login Success ≠ Account Compromise",
        "Parser Failure ≠ Detector False Negative",
        "Counterfactual Change ≠ Real-world Evasion Success",
        "VERIFIED",
        "PARTIAL",
        "REJECTED",
        "NOT_EVALUATED",
        "DETECTED",
        "NOT_DETECTED",
        "EXECUTION_FAILED",
        "PRESERVED",
        "LOST",
        "GAINED",
        "UNCHANGED_ABSENT",
        "INCOMPARABLE",
        "UNDETERMINED",
        "인증 실패 행 1개 제거",
        "입력 행 순서 변경",
        "독립적으로",
        "문서용 주소",
        "외부 API, network, LLM",
        "실제 사용자 자료: `NO_GO`",
        "조직 운영: `NO_GO`",
        "자동 대응: `NO_GO`",
        "uv run pytest -q",
        "uv run python -m app.evaluation",
    ):
        assert contract in text


def test_er0_document_is_indexed():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "[ER-0 Evidence Research Contract](evidence_research_er0.md)" in index
