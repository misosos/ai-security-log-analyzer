from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_independent_review_er1c_r.md"
TEMPLATE = ROOT / "docs" / "templates" / "counterfactual_independent_review_template.md"
POLICY = ROOT / "docs" / "templates" / "counterfactual_review_policy_er1c_r.md"


def test_er1c_r_review_documents_are_present_and_keep_human_gate_pending():
    text = DOC.read_text(encoding="utf-8")
    template = TEMPLATE.read_text(encoding="utf-8")
    policy = POLICY.read_text(encoding="utf-8")
    for required in (
        "755c74d7934aeb1499077b5b620e86f079be135a", "41818608175",
        "30개", "Label-Blind", "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MATCH", "DISAGREEMENT", "ER-1D", "실제 사용자 자료: `NO_GO`",
    ):
        assert required in text
    assert "검토자 이름" in template and "서명" in template and "완료 날짜" in template
    assert "INDEPENDENT_HUMAN_REVIEW_COMPLETED" not in template
    assert "Brute Force" in policy and "Password Spraying-like" in policy
    assert "PATTERN_PRESENT" not in text.split("## 4.")[1].split("## 5.")[0]


def test_er1c_r_documentation_is_indexed():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "counterfactual_independent_review_er1c_r.md" in index
