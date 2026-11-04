from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_holdout_validation_er1c.md"


def test_er1c_documentation_preserves_audit_provenance_and_scope():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "41810925590",
        "f17ed6f0c1ff5e8e1a11e21ad69772fcb5c22bc6",
        "AUTOMATED_CONTRACT_VALIDATED",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "manifest_sha256",
        "PRESERVED",
        "INCOMPARABLE",
        "Production",
        "실제 사용자 자료: `NO_GO`",
        "조직 운영: `NO_GO`",
        "자동 대응: `NO_GO`",
    ):
        assert phrase in text
    assert "운영 탐지 정확도" in text
    assert "블라인드 리뷰가 완료됐다고 주장하지 않는다" in text


def test_er1c_documentation_is_indexed():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "counterfactual_holdout_validation_er1c.md" in index
