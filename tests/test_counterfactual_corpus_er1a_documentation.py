from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_corpus_er1a.md"


def test_er1a_documentation_preserves_scope_and_defers_detector_comparison():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "ER-0 요구사항 보존",
        "ER-1A 완료",
        "ER-1B 이관",
        "Mutation",
        "Parser",
        "독립 라벨",
        "실제 사용자 자료: `NO_GO`",
        "조직 운영: `NO_GO`",
        "자동 대응: `NO_GO`",
        "DETECTOR_NOT_RUN",
        "COMPARISON_NOT_RUN",
    ):
        assert phrase in text
    assert "detector output" in text.lower()
    assert "sample_logs/detector_accuracy/" in text
    assert "17개" not in text


def test_er1a_documentation_is_indexed():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "counterfactual_corpus_er1a.md" in index
