from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_evaluation_documented_contract():
    document = (ROOT / "docs/detection_evaluation.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for term in (
        "uv run python -m app.evaluation", "synthetic", "TP", "FP", "FN", "TN",
        "not_applicable", "Phase 6.1", "현재 구현", "계정", "no-go",
        "https://www.unb.ca/cic/datasets/ids-2017.html",
        "https://www.unb.ca/cic/datasets/ids-2018.html",
        "https://github.com/logpai/loghub",
    ):
        assert term in document
    assert "docs/detection_evaluation.md" in readme
    assert "운영 환경 탐지율" in readme
