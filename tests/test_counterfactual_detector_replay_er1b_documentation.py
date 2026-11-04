from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_detector_replay_er1b.md"


def test_er1b_documentation_covers_replay_states_comparison_and_limits():
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "ER-1A",
        "analyze_with_source_role_snapshot",
        "AnalysisRunOwner",
        "BruteWindowContext",
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
        "canonical JSON",
        "16개",
        "실제 사용자 자료: `NO_GO`",
        "조직 운영: `NO_GO`",
        "자동 대응: `NO_GO`",
        "ER-1C",
    ):
        assert phrase in text
    assert "운영 탐지 정확도" in text
    assert "Push하지 않았다" in text


def test_er1b_documentation_is_indexed():
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "counterfactual_detector_replay_er1b.md" in index
