from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_14d_documentation_records_memory_boundary_and_validation() -> None:
    document = ROOT / "docs/investigation_review_workflow_state_ui_36_14d.md"
    text = document.read_text(encoding="utf-8")
    for required in (
        "PHASE_36_14D_REVIEW_WORKFLOW_STATE_UI_LOCAL_CONDITIONAL_GO",
        "5ac3e784b9884aec6e8bde21e3661cb04513b47b",
        "41424680105",
        "crypto.getRandomValues()",
        "unreviewed",
        "in_review",
        "reviewed",
        "deferred",
        "revision 0",
        "128개",
        "NO_GO",
        "36.14E",
        "36.14F",
        "NOT_TESTED",
    ):
        assert required in text

    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "investigation_review_workflow_state_ui_36_14d.md" in index
