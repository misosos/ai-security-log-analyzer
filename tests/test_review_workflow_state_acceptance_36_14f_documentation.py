from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_14f_acceptance_record_is_complete() -> None:
    document = ROOT / "docs/investigation_review_workflow_state_acceptance_36_14f.md"
    assert document.is_file(), "Phase 36.14F acceptance record is missing"
    text = document.read_text(encoding="utf-8")
    for required in (
        "PHASE_36_14F_REVIEW_WORKFLOW_STATE_USER_ACCEPTED",
        "b7149a8bfb09c60dc3acbfd31b0402071dfb0b7c",
        "41453278845",
        "12/12",
        "document memory",
        "최초 응답",
        "ㅔpass",
        "external_requests=0",
        "checklist POST",
        "390px",
        "320px",
        "Safari",
        "screen reader",
        "NOT_TESTED",
        "NO_GO",
    ):
        assert required in text

    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "investigation_review_workflow_state_acceptance_36_14f.md" in index
