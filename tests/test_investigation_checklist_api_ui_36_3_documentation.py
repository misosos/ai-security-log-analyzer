from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_checklist_api_ui_36_3.md"


def test_phase_36_3_api_ui_record_exists_and_states_closed_boundaries():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "# Phase 36.3", "`POST /api/v1/investigations/checklist`", "explicit click",
        "unknown source role", "review_priority", "risk", "stale", "citation",
        "analysis unchanged", "model", "external requests", "Safari", "VoiceOver",
        "CONDITIONAL_GO", "NO_GO", "NOT_TESTED", "source_role=unknown",
        "Linux", "real user",
    ):
        assert required.lower() in text.lower()


def test_phase_36_3_public_surface_is_not_claimed_as_organization_ready():
    text = DOC.read_text(encoding="utf-8").lower()
    assert "actual organization logs" in text
    assert "automatic response" in text
    assert "user comprehension" in text
