"""Acceptance record keeps CI, automated checks, Safari, and user responses distinct."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_3a_acceptance_record_has_evidence_and_final_responses():
    path = ROOT / "docs/investigation_checklist_acceptance_36_3a.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    for required in (
        "40518020614",
        "44cdfb439513c412a3c9a30dc11657a463451978",
        "Safari",
        "Chromium",
        "external_requests=0",
        "**FAIL**",
        "**PASS**",
        "first rescore sequence",
        "final isolated recapture",
        "NOT_TESTED",
        "NO_GO",
        "Real user logs",
        "organization",
        "VoiceOver",
    ):
        assert required in text


def test_phase_36_3_record_links_independent_acceptance_without_overclaim():
    path = ROOT / "docs/investigation_checklist_api_ui_36_3.md"
    text = path.read_text(encoding="utf-8")
    assert "investigation_checklist_acceptance_36_3a.md" in text
    assert "VoiceOver" in text and "NOT_TESTED" in text
    assert "undetermined" in text and "no role was guessed" in text
