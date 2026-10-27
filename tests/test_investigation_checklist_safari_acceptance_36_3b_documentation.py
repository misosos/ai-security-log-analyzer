"""Keep Safari-specific acceptance evidence separate from Chromium automation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_safari_acceptance_record_pins_gate_and_manual_statuses():
    path = ROOT / "docs/investigation_checklist_safari_acceptance_36_3b.md"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    for required in (
        "40542403261",
        "ec41d708db67c5de50b9dba4a092fcbfdc964ffc",
        "Safari **18.6**",
        "macOS **15.7.7**",
        "Keyboard-only navigation",
        "VoiceOver",
        "Native Safari 200% zoom",
        "Exact 320 CSS px",
        "Web Inspector",
        "**NOT_TESTED**",
        "USER_HOME_ISOLATION_BLOCKED",
        "User comprehension remains **10/10 PASS**",
        "NO_GO",
    ):
        assert required in text
    assert text.count("| **NOT_TESTED** |") == 6


def test_safari_acceptance_does_not_treat_chromium_as_safari_evidence():
    path = ROOT / "docs/investigation_checklist_safari_acceptance_36_3b.md"
    text = path.read_text(encoding="utf-8")
    assert "Chromium results do not replace Safari checks" in text
    assert "WCAG 2.2 AA claim" in text
    assert "Vector/VM remains `USER_ACTION_REQUIRED / ISOLATION_BLOCKED`" in text
