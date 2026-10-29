from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_checklist_state_consistency_36_7a.md"


def test_phase_36_7a_records_root_cause_and_non_overlapping_state_rendering() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "4edafe2a5bda2b2792b02896a9648caa13000bc2",
        "40857535502",
        "ReferenceError",
        "frontend/app.js:1866",
        "CHECKLIST_REAL_AVAILABLE_UI_STATE_MISMATCH",
        "available",
        "refused",
        "unavailable",
        "stale",
        "POST는 1건",
        "부분목록 0개",
        "135,820 bytes",
        "160 KiB",
        "3101 passed",
        "NOT_TESTED",
        "NO_GO",
    ):
        assert required in text


def test_phase_36_7a_browser_contract_tests_real_response_and_controlled_render_failure() -> None:
    source = (ROOT / "tests" / "ui_accessibility_axe_pilot_28_1.mjs").read_text(encoding="utf-8")
    for required in (
        "CHECKLIST_REAL_AVAILABLE_UI_STATE_MISMATCH",
        "CHECKLIST_RENDER_EXCEPTION_PARTIAL_UI_REMAINS",
        "SYNTHETIC_RENDER_FAILURE_CANARY",
        "CHECKLIST_RENDER_EXCEPTION count=1 status=error partial_steps=0",
        "CHECKLIST_OPT_IN_COUNT_FAILED",
        "CHECKLIST_ANALYSIS_MUTATION",
        "target.width < 44 || target.height < 44",
        "min-width: 44px",
    ):
        if required == "min-width: 44px":
            assert required in (ROOT / "frontend" / "style.css").read_text(encoding="utf-8")
        else:
            assert required in source
