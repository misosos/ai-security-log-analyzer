from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_ci_recovery_36_6e.md"


def test_phase_36_6e_ci_recovery_records_failure_and_geometry_contract() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "611811ac2ba39272c33c3e91566a0eb7f747f419",
        "40828907926",
        "123298296537",
        "WORKSPACE_TASK_TAB_TARGET_SPACING_FAILED",
        "Linux CI 로그에는 사각형 좌표가 없",
        "44×44px",
        "200% equivalent",
        "160 KiB",
        "NOT_TESTED",
        "Phase 36.6F",
        "NO_GO",
    ):
        assert required in text


def test_browser_suite_checks_wrapped_target_separation_without_weakening_threshold() -> None:
    source = (ROOT / "tests" / "ui_accessibility_axe_pilot_28_1.mjs").read_text(encoding="utf-8")
    assert "function targetGapPx(first, second)" in source
    assert "TARGET_GAP_WRAPPED_ROW_GEOMETRY_FAILED" in source
    assert "TARGET_GAP_OVERLAP_NOT_DETECTED" in source
    assert "TARGET_GAP_SHORT_HORIZONTAL_NOT_DETECTED" in source
    assert "TARGET_GAP_SHORT_VERTICAL_NOT_DETECTED" in source
    assert "targetGapPx(layout.rects[index], rect) >= 8" in source
    assert "targetGapPx(taskTargets[0], taskTargets[1]) >= 8" in source
