from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_14e_security_and_accessibility_record_is_complete() -> None:
    document = ROOT / "docs/investigation_review_workflow_state_security_accessibility_36_14e.md"
    assert document.is_file(), "Phase 36.14E security/accessibility evidence record is missing"
    text = document.read_text(encoding="utf-8")
    for required in (
        "41435552667",
        "TDD",
        "STALE_REVISION",
        "128",
        "다중 탭",
        "document memory",
        "Web Storage",
        "상태 API 요청 0건",
        "분석 불변성",
        "keyboard",
        "200%",
        "axe",
        "rollback",
        "11-reflow-200.png",
        "median/p95/max",
        "NOT_TESTED",
        "36.14F",
        "NO_GO",
    ):
        assert required in text


def test_rollback_switch_conditionally_loads_workflow_asset() -> None:
    app = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
    html = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
    assert "const REVIEW_WORKFLOW_STATE_UI_ENABLED = true;" in app
    assert 'if (REVIEW_WORKFLOW_STATE_UI_ENABLED) await import("/assets/investigation-review-state-36-14d.js");' in app
    assert '<script src="/assets/investigation-review-state-36-14d.js"' not in html
    assert '<script src="/assets/app.js" type="module"></script>' in html


def test_security_e2e_is_synthetic_and_bounds_runtime_requests() -> None:
    harness = (ROOT / "tests/ui_review_workflow_state_security_36_14e.mjs").read_text(encoding="utf-8")
    for required in (
        "launchPersistentContext(profile",
        "'127.0.0.1'",
        "WORKFLOW_PRIVATE_CANARY_36_14E",
        "STALE_REVISION",
        "129",
        "checklistPosts",
        "externalRequests",
        "390",
        "320",
        "'200%'",
    ):
        assert required in harness
