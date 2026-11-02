from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_document_memory_store_module_is_present_and_exports_closed_contract() -> None:
    module = ROOT / "frontend/investigation-review-state-36-14d.js"
    assert module.is_file(), "Phase 36.14D document-memory store module is missing"
    text = module.read_text(encoding="utf-8")
    for token in (
        "createStore", "getRandomValues", "STALE_REVISION", "INVALID_TRANSITION",
        "UNKNOWN_ANALYSIS", "UNKNOWN_CASE", "reset", "MAX_CASES_PER_ANALYSIS",
    ):
        assert token in text
    assert "Math.random" not in text
    assert "localStorage" not in text
    assert "sessionStorage" not in text
    for forbidden in ("indexedDB", "document.cookie", "XMLHttpRequest", "fetch(", "fingerprint", "checkpoint", "src_ip", "hostname"):
        assert forbidden not in text
    for field in ("schema_version", "analysis_ref", "case_ref", "review_state", "revision"):
        assert field in text


def test_production_shell_has_explicit_workflow_rollback_and_ui_contract() -> None:
    app = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
    html = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
    queue = (ROOT / "frontend/review-queue-ui-36-13a.js").read_text(encoding="utf-8")
    assert "REVIEW_WORKFLOW_STATE_UI_ENABLED" in app
    assert "review state unavailable" in app.lower() or "검토 상태를 사용할 수 없습니다" in app
    assert "검토 상태" in html and "review-queue-state-36-14d" in html
    assert "review-queue-state-36-14d" in queue and "setWorkflowStateProvider" in queue
    assert "reviewWorkflowUi" in app


def test_fixed_workflow_asset_is_not_a_public_api_schema_change() -> None:
    from app.api import app as production_app

    paths = production_app.openapi()["paths"]
    assert "/assets/investigation-review-state-36-14d.js" not in paths
    assert "/api/v1/investigations/review-state" not in paths
