from pathlib import Path
from fastapi.testclient import TestClient
from app.api import create_app

ASSETS = ("/assets/evaluation-snapshot-validator-v1.js", "/assets/evaluation-review-viewer-v1.js", "/assets/evaluation-review-viewer-v1.css")


def _client(enabled):
    app = create_app(enable_evidence_review_viewer=enabled, evidence_review_port=8000 if enabled else None)
    return TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 1234))


def test_off_hides_every_evaluation_asset_and_html():
    client = _client(False)
    html = client.get("/").content
    assert html == Path("frontend/index.html").read_bytes()
    assert b"evaluation-review-root" not in html
    for path in (*ASSETS, "/assets/evaluation-snapshot-v1.json"):
        assert client.get(path).status_code == 404


def test_on_exposes_isolated_workspace_and_assets():
    client = _client(True)
    html = client.get("/").text
    assert 'id="evaluation-review-root"' in html
    assert 'id="nav-evaluation"' in html
    for path in ASSETS:
        assert client.get(path).status_code == 200


def test_browser_validator_is_separate_and_bounded():
    source = Path("frontend/evaluation-snapshot-validator-v1.js").read_text()
    assert "crypto.subtle.digest" in source
    assert "131072" in source


def test_enabled_html_preserves_live_script_when_live_service_is_present():
    from app.web_ui import serve_evaluation_index
    assert b'/assets/live-monitoring.js' in serve_evaluation_index(True).body
    assert b'/assets/live-monitoring.js' not in serve_evaluation_index(False).body


def test_viewer_avoids_dynamic_html_and_storage_sinks():
    source = Path("frontend/evaluation-review-viewer-v1.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "localStorage", "sessionStorage", "indexedDB", "eval(", "new Function"):
        assert forbidden not in source
