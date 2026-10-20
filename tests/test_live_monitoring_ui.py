"""Static safety contract and deterministic Node behavior for the optional live UI."""

from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess

from fastapi.testclient import TestClient

from app.api import create_app


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "frontend" / "index.html"
JS = ROOT / "frontend" / "live-monitoring.js"
CSS = ROOT / "frontend" / "style.css"
ACCEPTANCE = ROOT / "docs" / "live_monitoring_acceptance_15_1.md"


class _Nodes(HTMLParser):
    def __init__(self):
        super().__init__()
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        self.nodes.append((tag, dict(attrs)))


def test_live_area_is_separate_accessible_and_hidden_until_status():
    source = HTML.read_text(encoding="utf-8")
    parser = _Nodes()
    parser.feed(source)
    by_id = {attrs["id"]: (tag, attrs) for tag, attrs in parser.nodes if "id" in attrs}
    assert by_id["live-monitoring"][0] == "section"
    assert "hidden" in by_id["live-monitoring"][1]
    assert by_id["live-heading"][0] == "h2"
    for key in ("live-show-pending", "live-pause", "live-reconnect"):
        assert by_id[key][0] == "button"
        assert by_id[key][1]["type"] == "button"
    assert by_id["live-connection-state"][1] == {
        "id": "live-connection-state", "role": "status", "aria-live": "polite",
    }
    assert by_id["live-pending-status"][1]["aria-live"] == "polite"
    assert by_id["live-observations"][0] == "ol"
    assert "표시가 일시 정지돼도 서버 수집은 계속됩니다" in source
    assert "안전이나 해결을 뜻하지 않습니다" in source
    assert "침해 확정이나 공격 성공의 증거가 아닙니다" in source
    assert 'src="/assets/live-monitoring.js"' in source


def test_live_script_is_fixed_self_hosted_asset_only_in_demo_app():
    with TestClient(create_app()) as client:
        response = client.get("/assets/live-monitoring.js")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/javascript")
        assert response.headers["cache-control"] == "no-store"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert client.get("/api/v1/live/status").json()["error_code"] == "LIVE_MONITORING_NOT_ENABLED"
        assert "/assets/live-monitoring.js" not in client.get("/openapi.json").json()["paths"]
    source = (ROOT / "app" / "api.py").read_text(encoding="utf-8")
    assert 'if not enable_linux_audit_api:' in source
    assert '"/assets/live-monitoring.js", serve_live_monitoring_script' in source


def test_live_script_has_no_unsafe_dom_storage_or_remote_resource():
    source = JS.read_text(encoding="utf-8")
    for token in (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
        "new Function", "localStorage", "sessionStorage", "indexedDB", "document.cookie",
        "serviceWorker", "console.log", "console.error", "http://", "https://",
        "setTimeout(", "setInterval(",
    ):
        assert token not in source
    assert 'const STATUS_URL = "/api/v1/live/status"' in source
    assert 'const EVENTS_URL = "/api/v1/live/events"' in source
    assert "new EventSource(EVENTS_URL)" in source
    assert "document.createElement" in source
    assert ".textContent" in source
    assert "MAX_PENDING_ITEMS = 32" in source
    assert "MAX_PENDING_BYTES = 16384" in source
    assert "new TextEncoder()" in source
    assert "window.addEventListener(\"pagehide\", closeSource)" in source
    css = CSS.read_text(encoding="utf-8")
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "overflow-wrap: anywhere" in css
    assert re.search(r"@media \(max-width: 42rem\)", css)


def test_live_ui_node_behavior():
    completed = subprocess.run(
        ["node", "tests/live_monitoring_ui_behavior.cjs"], cwd=ROOT,
        capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_phase_15_1_acceptance_record_separates_actual_and_untested_checks():
    record = ACCEPTANCE.read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "live_monitoring_acceptance_15_1.md" in index
    for label in ("PASS", "FAIL", "NOT_TESTED", "BLOCKED", "CONDITIONAL GO"):
        assert label in record
    assert "WebDriver" in record
    assert "keyboard-only" in record
    assert "200%" in record
    assert "320 CSS px" in record
    assert "콘솔" in record
    assert "수동 재연결" in record
    assert "WCAG 2.2 AA 준수" in record
