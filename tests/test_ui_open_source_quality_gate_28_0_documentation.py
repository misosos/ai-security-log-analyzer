"""Phase 28.0 design must preserve the local UI and evaluation boundaries."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs" / "ui_open_source_quality_gate_28_0.md"


def test_gate_records_versioned_candidates_and_supply_chain_review():
    text = GATE.read_text(encoding="utf-8")
    for term in (
        "@axe-core/playwright` 4.14.0", "@playwright/test` 1.64.1",
        "govuk-frontend` 6.5.1", "Lucide release 1.59.0",
        "chart.js` 4.5.1", "uplot` 1.6.32",
        "@awesome.me/webawesome` 3.14.0", "Shoelace 2.20.1",
        "MPL-2.0", "Apache-2.0", "MIT", "ISC", "전이",
        "native", "install", "네트워크", "미검증",
    ):
        assert term in text


def test_gate_keeps_automation_manual_and_privacy_separate():
    text = GATE.read_text(encoding="utf-8")
    for term in (
        "dev/test 전용", "production JS/CSS/API", "초기 화면",
        "새 결과 대기", "명시적 결과 적용", "DEGRADED", "FAILED",
        "replay gap", "critical/serious", "WCAG 2.2 AA",
        "실제 Safari", "Keyboard-only", "200%", "VoiceOver",
        "DOM text", "CI 업로드하지 않는다", "임시 HOME/XDG_CONFIG_HOME",
        "raw data", "IP", "path/query", "EventSource", "CSP",
    ):
        assert term in text
    assert "https://www.w3.org/WAI/test-evaluate/tools/selecting/" in text
    assert "https://playwright.dev/docs/browsers" in text


def test_gate_describes_existing_code_without_changing_it():
    text = GATE.read_text(encoding="utf-8")
    ui = (ROOT / "app" / "web_ui.py").read_text(encoding="utf-8")
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    live = (ROOT / "frontend" / "live-monitoring.js").read_text(encoding="utf-8")
    assert "script-src 'self'" in ui
    assert "img-src 'none'" in ui
    assert "font-src 'none'" in ui
    assert 'src="/assets/live-monitoring.js"' in html
    assert "new EventSource(EVENTS_URL)" in live
    assert "새 결과 N건 보기" in text
    assert "schema" in text
    assert "설치" in text
