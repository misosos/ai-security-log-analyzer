"""Cases expose a short comparison first and preserve details on request."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
HTML = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
CSS = (ROOT / "frontend/style.css").read_text(encoding="utf-8")


def test_case_summary_is_short_and_full_timeline_is_nested():
    assert "case-disclosure-label" in APP
    assert "case-short-time" in APP
    assert "supporting_relation_count" in APP
    assert "timeline-disclosure" in APP
    assert "시간순 기록" in APP and "건 보기" in APP
    assert "display_kst.slice(0, 19)" in APP
    assert "appendTime(time, caseItem.start_time, caseItem.end_time)" in APP
    assert "renderObservedSection(caseItem" in APP
    assert ".case-heading-row" in CSS


def test_result_rail_prioritizes_interpretation_and_preserves_report():
    assert 'id="result-interpretation"' in HTML
    assert 'id="capabilities-details"' in HTML
    assert 'id="report-download"' in HTML
    assert 'id="report-button"' in HTML
    assert 'id="independent-details"' in HTML
