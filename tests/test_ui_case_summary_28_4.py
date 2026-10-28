"""Cases expose a short comparison first and preserve details on request."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
HTML = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
CSS = (ROOT / "frontend/style.css").read_text(encoding="utf-8")


def test_case_summary_is_compact_and_full_detail_is_route_scoped():
    assert "review-case-card" in APP
    assert 'function renderCaseOverview(cases)' in APP
    assert 'function renderCaseDetail(caseItem, index)' in APP
    assert 'id="case-detail-view"' in HTML
    assert 'id="case-list"' in HTML
    assert 'caseByRef.set(item.checklist_ref' in APP
    assert 'resultsDashboard.hidden = true' in APP
    assert 'caseDetailView.hidden = false' in APP
    assert "case-short-time" in APP
    assert "supporting_relation_count" in APP
    assert "function renderExactTimes(caseItem)" in APP
    assert 'entry.start_time.display_kst.slice(11, 19)' in APP
    assert 'function renderTimeline(caseItem)' in APP
    assert 'timeline-relation' in CSS
    assert '분석상 연결 · 인과관계 미확정' in APP
    assert 'history.pushState({reviewWorkspaceDetail: true}' in APP
    assert '상세 분석 보기' in APP
    assert 'function caseItemShortSummary(item)' in APP
    assert 'timeline-disclosure' not in APP
    assert 'function renderCaseOverview(cases)' in APP
    assert ".case-heading-row" in CSS


def test_result_rail_prioritizes_interpretation_and_preserves_report():
    assert 'id="result-interpretation"' in HTML
    assert 'id="capabilities-details"' in HTML
    assert 'id="report-download"' in HTML
    assert 'id="report-button"' in HTML
    assert 'id="independent-details"' in HTML
