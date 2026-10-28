from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend/index.html").read_text(encoding="utf-8")
CSS = (ROOT / "frontend/style.css").read_text(encoding="utf-8")
APP = (ROOT / "frontend/app.js").read_text(encoding="utf-8")
LIVE = (ROOT / "frontend/live-monitoring.js").read_text(encoding="utf-8")


def test_workspace_has_named_navigation_and_single_selected_panel():
    assert 'id="workspace-nav"' in HTML
    assert 'aria-label="작업 영역"' in HTML
    for name in ("시작", "내 로그 분석", "Linux Audit", "결과"):
        assert name in HTML
    assert 'id="nav-live"' in HTML and "실시간 모니터링" in HTML
    assert 'id="nav-start"' in HTML and 'aria-current="page"' in HTML
    assert 'id="workspace-results"' in HTML
    assert 'function showView(' in APP
    assert 'panel.hidden = key !== view' in APP


def test_result_is_a_selected_workspace_view_after_explicit_action():
    assert 'window.workspaceNavigation.showResult("batch")' in APP
    assert 'window.workspaceNavigation.showResult("live")' in LIVE
    assert 'window.workspaceNavigation.setPending(' in LIVE
    assert 'id="live-results"' in HTML
    assert 'id="nav-live-badge"' in HTML
    assert 'id="nav-results"' in HTML
    assert 'id="result-empty"' in HTML
    assert 'caseSection.hidden = cases.length === 0' in APP
    assert 'independentDetails.hidden = observations.length === 0' in APP


def test_navigation_does_not_restart_stream_or_persist_analysis_state():
    assert 'new EventSource(EVENTS_URL)' in LIVE
    assert LIVE.count('new EventSource(EVENTS_URL)') == 1
    for source in (APP, LIVE):
        for forbidden in ("localStorage", "sessionStorage", "innerHTML", "insertAdjacentHTML"):
            assert forbidden not in source
    assert 'history.pushState({reviewWorkspaceDetail: true}' in APP
    assert 'history.pushState({reviewWorkspaceDetail: true}, "", `#/investigations/${caseRef}`)' in APP
    assert 'const match = /^#\\/investigations\\/(c_[0-9a-f]{24})$/' in APP
    assert "reviewListScrollY" in APP and "reviewFocusId" in APP


def test_responsive_navigation_is_text_based_and_does_not_fix_sidebar():
    assert '.workspace-nav' in CSS
    assert 'id="workspace-nav-details"' in HTML
    assert 'id="workspace-nav-toggle"' in HTML
    assert 'position: fixed' not in CSS
    assert '.app-shell' in CSS
    assert '@media (max-width:' in CSS
    assert 'id="nav-start"' in HTML and 'id="nav-results"' in HTML


def test_full_width_application_shell_and_start_choices():
    assert 'class="app-shell"' in HTML
    assert 'class="app-area"' in HTML
    assert 'class="app-content"' in HTML
    assert HTML.index('id="workspace-nav"') < HTML.index('class="site-header"') < HTML.index('id="main"')
    assert 'id="audit-choice-button"' in HTML
    assert HTML.count('class="action-card"') == 3
    assert 'class="site-footer"' not in HTML
    assert 'grid-template-columns: 240px minmax(0, 1fr)' in CSS
    assert '.shell { width: min(' not in CSS
    assert 'min-height: max(20rem' not in CSS
