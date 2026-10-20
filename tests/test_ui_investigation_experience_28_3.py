from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
LIVE = (ROOT / "frontend" / "live-monitoring.js").read_text(encoding="utf-8")


def test_first_choice_and_secondary_details_are_clear():
    assert "예시 데이터로 둘러보기" in HTML
    assert 'id="local-choice-button"' in HTML
    assert "내 로그 분석하기" in HTML
    assert 'id="local-choice-details"' in HTML
    assert '<details class="first-visit-details secondary-details"' in HTML
    assert "로컬에서" in HTML and "침해 확정" in HTML
    assert "합성 상태 표시" not in HTML


def test_default_result_and_live_density_is_bounded():
    summary = APP.split("function renderSummary(data)", 1)[1].split("function renderCaseOverview", 1)[0]
    assert len(re.findall(r'^\s*\["[^\"]+", data\.', summary, re.M)) <= 4
    assert 'card.open = item.included_highest_risk' not in APP
    assert 'id="live-result-details"' in HTML
    assert 'id="independent-details"' in HTML
    assert "연결과 처리 세부" in HTML


def test_internal_live_copy_is_not_rendered():
    assert " · revision ${" not in LIVE
    assert "게시 기록 ${" not in LIVE
    assert "새 결과 변경 ${" not in LIVE
    assert "현재 활성 관찰 ${" not in LIVE
    assert "일부 기록을 이어받지 못" in LIVE
