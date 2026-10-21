"""Keep Safari user evidence distinct from automated accessibility results."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / "docs/ui_safari_acceptance_28_5.md").read_text(encoding="utf-8")
INDEX = (ROOT / "docs/index.md").read_text(encoding="utf-8")


def test_safari_acceptance_has_gate_and_manual_boundaries():
    for required in (
        "6df8bc3419a655456fb423d16a36d1b503ea7732",
        "39454069860", "Safari 18.6", "macOS 15.7.7", "PASS", "FAIL",
        "NOT_TESTED", "200%", "320 CSS px", "VoiceOver", "Web Inspector",
        "EventSource", "keyboard", "focus", "CSP", "개인정보", "SIGINT",
        "WCAG 2.2 AA", "2,378 passed", "79/79", "21/21", "70/70",
    ):
        assert required in DOC
    assert "ui_safari_acceptance_28_5.md" in INDEX


def test_safari_result_is_not_filled_from_automatic_checks():
    assert "자동 Chromium 검사와 이전 화면에 대한 PASS는 이 표의 Safari 결과가 아니다" in DOC
    assert "Safari WebDriver는 사용하지 않았고" in DOC
    assert "자동 Chromium 조작을 keyboard-only PASS 증거로 사용하지 않는다" in DOC
    assert "정확한 320 CSS px Safari 수동 검수 | NOT_TESTED" in DOC
    assert "VoiceOver 전체 페이지 읽기 | NOT_TESTED" in DOC
