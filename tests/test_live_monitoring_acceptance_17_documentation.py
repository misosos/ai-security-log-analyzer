"""Keep actual Safari acceptance distinct from automated evidence and release approval."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "docs/live_monitoring_acceptance_17.md"


def test_phase_17_records_environment_scoped_results_and_release_gate():
    text = ACCEPTANCE.read_text(encoding="utf-8")
    for marker in (
        "| 검수 항목 | 환경 | 판정 | 증거 | 남은 한계 |",
        "Safari 18.6", "WebDriver", "keyboard-only", "200%",
        "Web Inspector", "PASS", "PARTIAL", "NOT_TESTED", "BLOCKED",
        "CONDITIONAL GO", "릴리스 실행 GO는 아니다", "FROM_END",
        "observation_changes", "analysis_changes", "Last-Event-ID",
        "FAILED", "SIGINT", "listener", "임시 자료", "개인정보",
    ):
        assert marker in text
    assert "WebDriver의 DOM click·script" in text
    assert "사람의 실제 키보드" not in text or "대체" in text
    assert "WCAG 2.2 AA 준수 주장은 없다" in text
    for secret in (
        "SYNTHETIC_ACCOUNT_CANARY_P17", "SYNTHETIC_SOURCE_FILENAME_CANARY_P17",
        "RAW_LINE_CANARY_P17", "192.0.2.123",
    ):
        assert secret not in text


def test_phase_17_links_and_v02_release_gate_do_not_rewrite_v01_history():
    for name in (
        "README.md", "docs/live_log_monitoring_design.md",
        "docs/live_analysis_16_4_audit.md", "docs/release_checklist.md",
    ):
        assert "live_monitoring_acceptance_17.md" in (ROOT / name).read_text(encoding="utf-8")
    checklist = (ROOT / "docs/release_checklist.md").read_text(encoding="utf-8")
    assert "v0.1.0 역사적 판정과 별개" in checklist
    assert "v0.2.0 tag/Release 실행 여부를 별도 결정" in checklist
    assert "- [ ] 실제 사용자 Safari keyboard-only" in checklist


def test_phase_17_1_user_confirmation_is_separate_from_untested_gap():
    text = ACCEPTANCE.read_text(encoding="utf-8")
    current = text.split("## Phase 17.1 후속 사용자 직접 검수", 1)[1]
    for marker in (
        "904712d175a91f1bdb8d015bfa037b41ea1317c8",
        "38355709414", "1,991 passed",
        "keyboard-only", "Safari 페이지 확대 200%", "Web Inspector",
        "pause 중 append", "terminal", "실제 Safari replay gap 복구 화면",
        "NOT_TESTED", "CONDITIONAL GO", "active_connections 0",
        "CSS viewport", "VoiceOver", "WCAG 2.2 AA",
    ):
        assert marker in current
    assert "| 실제 Safari replay gap 복구 화면 | 사용자 직접 Safari | NOT_TESTED |" in current
    assert "| 화면 일시 정지 선택 | 사용자 직접 Safari | PASS |" in current
    assert "| 실제 Safari 페이지 확대 200%의 핵심 버튼·네 영역 사용성 | 사용자 직접 Safari | PASS |" in current
    assert "WebDriver" in current and "대체하지 않음" in current

    checklist = (ROOT / "docs/release_checklist.md").read_text(encoding="utf-8")
    latest = checklist.split("### Phase 17.1 사용자 직접 확인", 1)[1]
    assert "- [ ] 실제 Safari replay gap 화면" in latest
    assert "- [x] 사용자가 Safari keyboard-only" in latest
    assert "- [ ] 이번 검수 커밋의 원격 CI" in latest
