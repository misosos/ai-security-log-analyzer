"""Keep the Phase 16.4 acceptance scope and limitations discoverable."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs/live_analysis_16_4_audit.md"


def test_audit_has_traceability_and_non_success_states():
    text = AUDIT.read_text(encoding="utf-8")
    for marker in (
        "## 요구사항 추적성", "## 하나의 application runtime 흐름",
        "## Replay·복구와 실패 경계", "## 개인정보 및 브라우저 범위",
        "## 성능 — 개발용 합성 측정", "## 판정과 릴리스 경계",
        "PASS", "PARTIAL", "NOT_TESTED", "CONDITIONAL GO",
        "observation_changes", "analysis_changes", "Last-Event-ID",
        "256", "128KiB", "16KiB", "keyboard-only", "tracemalloc",
    ):
        assert marker in text
    assert "운영 SLA가 아니다" in text
    assert "exactly-once" in text
    assert "WCAG 2.2 AA 준수 주장을 하지 않는다" in text


def test_current_docs_link_to_audit_without_declaring_broader_live_scope():
    for name in ("README.md", "docs/live_log_monitoring_design.md",
                 "docs/live_analysis_correlation_case_design.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "live_analysis_16_4_audit.md" in text
    text = AUDIT.read_text(encoding="utf-8")
    assert "SSH/access live analysis, cross-source" in text
    for private_value in ("ACCOUNT_PRIVATE_CANARY", "PRIVATE_EXCEPTION_CANARY", "192.0.2.123"):
        assert private_value not in text
