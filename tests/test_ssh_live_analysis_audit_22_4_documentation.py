"""Phase 22.4 evidence must distinguish automated and manual acceptance."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ssh_audit_records_bounds_and_unverified_manual_work():
    record = (ROOT / "docs/ssh_live_analysis_audit_22_4.md").read_text(encoding="utf-8")
    for meaning in (
        "CONDITIONAL GO", "PASS", "PARTIAL", "NOT_TESTED", "NO-GO",
        "Safari 18.6 WebDriver", "keyboard-only", "Web Inspector", "23 fault ID",
        "ack 전", "ack 후", "FROM_END", "access는 detection-only",
        "SSH durable checkpoint", "rotation/copytruncate", "cross-source",
        "운영 SLA", "Trusted 내부 prefix", "tracemalloc", "status HTTP",
    ):
        assert meaning in record
    assert "Safari 18.6 WebDriver DOM click은 수동 검증을 대체하지 않는다" in record
    assert "계정 탈취, 동일 행위자 또는 인과관계를 증명하지 않는다" in record
