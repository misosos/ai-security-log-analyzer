"""Ubuntu evidence and untested human acceptance remain separate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_unified_setup_acceptance_records_evidence_and_limits() -> None:
    record = (ROOT / "docs/monitor_setup_acceptance_30_3.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    prior = (ROOT / "docs/monitor_setup_unified_audit_30_2.md").read_text(encoding="utf-8")
    for required in (
        "a8f046485d923db8b0f24e0c11e38054b76d7775", "39558109981",
        "Ubuntu 24.04", "46 passed", "2413 passed", "artifact", "0700", "0600",
        "application", "SSH", "checkpoint", "SSE", "advisory lock", "reset",
        "delete", "원본", "개인정보", "정리", "NOT_TESTED", "사용자 직접",
        "CHECKPOINT_REVIEW_GUIDANCE_FAILED", "CHECKPOINT_REVIEW_FALSE_ABSENCE",
        "pytrace=False", "fixture 소스 줄",
        "network filesystem", "SIGKILL", "rotation/copytruncate", "exactly-once",
        "Secure erase",
    ):
        assert required in record
    assert "monitor_setup_acceptance_30_3.md" in index
    assert "monitor_setup_acceptance_30_3.md" in prior
    assert "macOS application 사용자 흐름, SSH 사용자 흐름" in record
    assert "**NOT_TESTED**" in record
