"""Phase 21.6 must not present an unproven handoff as supported."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_two_generation_recovery_gate_is_explicit() -> None:
    contract = (ROOT / "docs/live_rotation_21_6.md").read_text(encoding="utf-8")
    for term in (
        "NO-GO", "old writer", "EOF", "quiescence", "partial line",
        "copytruncate", "TOCTOU", "crash window", "256", "256 KiB",
        "Linux", "macOS", "개인정보", "보존 기간", "승인",
        "file_device", "file_inode", "replay_start_offset", "committed_offset",
    ):
        assert term.lower() in contract.lower()
    assert "live_rotation_21_6.md" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "live_rotation_21_6.md" in (
        ROOT / "docs/live_log_monitoring_design.md").read_text(encoding="utf-8")
