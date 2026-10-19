"""A rename handoff must not be inferred from a temporary EOF or path change."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_rotation_handoff_gate_is_explicit() -> None:
    contract = (ROOT / "docs/live_rotation_21_5.md").read_text(encoding="utf-8")
    for term in (
        "NO-GO", "old writer", "EOF", "partial line", "256", "256 KiB",
        "copytruncate", "checkpoint", "ack", "publication", "replay",
        "inotify", "FSEvents", "exactly-once", "개인정보", "macOS", "Linux",
    ):
        assert term.lower() in contract.lower()
    for name in ("docs/index.md", "docs/live_log_monitoring_design.md",
                 "docs/local_collector_v030_design.md"):
        assert "live_rotation_21_5.md" in (ROOT / name).read_text(encoding="utf-8")
