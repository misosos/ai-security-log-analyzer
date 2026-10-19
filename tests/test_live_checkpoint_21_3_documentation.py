"""The process-restart acceptance contract remains linked and honest."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_process_restart_acceptance_contract() -> None:
    contract = (ROOT / "docs/live_checkpoint_21_3.md").read_text(encoding="utf-8")
    for term in (
        "FROM_END", "Last-Event-ID", "FOREIGN_SESSION", "published_total=0",
        "observation_changes", "analysis_changes", "CASE-BRUTE-SUCCESS-01",
        "2^53-1", "충돌 확률", "exactly-once", "rotation/truncation",
        "Safari", "전원 손실",
    ):
        assert term in contract
    for name in ("docs/index.md", "docs/live_log_monitoring_design.md"):
        assert "live_checkpoint_21_3.md" in (ROOT / name).read_text(encoding="utf-8")
