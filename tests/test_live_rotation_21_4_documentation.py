"""The pre-ack source check is bounded, not a rotation recovery claim."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pre_ack_rotation_boundary_is_documented() -> None:
    contract = (ROOT / "docs/live_rotation_21_4.md").read_text(encoding="utf-8")
    for term in (
        "SOURCE_CHANGED_BEFORE_ACK", "FIFO release", "DEGRADED", "queue ack",
        "checkpoint", "publication", "truncate", "재성장", "race",
        "exactly-once", "Linux", "Safari",
    ):
        assert term.lower() in contract.lower()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/live_log_monitoring_design.md").read_text(encoding="utf-8")
    assert "docs/live_rotation_21_4.md" in readme
    assert "live_rotation_21_4.md" in design
    assert "자동 rotation 복구" in readme
