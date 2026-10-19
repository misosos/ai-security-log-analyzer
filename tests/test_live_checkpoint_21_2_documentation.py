"""Phase 21.2's bounded ownership and crash-window claims stay explicit."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_checkpoint_21_2_contract_is_linked_and_bounded() -> None:
    contract = (ROOT / "docs/live_checkpoint_21_2.md").read_text(encoding="utf-8")
    for term in ("CHECKPOINT_UNSAFE", "CHECKPOINT_FAILED_AFTER_PUBLICATION",
                 "FIFO", "atomic replace", "parent fsync", "post-read",
                 "과거 publication 억제", "NOT_TESTED", "exactly-once"):
        assert term.lower() in contract.lower()
    for name in ("docs/index.md", "docs/live_checkpoint_21.md",
                 "docs/local_collector_v030_design.md"):
        assert "live_checkpoint_21_2.md" in (ROOT / name).read_text(encoding="utf-8")
