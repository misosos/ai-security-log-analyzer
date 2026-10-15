"""New-epoch reset must stay an explicit, bounded local CLI operation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_21_7_contract_is_linked_and_bounded() -> None:
    contract = (ROOT / "docs/live_checkpoint_epoch_reset_21_7.md").read_text(encoding="utf-8")
    for term in (
        "--reset-checkpoint", "y/yes", "FROM_END", "fail closed", "checkpoint",
        "원본 로그", "설정", "SSE", "rotation", "copytruncate", "0700", "0600",
        "TOCTOU", "secure erase", "backup", "crash dump", "동시", "승인",
    ):
        assert term.lower() in contract.lower()
    for file in ("README.md", "docs/monitor_setup_20.md", "docs/live_checkpoint_21.md"):
        assert "live_checkpoint_epoch_reset_21_7.md" in (ROOT / file).read_text(encoding="utf-8")
