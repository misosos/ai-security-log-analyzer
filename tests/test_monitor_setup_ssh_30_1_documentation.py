"""Current SSH setup documentation stays aligned with the implemented boundary."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_current_setup_and_design_history_are_distinct() -> None:
    guide = (ROOT / "docs/monitor_setup_ssh_30_1.md").read_text(encoding="utf-8")
    plan = (ROOT / "docs/monitor_setup_ssh_design_30_0.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for token in (
        "4,096 byte", "16줄", "2,048 byte", "strict UTF-8", "FROM_END",
        "BOUNDED_REPLAY_V1", "FAIL_CLOSED", "0700", "0600", "no-clobber",
        "--show", "--delete", "--reset-checkpoint", "shell history", "원문",
        "계정", "IP", "hostname", "secure erase", "다중 source", "cross-source",
        "rotation/copytruncate", "exactly-once", "무유실", "탐지율",
    ):
        assert token in guide
    assert "후속 구현" in plan and "monitor_setup_ssh_30_1.md" in plan
    assert "설정 마법사는 아직 SSH 설정을 만들지 않습니다" not in readme
    assert "monitor_setup_ssh_30_1.md" in readme and "monitor_setup_ssh_30_1.md" in index
