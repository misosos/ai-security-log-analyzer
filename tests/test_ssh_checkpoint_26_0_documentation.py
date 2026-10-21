"""Guard the narrow SSH checkpoint contract and historical compatibility."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "docs" / "ssh_checkpoint_recovery_26_0.md"


def test_ssh_checkpoint_documented_scope_and_privacy() -> None:
    document = DOCUMENT.read_text(encoding="utf-8")
    for contract in (
        "private 기본 위치", "BOUNDED_REPLAY_V1", "FROM_END",
        "명시적 v1 SSH", "application v2 checkpoint", "schema version 1",
        "256 완성 줄", "256 KiB", "이전 SSE", "ack 전", "ack 뒤",
        "source_role", "config role", "raw line", "계정·IP", "0700/0600",
        "rotation", "copytruncate", "exactly-once", "Ubuntu", "CONDITIONAL GO",
    ):
        assert contract in document


def test_readme_links_ssh_checkpoint_and_historical_manual_setup() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/ssh_checkpoint_recovery_26_0.md" in readme
    assert "설정 마법사는 아직 SSH 설정을 만들지 않는다" in (ROOT / "docs/releases/v0.3.0.md").read_text(encoding="utf-8")
    assert "명시적 v1 SSH" in (ROOT / "docs/ssh_checkpoint_recovery_26_0.md").read_text(encoding="utf-8")
    assert "Rotation·copytruncate의 자동 연결은 없습니다" in readme
