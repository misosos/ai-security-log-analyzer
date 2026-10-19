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


def test_readme_keeps_manual_ssh_setup_and_legacy_runtime_distinct() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/ssh_checkpoint_recovery_26_0.md" in readme
    assert "마법사는 아직 SSH 설정을 생성하지 않습니다" in readme
    assert "SSH의 명시적 v1 설정은 checkpoint 없이" in readme
    assert "rotation·truncation은 자동 복구하지 않고 중단" in readme
