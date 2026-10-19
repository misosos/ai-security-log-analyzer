"""Observed truncation is not automatic rotation recovery."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_current_rotation_boundary_is_explicit_and_linked() -> None:
    contract = (ROOT / "docs/live_rotation_21_1.md").read_text(encoding="utf-8")
    for term in ("SOURCE_TRUNCATED", "read offset", "checkpoint", "ack",
                 "copytruncate", "재성장", "fail-closed", "자동 rotation"):
        assert term.lower() in contract.lower()
    for name in ("docs/index.md", "docs/local_collector_v030_design.md",
                 "docs/live_checkpoint_21.md"):
        assert "live_rotation_21_1.md" in (ROOT / name).read_text(encoding="utf-8")
    assert "무유실" in contract and "보장 없음" in contract


def test_phase_19_example_remains_historical_not_current_policy() -> None:
    design = (ROOT / "docs/local_collector_v030_design.md").read_text(encoding="utf-8")
    assert "Phase 19 제안 당시의 `DISABLED` 예시" in design
    assert "`DISABLED`와 `BOUNDED_REPLAY_V1`" in design
    assert "Phase 21에서 같은 파일의 durable bounded checkpoint까지 구현" in design
