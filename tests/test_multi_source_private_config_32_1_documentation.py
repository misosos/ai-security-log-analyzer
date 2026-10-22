"""V3 configuration documentation must not imply that two-source runtime exists."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_scope_and_privacy_limits_are_explicit() -> None:
    text = (ROOT / "docs/multi_source_private_config_32_1.md").read_text(encoding="utf-8")
    for required in (
        "Phase 32.1A", "Phase 32.1B", "Phase 32.2", "Phase 32.3",
        "application", "SSH", "절대 경로", "checkpoint_name",
        "checkpoint_lock_name", "0700", "0600", "no-clobber",
        "v1", "v2", "UNSUPPORTED_SCHEMA", "미구현", "API·SSE·UI",
        "cross-source correlation", "PentAGI",
    ):
        assert required in text
    assert "multi_source_private_config_32_1.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")
