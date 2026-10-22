"""Internal pair runtime evidence must stay distinct from public product support."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_32_1b_documented_scope_and_limits() -> None:
    document = ROOT / "docs/multi_source_runtime_32_1b.md"
    text = document.read_text(encoding="utf-8")
    for required in ("Phase 32.1A", "Phase 32.1B", "Phase 32.2", "Phase 32.3",
                     "application", "SSH", "256", "8,192", "100 ms",
                     "DEGRADED", "FAILED", "NO-GO", "--monitor", "API·SSE·UI",
                     "exactly-once", "cross-source"):
        assert required in text
    assert document.name in (ROOT / "docs/index.md").read_text(encoding="utf-8")
