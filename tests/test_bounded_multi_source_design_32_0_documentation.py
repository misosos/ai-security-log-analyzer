"""Keep the two-source proposal bounded and separate from implemented support."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/bounded_multi_source_monitoring_32_0.md"


def test_phase_31_is_closed_without_pentagi_execution() -> None:
    record = (ROOT / "docs/disposable_vm_isolation_31_2a.md").read_text(encoding="utf-8")
    for required in (
        "Phase 31 최종 판정", "Phase 31.2B: NO-GO", "3/3",
        "SOURCE_IMAGE_BINDING_UNPROVEN", "Docker socket", "runtime download",
        "callback", "LLM", "egress", "데이터 보존", "production dependency",
    ):
        assert required in record


def test_design_has_bounded_separate_contracts() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    for required in (
        "설계 gate", "application 최대 1개", "SSH 최대 1개", "총 2개",
        "schema_version", "v1", "v2", "자동 migration 금지",
        "source별", "round-robin", "global byte", "global time",
        "ack 전", "ack 후", "checkpoint", "reset", "delete",
        "observation_changes", "analysis_changes", "replay gap",
        "256-event", "0.5초", "p95", "Hypothesis", "Safari",
        "Phase 32.1", "NO-GO", "PentAGI", "access", "Linux Audit",
    ):
        assert required in text
    assert "bounded_multi_source_monitoring_32_0.md" in (ROOT / "docs/index.md").read_text(encoding="utf-8")


def test_design_does_not_claim_product_support_or_raw_publication() -> None:
    text = DESIGN.read_text(encoding="utf-8")
    for forbidden in ("구현 완료", "운영 SLA 보장", "exactly-once 보장", "무유실 보장"):
        assert forbidden not in text
    assert "raw event SSE 금지" in text
