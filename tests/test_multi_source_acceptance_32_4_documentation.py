"""Keep Phase 32.4 evidence sources and unsupported claims explicit."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_32_4_records_remote_local_and_human_evidence_separately():
    record = (ROOT / "docs/multi_source_acceptance_32_4.md").read_text(encoding="utf-8")
    for expected in (
        "39902991518", "NOT_TESTED", "출력 이해도", "Safari", "Web Inspector",
        "Linux", "macOS", "2,528 passed", "79/79", "21/21", "70/70",
        "운영 SLA", "Cross-source", "exactly-once", "SIGKILL",
    ):
        assert expected in record
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "multi_source_acceptance_32_4.md" in index
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "multi_source_acceptance_32_4.md" in readme
