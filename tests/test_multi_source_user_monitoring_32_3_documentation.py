"""Document the implemented 32.3 boundary and keep human acceptance pending."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_phase_matrix_and_acceptance_status_are_explicit():
    text = (ROOT / "docs/multi_source_user_monitoring_32_3.md").read_text(encoding="utf-8")
    for expected in ("32.1A", "32.1B", "32.2", "32.3", "schema 2", "schema 3",
                     "NOT_TESTED", "Safari", "cross-source", "exactly-once",
                     "benchmark_multi_source_user_flow_32_3.py", "soak_multi_source_32_3.py"):
        assert expected in text
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "multi_source_user_monitoring_32_3.md" in index
    assert "safari_multi_source_acceptance_32_3.md" in index


def test_user_guide_never_claims_rotation_or_cross_source_support():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for expected in ("--multi-source", "--role application", "Rotation/copytruncate",
                     "cross-source 분석", "exactly-once"):
        assert expected in readme
