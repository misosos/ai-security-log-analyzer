from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "enterprise_log_collection_architecture_35_0.md"


def test_phase_35_architecture_has_required_sections_and_decision():
    text = DOC.read_text(encoding="utf-8")
    for section in (
        "## Decision", "## Current Evidence", "## Candidate Comparison",
        "## Proposed Architecture", "## Data Contract", "## Trust Boundaries",
        "## Failure Semantics", "## Privacy", "## AI Assistance Boundary",
        "## Supply Chain", "## Verification Plan", "## Limitations",
        "## Phase 35.1 Entry Criteria",
    ):
        assert section in text
    assert "Vector 0.60.0" in text
    assert "CONDITIONAL_GO" in text
    assert "NOT_TESTED" in text
    assert "NO_GO" in text


def test_candidate_matrix_and_envelope_are_closed_and_evidence_bounded():
    text = DOC.read_text(encoding="utf-8")
    for candidate in ("Fluent Bit", "Vector", "OpenTelemetry Collector", "자체 TCP", "file tail"):
        assert candidate in text
    for field in (
        "schema_version", "source_role", "event_time", "collector_instance_alias",
        "sequence_hint", "payload_length", "payload", "truncation", "possibly_retried",
    ):
        assert field in text
    assert "sequence_hint" in text and "exactly-once ID가 아니다" in text
    assert "실제 사용자 자료" in text and "설치·다운로드·실행하지 않았다" in text
    assert "2026-10-26" in text


def test_phase_34_closure_and_documentation_links_are_current():
    acceptance = (ROOT / "docs/loopback_tcp_syslog_management_acceptance_34_5.md").read_text(encoding="utf-8")
    phase_34 = (ROOT / "docs/automatic_log_collection_design_34_0.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    assert "합성 loopback 관리 pilot: `GO`" in acceptance
    assert "실제 사용자 자료·조직 운영: `NO_GO`" in acceptance
    assert "enterprise_log_collection_architecture_35_0.md" in phase_34
    assert "docs/index.md" in readme
    assert "enterprise_log_collection_architecture_35_0.md" in index
