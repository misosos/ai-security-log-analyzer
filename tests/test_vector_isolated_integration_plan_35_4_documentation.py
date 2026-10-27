from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/vector_isolated_integration_plan_35_4.md"


def test_vector_isolated_plan_records_exact_linux_acceptance_and_scope() -> None:
    text = PLAN.read_text(encoding="utf-8")
    for required in (
        "Decision",
        "Current Evidence",
        "Candidate Platform",
        "Topology",
        "Configuration Contract",
        "Wire Acceptance",
        "Isolation Gate",
        "Resource Budget",
        "Failure Semantics",
        "Privacy and AI Boundary",
        "Phase 35.4 Entry Criteria",
        "40452774780",
        "5cdf941291204a48edace62a25c1e1fbe3350a75",
        "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0",
        "0d0b35865036f8b5c2f0104d9744fa84985ffff1",
        "artifacts/vector_0_60_0_manifest.json",
        "CHECKSUM_ONLY_ACCEPTED_FOR_ISOLATED_PILOT",
        "UNRESOLVED",
        "NO_GO",
        "NOT_TESTED",
        "binary was never executed",
    ):
        assert required in text

    assert "89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc" in text
    assert "58,655,370 bytes" in text
    assert "JSONL runtime" in text


def test_acceptance_record_is_updated_only_with_confirmed_remote_evidence() -> None:
    text = (ROOT / "docs/collector_jsonl_runtime_linux_acceptance_35_3a.md").read_text(
        encoding="utf-8"
    )
    assert "40452774780" in text
    assert "5cdf941291204a48edace62a25c1e1fbe3350a75" in text
    assert "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0" in text
    assert "JSONL runtime의 합성 Ubuntu 수용 범위만 `GO`" in text


def test_project_entry_points_link_the_new_plan_and_preserve_no_go() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for text in (readme, index):
        assert "vector_isolated_integration_plan_35_4.md" in text
        assert "Vector 실제 연동" in text or "Vector 실행" in text
        assert "NO_GO" in text
