import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_preflight_document_has_required_evidence_and_decision_sections():
    doc = (ROOT / "docs/vector_artifact_preflight_35_4a.md").read_text()
    for heading in (
        "## Start Gate",
        "## Artifact Identity and Download",
        "## Archive and Binary Inspection",
        "## Disk and Resource Budget",
        "## Closed Vector Configuration Candidate",
        "## `vector validate` Static Review",
        "## Isolation Procedure and Decision",
        "## Wire Fixtures and Boundaries",
        "## Local Verification",
        "## Limitations",
        "## Official Sources Checked",
    ):
        assert heading in doc
    assert "40455658366" in doc
    assert "COLLECTOR_JSONL_LINUX_ACCEPTANCE_PASS roles=2 runs=80 synthetic=1 leaks=0" in doc
    assert "ISOLATION_BLOCKED" in doc
    assert "NO_GO" in doc
    assert "2,948 passed, 1 failed, 2 existing warnings" in doc
    assert "isolated diagnostic run of that test passed" in doc


def test_preflight_manifest_has_closed_non_placeholder_values():
    manifest = json.loads(
        (ROOT / "docs/artifacts/vector_0_60_0_x86_64_preflight.json").read_text()
    )
    assert set(manifest) == {
        "schema_version", "product", "version", "tag", "source_commit", "release",
        "observed_platform", "artifact", "archive_inspection", "binary", "cleanup",
        "resource_budget", "configuration_validation", "decision",
    }
    assert manifest["decision"] == "ISOLATION_BLOCKED"
    assert manifest["cleanup"]["vector_process_created"] is False
    assert manifest["cleanup"]["temporary_archive_and_staging_removed"] is True
    assert len(manifest["archive_inspection"]["members"]) == manifest["archive_inspection"]["member_count"]
    assert max(map(lambda item: len(item.encode()), manifest["archive_inspection"]["members"])) == (
        manifest["archive_inspection"]["max_member_path_bytes"]
    )
    for value in manifest["artifact"]["sha256"]:
        assert value in "0123456789abcdef"
