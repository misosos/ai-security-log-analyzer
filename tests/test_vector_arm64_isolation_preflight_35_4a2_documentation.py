from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_arm64_preflight_record_has_gate_host_resource_and_isolation_evidence():
    doc = (ROOT / "docs/vector_arm64_isolation_preflight_35_4a2.md").read_text()
    for phrase in (
        "572a9e38e9fe4a22f17f4e645f3db214b12d9028",
        "40462392016",
        "Ubuntu 24.04.5 LTS",
        "aarch64",
        "NAT",
        "ISOLATION_BLOCKED",
        "RESOURCE_BLOCKED",
        "USER_ACTION_REQUIRED",
        "Vector는 실행하지 않았다",
        "UNRESOLVED",
        "3건",
        "NO_GO",
    ):
        assert phrase in doc
    for heading in (
        "## Start Gate",
        "## Platform Decision",
        "## ARM64 Artifact Preflight",
        "## Static Binary Inspection",
        "## Disk and Resource Budget",
        "## VMware Host Inventory",
        "## Guest Inventory Procedure",
        "## Network Isolation Procedure",
        "## Non-root and Resource Limits",
        "## Configuration and Wire Fixtures",
        "## Decision and Remaining Actions",
    ):
        assert heading in doc


def test_plan_and_prior_preflight_distinguish_x86_static_from_arm64_target():
    plan = (ROOT / "docs/vector_isolated_integration_plan_35_4.md").read_text()
    old = (ROOT / "docs/vector_artifact_preflight_35_4a.md").read_text()
    assert "first execution target is Ubuntu 24.04 ARM64" in plan
    assert "x86_64 static preflight remains recorded" in plan
    assert "Ubuntu 24.04.5 LTS aarch64" in old
    assert "VMX" in (ROOT / "docs/vector_arm64_isolation_preflight_35_4a2.md").read_text()
    assert "ISOLATION_BLOCKED" in old


def test_readme_and_index_report_arm64_gate_without_claiming_execution():
    for relative in ("README.md", "docs/index.md"):
        text = (ROOT / relative).read_text()
        assert "ARM64" in text
        assert "미실행" in text
        assert "ISOLATION_BLOCKED" in text
