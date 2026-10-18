"""Keep the Phase 24.0 supply-chain gate tied to this checkout's scope."""

from pathlib import Path
import re
import tomllib


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs" / "software_supply_chain_gate_24_0.md"


def test_gate_selects_a_conditional_local_lock_and_sbom_pilot():
    text = GATE.read_text(encoding="utf-8")
    assert "CONDITIONAL GO" in text
    assert "OSV-Scanner v2.7.0" in text
    assert "uv 0.11.26" in text
    assert "uv.lock" in text
    assert "CycloneDX 1.5" in text
    assert "preview" in text
    assert "SUPPLY_CHAIN_BLOCKED" in text
    for boundary in (
        "runtime/dev", "macOS", "Ubuntu", "offline", "DB", "attestation",
        "license", "provenance", "SCAN_INDETERMINATE",
    ):
        assert boundary in text
    assert "finding 0건을 주장하지 않는다" in text


def test_gate_covers_candidate_tradeoffs_and_data_boundary():
    text = GATE.read_text(encoding="utf-8")
    for candidate in (
        "pip-audit", "OSV-Scanner", "Syft", "Grype", "Trivy",
        "CycloneDX Python", "Dependabot Core", "dependency review action",
        "CodeQL",
    ):
        assert candidate in text
    for boundary in (
        "secret candidate", "실제 로그", "monitor config", "checkpoint",
        "SBOM", "source", "GitHub artifact", "Release asset", "secure erase",
        "pull_request_target", "contents: read",
    ):
        assert boundary in text
    assert "finding 없음은 안전 증명이 아니다" in text
    assert "ID·정확한 package/version 범위·이유·reviewer·만료일" in text


def test_current_project_is_source_checkout_without_new_scanner_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = project["project"]["dependencies"]
    dev = project["dependency-groups"]["dev"]
    assert len(runtime) == 6
    assert "hypothesis==6.170.0" in dev
    assert "schemathesis==4.31.1" in dev
    assert not any(
        scanner in item.lower()
        for item in runtime + dev
        for scanner in ("osv-scanner", "pip-audit", "syft", "grype", "trivy", "cyclonedx")
    )
    assert not (ROOT / "package.json").exists()
    assert not (ROOT / "Dockerfile").exists()
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "permissions:\n  contents: read" in workflow
    assert "pull_request_target" not in workflow
    assert "upload-artifact" not in workflow
    assert "osv-scanner" not in workflow.lower()
    assert len(re.findall(r"uses: [^\s]+@[0-9a-f]{40}\b", workflow)) >= 2
