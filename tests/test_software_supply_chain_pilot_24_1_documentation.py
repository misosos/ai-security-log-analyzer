"""Guard the observed Phase 24.1 limits without making scanner CI mandatory."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "docs" / "software_supply_chain_pilot_24_1.md"


def test_pilot_records_verification_and_real_observations():
    text = PILOT.read_text(encoding="utf-8")
    for statement in (
        "NO-GO", "v2.7.0", "bfe2f84abd2f09fe0b83ba7f6dad40d296762f40",
        "multiple.intoto.jsonl", "SLSA provenance v0.2", "macOS arm64",
        "Ubuntu에서 실행하지 않았다", "36,436,224 byte", "osv-scalibr/PyPI/all.zip",
        "37", "57", "hash 0/57", "license 0/57", "source artifact URL 0/57",
        "-L runtime.cdx.json", "-S", "DB 없는", "SCAN_INDETERMINATE", "0644",
        "finding 0건", "serialNumber", "Asia/Seoul", "source.path",
    ):
        assert statement in text
    assert "/Users/" not in text
    assert "/home/" not in text


def test_no_new_scanner_dependency_or_workflow_step():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = project["project"]["dependencies"] + project["dependency-groups"]["dev"]
    assert all("osv-scanner" not in item.lower() for item in deps)
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "osv-scanner" not in workflow.lower()
    assert "upload-artifact" not in workflow
    assert "contents: read" in workflow
    assert "--offline" in PILOT.read_text(encoding="utf-8")
