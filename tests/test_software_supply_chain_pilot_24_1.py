"""Bounded local inventory checks; no scanner or network is invoked in pytest."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from scripts.supply_chain_pilot_24_1 import inspect_sbom, inspect_scan


ROOT = Path(__file__).resolve().parents[1]


def _export(path: Path, *, timezone: str, development: bool) -> dict:
    command = [
        "uv", "export", "--quiet", "--preview-features", "sbom-export",
        "--locked", "--offline", "--format", "cyclonedx1.5",
        "--output-file", str(path),
    ]
    if not development:
        command.append("--no-dev")
    result = subprocess.run(
        command, cwd=ROOT, env={**os.environ, "TZ": timezone},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, timeout=10, check=False, preexec_fn=lambda: os.umask(0o077),
    )
    assert result.returncode == 0, "fixed local SBOM export failed"
    assert path.stat().st_mode & 0o777 == 0o600
    return json.loads(path.read_text(encoding="utf-8"))


def test_locked_uv_export_separates_groups_and_canonical_inventory(tmp_path):
    runtime_utc = _export(tmp_path / "runtime-utc.json", timezone="UTC", development=False)
    runtime_kst = _export(tmp_path / "runtime-kst.json", timezone="Asia/Seoul", development=False)
    dev_utc = _export(tmp_path / "dev-utc.json", timezone="UTC", development=True)
    dev_kst = _export(tmp_path / "dev-kst.json", timezone="Asia/Seoul", development=True)
    runtime = inspect_sbom(runtime_utc)
    dev = inspect_sbom(dev_utc)
    assert runtime.component_count == 37
    assert dev.component_count == 57
    assert runtime.dependency_count == 38
    assert dev.dependency_count == 58
    assert runtime.canonical_sha256 == inspect_sbom(runtime_kst).canonical_sha256
    assert dev.canonical_sha256 == inspect_sbom(dev_kst).canonical_sha256
    runtime_names = {item["name"] for item in runtime_utc["components"]}
    dev_names = {item["name"] for item in dev_utc["components"]}
    assert runtime_names < dev_names
    assert {"hypothesis", "schemathesis"}.isdisjoint(runtime_names)
    assert {"hypothesis", "schemathesis"} <= dev_names
    # This is a pilot blocker, not an assertion that hashes/licenses are optional.
    assert not runtime.has_all_hashes and not dev.has_all_hashes
    assert not runtime.has_all_licenses and not dev.has_all_licenses


def test_sbom_rejects_private_metadata_and_missing_inventory():
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root", "name": "synthetic", "version": "1"}},
        "components": [{"bom-ref": "pkg", "name": "synthetic", "version": "1",
                        "purl": "pkg:pypi/synthetic@1"}],
        "dependencies": [{"ref": "root", "dependsOn": ["pkg"]}],
    }
    assert inspect_sbom(document).component_count == 1
    document["metadata"]["private"] = "/Users/private/monitor-config"
    with pytest.raises(ValueError, match="SBOM_PRIVATE_METADATA"):
        inspect_sbom(document)
    document["metadata"].pop("private")
    for canary in (
        "SYNTHETIC_ACCOUNT_CANARY", "198.51.100.42",
        "?synthetic_query=CANARY", "SYNTHETIC_RAW_LINE_CANARY",
        "SYNTHETIC_CREDENTIAL_CANARY",
    ):
        document["metadata"]["private"] = canary
        with pytest.raises(ValueError, match="SBOM_PRIVATE_METADATA"):
            inspect_sbom(document, forbidden=(canary,))
    document["metadata"].pop("private")
    document["metadata"]["private"] = "/private/var/folders/synthetic-private"
    with pytest.raises(ValueError, match="SBOM_PRIVATE_METADATA"):
        inspect_sbom(document)
    document["metadata"].pop("private")
    document["components"] = []
    with pytest.raises(ValueError, match="SBOM_INVALID"):
        inspect_sbom(document)


def test_scanner_status_requires_extracted_packages_and_matching_exit_code():
    clean = {"results": [{"packages": [{"package": {"name": "synthetic"}}]}]}
    finding = {"results": [{"packages": [{"package": {"name": "synthetic"},
                                           "vulnerabilities": [{"id": "OSV-SYNTHETIC"}]}]}]}
    assert inspect_scan(0, clean, 1).state == "ZERO_FINDINGS"
    assert inspect_scan(1, finding, 1).state == "FINDINGS"
    for exit_code, report, expected in (
        (127, {}, 1), (128, {}, 1), (0, {"results": []}, 1),
        (0, clean, 2), (1, clean, 1), (0, finding, 1),
    ):
        assert inspect_scan(exit_code, report, expected).state == "SCAN_INDETERMINATE"
