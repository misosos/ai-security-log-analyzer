"""Development-only checks for private CycloneDX and OSV pilot evidence.

This module neither invokes a scanner nor reads repository or user files.
Callers must keep input SBOMs and scanner JSON in private temporary storage.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any


@dataclass(frozen=True)
class SbomEvidence:
    component_count: int
    dependency_count: int
    has_all_hashes: bool
    has_all_licenses: bool
    canonical_sha256: str


@dataclass(frozen=True)
class ScanEvidence:
    state: str
    package_count: int
    vulnerability_count: int


def inspect_sbom(document: dict[str, Any], *, forbidden: tuple[str, ...] = ()) -> SbomEvidence:
    """Validate the inventory graph without returning paths or raw components."""
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM_INVALID")
    if document.get("specVersion") != "1.5":
        raise ValueError("SBOM_INVALID")
    components = document.get("components")
    dependencies = document.get("dependencies")
    if not isinstance(components, list) or not isinstance(dependencies, list):
        raise ValueError("SBOM_INVALID")
    if not components or not all(isinstance(item, dict) for item in components):
        raise ValueError("SBOM_INVALID")
    refs = {item.get("bom-ref") for item in components}
    if None in refs or len(refs) != len(components):
        raise ValueError("SBOM_INVALID")
    if not all(
        isinstance(item.get("name"), str)
        and isinstance(item.get("version"), str)
        and isinstance(item.get("purl"), str)
        and item["purl"].startswith("pkg:pypi/")
        for item in components
    ):
        raise ValueError("SBOM_INVALID")
    root = document.get("metadata", {}).get("component", {}).get("bom-ref")
    known = refs | {root}
    if root is None or not all(
        isinstance(item, dict)
        and item.get("ref") in known
        and isinstance(item.get("dependsOn", []), list)
        and all(ref in known for ref in item.get("dependsOn", []))
        for item in dependencies
    ):
        raise ValueError("SBOM_INVALID")
    raw = json.dumps(document, ensure_ascii=False)
    if re.search(r"/Users/|/home/|/private/var/|/var/folders/|file://|[A-Za-z]:\\\\Users\\\\|\.env\b|monitor.config|checkpoint", raw, re.I) or any(
        item and item in raw for item in forbidden
    ):
        raise ValueError("SBOM_PRIVATE_METADATA")
    canonical = {
        "root": {
            "name": document["metadata"]["component"].get("name"),
            "version": document["metadata"]["component"].get("version"),
        },
        "components": sorted(
            ({key: item[key] for key in ("bom-ref", "name", "version", "purl")}
             for item in components),
            key=lambda item: item["bom-ref"],
        ),
        "dependencies": sorted(
            ({"ref": item["ref"], "dependsOn": sorted(item.get("dependsOn", []))}
             for item in dependencies),
            key=lambda item: item["ref"],
        ),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return SbomEvidence(
        component_count=len(components),
        dependency_count=len(dependencies),
        has_all_hashes=all(bool(item.get("hashes")) for item in components),
        has_all_licenses=all(bool(item.get("licenses")) for item in components),
        canonical_sha256=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    )


def inspect_scan(exit_code: int, report: dict[str, Any], expected_packages: int) -> ScanEvidence:
    """Never interpret a failed or non-extracting scan as zero findings."""
    if type(exit_code) is not int or type(expected_packages) is not int or expected_packages < 1:
        return ScanEvidence("SCAN_INDETERMINATE", 0, 0)
    if exit_code not in (0, 1) or not isinstance(report, dict):
        return ScanEvidence("SCAN_INDETERMINATE", 0, 0)
    results = report.get("results")
    if not isinstance(results, list):
        return ScanEvidence("SCAN_INDETERMINATE", 0, 0)
    packages: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
            return ScanEvidence("SCAN_INDETERMINATE", 0, 0)
        packages.extend(result["packages"])
    if len(packages) != expected_packages or not all(isinstance(item, dict) for item in packages):
        return ScanEvidence("SCAN_INDETERMINATE", len(packages), 0)
    if not all(isinstance(item.get("vulnerabilities", []), list) for item in packages):
        return ScanEvidence("SCAN_INDETERMINATE", len(packages), 0)
    vulnerabilities = [
        vulnerability
        for package in packages
        for vulnerability in package.get("vulnerabilities", [])
    ]
    if not all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in vulnerabilities):
        return ScanEvidence("SCAN_INDETERMINATE", len(packages), 0)
    if (exit_code == 0 and vulnerabilities) or (exit_code == 1 and not vulnerabilities):
        return ScanEvidence("SCAN_INDETERMINATE", len(packages), len(vulnerabilities))
    state = "FINDINGS" if vulnerabilities else "ZERO_FINDINGS"
    return ScanEvidence(state, len(packages), len(vulnerabilities))
