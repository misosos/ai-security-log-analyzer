"""Keep the Phase 24.2 limits visible without treating an SBOM as a release gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bundle_documentation_contract() -> None:
    document = (ROOT / "docs/dependency_evidence_bundle_24_2.md").read_text()
    readme = (ROOT / "README.md").read_text()
    for phrase in (
        "uv.lock", "runtime-requirements.txt", "development-requirements.txt",
        "runtime.cdx.json", "development.cdx.json", "manifest.json",
        "checksums.sha256", "0700", "0600", "canonical graph", "UUID",
        "timestamp", "license", "NO-GO", "Ubuntu", "private",
    ):
        assert phrase in document
    assert "docs/dependency_evidence_bundle_24_2.md" in readme
    assert "공식 vulnerability/release gate는 아직 완료되지 않았습니다" in readme
