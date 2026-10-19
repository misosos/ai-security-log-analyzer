"""Keep the Phase 24.2 limits visible without treating an SBOM as a release gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_bundle_documentation_contract() -> None:
    document = (ROOT / "docs/dependency_evidence_bundle_24_2.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    for phrase in (
        "uv.lock", "runtime-requirements.txt", "development-requirements.txt",
        "runtime.cdx.json", "development.cdx.json", "manifest.json",
        "checksums.sha256", "0700", "0600", "canonical graph", "UUID",
        "timestamp", "license", "NO-GO", "Ubuntu", "private",
    ):
        assert phrase in document
    assert "dependency_evidence_bundle_24_2.md" in index
    assert "Ubuntu 실행·CI gate·vulnerability DB·license 판단·릴리스 asset은 포함하지 않는다" in document
    assert "공식 release gate NO-GO" in document
