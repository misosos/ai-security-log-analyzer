import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "docs" / "vector_supply_chain_audit_35_1.md"
MANIFEST = ROOT / "docs" / "artifacts" / "vector_0_60_0_manifest.json"


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def test_audit_has_required_static_review_sections_and_stays_non_operational():
    text = AUDIT.read_text(encoding="utf-8")
    for heading in (
        "## Upstream Identity",
        "## Artifact Inventory",
        "## Signature, Provenance and SBOM",
        "## License",
        "## Archive Static Inspection",
        "## Dependency and Build Metadata",
        "## Default Network and Telemetry",
        "## Filesystem and Permissions",
        "## File Source Contract",
        "## Socket Sink and Framing",
        "## Buffer and Delivery Semantics",
        "## Privacy Data Flow",
        "## AI Boundary",
        "## Phase 35.2 Entry Decision",
        "## Cleanup",
        "## Limitations",
    ):
        assert heading in text
    assert "설치·실행하지 않았다" in text
    assert "실제 로그" in text
    assert "PRECONDITION_PENDING" in text
    assert "CUSTOM_FRAMING_REQUIRED" in text or "TRANSFORM_REQUIRED" in text


def test_manifest_is_closed_and_has_no_unresolved_placeholders():
    payload = json.loads(
        MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
    )
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert json.loads(canonical, object_pairs_hook=_reject_duplicate_keys) == payload
    assert set(payload) == {"artifacts"}
    assert isinstance(payload["artifacts"], list) and payload["artifacts"]
    expected_keys = {
        "url", "filename", "platform", "architecture", "size_bytes", "sha256",
        "signature", "sbom", "provenance", "validation_status",
    }
    seen = set()
    for item in payload["artifacts"]:
        assert set(item) == expected_keys
        assert isinstance(item["platform"], str) and item["platform"]
        assert isinstance(item["architecture"], str) and item["architecture"]
        assert item["validation_status"] in {
            "BYTE_HASH_MATCHED_OFFICIAL_CHECKSUM",
            "BYTE_HASH_AND_ARCHIVE_MATCHED_OFFICIAL_CHECKSUM",
            "BYTE_HASH_MATCHED_RELEASE_API_DIGEST",
            "SOURCE_ARCHIVE_OBSERVED_UNAUTHENTICATED",
            "REGISTRY_METADATA_ONLY",
            "OFFICIAL_CHECKSUM_METADATA_ONLY",
            "OFFICIAL_RELEASE_METADATA_ONLY",
            "NOT_PUBLISHED",
            "NOT_INSPECTED",
        }
        assert item["signature"] in {
            "NOT_PUBLISHED", "SOURCE_COMMIT_SIGNATURE_ONLY", "NOT_CHECKED",
        }
        assert item["sbom"] in {"NOT_PUBLISHED", "NOT_CHECKED", "AVAILABLE_NOT_VERIFIED"}
        assert item["provenance"] in {
            "NOT_PUBLISHED", "SOURCE_COMMIT_ONLY", "NOT_CHECKED",
        }
        if item["sha256"] is not None:
            assert re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        else:
            assert item["validation_status"] in {"NOT_PUBLISHED", "NOT_INSPECTED"}
        if item["size_bytes"] is not None:
            assert type(item["size_bytes"]) is int and item["size_bytes"] > 0
        if item["filename"] is not None:
            assert item["filename"] and "/" not in item["filename"] and "\\" not in item["filename"]
            seen.add(item["filename"])
        else:
            assert item["validation_status"] == "NOT_PUBLISHED"
        if item["url"] is not None:
            assert item["url"].startswith("https://")
        else:
            assert item["validation_status"] == "NOT_PUBLISHED"
        for value in item.values():
            assert value != ""
    assert "vector-0.60.0-x86_64-unknown-linux-gnu.tar.gz" in seen
    assert "vector-0.60.0-aarch64-unknown-linux-gnu.tar.gz" in seen
    assert "vector-0.60.0-arm64-apple-darwin.tar.gz" in seen


def test_phase_35_1_status_and_navigation_links_are_current():
    design = (ROOT / "docs" / "enterprise_log_collection_architecture_35_0.md").read_text(encoding="utf-8")
    phase_34 = (ROOT / "docs" / "automatic_log_collection_design_34_0.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "Phase 35.1" in design and "PRECONDITION_PENDING" in design
    assert "Phase 35.1" in phase_34 and "Vector 0.60.0" in phase_34
    assert "실제 사용자 로그 수집과 조직 운영은 계속 지원하지 않습니다" in readme
    assert "vector_supply_chain_audit_35_1.md" in index
    assert "vector_0_60_0_manifest.json" in AUDIT.read_text(encoding="utf-8")
