import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "application_ascii.jsonl": "2beead5c89e0720730d5d3cfd29013cac97f5ac16836b0e975551d8276f801fe",
    "application_korean.jsonl": "ce99e0c554a4044f5fac5113494ac4a786748b6deaedddde3d3c98f38b40d058",
    "ssh_ascii.jsonl": "89d6a74a6ba4b347a4f0f18f8b1aa125474b13e9dfd89ee13ae8049cc713adf2",
    "ssh_korean.jsonl": "e97333d9320c5e3b3374561d7c269b6b5c25fac80800f2e46b97dd7e3ccdaa7e",
    "vector_candidate.yaml": "e169f0b680362526bfb2b5c79b3106fed1b5b921acb0b42a51cc1232138a5e2e",
}


def _load_unique_json(path: Path):
    def reject_duplicates(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AssertionError("manifest duplicate key")
            result[key] = value
        return result

    return json.loads(path.read_text(), object_pairs_hook=reject_duplicates)


def test_arm64_manifest_pins_download_and_static_binary_evidence():
    manifest = _load_unique_json(
        ROOT / "docs/artifacts/vector_0_60_0_aarch64_preflight.json"
    )
    assert set(manifest) == {
        "schema_version", "product", "version", "tag", "source_commit", "platform",
        "artifact", "archive", "binary", "disk_budget", "cleanup",
        "credential_findings", "vmware_host", "decision", "blockers",
    }
    assert type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
    assert manifest["version"] == "0.60.0"
    assert manifest["source_commit"] == "0d0b35865036f8b5c2f0104d9744fa84985ffff1"
    assert manifest["platform"] == "ubuntu-24.04-aarch64-gnu"
    assert manifest["artifact"]["bytes"] == 56_805_541
    assert manifest["artifact"]["sha256"] == (
        "1540662d8bc33af5afd287f821ba930417e0f3124073bc9db6a29c59dda88dbb"
    )
    assert manifest["artifact"]["official_checksum_match"] is True
    assert manifest["artifact"]["final_download_host"] == "release-assets.githubusercontent.com"
    assert manifest["archive"]["member_count"] == 53
    assert manifest["archive"]["expanded_regular_bytes"] == 151_119_387
    assert manifest["archive"]["unsafe_members"] == 0
    assert manifest["binary"]["bytes"] == 150_906_952
    assert manifest["binary"]["sha256"] == (
        "c0231b1714541a10cfb03a9e965a81a98d6e97401f4c738dc7f741d60cefab7a"
    )
    assert manifest["binary"]["architecture"] == "AArch64"
    assert manifest["binary"]["executed"] is False
    assert manifest["binary"]["interpreter"] == "/lib/ld-linux-aarch64.so.1"
    assert manifest["decision"] == "USER_ACTION_REQUIRED"
    assert manifest["blockers"] == ["ISOLATION_BLOCKED", "RESOURCE_BLOCKED"]
    assert manifest["vmware_host"]["configured_vcpus"] == 2
    assert manifest["vmware_host"]["configured_memory_mib"] == 6144


def test_vector_candidate_and_jsonl_fixtures_are_architecture_independent():
    core = _load_unique_json(ROOT / "tests/fixtures/vector_jsonl_35_4a/vector_candidate.yaml")
    assert core["api"]["enabled"] is False
    assert core["sinks"]["jsonl_adapter"]["encoding"]["codec"] == "json"
    original_dir = ROOT / "tests/fixtures/vector_jsonl_35_4a"
    for name, expected in EXPECTED.items():
        assert hashlib.sha256((original_dir / name).read_bytes()).hexdigest() == expected


def test_arm64_manifest_does_not_claim_signature_or_binary_provenance():
    manifest = _load_unique_json(ROOT / "docs/artifacts/vector_0_60_0_aarch64_preflight.json")
    assert manifest["artifact"]["signature"] == "NOT_PUBLISHED"
    assert manifest["artifact"]["sbom"] == "NOT_PUBLISHED"
    assert manifest["artifact"]["attestation"] == "NOT_PUBLISHED"
    assert manifest["artifact"]["provenance"] == "CHECKSUM_ONLY"
    assert manifest["credential_findings"] == {"unresolved": 3, "cleared": 0}
    assert manifest["cleanup"]["archive_removed"] is True
    assert manifest["cleanup"]["staging_removed"] is True
    assert manifest["cleanup"]["secure_erase_claimed"] is False


def test_existing_artifact_inventory_matches_independently_checked_arm64_bytes():
    manifest = _load_unique_json(ROOT / "docs/artifacts/vector_0_60_0_manifest.json")
    item = next(
        entry for entry in manifest["artifacts"]
        if entry["filename"] == "vector-0.60.0-aarch64-unknown-linux-gnu.tar.gz"
    )
    assert item["size_bytes"] == 56_805_541
    assert item["sha256"] == (
        "1540662d8bc33af5afd287f821ba930417e0f3124073bc9db6a29c59dda88dbb"
    )
    assert item["validation_status"] == "BYTE_HASH_AND_ARCHIVE_MATCHED_OFFICIAL_CHECKSUM"
