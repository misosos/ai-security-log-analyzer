import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_preflight_manifest_pins_the_expected_ubuntu_x86_64_bytes():
    manifest = json.loads(
        (ROOT / "docs/artifacts/vector_0_60_0_x86_64_preflight.json").read_text()
    )
    assert manifest["version"] == "0.60.0"
    assert manifest["source_commit"] == "0d0b35865036f8b5c2f0104d9744fa84985ffff1"
    assert manifest["artifact"]["actual_bytes"] == 58_655_370
    assert manifest["artifact"]["sha256"] == (
        "89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc"
    )
    assert manifest["artifact"]["official_checksum_match"] is True
    assert manifest["artifact"]["binary_executed"] is False
    assert len(manifest["artifact"]["sha256"]) == 64
    assert manifest["artifact"]["detached_signature"] == "NOT_PUBLISHED"
    assert manifest["artifact"]["sbom"] == "NOT_PUBLISHED"
    assert manifest["artifact"]["attestation"] == "NOT_PUBLISHED"
    assert manifest["archive_inspection"]["unsafe_members"] == 0
    assert manifest["binary"]["sha256"] == (
        "1e6a3f7b6b03aac5f95803007d66ed71897162c5160aa401af81e55d1477ba2e"
    )
    assert manifest["binary"]["stripped"] is False


def test_preflight_record_states_unresolved_supply_chain_and_isolation_limits():
    doc = (ROOT / "docs/vector_artifact_preflight_35_4a.md").read_text()
    for phrase in (
        "ISOLATION_BLOCKED",
        "checksum-only",
        "UNRESOLVED 3",
        "Vector binary를 실행하지 않았다",
        "실제 사용자 로그",
        "15%",
    ):
        assert phrase in doc
