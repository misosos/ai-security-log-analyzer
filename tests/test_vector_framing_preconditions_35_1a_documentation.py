from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "docs" / "vector_framing_preconditions_35_1a.md"


def test_framing_precondition_record_has_required_decisions_and_remains_static():
    text = REVIEW.read_text(encoding="utf-8")
    for heading in (
        "## Decision",
        "## Start Gate",
        "## Native Framing Trace",
        "## VRL Feasibility",
        "## Adapter Comparison",
        "## Credential String Classification",
        "## Provenance Residual Risk",
        "## Selected Next Step",
        "## Privacy Boundary",
        "## AI Boundary",
        "## Verification",
        "## Limitations",
    ):
        assert heading in text
    assert "CUSTOM_FRAMING_UNPROVEN" in text
    assert "PHASE_35_2_ADAPTER_CORE_REQUIRED" in text
    assert "설치·실행하지 않았다" in text
    assert "INCOMPATIBLE" in text


def test_prior_supply_chain_record_and_manifest_are_reconciled():
    prior = (ROOT / "docs" / "vector_supply_chain_audit_35_1.md").read_text(
        encoding="utf-8"
    )
    design = (ROOT / "docs" / "enterprise_log_collection_architecture_35_0.md").read_text(
        encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "0d0b35865036f8b5c2f0104d9744fa84985ffff1" in prior
    assert "89a9f134dcc35a6fbba9cb8ad0fec2d4802657bba6cb1c374a30660ef9456bdc" in prior
    assert "TRANSFORM_REQUIRED" in prior and "PRECONDITION_PENDING" in prior
    assert "PRECONDITION_PENDING" in design
    assert "실제 사용자 로그 수집과 조직 운영은 계속 지원하지 않습니다" in readme
    assert "vector_framing_preconditions_35_1a.md" in index


def test_adapter_contract_is_closed_and_does_not_change_existing_listener():
    text = REVIEW.read_text(encoding="utf-8")
    for required in (
        "기존 RFC 6587 listener는 변경하지 않는다",
        "duplicate key",
        "NaN",
        "Infinity",
        "source_role",
        "line byte",
        "queue byte",
        "public API",
    ):
        assert required in text
