from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_verified_source_role_record_documents_provenance_and_fallbacks():
    document = (ROOT / "docs/investigation_checklist_verified_role_36_4.md").read_text()
    for section in (
        "## Decision", "## Source Role Provenance", "## Snapshot Consistency",
        "## API and UI Contract", "## Privacy", "## Analysis Invariance",
        "## Verification", "## Limitations",
    ):
        assert section in document
    for required in (
        "application", "ssh", "access", "unknown", "investigation-checklist/v2",
        "mixed", "stale", "cross-case", "NO_GO", "NOT_TESTED / USER_HOME_ISOLATION_BLOCKED",
        "Vector", "model", "source metadata", "detection", "risk",
    ):
        assert required.casefold() in document.casefold()


def test_phase_36_status_pages_point_to_verified_role_record_without_claiming_go():
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    assert "investigation_checklist_verified_role_36_4.md" in readme
    assert "investigation_checklist_verified_role_36_4.md" in index
    assert "CONDITIONAL_GO" in readme
    assert "CONDITIONAL_GO" in index
