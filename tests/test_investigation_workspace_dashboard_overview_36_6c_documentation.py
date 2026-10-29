from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_dashboard_overview_36_6c.md"


def test_phase_36_6c_document_records_dashboard_overview_scope_and_semantic_count_boundary() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "235f0f0a7f85b6b52d9699f5f69f521656c435ad",
        "40813067070",
        "investigation-workspace-ui/v1",
        "limitation_count",
        "분석 한계",
        "unverified_items",
        "추가 확인 필요 항목 수",
        "projection 필드",
        "POST 0",
        "rollback",
        "320",
        "200%",
        "19px",
        "36.6D",
        "NOT_TESTED",
        "NO_GO",
    ):
        assert required in text


def test_phase_36_6c_status_is_linked_without_claiming_old_renderer_removal() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "investigation_workspace_dashboard_overview_36_6c.md" in readme
    assert "investigation_workspace_dashboard_overview_36_6c.md" in index
    assert "rollback" in readme.lower()
    assert "기존 UI" in index
