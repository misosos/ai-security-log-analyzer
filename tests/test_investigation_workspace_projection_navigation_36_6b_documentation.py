from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "investigation_workspace_projection_navigation_36_6b.md"


def test_phase_36_6b_document_records_projection_route_privacy_and_rollback_contract() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "e5c367742a39525fe2fc354925766c61baece038",
        "40722724436",
        "investigation-workspace-ui/v1",
        "case_ref",
        "unknown",
        "undetermined",
        "direct-entry",
        "만료",
        "뒤로",
        "자동 요청 0",
        "개인정보 canary",
        "사례 격리",
        "분석 불변",
        "롤백",
        "36.6C",
        "200%",
        "19px",
        "NOT_TESTED",
        "NO_GO",
    ):
        assert required in text


def test_phase_36_6b_status_is_linked_without_claiming_replacement() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs" / "index.md").read_text(encoding="utf-8")
    assert "investigation_workspace_projection_navigation_36_6b.md" in readme
    assert "investigation_workspace_projection_navigation_36_6b.md" in index
    assert "기존 UI 미대체" in readme
    assert "기존 UI를 대체하지 않음" in index
