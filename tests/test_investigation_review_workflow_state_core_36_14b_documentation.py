from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/investigation_review_workflow_state_core_36_14b.md"


def test_review_workflow_core_design_and_boundary_are_documented() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "unreviewed", "in_review", "reviewed", "deferred",
        "revision", "compare-and-set", "128", "memory-only",
        "API/UI", "NO_GO", "ROLLBACK", "analysis_ref", "case_ref",
        "Privacy", "Hypothesis", "36.14C",
    ):
        assert required.casefold() in text.casefold()
    assert "Production API/UI 승인" in text


def test_core_is_not_imported_by_production_request_or_frontend_path() -> None:
    forbidden = "investigation_review_state_36_14b"
    for base in (ROOT / "app", ROOT / "frontend"):
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".js", ".css", ".html"}:
                if path.name == "investigation_review_state_36_14b.py":
                    continue
                assert forbidden not in path.read_text(encoding="utf-8")
