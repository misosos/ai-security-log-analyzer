import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_2_record_has_closed_semantic_and_privacy_contract():
    path = ROOT / "docs/lexical_investigation_checklist_36_2.md"
    assert path.is_file()
    text = path.read_text()
    for token in (
        "Phase 36.2", "Phase 33.1", "structural", "semantic", "citation",
        "no model", "no network", "NO_GO", "NOT_TESTED", "over-citation",
        "path traversal", "process execution", "meaningful", "36.1",
        "8개", "Phase 35.4B", "USER_ACTION_REQUIRED", "Vector",
        "detection", "relation", "risk", "case",
    ):
        assert token.lower() in text.lower(), token


def test_phase_36_2_links_and_review_fixture_are_closed_and_not_user_pass():
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    for text in (readme, index):
        assert "lexical_investigation_checklist_36_2.md" in text
    fixture = json.loads(
        (ROOT / "tests/fixtures/investigation_checklist_user_review_36_2.json").read_text()
    )
    assert fixture["synthetic_only"] is True
    assert fixture["user_acceptance_status"] == "NOT_TESTED"
    assert fixture["captured_cli_or_ui"] is False
    assert len(fixture["items"]) == 8


def test_phase_36_1_and_phase_33_1_baselines_are_explicitly_preserved():
    docs = (
        ROOT / "docs/deterministic_investigation_triage_36_1.md",
        ROOT / "docs/ai_investigation_triage_design_36_0.md",
        ROOT / "docs/local_ai_lexical_retrieval_33_1.md",
    )
    combined = "\n".join(path.read_text() for path in docs)
    assert "44" in combined
    assert "relation-gone:not-resolved" in combined
    assert "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6" in combined
