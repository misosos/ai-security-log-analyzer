from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_1_documentation_states_closed_scope_and_entry_gate():
    text = (ROOT / "docs/deterministic_investigation_triage_36_1.md").read_text()
    required = (
        "SafeInvestigationDTO", "investigation-assistance/v1", "모델",
        "Phase 33.1", "review_later", "review_soon", "undetermined",
        "citation", "NO_GO", "NOT_TESTED", "PHASE_36_2_READY",
        "Vector/VM", "44 synthetic cases", "Research Basis",
        "Observable Evidence Mapping", "not modify",
    )
    assert all(value in text for value in required)
    assert "tests/fixtures/investigation_triage_36_1.json" in text
    assert "tests/evaluate_investigation_triage_36_1.py" in text
    assert "tests/benchmark_investigation_triage_36_1.py" in text


def test_phase_36_0_and_33_0_status_link_to_36_1_without_claiming_model_use():
    design = (ROOT / "docs/ai_investigation_triage_design_36_0.md").read_text()
    phase33 = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text()
    assert "deterministic_investigation_triage_36_1.md" in design
    assert "Phase 36.1" in design
    assert "deterministic_investigation_triage_36_1.md" in phase33


def test_readme_and_index_link_to_internal_reference_only():
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    assert "결정적 조사 우선순위 기준선" in readme
    assert "deterministic_investigation_triage_36_1.md" in readme
    assert "deterministic_investigation_triage_36_1.md" in index
