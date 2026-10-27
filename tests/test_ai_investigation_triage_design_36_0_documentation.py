from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_36_design_closes_authority_privacy_and_output_contracts():
    doc = (ROOT / "docs/ai_investigation_triage_design_36_0.md").read_text()
    for heading in (
        "## Decision", "## Goals and Non-goals", "## Architecture",
        "## Safe Investigation DTO", "## Output Schema",
        "## Retrieval and Citation Boundary", "## Threat Model",
        "## Evaluation Contract", "## Tool Comparison", "## Roadmap",
        "## Limitations",
    ):
        assert heading in doc
    for contract in (
        "deterministic pipeline remains authoritative",
        "raw log", "account", "IP", "hostname", "file path",
        "exact timestamp", "user question", "unknown field",
        "citation_ids", "schema validation", "automatic action",
        "Vector was not run", "USER_ACTION_REQUIRED", "NO_GO",
        "UNEXPLAINED_NON_REPRODUCED",
    ):
        assert contract.lower() in doc.lower()
    assert "local_ai_lexical_retrieval_33_1.md" in doc
    assert "local_investigation_guidance_33_4.md" in doc


def test_phase_36_design_has_synthetic_evaluation_and_model_phase_gates():
    doc = (ROOT / "docs/ai_investigation_triage_design_36_0.md").read_text()
    assert "30" in doc and "합성" in doc
    for case in (
        "brute force", "password spray", "path traversal",
        "prompt injection", "개인정보", "invalid citation",
        "resource boundary", "conflicting observations",
    ):
        assert case.lower() in doc.lower()
    for phase in ("36.1", "36.2", "36.3", "36.4"):
        assert phase in doc
    for metric in (
        "privacy leak 0", "unsupported claim 0", "invalid citation 0",
        "analysis mutation 0", "tool/action 0", "injection execution 0",
    ):
        assert metric.lower() in doc.lower()


def test_project_index_and_readme_link_design_without_promoting_ai_or_vector():
    readme = (ROOT / "README.md").read_text()
    index = (ROOT / "docs/index.md").read_text()
    roadmap = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text()
    vector = (ROOT / "docs/vector_arm64_isolation_preflight_35_4a2.md").read_text()
    assert "ai_investigation_triage_design_36_0.md" in readme
    assert "ai_investigation_triage_design_36_0.md" in index
    assert "ai_investigation_triage_design_36_0.md" in roadmap
    assert "Phase 35.4B" in vector and "USER_ACTION_REQUIRED" in vector
    assert "Vector was not run" in vector or "Vector를 실행하지 않았다" in vector
