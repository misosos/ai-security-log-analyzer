from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_3c_record_keeps_blocked_and_not_tested_evidence_distinct():
    text = (ROOT / "docs/local_llm_pilot_33_3c.md").read_text(encoding="utf-8")
    for phrase in (
        "Final verdict: `ISOLATION_BLOCKED`",
        "39947087923",
        "total_count: 0",
        "4d8de514f84646a4d5e7277d36b22e4553cb298e",
        "vmrun list",
        "No guest command was run",
        "model/runtime artifact was downloaded",
        "24 synthetic scenarios",
        "NOT_TESTED",
        "PREFLIGHT_ATTESTATIONS_COMPLETE_REQUIRES_REVIEW",
        "No Docker Desktop",
        "Production integration is not approved",
    ):
        assert phrase in text
    assert "GO_FOR_INDEPENDENT_AI_AUDIT" not in text.split("Final disposition", 1)[1].split("### Scope not tested", 1)[0]


def test_phase_33_3c_gate_helper_never_claims_to_verify_the_vm():
    helper = (ROOT / "tests/local_llm_pilot_33_3c.py").read_text(encoding="utf-8")
    assert "does not inspect or control a" in helper
    assert "not an isolation measurement" in helper
    assert "ISOLATION_BLOCKED" in helper


def test_phase_33_ai_roadmaps_link_the_33_3c_retry():
    for path in (
        "README.md",
        "docs/index.md",
        "docs/local_ai_investigation_assistant_33_0.md",
        "docs/local_ai_lexical_retrieval_33_1.md",
        "docs/local_embedding_supply_chain_gate_33_2a.md",
        "docs/local_embedding_retrieval_pilot_33_2b.md",
        "docs/local_llm_supply_chain_gate_33_3a.md",
        "docs/local_llm_pilot_33_3b.md",
    ):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "local_llm_pilot_33_3c.md" in text
