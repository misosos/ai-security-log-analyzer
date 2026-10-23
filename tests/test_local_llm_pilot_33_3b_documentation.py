from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_3b_report_records_blocked_state_and_no_runtime_claim():
    record = (ROOT / "docs/local_llm_pilot_33_3b.md").read_text(encoding="utf-8")
    for phrase in (
        "ISOLATION_BLOCKED",
        "Docker CLI exists, but `docker info` could not connect",
        "VMware `vmrun` is present as a command",
        "QEMU 11.0.2 and its HVF accelerator are installed",
        "No model weights, GGUF, tokenizer files, runtime source/binary",
        "Qwen/Qwen3-0.6B-GGUF",
        "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031",
        "Temperature 0",
        "24 cases",
        "Phase 33.2B embedding production `NO_GO`",
    ):
        assert phrase in record
    assert "not `GO_FOR_INDEPENDENT_AI_AUDIT`" in record


def test_phase_33_3b_harness_is_test_only_and_does_not_launch_a_runtime():
    harness = (ROOT / "tests/local_llm_pilot_33_3b.py").read_text(encoding="utf-8")
    test = (ROOT / "tests/test_local_llm_pilot_33_3b.py").read_text(encoding="utf-8")
    assert "This module never starts a model or runtime" in harness
    assert "subprocess" not in harness.lower()
    assert "socket" not in harness.lower()
    assert "requests." not in harness
    assert "llama-cli" not in harness
    assert "synthetic" in test.lower()


def test_phase_33_3b_roadmaps_link_the_blocked_attempt():
    for path in (
        "docs/local_ai_investigation_assistant_33_0.md",
        "docs/local_ai_lexical_retrieval_33_1.md",
        "docs/local_embedding_supply_chain_gate_33_2a.md",
        "docs/local_embedding_retrieval_pilot_33_2b.md",
        "docs/local_llm_supply_chain_gate_33_3a.md",
        "docs/index.md",
        "README.md",
    ):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "local_llm_pilot_33_3b.md" in text or path == "README.md"
    assert "ISOLATION_BLOCKED" in (ROOT / "README.md").read_text(encoding="utf-8")
