from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_3d_record_preserves_stop_and_evidence_boundaries():
    text = (ROOT / "docs/local_llm_pilot_33_3d.md").read_text(encoding="utf-8")
    for phrase in (
        "Final verdict: `SUPPLY_CHAIN_BLOCKED`",
        "8172be908c9a1c9478ad1dddd0e1b3354cb3907c",
        "39949787930",
        "zero artifacts",
        "user-reported",
        "not session-verified",
        "c1899de289a04d12100db370d81485cdf75e47ca",
        "620d2225cc436ab0b001e3200e590e3b286ef9ab",
        "e09616b190cf124e818d8a740468d4e84086015c",
        "3 GiB",
        "24 synthetic scenarios × 3 runs × UTC/Asia-Seoul",
        "NOT_TESTED",
        "No model, tokenizer, runtime source/binary, wheel, GGUF, cache",
        "PREFLIGHT_COMPLETE_REQUIRES_REVIEW",
    ):
        assert phrase in text
    assert "No model, tokenizer, runtime source/binary, wheel, GGUF, cache" in text
    assert "GO_FOR_INDEPENDENT_AI_AUDIT" not in text.split("## Final disposition", 1)[1]


def test_ai_roadmaps_link_phase_33_3d_and_keep_lexical_only():
    for relative in (
        "README.md",
        "docs/index.md",
        "docs/local_ai_investigation_assistant_33_0.md",
        "docs/local_ai_lexical_retrieval_33_1.md",
        "docs/local_embedding_supply_chain_gate_33_2a.md",
        "docs/local_embedding_retrieval_pilot_33_2b.md",
        "docs/local_llm_supply_chain_gate_33_3a.md",
        "docs/local_llm_pilot_33_3b.md",
    ):
        assert "local_llm_pilot_33_3d.md" in (ROOT / relative).read_text(encoding="utf-8")
    text = (ROOT / "docs/local_llm_pilot_33_3d.md").read_text(encoding="utf-8")
    assert "Embedding production `NO_GO`" in text
    assert "lexical-only retrieval" in text


def test_preflight_helpers_are_side_effect_free_contract_checks():
    helper = (ROOT / "tests/local_llm_pilot_33_3d.py").read_text(encoding="utf-8")
    assert "never accesses a VM" in helper
    assert "no filesystem reads" in helper
    assert "PREFLIGHT_COMPLETE_REQUIRES_REVIEW" in helper
    assert "subprocess" not in helper
    assert "urlopen" not in helper
