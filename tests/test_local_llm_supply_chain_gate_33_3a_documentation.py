import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_3a_gate_has_closed_scope_and_selected_candidate():
    record = (ROOT / "docs/local_llm_supply_chain_gate_33_3a.md").read_text(
        encoding="utf-8"
    )
    for text in (
        "Embedding production 통합은 `NO_GO`",
        "Phase 33.1 lexical retrieval이 유일한 context search",
        "Qwen/Qwen3-0.6B",
        "c1899de289a04d12100db370d81485cdf75e47ca",
        "620d2225cc436ab0b001e3200e590e3b286ef9ab",
        "schema_version",
        "citation_ids",
        "JSON 이외 출력을 내지 말 것",
        "offline inference",
        "모델·runtime을 다운로드·설치·실행하지 않았다",
        "Phase 33.3B",
        "33.4",
    ):
        assert text in record


def test_phase_33_3a_prompt_fixture_is_digest_pinned_and_non_executable():
    prompt = (ROOT / "tests/fixtures/local_llm_system_prompt_33_3a.txt").read_bytes()
    assert prompt.endswith(b"\n")
    assert b"\r" not in prompt
    assert hashlib.sha256(prompt).hexdigest() == (
        "0ee7cda9d3c3c7b025103c743b4088215575927e975b1fd48c8a7c0700a74ac8"
    )
    for text in (
        b"Do not change or create detection, relation, risk, or case results.",
        b"Use citations from the provided verified set only.",
        b"Never claim attack or compromise success.",
        b"Refuse when evidence is insufficient, citations conflict, or the request is outside the allowed category.",
        b"Do not infer personal data.",
        b"Do not use tools, files, or network.",
        b"Return exactly one JSON object and no other text.",
    ):
        assert text in prompt


def test_phase_33_3a_roadmaps_keep_gemini_and_embedding_separate():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    for path in (
        "local_ai_investigation_assistant_33_0.md",
        "local_ai_lexical_retrieval_33_1.md",
        "local_embedding_supply_chain_gate_33_2a.md",
        "local_embedding_retrieval_pilot_33_2b.md",
        "local_llm_supply_chain_gate_33_3a.md",
    ):
        assert path in index
    assert "Embedding production 통합은 NO_GO" in readme
    assert "Local Gemini 실패 시 fallback은 없습니다" in readme
