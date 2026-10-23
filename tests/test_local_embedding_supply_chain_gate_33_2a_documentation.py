from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_2a_gate_document_pins_candidates_and_lexical_baseline():
    text = (ROOT / "docs/local_embedding_supply_chain_gate_33_2a.md").read_text(
        encoding="utf-8"
    )

    for required in (
        "614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "d128750597153bb5987e10b1c3493a34e5a4502a",
        "5617a9f61b028005a4858fdac845db406aefb181",
        "e8f8c211226b894fcb81acc59f3b34ba3efd5f42",
        "CONDITIONAL_GO",
        "MIT",
        "Apache-2.0",
        "NO_GO",
        "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6",
        "91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115",
        "k1=1.2",
        "b=0.75",
        "threshold `2.2`",
        "11/11",
        "0.941",
        "100%",
        "과잉 인용",
        "safetensors",
        "SHA-256",
        "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477",
        "eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b",
        "pytorch_model.bin",
        "offline",
        "network deny",
        "실제 사용자 로그",
        "Phase 33.2B",
        "33.2B 준비 상태는 BLOCKED/PRECONDITION_PENDING",
        "다운로드·설치·실행하지 않았고",
        "Embedding vector도 안전한 공개 정보가 아니다",
        "API/SSE/UI, database, checkpoint, persistent cache 또는 일반 log에 넣지 않는다",
    ):
        assert required in text

    assert "trust_remote_code=True" in text
    assert "pickle" in text.lower()
    assert "privacy" in text.lower()
    assert "Docker Desktop" in text
    assert "Ubuntu VM" in text


def test_phase_33_2a_docs_and_readme_link_to_gate_without_claiming_install():
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    phase_33_0 = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text(
        encoding="utf-8"
    )
    phase_33_1 = (ROOT / "docs/local_ai_lexical_retrieval_33_1.md").read_text(
        encoding="utf-8"
    )

    assert "local_embedding_supply_chain_gate_33_2a.md" in index
    assert "33.2A" in readme
    assert "33.2A" in phase_33_0
    assert "33.2A" in phase_33_1
    assert "33.2B" in phase_33_1
