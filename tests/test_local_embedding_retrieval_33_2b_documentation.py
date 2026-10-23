import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_phase_33_2b_record_preserves_synthetic_only_no_integration_boundary():
    report = (ROOT / "docs/local_embedding_retrieval_pilot_33_2b.md").read_text(
        encoding="utf-8"
    )
    required = (
        "합성 자료로 격리 retrieval 비교 완료",
        "Production 통합은 `NO_GO`다",
        "614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477",
        "fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6",
        "fe698fbf34c16eee5c41f906c3633753682c34db2544e8a3fc77cd8f47069dcd",
        "91d498b9f40152dba3767371296a93f2fee682eb6bfc8742fd41859e6bf45115",
        "11/11",
        "0.941",
        "0.862624",
        "embedding-only",
        "hard memory cap",
        "실제 사용자 로그",
        "설명 답변 품질",
        "NO_GO",
    )
    for value in required:
        assert value in report
    assert "모델·wheel·cache는 검증한 `/private/tmp/phase-33-2b` 아래에만 두었고 inventory 확인 후 정리했다" in report
    assert "local_files_only=True" in report
    assert "trust_remote_code=False" in report
    assert "API/SSE/UI" in report


def test_model_and_runtime_manifests_pin_only_expected_artifact_metadata():
    model = json.loads((ROOT / "tests/fixtures/multilingual_e5_small_33_2b_manifest.json").read_text())
    runtime = json.loads((ROOT / "tests/fixtures/local_embedding_runtime_33_2b_manifest.json").read_text())
    assert model["repository"] == "intfloat/multilingual-e5-small"
    assert model["revision"] == "614241f622f53c4eeff9890bdc4f31cfecc418b3"
    assert model["license"] == "MIT"
    assert {row["path"] for row in model["files"]} == {
        "model.safetensors", "config.json", "tokenizer.json",
        "tokenizer_config.json", "special_tokens_map.json",
    }
    assert all(row["size_bytes"] > 0 and len(row["sha256"]) == 64 for row in model["files"])
    assert runtime["wheel_count"] == len(runtime["wheels"]) == 38
    assert runtime["wheel_bytes"] == sum(row["size_bytes"] for row in runtime["wheels"])
    assert all(row["file"].endswith(".whl") and len(row["sha256"]) == 64
               for row in runtime["wheels"])


def test_roadmap_and_readme_distinguish_pilot_from_product_integration():
    index = (ROOT / "docs/index.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    design = (ROOT / "docs/local_ai_investigation_assistant_33_0.md").read_text(
        encoding="utf-8"
    )
    baseline = (ROOT / "docs/local_ai_lexical_retrieval_33_1.md").read_text(
        encoding="utf-8"
    )
    gate = (ROOT / "docs/local_embedding_supply_chain_gate_33_2a.md").read_text(
        encoding="utf-8"
    )
    for text in (index, readme, design, baseline, gate):
        assert "33.2B" in text
        assert "local_embedding_retrieval_pilot_33_2b.md" in text
    assert "NO_GO" in design
    assert "production 통합은 보류합니다" in readme
    assert "production embedding integration" in baseline
