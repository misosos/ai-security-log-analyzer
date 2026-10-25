from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_33_3e_record_pins_inputs_and_records_resource_stop():
    doc = (ROOT / "docs/local_llm_artifact_closure_33_3e.md").read_text(encoding="utf-8")
    for phrase in (
        "Final verdict: `RESOURCE_NO_GO`",
        "4666bf17d794c6978ff0d10b1f9f3d5bc1093e72",
        "39982114651",
        "c1899de289a04d12100db370d81485cdf75e47ca",
        "620d2225cc436ab0b001e3200e590e3b286ef9ab",
        "197,071,951 bytes",
        "7,404,577,883 bytes",
        "5.1 GiB",
        "2,634 passed",
        "79/79",
        "21/21",
        "70/70",
        "No model inference",
        "license/install-hook",
    ):
        assert phrase in doc
    for private_marker in (
        "/" + "Users" + "/",
        "/" + "home" + "/",
        "10" + ".0.",
        "192" + ".168.",
    ):
        assert private_marker not in doc


def test_machine_manifests_match_fixed_model_runtime_and_wheel_contracts():
    import json

    model = json.loads((ROOT / "docs/artifacts/local_llm_model_manifest_33_3e.json").read_text())
    wheels = json.loads((ROOT / "docs/artifacts/local_llm_wheel_closure_33_3e.json").read_text())
    build = json.loads((ROOT / "docs/artifacts/local_llm_build_closure_33_3e.json").read_text())
    assert model["repository"] == "Qwen/Qwen3-0.6B"
    assert model["revision"] == "c1899de289a04d12100db370d81485cdf75e47ca"
    assert len(model["files"]) == 10
    assert wheels["total_wheel_bytes"] == 197_071_951
    assert wheels["wheel_bodies_downloaded"] is True
    assert wheels["python_patch_level_pinned"] is False
    assert wheels["transient_resolver_downloads"][0]["bytes"] == 1_256_108
    assert build["runtime"]["commit"] == "620d2225cc436ab0b001e3200e590e3b286ef9ab"
    assert build["os_build"]["build_closure_complete"] is False


def test_ai_roadmaps_link_33_3e_and_keep_lexical_baseline():
    for relative in (
        "README.md",
        "docs/index.md",
        "docs/local_ai_lexical_retrieval_33_1.md",
        "docs/local_llm_supply_chain_gate_33_3a.md",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "local_llm_artifact_closure_33_3e.md" in text
    doc = (ROOT / "docs/local_llm_artifact_closure_33_3e.md").read_text(encoding="utf-8")
    assert "33.1 lexical retrieval remains the only retrieval baseline" in doc
    assert "embedding production integration remains `NO_GO`" in doc
