"""Contract tests for the disposable, synthetic-only 33.2B pilot harness."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from local_embedding_pilot_33_2b import (
    PilotError,
    PilotManifest,
    ModelFilePin,
    RankedSection,
    build_candidate_citations,
    fuse_rrf,
    load_evaluation_cases,
    load_pilot_manifest,
    load_runtime_wheel_manifest,
    render_runtime_pins,
    MODEL_FILE_PINS,
    rank_cosine,
    validate_query,
    validate_candidate_citations,
    verify_runtime_wheelhouse,
)
from app.local_retrieval_33_1 import (
    Completeness, QueryCategory, SafeEvidence, SourceRole, load_corpus,
)


def _evidence():
    return SafeEvidence(
        SourceRole.APPLICATION, ("Brute Force",),
        ("Failed login followed by success",), "MEDIUM", "HIGH", (),
        (("observations", 3),), 120, Completeness.PARTIAL,
        "s_0123456789abcdef", ("DETECTION_IS_NOT_COMPROMISE", "REPLAY_GAP_MAY_BE_STALE",
                               "CHECKPOINT_RESET_STARTS_NEW_HISTORY"),
    )


def _manifest(tmp_path, *, changed=None):
    model = tmp_path / "model"
    model.mkdir()
    files = {
        "model.safetensors": b"synthetic-model-bytes",
        "config.json": b"{}\n",
        "tokenizer.json": b"{}\n",
        "tokenizer_config.json": b"{}\n",
        "special_tokens_map.json": b"{}\n",
    }
    for name, content in files.items():
        (model / name).write_bytes(content)
    pins = {
        name: ModelFilePin(len(content), hashlib.sha256(content).hexdigest())
        for name, content in files.items()
    }
    manifest = {
        "schema_version": 1,
        "repository": "intfloat/multilingual-e5-small",
        "revision": "614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "license": "MIT",
        "files": [
            {"path": name, "size_bytes": len(content),
             "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(files.items())
        ],
    }
    if changed:
        changed(manifest, model)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    return model, manifest_path, pins


def test_model_manifest_requires_exact_pinned_files_and_hashes(tmp_path):
    model, manifest, pins = _manifest(tmp_path)
    verified = load_pilot_manifest(model, manifest, pins=pins)
    assert isinstance(verified, PilotManifest)
    assert verified.revision == "614241f622f53c4eeff9890bdc4f31cfecc418b3"
    assert len(verified.files) == 5
    (model / "unexpected.bin").write_bytes(b"pickle")
    with pytest.raises(PilotError) as caught:
        load_pilot_manifest(model, manifest, pins=pins)
    assert caught.value.code == "MODEL_FILE_SET_INVALID"
    assert str(model) not in str(caught.value) + repr(caught.value)


@pytest.mark.parametrize("mutation,code", [
    ("wrong_hash", "MODEL_DIGEST_INVALID"),
    ("symlink", "MODEL_FILE_SET_INVALID"),
    ("unsafe_revision", "MANIFEST_INVALID"),
])
def test_model_manifest_fails_closed_without_echoing_paths(tmp_path, mutation, code):
    def mutate(manifest, model):
        if mutation == "wrong_hash":
            (model / "config.json").write_bytes(b"changed\n")
        elif mutation == "symlink":
            target = model / "config.json"
            target.unlink()
            target.symlink_to("tokenizer.json")
        else:
            manifest["revision"] = "main"

    model, manifest, pins = _manifest(tmp_path, changed=mutate)
    with pytest.raises(PilotError) as caught:
        load_pilot_manifest(model, manifest, pins=pins)
    assert caught.value.code == code
    assert str(tmp_path) not in str(caught.value) + repr(caught.value)


def test_embedding_ranking_is_bounded_finite_and_uses_stable_id_ties():
    rows = (
        RankedSection("d-b", "s-2", 0.8),
        RankedSection("d-a", "s-2", 0.8),
        RankedSection("d-a", "s-1", 0.8),
        RankedSection("d-c", "s-1", 0.2),
    )
    ranked = rank_cosine(rows, threshold=0.5, top_k=3)
    assert [(row.document_id, row.section_id) for row in ranked] == [
        ("d-a", "s-1"), ("d-a", "s-2"), ("d-b", "s-2"),
    ]
    assert all(round(row.score, 6) == row.score for row in ranked)
    for score in (float("nan"), float("inf"), -0.1):
        with pytest.raises(PilotError):
            rank_cosine((RankedSection("d", "s", score),), threshold=0, top_k=1)


def test_rrf_is_fixed_deterministic_and_bounded():
    lexical = (("d-b", "s-1"), ("d-a", "s-1"))
    embedding = (("d-a", "s-1"), ("d-c", "s-1"))
    rows = fuse_rrf(lexical, embedding, top_k=3)
    assert [(row.document_id, row.section_id, row.score) for row in rows] == [
        ("d-a", "s-1", 1 / 61 + 1 / 62),
        ("d-b", "s-1", 1 / 61),
        ("d-c", "s-1", 1 / 62),
    ]
    assert rows == fuse_rrf(lexical, embedding, top_k=3)


def test_embedding_citations_use_only_verified_corpus_sections_and_keep_no_vector():
    corpus = load_corpus()
    ranked = (RankedSection("brute-force", "meaning-limit", 0.7),)
    result = build_candidate_citations(ranked, corpus, corpus.digest)
    checked = validate_candidate_citations(result, corpus, requested_top_k=5)
    assert checked == result
    assert checked[0].document_id == "brute-force"
    encoded = json.dumps([item.model_dump(mode="json") for item in checked], sort_keys=True)
    assert "embedding" not in encoded.casefold()
    assert "vector" not in encoded.casefold()
    forged = checked[0].model_copy(update={"section_id": "missing"})
    with pytest.raises(PilotError) as caught:
        validate_candidate_citations((forged,), corpus, requested_top_k=5)
    assert caught.value.code == "CITATION_INVALID"
    assert corpus.digest not in str(caught.value) + repr(caught.value)


def test_citation_builder_rejects_old_corpus_digest_and_duplicate_ids():
    corpus = load_corpus()
    with pytest.raises(PilotError) as caught:
        build_candidate_citations(
            (RankedSection("brute-force", "meaning-limit", 0.7),), corpus, "0" * 64,
        )
    assert caught.value.code == "CORPUS_DIGEST_MISMATCH"
    with pytest.raises(PilotError):
        build_candidate_citations((
            RankedSection("brute-force", "meaning-limit", 0.7),
            RankedSection("brute-force", "meaning-limit", 0.6),
        ), corpus, corpus.digest)


def test_multilingual_eval_fixture_keeps_the_original_17_cases_and_refusal_contract():
    cases = load_evaluation_cases(
        Path(__file__).parent / "fixtures" / "local_embedding_eval_33_2b.json"
    )
    assert len(cases) == 31
    assert [case.case_id for case in cases[:17]] == [f"b{i:02d}" for i in range(1, 18)]
    assert sum(case.refusal is None for case in cases[:17]) == 11
    assert {case.category for case in cases} >= {
        QueryCategory.EXPLAIN_RISK,
        QueryCategory.EXPLAIN_RELATION,
    }
    item = _evidence()
    assert all(
        validate_query(case.query, case.category, item) is None
        for case in cases if case.refusal is None
    )
    assert all(
        validate_query(case.query, case.category, item) == case.refusal
        for case in cases if case.refusal is not None
    )


def test_tracked_artifact_manifest_matches_exact_pins():
    from local_embedding_pilot_33_2b import MODEL_FILE_PINS

    manifest = Path(__file__).parent / "fixtures" / "multilingual_e5_small_33_2b_manifest.json"
    value = json.loads(manifest.read_text(encoding="utf-8"))
    assert value["revision"] == "614241f622f53c4eeff9890bdc4f31cfecc418b3"
    assert {row["path"]: (row["size_bytes"], row["sha256"]) for row in value["files"]} == {
        name: (pin.size_bytes, pin.sha256) for name, pin in MODEL_FILE_PINS.items()
    }


def test_runtime_wheel_manifest_is_fixed_to_verified_native_mac_closure():
    manifest = Path(__file__).parent / "fixtures" / "local_embedding_runtime_33_2b_manifest.json"
    value = json.loads(manifest.read_text(encoding="utf-8"))
    rows = value["wheels"]
    assert value["schema_version"] == 1
    assert value["wheel_count"] == len(rows) == 38
    assert value["wheel_bytes"] == sum(row["size_bytes"] for row in rows)
    assert len({row["file"] for row in rows}) == len(rows)
    assert all(row["file"].endswith(".whl") and len(row["sha256"]) == 64 for row in rows)
    by_name = {row["file"]: row for row in rows}
    assert by_name["torch-2.14.1-cp312-cp312-macosx_14_0_arm64.whl"]["sha256"] == (
        "420dbf314c180ee4b86e9bc00aee5746a7d6e5bacdd7df925af671ed393f0b2e"
    )
    assert by_name["transformers-5.20.2-py3-none-any.whl"]["sha256"] == (
        "7ae75dbc1fb3922aff1b6c97b9e5479d6cf26fd86a8866bfb71324190479f807"
    )
    parsed = load_runtime_wheel_manifest(manifest)
    pins = render_runtime_pins(parsed).decode("utf-8")
    assert len(pins.splitlines()) == 38
    assert "torch==2.14.1 --hash=sha256:420dbf314c180ee4b86e9bc00aee5746a7d6e5bacdd7df925af671ed393f0b2e" in pins


def test_runtime_wheelhouse_verifier_rejects_tamper_and_unlisted_artifacts(tmp_path):
    from local_embedding_pilot_33_2b import _sha

    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    filename = "sample_pkg-1.2.3-py3-none-any.whl"
    content = b"synthetic wheel fixture"
    (wheelhouse / filename).write_bytes(content)
    manifest_path = tmp_path / "manifest.json"
    manifest = {
        "schema_version": 1,
        "runtime_lock_sha256": "a" * 64,
        "wheel_count": 1,
        "wheel_bytes": len(content),
        "wheels": [{"file": filename, "size_bytes": len(content), "sha256": _sha(content)}],
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    parsed = load_runtime_wheel_manifest(manifest_path)
    verify_runtime_wheelhouse(wheelhouse, parsed)
    (wheelhouse / "unlisted.whl").write_bytes(b"extra")
    with pytest.raises(PilotError) as caught:
        verify_runtime_wheelhouse(wheelhouse, parsed)
    assert caught.value.code == "MODEL_FILE_SET_INVALID"
