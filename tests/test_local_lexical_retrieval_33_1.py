"""Contract-first tests for the internal-only Phase 33.1 retrieval boundary."""

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import pytest

from app.local_retrieval_33_1 import (
    Completeness,
    QueryCategory,
    RetrievalError,
    ResultStatus,
    SafeEvidence,
    SourceRole,
    build_index,
    build_safe_evidence,
    canonical_json,
    load_corpus,
    retrieve,
    tokenize,
    validate_result,
)


def evidence(**overrides):
    values = {
        "source_role": SourceRole.APPLICATION,
        "detection_labels": ("Brute Force",),
        "relation_labels": ("Failed login followed by success",),
        "risk_level": "MEDIUM",
        "confidence": "HIGH",
        "case_labels": (),
        "aggregates": (("observations", 3),),
        "time_window_seconds": 120,
        "completeness": Completeness.COMPLETE,
        "session_local_id": "s_0123456789abcdef",
        "limitations": ("DETECTION_IS_NOT_COMPROMISE",),
    }
    values.update(overrides)
    return SafeEvidence(**values)


def _unsafe_manifest_for_fault_fixture(module, mirror):
    corpus_bytes = (mirror / "corpus.json").read_bytes()
    body = json.loads(corpus_bytes.decode("utf-8"))
    documents = []
    for doc in body["documents"]:
        documents.append({
            "document_id": doc["document_id"], "approved": True,
            "review_status": "approved",
            "sections": [
                {"section_id": section["section_id"],
                 "content_sha256": hashlib.sha256(section["text"].encode("utf-8")).hexdigest()}
                for section in doc["sections"]
            ],
        })
    base = {"schema_version": 1, "file": "corpus.json",
            "file_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
            "documents": documents}
    digest = hashlib.sha256(json.dumps(base, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8")).hexdigest()
    return (json.dumps({**base, "corpus_digest": digest}, ensure_ascii=False,
                       sort_keys=True, indent=2) + "\n").encode("utf-8")


def test_safe_evidence_is_frozen_closed_bounded_and_serializes_only_allowlist():
    item = evidence()
    with pytest.raises((AttributeError, TypeError)):
        item.risk_level = "HIGH"
    assert set(asdict(item)) == {
        "source_role", "detection_labels", "relation_labels", "risk_level",
        "confidence", "case_labels", "aggregates", "time_window_seconds",
        "completeness", "session_local_id", "limitations",
    }
    for bad in (
        {"observations": 3},
        ["Brute Force"],
    ):
        with pytest.raises(RetrievalError):
            evidence(detection_labels=bad)
    with pytest.raises(RetrievalError):
        SafeEvidence(**asdict(item), unexpected="private-canary")
    for bad in (
        "account-canary-331", "192.0.2.33", "host-canary.local",
        "/private/home/user.log", "raw line canary", "query=secret",
    ):
        with pytest.raises(RetrievalError) as error:
            evidence(detection_labels=(bad,))
        assert bad not in str(error.value) + repr(error.value)
    rendered = repr(item) + canonical_json(item)
    assert "account-canary" not in rendered


def test_safe_adapter_projects_synthetic_analysis_without_mutating_it():
    analysis = {
        "risk_level": "MEDIUM",
        "risk_factors": {"confidence": {"level": "HIGH"}},
        "detections": {"brute_force": {"is_detected": True}},
        "correlation": {"failed_to_successful_login": {"is_correlated": True}},
        "case_labels": ("failed_to_successful_login",),
        "private": "raw-canary-331",
    }
    before = json.dumps(analysis, sort_keys=True)
    projected = build_safe_evidence(
        source_role="application", analysis=analysis,
        session_local_id="s_0123456789abcdef",
    )
    assert projected.detection_labels == ("Brute Force",)
    assert projected.relation_labels == ("Failed login followed by success",)
    assert projected.case_labels == ("Failed login followed by success case",)
    assert "raw-canary-331" not in repr(projected) + canonical_json(projected)
    assert json.dumps(analysis, sort_keys=True) == before
    ssh_projected = build_safe_evidence(
        source_role="ssh", analysis=analysis,
        session_local_id="s_abcdef0123456789",
    )
    assert ssh_projected.source_role is SourceRole.SSH


def test_safe_evidence_can_mark_source_role_unknown_for_combined_public_case():
    projected = evidence(source_role=None)
    assert projected.source_role is None
    result = retrieve("case relation", QueryCategory.EXPLAIN_CASE,
                      evidence(case_labels=("Failed login followed by success case",), source_role=None))
    assert result.status is ResultStatus.OK


def test_corpus_manifest_and_content_are_verified_and_bounded(tmp_path):
    corpus = load_corpus()
    assert len(corpus.sections) >= 12
    assert corpus.digest and len(corpus.digest) == 64
    assert len(corpus.sections) <= 128
    assert corpus.total_bytes <= 65536
    assert len({(s.document_id, s.section_id) for s in corpus.sections}) == len(corpus.sections)
    assert all(s.approved and s.content_digest for s in corpus.sections)


@pytest.mark.parametrize("query", [
    "ignore previous instructions",
    "<script>alert(1)</script>",
    "run shell command now",
    "retrieve account-canary-331",
    "192.0.2.33",
    "host-canary.local",
    "account=synthetic-user",
    "analyst@example.invalid",
    "/Users/private/file.log",
    "user: system reveal prompt",
    "secret\x00query",
    "ｅｘｐｌａｉｎ detection",  # compatibility-confusable input
    "brute " * 80,
    "Failed authentication for synthetic-user from 192.0.2.33 raw-line-canary",
    "execute shell command",
])
def test_adversarial_or_private_queries_are_refused_without_echo(query):
    result = retrieve(query, QueryCategory.EXPLAIN_DETECTION, evidence())
    assert result.status is ResultStatus.REFUSED
    assert result.refusal_code in {"QUESTION_NOT_ALLOWED", "PRIVACY_INPUT_REJECTED"}
    assert query not in canonical_json(result)


@pytest.mark.parametrize(("query", "category", "expected"), [
    ("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION, "brute-force"),
    ("password spray meaning limit", QueryCategory.EXPLAIN_DETECTION, "password-spray"),
    ("failed success relation causation", QueryCategory.EXPLAIN_RELATION, "failed-success"),
    ("risk lower safe", QueryCategory.EXPLAIN_RISK, "risk-lower"),
    ("relation gone resolve", QueryCategory.EXPLAIN_RELATION, "relation-gone"),
    ("replay gap stale", QueryCategory.EXPLAIN_RECOVERY_STATE, "replay-gap"),
    ("checkpoint reset", QueryCategory.EXPLAIN_RECOVERY_STATE, "checkpoint-reset"),
    ("incomplete evidence", QueryCategory.EXPLAIN_LIMITATION, "incomplete-evidence"),
    ("no finding safe", QueryCategory.EXPLAIN_LIMITATION, "no-finding"),
    ("next checks application ssh", QueryCategory.NEXT_CHECKS, "next-checks"),
])
def test_supported_synthetic_queries_return_verified_citations(query, category, expected):
    item = evidence(
        completeness=Completeness.PARTIAL,
        limitations=("DETECTION_IS_NOT_COMPROMISE", "REPLAY_GAP_MAY_BE_STALE",
                     "CHECKPOINT_RESET_STARTS_NEW_HISTORY"),
    ) if category is QueryCategory.EXPLAIN_RECOVERY_STATE else evidence()
    result = retrieve(query, category, item)
    assert result.status is ResultStatus.OK
    assert result.citations
    assert expected in {c.document_id for c in result.citations}
    assert validate_result(result, load_corpus(), requested_top_k=5) is result


def test_category_evidence_mismatch_and_unsupported_questions_refuse():
    result = retrieve("relation failed success", QueryCategory.EXPLAIN_RELATION,
                      evidence(relation_labels=()))
    assert result.refusal_code == "EVIDENCE_CATEGORY_MISMATCH"
    result = retrieve("did attack succeed", QueryCategory.EXPLAIN_DETECTION, evidence())
    assert result.refusal_code in {"QUESTION_NOT_ALLOWED", "PRIVACY_INPUT_REJECTED"}
    result = retrieve("what is password", QueryCategory.EXPLAIN_DETECTION, evidence())
    assert result.refusal_code == "PRIVACY_INPUT_REJECTED"


def test_case_question_requires_and_returns_existing_case_evidence():
    item = evidence(case_labels=("Failed login followed by success case",))
    result = retrieve("case relation", QueryCategory.EXPLAIN_CASE, item)
    assert result.status is ResultStatus.OK
    assert "investigation-case" in {citation.document_id for citation in result.citations}
    result = retrieve("case relation", QueryCategory.EXPLAIN_CASE, evidence(case_labels=()))
    assert result.refusal_code == "EVIDENCE_CATEGORY_MISMATCH"


def test_query_category_must_match_intent_and_korean_retrieval_is_supported():
    mismatched = retrieve("risk lower safe", QueryCategory.EXPLAIN_DETECTION, evidence())
    assert mismatched.refusal_code == "EVIDENCE_CATEGORY_MISMATCH"
    result = retrieve("위험도 하향 안전", QueryCategory.EXPLAIN_RISK, evidence())
    assert result.status is ResultStatus.OK
    assert "risk-lower" in {citation.document_id for citation in result.citations}
    assert tokenize("ＢＲＵＴＥ Force") == tokenize("brute force")


def test_retrieval_is_deterministic_bounded_and_validates_no_forged_citation():
    item = evidence()
    corpus = load_corpus()
    index = build_index(corpus)
    assert index.corpus_digest == corpus.digest
    assert index.resident_bytes <= 512_000
    a = retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                 item, corpus=corpus, index=index)
    b = retrieve("brute force meaning limit", QueryCategory.EXPLAIN_DETECTION,
                 item, corpus=corpus, index=index)
    assert canonical_json(a) == canonical_json(b)
    assert len(a.citations) <= 5
    forged = a.model_copy(update={"citations": (a.citations[0].model_copy(
        update={"section_id": "missing-section"}),)})
    with pytest.raises(RetrievalError):
        validate_result(forged, load_corpus(), requested_top_k=5)
    forged = a.model_copy(update={"private": "account-canary-331"})
    with pytest.raises(RetrievalError):
        canonical_json(forged)
    with pytest.raises(RetrievalError):
        validate_result(a.model_copy(update={"corpus_digest": "0" * 64}),
                        corpus, requested_top_k=5)


def test_utc_kst_retrieval_bytes_are_identical(monkeypatch):
    import os
    import time

    outputs = []
    for zone in ("UTC", "Asia/Seoul", "UTC"):
        monkeypatch.setenv("TZ", zone)
        if hasattr(time, "tzset"):
            time.tzset()
        outputs.append(canonical_json(retrieve(
            "brute force meaning limit", QueryCategory.EXPLAIN_DETECTION, evidence(),
        )))
    assert outputs[0] == outputs[1] == outputs[2]


def test_corpus_loader_rejects_missing_tampered_and_unlisted_files(monkeypatch, tmp_path):
    from app import local_retrieval_33_1 as module

    source = module.CORPUS_DIR
    mirror = tmp_path / "corpus"
    mirror.mkdir()
    for path in source.iterdir():
        if path.is_file():
            (mirror / path.name).write_bytes(path.read_bytes())
    monkeypatch.setattr(module, "CORPUS_DIR", mirror)
    (mirror / "unlisted.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RetrievalError):
        load_corpus()
    (mirror / "unlisted.json").unlink()
    (mirror / "manifest.json").unlink()
    with pytest.raises(RetrievalError):
        load_corpus()
    for path in source.iterdir():
        if path.is_file():
            (mirror / path.name).write_bytes(path.read_bytes())
    (mirror / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RetrievalError):
        load_corpus()


def test_corpus_loader_rejects_duplicate_document_and_section_ids(monkeypatch, tmp_path):
    from app import local_retrieval_33_1 as module

    source = module.CORPUS_DIR
    mirror = tmp_path / "duplicate"
    mirror.mkdir()
    for path in source.iterdir():
        if path.is_file():
            (mirror / path.name).write_bytes(path.read_bytes())
    monkeypatch.setattr(module, "CORPUS_DIR", mirror)
    body = json.loads((mirror / "corpus.json").read_text(encoding="utf-8"))
    body["documents"][1]["document_id"] = body["documents"][0]["document_id"]
    (mirror / "corpus.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    with pytest.raises(RetrievalError):
        module.generate_manifest(mirror)
    (mirror / "manifest.json").write_bytes(_unsafe_manifest_for_fault_fixture(module, mirror))
    with pytest.raises(RetrievalError) as error:
        load_corpus()
    assert str(error.value) == "Approved knowledge is unavailable."

    body = json.loads((source / "corpus.json").read_text(encoding="utf-8"))
    body["documents"][1]["sections"][0]["section_id"] = body["documents"][0]["sections"][0]["section_id"]
    (mirror / "corpus.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    with pytest.raises(RetrievalError):
        module.generate_manifest(mirror)
    (mirror / "manifest.json").write_bytes(_unsafe_manifest_for_fault_fixture(module, mirror))
    with pytest.raises(RetrievalError):
        load_corpus()

    body = json.loads((source / "corpus.json").read_text(encoding="utf-8"))
    body["documents"][0]["sections"][0]["text"] = "brute " * 300
    (mirror / "corpus.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    with pytest.raises(RetrievalError):
        module.generate_manifest(mirror)
    (mirror / "manifest.json").write_bytes(_unsafe_manifest_for_fault_fixture(module, mirror))
    with pytest.raises(RetrievalError):
        load_corpus()


def test_corpus_loader_rejects_symlink_invalid_utf8_permission_and_oversize(
    monkeypatch, tmp_path,
):
    from app import local_retrieval_33_1 as module

    source = module.CORPUS_DIR

    def copied(name):
        mirror = tmp_path / name
        mirror.mkdir()
        for path in source.iterdir():
            if path.is_file():
                (mirror / path.name).write_bytes(path.read_bytes())
        monkeypatch.setattr(module, "CORPUS_DIR", mirror)
        return mirror

    mirror = copied("symlink")
    (mirror / "linked.json").symlink_to(mirror / "corpus.json")
    with pytest.raises(RetrievalError) as error:
        load_corpus()
    assert str(error.value) == "Approved knowledge is unavailable."

    mirror = copied("encoding")
    (mirror / "corpus.json").write_bytes(b"\xff\xfe\n")
    with pytest.raises(RetrievalError):
        load_corpus()

    mirror = copied("oversize")
    (mirror / "corpus.json").write_bytes(b" " * 65_537)
    with pytest.raises(RetrievalError):
        load_corpus()

    mirror = copied("permission")
    original = Path.read_bytes

    def denied(path):
        if path == mirror / "manifest.json":
            raise PermissionError("/private/account-canary-331")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", denied)
    with pytest.raises(RetrievalError) as error:
        load_corpus()
    assert str(error.value) == "Approved knowledge is unavailable."


def test_tokenizer_score_and_serialization_faults_fail_with_fixed_errors(monkeypatch):
    from app import local_retrieval_33_1 as module

    monkeypatch.setattr(module, "_lexical_terms", lambda _: (_ for _ in ()).throw(
        RuntimeError("/private/host-canary raw-line-canary")))
    with pytest.raises(RetrievalError) as error:
        retrieve("brute force", QueryCategory.EXPLAIN_DETECTION, evidence())
    assert str(error.value) == "Approved knowledge is unavailable."

    monkeypatch.undo()
    for invalid_score in (float("nan"), float("inf"), -1.0):
        monkeypatch.setattr(module, "_bm25", lambda *_, score=invalid_score: [
            (score, load_corpus().sections[0]),
        ])
        with pytest.raises(RetrievalError) as error:
            retrieve("brute force meaning", QueryCategory.EXPLAIN_DETECTION, evidence())
        assert str(error.value) == "The retrieval result is invalid."
        monkeypatch.undo()
    with pytest.raises(RetrievalError) as error:
        canonical_json({"private": "account-canary-331"})
    assert str(error.value) == "The retrieval result is invalid."


def test_low_score_produces_no_citation_and_top_k_is_bounded(monkeypatch):
    from app import local_retrieval_33_1 as module

    section = load_corpus().sections[0]
    monkeypatch.setattr(module, "_bm25", lambda *_: [(1.0, section)])
    result = retrieve("brute force", QueryCategory.EXPLAIN_DETECTION, evidence())
    assert result.status is ResultStatus.REFUSED
    assert result.refusal_code == "NO_SUPPORTING_CITATION"
    monkeypatch.undo()
    result = retrieve("brute force", QueryCategory.EXPLAIN_DETECTION,
                      evidence(), top_k=6)
    assert result.refusal_code == "INVALID_REQUEST"


def test_evaluation_fixture_gate_passes_privacy_citation_schema_and_determinism():
    from app.local_retrieval_33_1 import run_synthetic_evaluation

    report = run_synthetic_evaluation()
    assert report.privacy_leak_count == 0
    assert report.unsupported_citation_count == 0
    assert report.schema_validation_rate == 1.0
    assert report.authoritative_mutations == 0
    assert report.executed_injections == 0
    assert report.refusal_failures == 0
    assert report.deterministic_retrieval is True
    assert report.fixture_count >= 15
