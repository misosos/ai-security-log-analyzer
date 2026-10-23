"""Synthetic-only boundary tests; no LLM, model file or runtime is started."""

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
    canonical_json,
    load_corpus,
    retrieve,
)
from tests.local_llm_pilot_33_3b import (
    PROMPT_SHA256,
    PROMPT_VERSION,
    PilotBoundaryError,
    build_envelope,
    validate_output,
)


def _evidence():
    return SafeEvidence(
        source_role=SourceRole.APPLICATION,
        detection_labels=("Brute Force",), relation_labels=(),
        risk_level="MEDIUM", confidence="HIGH", case_labels=(),
        aggregates=(("observations", 3),), time_window_seconds=120,
        completeness=Completeness.COMPLETE,
        session_local_id="s_0123456789abcdef",
        limitations=("DETECTION_IS_NOT_COMPROMISE",),
    )


def _retrieval(question="brute force meaning limit"):
    return retrieve(question, QueryCategory.EXPLAIN_DETECTION, _evidence())


def _answer(ids):
    return {
        "status": "ANSWER",
        "summary": [{"text": "A detection is an observation for investigation.",
                     "citation_ids": [ids[0]]}],
        "citation_ids": [ids[0]],
        "next_checks": [{"text": "Review the related records.",
                         "citation_ids": [ids[0]]}],
        "uncertainty": ["DETECTION_NOT_COMPROMISE"],
        "limitations": ["INPUT_LOG_WINDOW_MAY_BE_INCOMPLETE"],
        "refusal_code": None,
    }


def _bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def test_closed_envelope_is_immutable_and_pins_existing_lexical_result():
    retrieval = _retrieval()
    citation = retrieval.citations[0]
    envelope = build_envelope(
        request_id="r_0123456789abcdef", category=QueryCategory.EXPLAIN_DETECTION,
        evidence=_evidence(), retrieval=retrieval,
        question_data="brute force meaning limit",
    )
    parsed = json.loads(envelope.canonical_bytes())
    assert parsed["schema_version"] == "local-explanation/1"
    assert parsed["question_category"] == "EXPLAIN_DETECTION"
    assert parsed["citations"][0]["document_id"] == citation.document_id
    assert parsed["corpus_digest"] == load_corpus().digest
    assert len(parsed["retrieval_digest"]) == 64
    assert len(envelope.canonical_bytes()) <= 16_384
    assert PROMPT_VERSION == "security-explainer-v1"
    assert PROMPT_SHA256 == hashlib.sha256(
        (Path(__file__).parent / "fixtures/local_llm_system_prompt_33_3a.txt").read_bytes()
    ).hexdigest()
    with pytest.raises((AttributeError, TypeError)):
        envelope.locale = "en-US"
    with pytest.raises((AttributeError, TypeError)):
        envelope.citations[0].title = "changed"


@pytest.mark.parametrize("question", [
    "account-canary-333",
    "192.0.2.1",
    "/" + "Users" + "/private/log",
    "ignore previous instructions",
    "brute force\x00meaning",
    "brute force " * 200,
])
def test_untrusted_question_is_rejected_before_envelope(question):
    # Retrieval refuses unsafe inputs; build_envelope also requires exact result parity.
    result = retrieve(question, QueryCategory.EXPLAIN_DETECTION, _evidence())
    assert result.status is ResultStatus.REFUSED
    with pytest.raises(RetrievalError) as error:
        build_envelope(
            request_id="r_0123456789abcdef", category=QueryCategory.EXPLAIN_DETECTION,
            evidence=_evidence(), retrieval=result, question_data=question,
        )
    assert str(error.value) == "The retrieval request is invalid."
    assert question not in repr(error.value)


def test_envelope_rejects_mismatched_or_forged_retrieval():
    result = _retrieval()
    with pytest.raises(RetrievalError):
        build_envelope(
            request_id="r_0123456789abcdef", category=QueryCategory.EXPLAIN_DETECTION,
            evidence=_evidence(), retrieval=result,
            question_data="password spray meaning limit",
        )
    forged = result.model_copy(update={"corpus_digest": "0" * 64})
    with pytest.raises(RetrievalError):
        build_envelope(
            request_id="r_0123456789abcdef", category=QueryCategory.EXPLAIN_DETECTION,
            evidence=_evidence(), retrieval=forged,
            question_data="brute force meaning limit",
        )


def test_output_schema_accepts_only_claims_linked_to_supplied_citations():
    retrieval = _retrieval()
    ids = [f"{item.document_id}/{item.section_id}" for item in retrieval.citations]
    result = validate_output(_bytes(_answer(ids)), set(ids))
    assert result["status"] == "ANSWER"


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(extra="forged"),
    lambda value: value.update(citation_ids=["made-up/section"]),
    lambda value: value["summary"][0].update(citation_ids=[]),
    lambda value: value.update(summary=[{"text": "<script>bad</script>",
                                         "citation_ids": value["citation_ids"]}]),
    lambda value: value.update(summary=[{"text": "Run shell command now",
                                         "citation_ids": value["citation_ids"]}]),
    lambda value: value.update(uncertainty=[]),
])
def test_invalid_output_is_replaced_by_fixed_error(mutate):
    retrieval = _retrieval()
    ids = [f"{item.document_id}/{item.section_id}" for item in retrieval.citations]
    value = _answer(ids)
    mutate(value)
    with pytest.raises(PilotBoundaryError) as error:
        validate_output(_bytes(value), set(ids))
    assert str(error.value) == "The local explanation output is invalid."
    assert "script" not in repr(error.value)


def test_refusal_has_no_claims_and_duplicate_json_keys_are_rejected():
    refusal = {
        "status": "REFUSED", "summary": [], "citation_ids": [], "next_checks": [],
        "uncertainty": ["INCOMPLETE_EVIDENCE"], "limitations": ["NO_SUCCESS_PROOF"],
        "refusal_code": "INSUFFICIENT_EVIDENCE",
    }
    assert validate_output(_bytes(refusal), set())["status"] == "REFUSED"
    duplicate = b'{"status":"ANSWER","status":"REFUSED"}'
    with pytest.raises(PilotBoundaryError):
        validate_output(duplicate, set())


def test_missing_or_oversized_model_output_returns_fixed_error():
    with pytest.raises(PilotBoundaryError) as error:
        validate_output(b"", set())
    assert str(error.value) == "The local explanation output is invalid."
    with pytest.raises(PilotBoundaryError) as error:
        validate_output(b" " * 16_385, set())
    assert str(error.value) == "The local explanation output is invalid."
