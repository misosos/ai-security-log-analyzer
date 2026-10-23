"""Test-only envelope and output boundary for the blocked Phase 33.3B pilot.

This module never starts a model or runtime. Semantic entailment still requires
human adjudication; the validator below checks only closed structure and safe
mechanical constraints.
"""

from dataclasses import dataclass
from dataclasses import asdict
import hashlib
import json
import re

from app.local_retrieval_33_1 import (
    QueryCategory,
    RetrievalError,
    RetrievalResult,
    ResultStatus,
    SafeEvidence,
    canonical_json,
    load_corpus,
    retrieve,
    validate_result,
)


PROMPT_VERSION = "security-explainer-v1"
PROMPT_SHA256 = "0ee7cda9d3c3c7b025103c743b4088215575927e975b1fd48c8a7c0700a74ac8"
MAX_ENVELOPE_BYTES = 16_384
MAX_QUESTION_BYTES = 1_024
MAX_CITATIONS = 5
MAX_OUTPUT_BYTES = 16_384
_UNCERTAINTY_CODES = frozenset({
    "DETECTION_NOT_COMPROMISE", "CORRELATION_NOT_CAUSATION",
    "INCOMPLETE_EVIDENCE", "STALE_AFTER_GAP", "NO_FINDING_NOT_SAFE",
    "RISK_CONFIDENCE_DISTINCT", "RELATION_NOT_RESOLVED",
})
_LIMITATION_CODES = frozenset({
    "INPUT_LOG_WINDOW_MAY_BE_INCOMPLETE", "SINGLE_SOURCE_ONLY",
    "NO_SUCCESS_PROOF", "CHECKPOINT_RESET_NEW_HISTORY",
    "NO_CROSS_SOURCE_ANALYSIS", "NO_CAUSAL_CLAIM",
})
_REFUSAL_CODES = frozenset({
    "INSUFFICIENT_EVIDENCE", "CITATION_CONFLICT", "OUT_OF_SCOPE",
    "PRIVATE_DATA_REQUEST", "INVALID_MODEL_OUTPUT",
})


class PilotBoundaryError(ValueError):
    """Fixed test-only failure; rejected model bytes are never attached."""


@dataclass(frozen=True, slots=True)
class CitationInput:
    document_id: str
    section_id: str
    title: str
    excerpt: str
    lexical_score: float
    source_ref: str


@dataclass(frozen=True, slots=True)
class ExplanationEnvelope:
    schema_version: str
    request_id: str
    question_category: QueryCategory
    evidence: SafeEvidence
    citations: tuple[CitationInput, ...]
    corpus_digest: str
    retrieval_digest: str
    locale: str
    output_limit: int
    question_data: str

    def canonical_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "question_category": self.question_category.value,
            "evidence": json.loads(canonical_json(self.evidence)),
            "citations": [asdict(item) for item in self.citations],
            "corpus_digest": self.corpus_digest,
            "retrieval_digest": self.retrieval_digest,
            "locale": self.locale,
            "output_limit": self.output_limit,
            "question_data": self.question_data,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise RetrievalError("INVALID_REQUEST")
        return encoded


def build_envelope(*, request_id: str, category: QueryCategory,
                   evidence: SafeEvidence, retrieval: RetrievalResult,
                   question_data: str, locale: str = "ko-KR",
                   output_limit: int = 512) -> ExplanationEnvelope:
    try:
        corpus = load_corpus()
        if type(request_id) is not str or not re.fullmatch(r"r_[a-f0-9]{16}", request_id):
            raise ValueError
        if type(category) is not QueryCategory or type(evidence) is not SafeEvidence:
            raise ValueError
        if type(retrieval) is not RetrievalResult or retrieval.status is not ResultStatus.OK:
            raise ValueError
        validate_result(retrieval, corpus, requested_top_k=MAX_CITATIONS)
        expected = retrieve(question_data, category, evidence, corpus=corpus,
                            top_k=MAX_CITATIONS)
        if expected.status is not ResultStatus.OK or canonical_json(expected) != canonical_json(retrieval):
            raise ValueError
        if retrieval.query_category is not category or not retrieval.citations:
            raise ValueError
        if type(question_data) is not str or not question_data.strip():
            raise ValueError
        if len(question_data.encode("utf-8")) > MAX_QUESTION_BYTES:
            raise ValueError
        if any(ord(char) < 32 or ord(char) == 127 for char in question_data):
            raise ValueError
        if locale not in {"ko-KR", "en-US"} or type(output_limit) is not int:
            raise ValueError
        if not 1 <= output_limit <= 512 or len(retrieval.citations) > MAX_CITATIONS:
            raise ValueError
        citations = tuple(CitationInput(**c.model_dump(mode="json"))
                          for c in retrieval.citations)
        retrieval_bytes = json.dumps([asdict(item) for item in citations],
                                     ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")
        envelope = ExplanationEnvelope(
            "local-explanation/1", request_id, category, evidence, citations,
            corpus.digest, hashlib.sha256(retrieval_bytes).hexdigest(), locale,
            output_limit, question_data,
        )
        envelope.canonical_bytes()
        return envelope
    except RetrievalError:
        raise
    except Exception:
        raise RetrievalError("INVALID_REQUEST") from None


class _DuplicateKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKey
        output[key] = value
    return output


_OUTPUT_KEYS = {
    "status", "summary", "citation_ids", "next_checks", "uncertainty",
    "limitations", "refusal_code",
}
_UNSAFE_TEXT = re.compile(
    r"(?is)(?:<\s*/?\s*(?:script|style|think|html)|!\[[^]]*\]\([^)]*\)|"
    r"\]\((?:javascript|data):|(?:^|\s)(?:javascript|data):|"
    r"(?:\d{1,3}\.){3}\d{1,3}|/(?:Users|home)/|raw[-_ ]?log|"
    r"account[-_ ]?canary|host[-_ ]?canary|ip[-_ ]?canary|"
    r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|"
    r"(?:^|\s)(?:sudo|bash|sh|curl|wget|rm)\b|"
    r"run\s+(?:a\s+)?(?:shell|tool|command)\b)"
)


def validate_output(raw: bytes, input_citation_ids: set[str]) -> dict:
    """Validate mechanical output bounds; does not prove claim entailment."""
    try:
        if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
            raise ValueError
        if type(input_citation_ids) is not set or len(input_citation_ids) > MAX_CITATIONS:
            raise ValueError
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
        if type(value) is not dict or set(value) != _OUTPUT_KEYS:
            raise ValueError
        if value["status"] not in {"ANSWER", "REFUSED"}:
            raise ValueError
        if type(value["summary"]) is not list or len(value["summary"]) > 3:
            raise ValueError
        if type(value["next_checks"]) is not list or len(value["next_checks"]) > 3:
            raise ValueError
        if type(value["citation_ids"]) is not list or len(value["citation_ids"]) > MAX_CITATIONS:
            raise ValueError
        if any(type(item) is not str or item not in input_citation_ids
               for item in value["citation_ids"]):
            raise ValueError
        if len(set(value["citation_ids"])) != len(value["citation_ids"]):
            raise ValueError
        used_ids = set()
        for field, max_text, max_items in (("summary", 240, 3), ("next_checks", 160, 3)):
            for claim in value[field]:
                if type(claim) is not dict or set(claim) != {"text", "citation_ids"}:
                    raise ValueError
                if type(claim["text"]) is not str or not 1 <= len(claim["text"]) <= max_text:
                    raise ValueError
                ids = claim["citation_ids"]
                if type(ids) is not list or not 1 <= len(ids) <= max_items:
                    raise ValueError
                if any(type(item) is not str or item not in input_citation_ids for item in ids):
                    raise ValueError
                used_ids.update(ids)
        if used_ids != set(value["citation_ids"]):
            raise ValueError
        for field in ("uncertainty", "limitations"):
            items = value[field]
            if type(items) is not list or not 1 <= len(items) <= 8:
                raise ValueError
            allowed = _UNCERTAINTY_CODES if field == "uncertainty" else _LIMITATION_CODES
            if any(type(item) is not str or item not in allowed for item in items):
                raise ValueError
        if value["status"] == "REFUSED":
            if value["summary"] or value["next_checks"] or value["citation_ids"]:
                raise ValueError
            if type(value["refusal_code"]) is not str or value["refusal_code"] not in _REFUSAL_CODES:
                raise ValueError
        elif value["refusal_code"] is not None or not value["summary"]:
            raise ValueError
        texts = [claim["text"] for field in ("summary", "next_checks")
                 for claim in value[field]]
        if any(_UNSAFE_TEXT.search(text) or any(ord(char) < 32 for char in text)
               for text in texts):
            raise ValueError
        return value
    except Exception:
        raise PilotBoundaryError("The local explanation output is invalid.") from None
