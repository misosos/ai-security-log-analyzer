"""Internal, deterministic investigation assistance with no model/provider path."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import ipaddress
import json
import re
import threading
import unicodedata
from typing import Mapping

from app.local_retrieval_33_1 import (
    Completeness,
    Corpus,
    LexicalIndex,
    QueryCategory,
    RetrievalError,
    ResultStatus,
    SafeEvidence,
    SourceRole,
    TRUSTED_CORPUS_DIGEST,
    build_index,
    load_corpus,
    retrieve,
    validate_result,
)


CORPUS_DIGEST = TRUSTED_CORPUS_DIGEST
MAX_INPUT_BYTES = 4_096
MAX_OUTPUT_BYTES = 8_192
MAX_LIST_ITEMS = 16
MAX_TEXT_BYTES = 512
MAX_PRIORITY_REASONS = 4
MAX_INVESTIGATION_STEPS = 5
MAX_UNCERTAINTY = 4
MAX_CITATIONS = 8
MAX_CONCURRENT_REQUESTS = 1

DTO_FIELDS = (
    "schema_version", "request_id", "case_ref", "source_role",
    "observation_categories", "detection_codes", "relation_codes", "risk_band",
    "case_status", "event_count_bucket", "time_window_bucket",
    "evidence_completeness", "limitation_codes", "verified_citation_ids",
    "corpus_digest",
)
_CREATE_FIELDS = tuple(name for name in DTO_FIELDS if name != "verified_citation_ids")
OUTPUT_FIELDS = (
    "schema_version", "request_id", "case_ref", "review_priority",
    "priority_reasons", "investigation_steps", "explanation", "uncertainty",
    "limitation_codes", "generated_by", "status",
)


class ReviewPriority(StrEnum):
    REVIEW_NOW = "review_now"
    REVIEW_SOON = "review_soon"
    REVIEW_LATER = "review_later"
    UNDETERMINED = "undetermined"


class EvidenceCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    CONFLICTING = "conflicting"
    UNKNOWN = "unknown"


class TriageError(Exception):
    _MESSAGES = {
        "DTO_INVALID": "Investigation assistance input is invalid.",
        "CITATION_INVALID": "Approved citation could not be verified.",
        "OUTPUT_INVALID": "Investigation assistance output is invalid.",
        "CORPUS_UNAVAILABLE": "Approved investigation guidance is unavailable.",
    }

    def __init__(self, code: str):
        self.code = code if code in self._MESSAGES else "DTO_INVALID"
        super().__init__(self._MESSAGES[self.code])


_ROLES = frozenset({"application", "ssh", "access", "unknown"})
_OBSERVATION_CATEGORIES = frozenset({
    "authentication", "web_request", "process_execution", "relation", "risk",
    "case_lifecycle", "unknown",
})
_DETECTION_CODES = frozenset({
    "brute_force", "password_spraying_like", "path_traversal", "sql_injection_like",
    "xss_like", "sensitive_resource_probing_like", "web_scanning_like",
})
_RELATION_CODES = frozenset({
    "failed_to_successful_login", "brute_force_to_successful_login",
    "password_spray_to_successful_login",
})
_RISK_BANDS = frozenset({"LOW", "MEDIUM", "HIGH", "UNKNOWN"})
_CASE_STATUSES = frozenset({"open", "stale", "unknown"})
_EVENT_BUCKETS = frozenset({"0", "1", "2_5", "6_20", "21_plus"})
_TIME_BUCKETS = frozenset({"under_5m", "5_60m", "over_60m", "unknown"})
_COMPLETENESS = frozenset(item.value for item in EvidenceCompleteness)
_LIMITATIONS = frozenset({
    "DETECTION_IS_NOT_COMPROMISE", "CORRELATION_IS_NOT_CAUSATION",
    "NO_FINDING_IS_NOT_SAFE", "RISK_DOWN_IS_NOT_SAFE",
    "RELATION_GONE_IS_NOT_RESOLVED", "REPLAY_GAP_MAY_BE_STALE",
    "CHECKPOINT_RESET_STARTS_NEW_HISTORY", "INCOMPLETE_EVIDENCE",
    "APPLICATION_SSH_NOT_CROSS_CORRELATED",
})
_REQUEST_ID = re.compile(r"r_[0-9a-f]{24}\Z")
_CASE_REF = re.compile(r"c_[0-9a-f]{24}\Z")
_CITATION_ID = re.compile(r"[a-z0-9-]{1,48}:[a-z0-9-]{1,48}\Z")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w.-])")
_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[A-Za-z]{2,}\b")
_ACCOUNT_OR_SECRET = re.compile(
    r"\b(?:account|username|user|hostname|host|ip|credential|password|token|secret)\s*[:=]",
    re.IGNORECASE,
)
_URL = re.compile(r"(?:https?://|www\.)", re.IGNORECASE)
_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\([^)]*\)")
_ABS_PATH = re.compile(r"(?:^|\s)(?:/|~[/\\])")
_ACTION_LANGUAGE = re.compile(
    r"\b(?:sudo|shell|bash|powershell|curl|wget|execute|run\s+(?:this|the|command)|"
    r"delete\s+(?:the|file)|block\s+(?:the|this)|lock\s+(?:the|this)|kill\s+(?:the|this)|tool\s+call)\b",
    re.IGNORECASE,
)
_BIDI = frozenset(chr(code) for code in (
    *range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F, 0x061C,
))

_DETECTION_LABELS = {
    "brute_force": "Brute Force",
    "password_spraying_like": "Password Spraying-like",
    "path_traversal": "Path Traversal",
    "sql_injection_like": "SQL Injection-like",
    "xss_like": "XSS-like",
    "sensitive_resource_probing_like": "Sensitive Resource Probing-like",
    "web_scanning_like": "Web Scanning-like",
}
_RELATION_LABELS = {
    "failed_to_successful_login": "Failed login followed by success",
    "brute_force_to_successful_login": "Brute Force followed by success",
    "password_spray_to_successful_login": "Password Spraying-like followed by success",
}
_CASE_LABELS = {
    "failed_to_successful_login": "Failed login followed by success case",
    "brute_force_to_successful_login": "Brute Force followed by success case",
    "password_spray_to_successful_login": "Password Spraying-like followed by success case",
}
_DETECTION_QUERY = {
    "brute_force": "brute force meaning limit",
    "password_spraying_like": "password spray meaning limit",
}
_CITATION_TOPICS = {
    "next-checks": "operator follow-up",
    "nist-incident-response": "investigation procedure",
    "owasp-safe-logging": "safe log review",
    "failed-success": "authentication relation",
    "incomplete-evidence": "completeness",
    "conflicting-evidence": "evidence limits",
    "no-finding": "analysis limitation",
    "brute-force": "authentication detection",
    "password-spray": "authentication detection",
}
_CITATION_QUERIES = (
    ("next checks application ssh", QueryCategory.NEXT_CHECKS, "operator follow-up"),
    ("next checks application ssh", QueryCategory.NEXT_CHECKS, "investigation procedure"),
    ("next checks application ssh", QueryCategory.NEXT_CHECKS, "safe log review"),
)
_REASON_TEXT = {
    "priority_incomplete_evidence": "근거 범위가 불완전하여 자료 범위를 먼저 확인하도록 제안합니다.",
    "priority_relation_review": "기존 관계 관찰의 근거와 순서를 별도로 검토하도록 제안합니다.",
    "priority_detection_review": "기존 결정적 관찰의 근거와 범위를 검토하도록 제안합니다.",
    "priority_general_review": "현재 제공된 범주를 기준으로 후속 확인 순서를 제안합니다.",
    "priority_undetermined": "현재 근거만으로 검토 순서를 정할 수 없습니다.",
}
_STEP_TEXT = {
    "verify_evidence_coverage": "필요한 자료와 시간 범위가 충분히 포함됐는지 확인하세요.",
    "review_observation_context": "기존 관찰의 근거와 주변 운영 맥락을 확인하세요.",
    "review_relation_order": "관계에 포함된 각 관찰과 시간 순서를 따로 확인하세요.",
    "review_conflicting_evidence": "서로 다른 근거가 각각 무엇을 보여 주는지 확인하세요.",
}
_EXPLANATION_TEXT = (
    "이 결과는 분석가의 검토 순서를 돕는 참고 제안이며 기존 탐지·위험도·사례 결과를 바꾸지 않습니다."
)


def _fail(code: str) -> None:
    raise TriageError(code) from None


def _strict_int(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _tuple_field(value: object, allowed: frozenset[str], maximum: int) -> tuple[str, ...]:
    if type(value) not in (tuple, list) or len(value) > maximum:
        _fail("DTO_INVALID")
    values = tuple(value)
    if any(type(item) is not str or item not in allowed for item in values):
        _fail("DTO_INVALID")
    if len(set(values)) != len(values):
        _fail("DTO_INVALID")
    return values


def _valid_opaque(value: object, pattern: re.Pattern[str]) -> bool:
    return (type(value) is str and pattern.fullmatch(value) is not None
            and len(set(value[2:])) >= 8)


def _validate_dto_values(values: Mapping[str, object], *, allow_citations: bool) -> dict:
    expected = set(DTO_FIELDS if allow_citations else _CREATE_FIELDS)
    if type(values) is not dict or set(values) != expected:
        _fail("DTO_INVALID")
    result = dict(values)
    if not _strict_int(result["schema_version"], 1):
        _fail("DTO_INVALID")
    if not _valid_opaque(result["request_id"], _REQUEST_ID):
        _fail("DTO_INVALID")
    if not _valid_opaque(result["case_ref"], _CASE_REF):
        _fail("DTO_INVALID")
    if result["request_id"][2:] == result["case_ref"][2:]:
        _fail("DTO_INVALID")
    if type(result["source_role"]) is not str or result["source_role"] not in _ROLES:
        _fail("DTO_INVALID")
    result["observation_categories"] = _tuple_field(
        result["observation_categories"], _OBSERVATION_CATEGORIES, 8,
    )
    result["detection_codes"] = _tuple_field(result["detection_codes"], _DETECTION_CODES, 16)
    result["relation_codes"] = _tuple_field(result["relation_codes"], _RELATION_CODES, 8)
    for field_name, allowed in (
        ("risk_band", _RISK_BANDS), ("case_status", _CASE_STATUSES),
        ("event_count_bucket", _EVENT_BUCKETS), ("time_window_bucket", _TIME_BUCKETS),
        ("evidence_completeness", _COMPLETENESS),
    ):
        if type(result[field_name]) is not str or result[field_name] not in allowed:
            _fail("DTO_INVALID")
    result["limitation_codes"] = _tuple_field(result["limitation_codes"], _LIMITATIONS, 16)
    digest = result["corpus_digest"]
    if type(digest) is not str or digest != CORPUS_DIGEST:
        _fail("DTO_INVALID")
    if allow_citations:
        citations = result["verified_citation_ids"]
        if (type(citations) not in (tuple, list) or len(citations) > MAX_CITATIONS
                or any(type(value) is not str or not _CITATION_ID.fullmatch(value)
                       for value in citations)
                or len(set(citations)) != len(citations)):
            _fail("DTO_INVALID")
        result["verified_citation_ids"] = tuple(citations)
    canonical = dict(result)
    for name in ("observation_categories", "detection_codes", "relation_codes", "limitation_codes"):
        canonical[name] = list(canonical[name])
    if not allow_citations:
        canonical["verified_citation_ids"] = []
    try:
        if len(json.dumps(canonical, ensure_ascii=False, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")) > MAX_INPUT_BYTES:
            _fail("DTO_INVALID")
    except TriageError:
        raise
    except Exception:
        _fail("DTO_INVALID")
    return result


@dataclass(frozen=True, slots=True, init=False, repr=False)
class SafeInvestigationDTO:
    schema_version: int
    request_id: str = field(repr=False)
    case_ref: str = field(repr=False)
    source_role: str
    observation_categories: tuple[str, ...]
    detection_codes: tuple[str, ...]
    relation_codes: tuple[str, ...]
    risk_band: str
    case_status: str
    event_count_bucket: str
    time_window_bucket: str
    evidence_completeness: str
    limitation_codes: tuple[str, ...]
    verified_citation_ids: tuple[str, ...] = field(repr=False)
    corpus_digest: str

    @classmethod
    def from_mapping(cls, value: object) -> "SafeInvestigationDTO":
        try:
            if type(value) is not dict:
                _fail("DTO_INVALID")
            checked = _validate_dto_values(value, allow_citations=True)
            _validate_verified_ids(checked)
            item = object.__new__(cls)
            for name in DTO_FIELDS:
                object.__setattr__(item, name, checked[name])
            return item
        except TriageError:
            raise
        except Exception:
            _fail("DTO_INVALID")

    @classmethod
    def from_json(cls, raw: str | bytes) -> "SafeInvestigationDTO":
        try:
            if type(raw) is bytes:
                if len(raw) > MAX_INPUT_BYTES:
                    _fail("DTO_INVALID")
                text = raw.decode("utf-8", errors="strict")
            elif type(raw) is str:
                if len(raw.encode("utf-8", errors="strict")) > MAX_INPUT_BYTES:
                    _fail("DTO_INVALID")
                text = raw
            else:
                _fail("DTO_INVALID")
            parsed = json.loads(text, object_pairs_hook=_reject_duplicate_pairs,
                                parse_constant=_reject_constant)
            return cls.from_mapping(parsed)
        except TriageError:
            raise
        except Exception:
            _fail("DTO_INVALID")

    def to_mapping(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "case_ref": self.case_ref,
            "source_role": self.source_role,
            "observation_categories": list(self.observation_categories),
            "detection_codes": list(self.detection_codes),
            "relation_codes": list(self.relation_codes),
            "risk_band": self.risk_band,
            "case_status": self.case_status,
            "event_count_bucket": self.event_count_bucket,
            "time_window_bucket": self.time_window_bucket,
            "evidence_completeness": self.evidence_completeness,
            "limitation_codes": list(self.limitation_codes),
            "verified_citation_ids": list(self.verified_citation_ids),
            "corpus_digest": self.corpus_digest,
        }

    def __repr__(self) -> str:
        return "SafeInvestigationDTO(<redacted>)"


def create_safe_investigation_dto(**values: object) -> SafeInvestigationDTO:
    """Create an immutable DTO after deriving its citations from the approved corpus."""
    try:
        supplied_citations = "verified_citation_ids" in values
        checked = _validate_dto_values(values, allow_citations=supplied_citations)
        citations = (checked["verified_citation_ids"] if supplied_citations
                     else _retrieve_citation_ids(checked))
        if supplied_citations:
            _validate_verified_ids(checked)
        return SafeInvestigationDTO.from_mapping({
            **checked,
            "verified_citation_ids": citations,
        })
    except TriageError:
        raise
    except Exception:
        _fail("DTO_INVALID")


def _safe_evidence(values: Mapping[str, object]) -> SafeEvidence:
    role = None
    if values["source_role"] in {"application", "ssh"}:
        role = SourceRole(values["source_role"])
    relation_labels = tuple(_RELATION_LABELS[item] for item in values["relation_codes"])
    case_labels = tuple(_CASE_LABELS[item] for item in values["relation_codes"])
    completeness_value = values["evidence_completeness"]
    completeness = (Completeness.UNKNOWN if completeness_value == EvidenceCompleteness.CONFLICTING.value
                   else Completeness(completeness_value))
    session = "s_" + hashlib.sha256(values["request_id"].encode("ascii")).hexdigest()[:16]
    return SafeEvidence(
        source_role=role,
        detection_labels=tuple(_DETECTION_LABELS[item] for item in values["detection_codes"]),
        relation_labels=relation_labels,
        risk_level="UNKNOWN",
        confidence="UNKNOWN",
        case_labels=case_labels,
        aggregates=(),
        time_window_seconds=None,
        completeness=completeness,
        session_local_id=session,
        limitations=tuple(values["limitation_codes"]),
    )


def _retrieval_ids_for_category(
    query: str, category: QueryCategory, evidence: SafeEvidence,
    corpus: Corpus, index: LexicalIndex, approved_topic: str,
) -> tuple[str, ...]:
    result = retrieve(query, category, evidence, corpus=corpus, index=index, top_k=5)
    result = validate_result(result, corpus, requested_top_k=5)
    if result.status is not ResultStatus.OK:
        return ()
    topic_sections = {
        (section.document_id, section.section_id): section
        for section in corpus.sections if section.approved_topic == approved_topic
    }
    return tuple(
        f"{citation.document_id}:{citation.section_id}"
        for citation in result.citations
        if (citation.document_id, citation.section_id) in topic_sections
    )


def _retrieve_citation_ids(values: Mapping[str, object]) -> tuple[str, ...]:
    try:
        corpus = load_corpus()
        if corpus.digest != CORPUS_DIGEST or corpus.digest != values["corpus_digest"]:
            _fail("CORPUS_UNAVAILABLE")
        index = build_index(corpus)
        evidence = _safe_evidence(values)
        found: list[str] = []
        for query, category, topic in _CITATION_QUERIES:
            found.extend(_retrieval_ids_for_category(query, category, evidence, corpus, index, topic))
        if values["relation_codes"]:
            found.extend(_retrieval_ids_for_category(
                "failed success relation causation", QueryCategory.EXPLAIN_RELATION,
                evidence, corpus, index, "authentication relation",
            ))
        if values["detection_codes"]:
            for code in values["detection_codes"]:
                query = _DETECTION_QUERY.get(code)
                if query:
                    found.extend(_retrieval_ids_for_category(
                        query, QueryCategory.EXPLAIN_DETECTION, evidence, corpus, index,
                        "authentication detection",
                    ))
        if values["evidence_completeness"] != EvidenceCompleteness.COMPLETE.value:
            limitation_query = (
                "conflicting evidence" if values["evidence_completeness"] == "conflicting"
                else "incomplete evidence"
            )
            topic = "evidence limits" if limitation_query.startswith("conflicting") else "completeness"
            found.extend(_retrieval_ids_for_category(
                limitation_query, QueryCategory.EXPLAIN_LIMITATION, evidence, corpus, index, topic,
            ))
        if not found:
            _fail("CITATION_INVALID")
        unique = tuple(dict.fromkeys(found))
        if len(unique) > MAX_CITATIONS:
            _fail("CITATION_INVALID")
        return unique
    except TriageError:
        raise
    except RetrievalError:
        _fail("CORPUS_UNAVAILABLE")
    except Exception:
        _fail("CORPUS_UNAVAILABLE")


def _validate_verified_ids(values: Mapping[str, object]) -> None:
    try:
        verified = _retrieve_citation_ids(values)
        if not values["verified_citation_ids"] or not set(values["verified_citation_ids"]).issubset(verified):
            _fail("CITATION_INVALID")
    except TriageError:
        raise
    except Exception:
        _fail("CITATION_INVALID")


@dataclass(frozen=True, slots=True, repr=False)
class CitedText:
    code: str
    text: str
    citation_ids: tuple[str, ...]

    def __repr__(self) -> str:
        return "CitedText(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class InvestigationAssistance:
    schema_version: int
    request_id: str = field(repr=False)
    case_ref: str = field(repr=False)
    review_priority: ReviewPriority
    priority_reasons: tuple[CitedText, ...]
    investigation_steps: tuple[CitedText, ...]
    explanation: CitedText
    uncertainty: tuple[str, ...]
    limitation_codes: tuple[str, ...]
    generated_by: str
    status: str

    def all_citation_ids(self) -> tuple[str, ...]:
        values = []
        for item in (*self.priority_reasons, *self.investigation_steps, self.explanation):
            values.extend(item.citation_ids)
        return tuple(dict.fromkeys(values))

    def to_mapping(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "case_ref": self.case_ref,
            "review_priority": self.review_priority.value,
            "priority_reasons": [_cited_mapping(item) for item in self.priority_reasons],
            "investigation_steps": [_cited_mapping(item) for item in self.investigation_steps],
            "explanation": _cited_mapping(self.explanation),
            "uncertainty": list(self.uncertainty),
            "limitation_codes": list(self.limitation_codes),
            "generated_by": self.generated_by,
            "status": self.status,
        }

    def to_json(self) -> str:
        try:
            encoded = json.dumps(self.to_mapping(), ensure_ascii=False, separators=(",", ":"),
                                 allow_nan=False).encode("utf-8")
            if len(encoded) > MAX_OUTPUT_BYTES:
                _fail("OUTPUT_INVALID")
            return encoded.decode("utf-8")
        except TriageError:
            raise
        except Exception:
            _fail("OUTPUT_INVALID")

    def __repr__(self) -> str:
        return "InvestigationAssistance(<redacted>)"


def _cited_mapping(item: CitedText) -> dict:
    return {"code": item.code, "text": item.text, "citation_ids": list(item.citation_ids)}


def _priority(item: SafeInvestigationDTO) -> tuple[ReviewPriority, str, tuple[str, ...]]:
    # Engineering heuristic for review ordering only. Risk, counts, and time buckets are ignored.
    if (item.source_role == "unknown" or "unknown" in item.observation_categories
            or item.evidence_completeness in {"conflicting", "unknown"}):
        return ReviewPriority.UNDETERMINED, "priority_undetermined", ("evidence_conflict_or_unknown",)
    if item.evidence_completeness == "partial":
        return ReviewPriority.REVIEW_SOON, "priority_incomplete_evidence", ("evidence_scope_incomplete",)
    if item.relation_codes:
        return ReviewPriority.REVIEW_SOON, "priority_relation_review", ()
    if item.detection_codes:
        return ReviewPriority.REVIEW_SOON, "priority_detection_review", ()
    if item.observation_categories:
        return ReviewPriority.REVIEW_LATER, "priority_general_review", ()
    return ReviewPriority.UNDETERMINED, "priority_undetermined", ("insufficient_context",)


def _select_citation(item: SafeInvestigationDTO, prefixes: tuple[str, ...]) -> str | None:
    for citation_id in item.verified_citation_ids:
        if citation_id.split(":", 1)[0] in prefixes:
            return citation_id
    return None


def _make_steps(item: SafeInvestigationDTO) -> tuple[CitedText, ...]:
    checks: list[CitedText] = []
    completeness_citation = _select_citation(item, ("incomplete-evidence", "conflicting-evidence"))
    generic_citation = _select_citation(item, ("next-checks", "nist-incident-response", "owasp-safe-logging"))
    relation_citation = _select_citation(item, ("failed-success",))
    if item.evidence_completeness != "complete" and completeness_citation:
        checks.append(CitedText("verify_evidence_coverage", _STEP_TEXT["verify_evidence_coverage"],
                                (completeness_citation,)))
    if item.relation_codes and relation_citation:
        checks.append(CitedText("review_relation_order", _STEP_TEXT["review_relation_order"],
                                (relation_citation,)))
    if (item.detection_codes or item.observation_categories) and generic_citation:
        checks.append(CitedText("review_observation_context", _STEP_TEXT["review_observation_context"],
                                (generic_citation,)))
    if not checks and generic_citation:
        checks.append(CitedText("verify_evidence_coverage", _STEP_TEXT["verify_evidence_coverage"],
                                (generic_citation,)))
    return tuple(checks[:MAX_INVESTIGATION_STEPS])


def _build_result(item: SafeInvestigationDTO, *, status: str = "available") -> InvestigationAssistance:
    if status != "available":
        if status not in {"refused", "unavailable"}:
            _fail("OUTPUT_INVALID")
        return InvestigationAssistance(
            schema_version=1, request_id=item.request_id, case_ref=item.case_ref,
            review_priority=ReviewPriority.UNDETERMINED, priority_reasons=(),
            investigation_steps=(), explanation=CitedText("", "", ()), uncertainty=(),
            limitation_codes=(), generated_by="deterministic_reference", status=status,
        )
    priority, reason_code, uncertainty = _priority(item)
    if reason_code == "priority_relation_review":
        reason_citation = _select_citation(item, ("failed-success",))
    elif reason_code == "priority_incomplete_evidence":
        reason_citation = _select_citation(item, ("incomplete-evidence", "conflicting-evidence"))
    else:
        reason_citation = _select_citation(item, ("next-checks", "nist-incident-response", "owasp-safe-logging"))
    steps = _make_steps(item)
    if not reason_citation and steps:
        reason_citation = steps[0].citation_ids[0]
    if not reason_citation or not steps:
        _fail("CITATION_INVALID")
    reasons = (CitedText(reason_code, _REASON_TEXT[reason_code], (reason_citation,)),)
    explanation_citation = _select_citation(item, ("investigation-case", "next-checks", "nist-incident-response"))
    if explanation_citation is None:
        explanation_citation = steps[0].citation_ids[0]
    explanation = CitedText("separate_assistance_only", _EXPLANATION_TEXT, (explanation_citation,))
    result = InvestigationAssistance(
        schema_version=1, request_id=item.request_id, case_ref=item.case_ref,
        review_priority=priority, priority_reasons=reasons,
        investigation_steps=steps, explanation=explanation,
        uncertainty=uncertainty, limitation_codes=item.limitation_codes,
        generated_by="deterministic_reference", status="available",
    )
    return validate_assistance_json(result.to_json(), item)


def build_investigation_assistance(item: SafeInvestigationDTO) -> InvestigationAssistance:
    if type(item) is not SafeInvestigationDTO:
        _fail("DTO_INVALID")
    try:
        values = item.to_mapping()
        if values["corpus_digest"] != CORPUS_DIGEST:
            return fixed_result(item, "unavailable")
        _validate_verified_ids(values)
        return _build_result(item)
    except TriageError as error:
        if error.code in {"CORPUS_UNAVAILABLE", "CITATION_INVALID"}:
            return fixed_result(item, "unavailable" if error.code == "CORPUS_UNAVAILABLE" else "refused")
        raise
    except Exception:
        return fixed_result(item, "unavailable")


def fixed_result(item: SafeInvestigationDTO, status: str) -> InvestigationAssistance:
    if type(item) is not SafeInvestigationDTO or status not in {"refused", "unavailable"}:
        _fail("OUTPUT_INVALID")
    return _build_result(item, status=status)


def _reject_duplicate_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _reject_constant(_value):
    raise ValueError


def _safe_text(value: object) -> bool:
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        return False
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} or char in _BIDI for char in value):
        return False
    if ("<" in value or ">" in value or _URL.search(value) or _MARKDOWN_LINK.search(value)
            or _ABS_PATH.search(value) or _EMAIL.search(value) or _ACCOUNT_OR_SECRET.search(value)
            or _IPV4.search(value) or _DOMAIN.search(value) or _ACTION_LANGUAGE.search(value)):
        return False
    try:
        for token in re.findall(r"[0-9A-Fa-f:]{2,}", value):
            if ":" in token:
                try:
                    ipaddress.ip_address(token)
                    return False
                except ValueError:
                    pass
    except Exception:
        return False
    return True


_REASON_CODES = frozenset(_REASON_TEXT)
_STEP_CODES = frozenset(_STEP_TEXT)
_UNCERTAINTY_CODES = frozenset({
    "evidence_conflict_or_unknown", "evidence_scope_incomplete", "insufficient_context",
})
_OUTPUT_STATUSES = frozenset({"available", "refused", "unavailable"})
_CITATION_PREFIXES_BY_CODE = {
    "priority_relation_review": frozenset({"failed-success"}),
    "priority_incomplete_evidence": frozenset({"incomplete-evidence", "conflicting-evidence"}),
    "priority_detection_review": frozenset({"next-checks", "nist-incident-response", "owasp-safe-logging"}),
    "priority_general_review": frozenset({"next-checks", "nist-incident-response", "owasp-safe-logging"}),
    "priority_undetermined": frozenset({"next-checks", "nist-incident-response", "owasp-safe-logging"}),
    "verify_evidence_coverage": frozenset({
        "incomplete-evidence", "conflicting-evidence", "next-checks",
        "nist-incident-response", "owasp-safe-logging",
    }),
    "review_observation_context": frozenset({"next-checks", "nist-incident-response", "owasp-safe-logging"}),
    "review_relation_order": frozenset({"failed-success"}),
    "review_conflicting_evidence": frozenset({"conflicting-evidence"}),
    "separate_assistance_only": frozenset({"next-checks", "nist-incident-response", "investigation-case"}),
}


def validate_assistance_json(raw: str | bytes, item: SafeInvestigationDTO) -> InvestigationAssistance:
    try:
        if type(item) is not SafeInvestigationDTO or type(raw) not in {str, bytes}:
            _fail("OUTPUT_INVALID")
        if type(raw) is bytes:
            if len(raw) > MAX_OUTPUT_BYTES:
                _fail("OUTPUT_INVALID")
            text = raw.decode("utf-8", errors="strict")
        else:
            if len(raw.encode("utf-8", errors="strict")) > MAX_OUTPUT_BYTES:
                _fail("OUTPUT_INVALID")
            text = raw
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_pairs,
                            parse_constant=_reject_constant)
        if type(parsed) is not dict or tuple(parsed) != OUTPUT_FIELDS:
            _fail("OUTPUT_INVALID")
        if not _strict_int(parsed["schema_version"], 1):
            _fail("OUTPUT_INVALID")
        if parsed["request_id"] != item.request_id or parsed["case_ref"] != item.case_ref:
            _fail("OUTPUT_INVALID")
        if type(parsed["review_priority"]) is not str:
            _fail("OUTPUT_INVALID")
        priority = ReviewPriority(parsed["review_priority"])
        status = parsed["status"]
        if type(status) is not str or status not in _OUTPUT_STATUSES:
            _fail("OUTPUT_INVALID")
        expected_priority, expected_reason, _ = _priority(item)
        if status == "available" and priority is not expected_priority:
            _fail("OUTPUT_INVALID")
        if parsed["generated_by"] != "deterministic_reference":
            _fail("OUTPUT_INVALID")
        raw_reasons, raw_steps = parsed["priority_reasons"], parsed["investigation_steps"]
        raw_uncertainty, raw_limitations = parsed["uncertainty"], parsed["limitation_codes"]
        if (type(raw_reasons) is not list or len(raw_reasons) > MAX_PRIORITY_REASONS
                or type(raw_steps) is not list or len(raw_steps) > MAX_INVESTIGATION_STEPS
                or type(raw_uncertainty) is not list or len(raw_uncertainty) > MAX_UNCERTAINTY
                or type(raw_limitations) is not list or len(raw_limitations) > 16):
            _fail("OUTPUT_INVALID")
        if (len(set(raw_uncertainty)) != len(raw_uncertainty)
                or any(type(value) is not str or value not in _UNCERTAINTY_CODES for value in raw_uncertainty)
                or len(set(raw_limitations)) != len(raw_limitations)
                or any(type(value) is not str or value not in item.limitation_codes for value in raw_limitations)):
            _fail("OUTPUT_INVALID")
        allowed_citations = set(item.verified_citation_ids)
        used_citations: set[str] = set()

        def parse_cited(value: object, allowed_codes: frozenset[str], *, allow_empty: bool = False) -> CitedText:
            if type(value) is not dict or tuple(value) != ("code", "text", "citation_ids"):
                _fail("OUTPUT_INVALID")
            code, body, citations = value["code"], value["text"], value["citation_ids"]
            if (type(code) is not str or code not in allowed_codes
                    or not ((allow_empty and body == "") or _safe_text(body))):
                _fail("OUTPUT_INVALID")
            expected_text = (_REASON_TEXT.get(code) if code in _REASON_CODES
                             else _STEP_TEXT.get(code) if code in _STEP_CODES
                             else _EXPLANATION_TEXT if code == "separate_assistance_only" else None)
            if body != expected_text and not (allow_empty and body == ""):
                _fail("OUTPUT_INVALID")
            if type(citations) is not list or not (0 if allow_empty else 1) <= len(citations) <= MAX_CITATIONS:
                _fail("OUTPUT_INVALID")
            if (any(type(cid) is not str or cid not in allowed_citations for cid in citations)
                    or len(set(citations)) != len(citations)):
                _fail("OUTPUT_INVALID")
            allowed_prefixes = _CITATION_PREFIXES_BY_CODE[code]
            if any(cid.split(":", 1)[0] not in allowed_prefixes for cid in citations):
                _fail("OUTPUT_INVALID")
            used_citations.update(citations)
            return CitedText(code, body, tuple(citations))

        reasons = tuple(parse_cited(row, _REASON_CODES) for row in raw_reasons)
        steps = tuple(parse_cited(row, _STEP_CODES) for row in raw_steps)
        if status in {"refused", "unavailable"}:
            empty_explanation = parsed["explanation"]
            if (type(empty_explanation) is not dict
                    or tuple(empty_explanation) != ("code", "text", "citation_ids")
                    or empty_explanation != {"code": "", "text": "", "citation_ids": []}):
                _fail("OUTPUT_INVALID")
            explanation = CitedText("", "", ())
        else:
            explanation = parse_cited(
                parsed["explanation"], frozenset({"separate_assistance_only"}),
            )
        if status == "available":
            if not reasons or not steps or not explanation.citation_ids:
                _fail("OUTPUT_INVALID")
            if len(reasons) != 1 or reasons[0].code != expected_reason:
                _fail("OUTPUT_INVALID")
        else:
            if (priority is not ReviewPriority.UNDETERMINED or reasons or steps
                    or explanation.text != "" or explanation.citation_ids or raw_uncertainty or raw_limitations):
                _fail("OUTPUT_INVALID")
        distinct = tuple(dict.fromkeys(
            cid for component in (*reasons, *steps, explanation) for cid in component.citation_ids
        ))
        if len(distinct) > MAX_CITATIONS or used_citations != set(distinct):
            _fail("OUTPUT_INVALID")
        return InvestigationAssistance(
            schema_version=1, request_id=item.request_id, case_ref=item.case_ref,
            review_priority=priority, priority_reasons=reasons,
            investigation_steps=steps, explanation=explanation,
            uncertainty=tuple(raw_uncertainty), limitation_codes=tuple(raw_limitations),
            generated_by="deterministic_reference", status=status,
        )
    except TriageError:
        raise
    except Exception:
        _fail("OUTPUT_INVALID")


class TriageAdmission:
    """Synchronous one-slot guard for internal callers; no API or background worker."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active = False
        self._closed = False

    def try_enter(self) -> bool:
        with self._lock:
            if self._closed or self._active:
                return False
            self._active = True
            return True

    def leave(self) -> None:
        with self._lock:
            self._active = False

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._active = False

    def __repr__(self) -> str:
        return "TriageAdmission(<state-redacted>)"
