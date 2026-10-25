"""Bounded read-only production adapter for Phase 33.1 lexical citations."""

from __future__ import annotations

import asyncio
from collections import deque
from hashlib import sha256
import json
import time
from threading import Lock
from typing import Literal

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from app.local_request_security import classify_local_request
from app.local_retrieval_33_1 import (
    Completeness, QueryCategory, RetrievalError, ResultStatus, SafeEvidence,
    TRUSTED_CORPUS_DIGEST, build_index, load_corpus, retrieve, validate_result,
)


MAX_REQUEST_BYTES = 8_192
MAX_RESPONSE_BYTES = 6_144
REQUEST_TIMEOUT_SECONDS = 2.0
MAX_CONCURRENT_REQUESTS = 1
RATE_LIMIT_COUNT = 12
RATE_LIMIT_WINDOW_SECONDS = 60.0

_DETECTION_LABELS = frozenset({
    "Brute Force", "Password Spraying-like", "Path Traversal",
    "SQL Injection-like", "XSS-like", "Sensitive Resource Probing-like",
    "Web Scanning-like",
})
_RELATION_MAP = {
    "Failed Login → Successful Login": "Failed login followed by success",
    "Brute Force → Successful Login": "Brute Force followed by success",
    "Password Spraying-like → Successful Login": "Password Spraying-like followed by success",
}
_CASE_MAP = {
    "Failed login followed by success": "Failed login followed by success case",
    "Brute Force followed by success": "Brute Force followed by success case",
    "Password Spraying-like followed by success": "Password Spraying-like followed by success case",
}
_CATEGORY_QUERIES = {
    QueryCategory.EXPLAIN_RELATION: "failed success relation causation",
    QueryCategory.EXPLAIN_RISK: "risk lower safe",
    QueryCategory.EXPLAIN_CASE: "case relation",
    QueryCategory.NEXT_CHECKS: "next checks application ssh",
    QueryCategory.EXPLAIN_RECOVERY_STATE: "replay gap stale",
    QueryCategory.EXPLAIN_LIMITATION: "no finding safe",
}
_REFUSAL_MESSAGES = {
    "STALE": "현재 사례와 도움말 요청을 연결하지 못했습니다. 최신 분석 결과에서 다시 선택하십시오.",
    "REFUSED": "이 항목에는 승인된 근거 도움말이 없습니다.",
}
_ERRORS = {
    "INVALID_REQUEST": (400, "도움말 요청을 확인할 수 없습니다."),
    "TOO_LARGE": (413, "도움말 요청 크기가 한도를 넘었습니다."),
    "LOCAL_ONLY": (403, "도움말은 이 로컬 화면에서만 사용할 수 있습니다."),
    "BUSY": (429, "다른 도움말 요청을 처리하고 있습니다."),
    "TIMEOUT": (503, "도움말을 준비하지 못했습니다. 잠시 후 다시 시도하십시오."),
    "UNAVAILABLE": (503, "승인된 도움말 자료를 확인할 수 없습니다."),
}


class SafePublicCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    case_id: StrictStr = Field(pattern=r"^c_[0-9a-f]{24}$", max_length=26)
    review_order: StrictInt = Field(ge=1, le=64)
    supported_detections: tuple[StrictStr, ...] = Field(max_length=16)
    supported_relations: tuple[StrictStr, ...] = Field(max_length=8)
    risk_level: Literal["HIGH", "MEDIUM", "LOW"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    observation_count: StrictInt = Field(ge=0, le=1_000_000)
    supporting_relation_count: StrictInt = Field(ge=0, le=1_000_000)

    @classmethod
    def from_payload(cls, payload: object) -> "SafePublicCase":
        try:
            value = cls.model_validate(payload)
            if (len(set(value.supported_detections)) != len(value.supported_detections)
                    or len(set(value.supported_relations)) != len(value.supported_relations)
                    or any(item not in _DETECTION_LABELS for item in value.supported_detections)
                    or any(item not in _RELATION_MAP for item in value.supported_relations)
                    or value.supporting_relation_count < len(value.supported_relations)):
                raise ValueError
            return value
        except Exception:
            raise GuidanceRequestError("INVALID_REQUEST") from None


class GuidanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1]
    case: SafePublicCase
    category: QueryCategory
    corpus_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$", max_length=64)


class GuidanceCitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    citation_id: StrictStr = Field(pattern=r"^[a-z0-9-]{1,48}:[a-z0-9-]{1,48}$", max_length=97)
    title: StrictStr = Field(min_length=1, max_length=160)
    summary: StrictStr = Field(min_length=1, max_length=512)
    source_ref: StrictStr = Field(pattern=r"^docs/[A-Za-z0-9_./-]+\.md$", max_length=128)


class GuidanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1] = 1
    status: Literal["AVAILABLE", "REFUSED", "STALE"]
    message: StrictStr = Field(min_length=1, max_length=160)
    citations: tuple[GuidanceCitation, ...] = Field(max_length=5)
    corpus_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$", max_length=64)


class GuidanceErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    error_code: Literal[
        "INVALID_REQUEST", "TOO_LARGE", "LOCAL_ONLY", "BUSY", "TIMEOUT", "UNAVAILABLE",
    ]
    user_message: StrictStr = Field(min_length=1, max_length=128)


class GuidanceRequestError(Exception):
    def __init__(self, code: str):
        self.code = code if code in _ERRORS else "INVALID_REQUEST"
        super().__init__("Guidance request is invalid.")


def _case_fields(case: SafePublicCase) -> dict:
    return {
        "review_order": case.review_order,
        "supported_detections": list(case.supported_detections),
        "supported_relations": list(case.supported_relations),
        "risk_level": case.risk_level,
        "confidence": case.confidence,
        "observation_count": case.observation_count,
        "supporting_relation_count": case.supporting_relation_count,
    }


def public_case_id(case: SafePublicCase) -> str:
    body = json.dumps(_case_fields(case), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    return "c_" + sha256(body).hexdigest()[:24]


def safe_public_case_payload(case: dict) -> dict:
    """Select public scalar fields, then create the deterministic opaque reference."""
    try:
        safe = SafePublicCase.model_validate({
            "case_id": "c_" + "0" * 24,
            "review_order": case["review_order"],
            "supported_detections": tuple(case["supported_detections"]),
            "supported_relations": tuple(case["supported_relations"]),
            "risk_level": case["included_highest_risk"],
            "confidence": case["included_highest_confidence"],
            "observation_count": case["observation_count"],
            "supporting_relation_count": case["supporting_relation_count"],
        })
        safe = safe.model_copy(update={"case_id": public_case_id(safe)})
        return safe.model_dump(mode="json")
    except Exception:
        raise GuidanceRequestError("INVALID_REQUEST") from None


class _GuidanceLimiter:
    def __init__(self):
        self.lock = Lock()
        self.active = 0
        self.requests: deque[float] = deque(maxlen=RATE_LIMIT_COUNT)

    def admit(self) -> bool:
        now = time.monotonic()
        with self.lock:
            while self.requests and now - self.requests[0] >= RATE_LIMIT_WINDOW_SECONDS:
                self.requests.popleft()
            if self.active >= MAX_CONCURRENT_REQUESTS or len(self.requests) >= RATE_LIMIT_COUNT:
                return False
            self.active += 1
            self.requests.append(now)
            return True

    def release(self) -> None:
        with self.lock:
            self.active = max(0, self.active - 1)


async def _read_bounded_json(request: Request) -> object:
    length = request.headers.get("content-length")
    if length is not None and (not length.isdecimal() or int(length) > MAX_REQUEST_BYTES):
        raise GuidanceRequestError("TOO_LARGE") from None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_REQUEST_BYTES:
            raise GuidanceRequestError("TOO_LARGE") from None
    def reject_duplicate_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    try:
        return json.loads(body, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise GuidanceRequestError("INVALID_REQUEST") from None


def _evidence(case: SafePublicCase) -> SafeEvidence:
    relation_labels = tuple(_RELATION_MAP[item] for item in case.supported_relations)
    case_labels = tuple(dict.fromkeys(_CASE_MAP[item] for item in relation_labels))
    limitations = ["DETECTION_IS_NOT_COMPROMISE"]
    if relation_labels:
        limitations.append("CORRELATION_IS_NOT_CAUSATION")
    return SafeEvidence(
        source_role=None,
        detection_labels=case.supported_detections,
        relation_labels=relation_labels,
        risk_level=case.risk_level,
        confidence=case.confidence,
        case_labels=case_labels,
        aggregates=(
            ("observations", case.observation_count),
            ("relations", case.supporting_relation_count),
            ("cases", 1),
            ("detections", len(case.supported_detections)),
        ),
        time_window_seconds=None,
        completeness=Completeness.COMPLETE,
        session_local_id="s_" + case.case_id[2:18],
        limitations=tuple(limitations),
    )


def _query_for(category: QueryCategory, case: SafePublicCase) -> str:
    if category is QueryCategory.EXPLAIN_DETECTION:
        if "Password Spraying-like" in case.supported_detections:
            return "password spray meaning limit"
        if "Brute Force" in case.supported_detections:
            return "brute force meaning limit"
        return "unsupported detection"
    return _CATEGORY_QUERIES[category]


def _process(value: GuidanceRequest) -> GuidanceResponse:
    corpus = load_corpus()
    if corpus.digest != TRUSTED_CORPUS_DIGEST or value.corpus_digest != corpus.digest:
        raise RetrievalError("CORPUS_INVALID") from None
    evidence = _evidence(value.case)
    result = retrieve(_query_for(value.category, value.case), value.category, evidence,
                      corpus=corpus, index=build_index(corpus))
    result = validate_result(result, corpus, requested_top_k=3)
    if result.corpus_digest != TRUSTED_CORPUS_DIGEST:
        raise RetrievalError("INVALID_RESULT") from None
    if result.status is not ResultStatus.OK or not result.citations:
        return GuidanceResponse(
            status="REFUSED", message=_REFUSAL_MESSAGES["REFUSED"],
            citations=(), corpus_digest=corpus.digest,
        )
    citations = tuple(GuidanceCitation(
        citation_id=f"{item.document_id}:{item.section_id}",
        title=item.title, summary=item.excerpt, source_ref=item.source_ref,
    ) for item in result.citations)
    return GuidanceResponse(
        status="AVAILABLE",
        message="조사 도움말입니다. 기존 탐지·관계·위험도·사례 결과를 변경하지 않습니다.",
        citations=citations, corpus_digest=corpus.digest,
    )


def _error(code: str) -> JSONResponse:
    status, message = _ERRORS[code]
    body = GuidanceErrorResponse(error_code=code, user_message=message)
    return JSONResponse(status_code=status, content=body.model_dump(mode="json"))


def create_guidance_endpoint():
    limiter = _GuidanceLimiter()

    async def guidance(request: Request):
        if classify_local_request(request) is not None:
            return _error("LOCAL_ONLY")
        if request.scope.get("query_string") or request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            return _error("INVALID_REQUEST")
        try:
            raw = await _read_bounded_json(request)
            value = GuidanceRequest.model_validate(raw)
            safe_case = SafePublicCase.from_payload(value.case.model_dump())
            value = value.model_copy(update={"case": safe_case})
        except GuidanceRequestError as error:
            return _error(error.code)
        except (ValidationError, TypeError, ValueError):
            return _error("INVALID_REQUEST")
        if not limiter.admit():
            return _error("BUSY")
        if value.corpus_digest != TRUSTED_CORPUS_DIGEST:
            limiter.release()
            return _error("UNAVAILABLE")
        if value.case.case_id != public_case_id(value.case):
            limiter.release()
            try:
                corpus = load_corpus()
                if corpus.digest != TRUSTED_CORPUS_DIGEST:
                    return _error("UNAVAILABLE")
                return GuidanceResponse(
                    status="STALE", message=_REFUSAL_MESSAGES["STALE"],
                    citations=(), corpus_digest=corpus.digest,
                )
            except RetrievalError:
                return _error("UNAVAILABLE")
        task = asyncio.create_task(asyncio.to_thread(_process, value))

        def complete(finished: asyncio.Task) -> None:
            try:
                finished.exception()
            except BaseException:
                pass
            finally:
                limiter.release()

        task.add_done_callback(complete)
        try:
            response = await asyncio.wait_for(asyncio.shield(task), REQUEST_TIMEOUT_SECONDS)
            body = response.model_dump_json().encode("utf-8")
            if len(body) > MAX_RESPONSE_BYTES:
                return _error("UNAVAILABLE")
            return response
        except TimeoutError:
            return _error("TIMEOUT")
        except Exception:
            return _error("UNAVAILABLE")

    return guidance


GUIDANCE_OPENAPI_REQUEST = {
    "required": True,
    "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "case", "category", "corpus_digest"],
        "properties": {
            "schema_version": {"type": "integer", "const": 1},
            "category": {"type": "string", "enum": [item.value for item in QueryCategory]},
            "corpus_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "case": {"type": "object", "additionalProperties": False,
                     "required": ["case_id", "review_order", "supported_detections",
                                  "supported_relations", "risk_level", "confidence",
                                  "observation_count", "supporting_relation_count"],
                     "properties": {
                         "case_id": {"type": "string", "pattern": "^c_[0-9a-f]{24}$"},
                         "review_order": {"type": "integer", "minimum": 1, "maximum": 64},
                         "supported_detections": {"type": "array", "maxItems": 16,
                                                  "items": {"type": "string", "enum": sorted(_DETECTION_LABELS)}},
                         "supported_relations": {"type": "array", "maxItems": 8,
                                                 "items": {"type": "string", "enum": list(_RELATION_MAP)}},
                         "risk_level": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                         "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                         "observation_count": {"type": "integer", "minimum": 0, "maximum": 1000000},
                         "supporting_relation_count": {"type": "integer", "minimum": 0, "maximum": 1000000},
                     }},
        }}}},
}
