"""Explicit, read-only API boundary for the internal lexical checklist."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import json
import re
import secrets
import threading
import time
from typing import Literal

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from app.investigation_checklist_36_2 import (
    ChecklistError, InvestigationChecklist, build_investigation_checklist,
)
from app.investigation_triage_36_1 import (
    CORPUS_DIGEST, SafeInvestigationDTO, create_safe_investigation_dto,
)
from app.local_request_security import classify_local_request
from app.local_retrieval_33_1 import load_corpus
from app.analyzer.incident_case_projection import InvestigationCaseDetailProjection
from app.investigation_role_snapshot_36_4 import BoundCaseSourceRole


ENDPOINT_PATH = "/api/v1/investigations/checklist"
MAX_REQUEST_BYTES = 512
MAX_RESPONSE_BYTES = 8192
MAX_CASES = 128
REGISTRY_TTL_SECONDS = 900.0
REQUEST_TIMEOUT_SECONDS = 3.0
GLOBAL_RATE_LIMIT = 30
CASE_RATE_LIMIT = 5
RATE_WINDOW_SECONDS = 60.0
MAX_ACTIVE = 2
_CASE_REF = re.compile(r"c_[0-9a-f]{24}\Z")
_REQUEST_FIELDS = ("schema_version", "case_ref")
CHECKLIST_OPENAPI_REQUEST = {
    "required": True,
    "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "case_ref"],
        "properties": {
            "schema_version": {"type": "integer", "const": 1},
            "case_ref": {"type": "string", "pattern": "^c_[0-9a-f]{24}$", "maxLength": 26},
        },
    }}},
}

_ERRORS = {
    "INVALID_REQUEST": (400, "요청 형식을 확인할 수 없습니다."),
    "NOT_FOUND": (404, "현재 분석 결과에서 사례를 찾을 수 없습니다."),
    "RATE_LIMITED": (429, "조사 점검표 요청 한도에 도달했습니다."),
    "BUSY": (429, "다른 조사 점검표 요청을 처리하고 있습니다."),
    "TIMEOUT": (503, "조사 점검표 준비 시간이 초과되었습니다."),
    "UNAVAILABLE": (503, "승인 근거를 확인할 수 없어 점검표를 준비하지 못했습니다."),
}
_UNAVAILABLE_TEXT = "승인 근거를 검증할 수 없어 점검표를 준비하지 못했습니다. 기존 분석 결과는 그대로 유지됩니다."


class ChecklistRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: StrictInt
    case_ref: StrictStr

    def valid(self) -> bool:
        return self.schema_version == 1 and _CASE_REF.fullmatch(self.case_ref) is not None


class ChecklistErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    error_code: Literal["INVALID_REQUEST", "NOT_FOUND", "RATE_LIMITED", "BUSY", "TIMEOUT", "UNAVAILABLE"]
    user_message: StrictStr


class ChecklistStepResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: StrictStr = Field(max_length=512)
    purpose_code: StrictStr = Field(max_length=48)
    citation_ids: tuple[StrictStr, ...] = Field(min_length=1, max_length=2)
    limitation_codes: tuple[StrictStr, ...] = Field(max_length=4)


class ChecklistCitationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    citation_id: StrictStr = Field(pattern=r"^[a-z0-9-]{1,48}:[a-z0-9-]{1,48}$", max_length=97)
    title: StrictStr = Field(min_length=1, max_length=160)
    summary: StrictStr = Field(min_length=1, max_length=512)


class ChecklistExplanationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: StrictStr = Field(max_length=1024)
    citation_ids: tuple[StrictStr, ...] = Field(max_length=8)


class ChecklistResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True,
                              serialize_by_alias=True, populate_by_name=True)
    schema_name: Literal["investigation-checklist/v2"] = Field(alias="schema")
    status: Literal["available", "refused", "unavailable"]
    source_role: Literal["application", "ssh", "access", "unknown"]
    source_role_label: Literal["애플리케이션 로그", "SSH 인증 로그", "접근 로그", "역할 정보 미확인"]
    review_priority: Literal["review_now", "review_soon", "review_later", "undetermined"]
    priority_meaning: Literal["analyst_review_order_only_not_security_risk"]
    category: Literal["authentication", "web_request", "relation", "unknown"]
    steps: tuple[ChecklistStepResponse, ...] = Field(max_length=5)
    explanation: ChecklistExplanationResponse
    uncertainty_codes: tuple[StrictStr, ...] = Field(max_length=4)
    limitation_codes: tuple[StrictStr, ...] = Field(max_length=16)
    citations: tuple[ChecklistCitationResponse, ...] = Field(max_length=8)
    citation_meaning: Literal["general_reference_not_case_evidence"]
    generated_by: Literal["deterministic_lexical_template"]


def _reject_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError


def parse_checklist_request(raw: bytes) -> ChecklistRequest:
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_REQUEST_BYTES:
            raise ValueError
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_pairs,
                            parse_constant=_reject_constant)
        if type(parsed) is not dict or tuple(parsed) != _REQUEST_FIELDS:
            raise ValueError
        request = ChecklistRequest.model_validate(parsed)
        if not request.valid():
            raise ValueError
        return request
    except (ValueError, UnicodeError, ValidationError, TypeError):
        raise ValueError("Checklist request is invalid.") from None


def _bucket_count(count: int) -> str:
    if count == 0:
        return "0"
    if count == 1:
        return "1"
    if count <= 5:
        return "2_5"
    if count <= 20:
        return "6_20"
    return "21_plus"


def trusted_case_fields_from_projection(
    case: InvestigationCaseDetailProjection,
    role_snapshot: BoundCaseSourceRole | None = None,
    analysis: object = None,
    projection: object = None,
) -> dict:
    """Project only closed categories from the trusted internal case; discard identifiers."""
    if type(case) is not InvestigationCaseDetailProjection:
        raise ValueError("Case adapter contract failed.") from None
    detections = {
        "Brute Force": "brute_force",
        "Password Spraying-like": "password_spraying_like",
        "Path Traversal": "path_traversal",
        "SQL Injection-like": "sql_injection_like",
        "XSS-like": "xss_like",
        "Sensitive Resource Probing-like": "sensitive_resource_probing_like",
        "Web Scanning-like": "web_scanning_like",
    }
    relations = {
        "Failed Login → Successful Login": "failed_to_successful_login",
        "Brute Force → Successful Login": "brute_force_to_successful_login",
        "Password Spraying-like → Successful Login": "password_spray_to_successful_login",
    }
    detection_names = tuple(dict.fromkeys(
        entry.detection_display_name for entry in case.timeline_entries + case.timeline_entries_without_time
        if entry.detection_display_name is not None
    ))
    relation_names = tuple(dict.fromkeys(
        entry.relation_display_name for entry in case.timeline_entries + case.timeline_entries_without_time
        if entry.relation_display_name is not None
    ))
    detection_codes = tuple(detections[name] for name in detection_names if name in detections)
    relation_codes = tuple(relations[name] for name in relation_names if name in relations)
    categories = set()
    if detection_codes:
        categories.add("web_request" if any(code in {
            "path_traversal", "sql_injection_like", "xss_like",
            "sensitive_resource_probing_like", "web_scanning_like",
        } for code in detection_codes) else "authentication")
    if relation_codes:
        categories.add("relation")
    if not categories:
        categories.add("unknown")
    limitations = set()
    if case.limitations:
        limitations.add("INCOMPLETE_EVIDENCE")
    if detection_codes:
        limitations.add("DETECTION_IS_NOT_COMPROMISE")
    if relation_codes:
        limitations.add("CORRELATION_IS_NOT_CAUSATION")
    verified_role = "unknown"
    if (type(role_snapshot) is BoundCaseSourceRole
        and role_snapshot.is_current(case, analysis, projection)
        and type(role_snapshot.source_role) is str
        and role_snapshot.source_role in {"application", "ssh", "access"}):
        verified_role = role_snapshot.source_role
    return {
        "schema_version": 1,
        "request_id": None,
        "case_ref": None,
        "source_role": verified_role,
        "observation_categories": tuple(sorted(categories)),
        "detection_codes": detection_codes,
        "relation_codes": relation_codes,
        "risk_band": case.row.included_highest_risk,
        "case_status": "open",
        "event_count_bucket": _bucket_count(case.row.observation_count),
        "time_window_bucket": "unknown",
        "evidence_completeness": "partial" if "INCOMPLETE_EVIDENCE" in limitations else "unknown",
        "limitation_codes": tuple(sorted(limitations)),
        "corpus_digest": CORPUS_DIGEST,
    }


@dataclass(frozen=True)
class _Entry:
    values: dict
    created: float


class ChecklistRegistry:
    """One-current-result registry; a new analysis invalidates the prior refs."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    @property
    def size(self) -> int:
        with self._lock:
            self._expire_locked()
            return len(self._entries)

    def _expire_locked(self):
        now = time.monotonic()
        self._entries = {
            key: value for key, value in self._entries.items()
            if now - value.created < REGISTRY_TTL_SECONDS
        }

    def attach(self, response, trusted_cases):
        """Return a response with random per-analysis refs and retain safe fields only."""
        if type(trusted_cases) is not tuple or len(trusted_cases) != len(response.cases):
            raise ValueError("Case adapter contract failed.") from None
        with self._lock:
            self._entries.clear()
            cases = []
            for index, case in enumerate(response.cases[:MAX_CASES]):
                case_ref = "c_" + secrets.token_hex(12)
                values = dict(trusted_cases[index])
                values["case_ref"] = case_ref
                self._entries[case_ref] = _Entry(values, time.monotonic())
                cases.append(case.model_copy(update={"checklist_ref": case_ref}))
            cases.extend(case.model_copy(update={"checklist_ref": None})
                         for case in response.cases[MAX_CASES:])
            return response.model_copy(update={"cases": tuple(cases)})

    def lookup(self, case_ref: str) -> dict | None:
        with self._lock:
            self._expire_locked()
            entry = self._entries.get(case_ref)
            return None if entry is None else dict(entry.values)


class _Limits:
    def __init__(self):
        self._lock = threading.Lock()
        self._global: deque[float] = deque()
        self._per_case: dict[str, deque[float]] = {}
        self._active = 0

    def admit(self, case_ref: str) -> str | None:
        now = time.monotonic()
        with self._lock:
            while self._global and now - self._global[0] >= RATE_WINDOW_SECONDS:
                self._global.popleft()
            if case_ref not in self._per_case and len(self._per_case) >= 128:
                self._per_case.pop(next(iter(self._per_case)))
            local = self._per_case.setdefault(case_ref, deque())
            while local and now - local[0] >= RATE_WINDOW_SECONDS:
                local.popleft()
            if len(self._global) >= GLOBAL_RATE_LIMIT or len(local) >= CASE_RATE_LIMIT:
                return "RATE_LIMITED"
            self._global.append(now)
            local.append(now)
            if self._active >= MAX_ACTIVE:
                return "BUSY"
            self._active += 1
        return None

    def release(self):
        with self._lock:
            self._active = max(0, self._active - 1)


def _error(code: str) -> JSONResponse:
    status, message = _ERRORS[code]
    model = ChecklistErrorResponse(error_code=code, user_message=message)
    return JSONResponse(status_code=status, content=model.model_dump())


def _category(values: dict) -> str:
    categories = set(values["observation_categories"])
    if "relation" in categories:
        return "relation"
    if "authentication" in categories:
        return "authentication"
    if "web_request" in categories:
        return "web_request"
    return "unknown"


def _response(item: SafeInvestigationDTO, checklist: InvestigationChecklist) -> ChecklistResponse:
    mapping = checklist.to_mapping()
    citations = []
    corpus = load_corpus()
    if corpus.digest != item.corpus_digest or corpus.digest != CORPUS_DIGEST:
        raise ChecklistError("CORPUS_UNAVAILABLE") from None
    by_id = {f"{section.document_id}:{section.section_id}": section
             for section in corpus.sections if section.approved and section.review_status == "approved"}
    ids = set()
    for step in mapping["steps"]:
        ids.update(step["citation_ids"])
    ids.update(mapping["explanation"]["citation_ids"])
    if checklist.status == "available":
        for citation_id in sorted(ids):
            section = by_id.get(citation_id)
            if section is None:
                raise ChecklistError("OUTPUT_INVALID") from None
            citations.append(ChecklistCitationResponse(
                citation_id=citation_id,
                title=section.title,
                summary="승인된 일반 조사 참고 자료입니다. 사례 발생의 증거가 아닙니다.",
            ))
    steps = tuple(ChecklistStepResponse(
        text=step["text"], purpose_code=step["purpose_code"],
        citation_ids=tuple(step["citation_ids"]),
        limitation_codes=tuple(step["limitation_codes"]),
    ) for step in mapping["steps"])
    role_labels = {
        "application": "애플리케이션 로그",
        "ssh": "SSH 인증 로그",
        "access": "접근 로그",
        "unknown": "역할 정보 미확인",
    }
    return ChecklistResponse(
        schema_name="investigation-checklist/v2", status=checklist.status,
        source_role=item.source_role, source_role_label=role_labels[item.source_role],
        review_priority=mapping["review_priority"],
        priority_meaning="analyst_review_order_only_not_security_risk",
        category=_category(item.to_mapping()), steps=steps,
        explanation=ChecklistExplanationResponse(
            text=(mapping["explanation"]["text"] if mapping["explanation"]["text"]
                  else _UNAVAILABLE_TEXT),
            citation_ids=tuple(mapping["explanation"]["citation_ids"]),
        ),
        uncertainty_codes=tuple(mapping["uncertainty"]),
        limitation_codes=tuple(mapping["limitation_codes"]), citations=tuple(citations),
        citation_meaning="general_reference_not_case_evidence",
        generated_by="deterministic_lexical_template",
    )


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdecimal() or int(declared) > MAX_REQUEST_BYTES):
        raise ValueError("invalid") from None
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            raise ValueError("invalid") from None
        body.extend(chunk)
    return bytes(body)


def create_checklist_endpoint(registry: ChecklistRegistry):
    if type(registry) is not ChecklistRegistry:
        raise TypeError("invalid registry")
    limits = _Limits()

    async def checklist(request: Request):
        if classify_local_request(request) is not None:
            return _error("INVALID_REQUEST")
        if request.scope.get("query_string") or request.headers.get("content-type", "").lower() != "application/json":
            return _error("INVALID_REQUEST")
        try:
            parsed = parse_checklist_request(await _read_body(request))
        except ValueError:
            return _error("INVALID_REQUEST")
        values = registry.lookup(parsed.case_ref)
        if values is None:
            return _error("NOT_FOUND")
        rejection = limits.admit(parsed.case_ref)
        if rejection is not None:
            return _error(rejection)
        def work():
            try:
                values["request_id"] = "r_" + secrets.token_hex(12)
                item = create_safe_investigation_dto(**values)
                result = build_investigation_checklist(item)
                model = _response(item, result)
                encoded = model.model_dump_json(by_alias=True).encode("utf-8")
                if len(encoded) > MAX_RESPONSE_BYTES:
                    raise ChecklistError("OUTPUT_INVALID") from None
                return JSONResponse(status_code=200, content=model.model_dump(mode="json", by_alias=True))
            except ChecklistError as error:
                if error.code == "INPUT_INVALID":
                    return _error("INVALID_REQUEST")
                return _error("UNAVAILABLE")
            except Exception:
                return _error("UNAVAILABLE")

        task = asyncio.create_task(asyncio.to_thread(work))
        task.add_done_callback(lambda _task: limits.release())
        try:
            return await asyncio.wait_for(asyncio.shield(task), REQUEST_TIMEOUT_SECONDS)
        except TimeoutError:
            return _error("TIMEOUT")

    return checklist
