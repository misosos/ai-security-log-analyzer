"""Bounded, sample-only API boundary; no request data enters analysis."""

import asyncio
from collections import deque
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from threading import Lock
import time
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.analyzer.incident_case_adapter import IncidentCaseAdapterError
from app.analyzer.incident_case_projection import InvestigationCaseProjection
from app.models.investigation_sample_api import (
    AnalysisSummary,
    Capabilities,
    CaseSummary,
    Evidence,
    IndependentObservation,
    InvestigationCase,
    InvestigationErrorResponse,
    InvestigationResponse,
    ReportExport,
    SampleContext,
    TextItem,
    TimelineEntry,
    Timestamp,
)


_ROOT = Path(__file__).resolve().parents[1]
_SAMPLE_DIR = _ROOT / "sample_logs"
_MAX_FIXTURE_BYTES = 4096
_RATE_CAPACITY = 12
_RATE_WINDOW_SECONDS = 60.0
_CONCURRENT_CAPACITY = 2
_TIMEOUT_SECONDS = 10.0
_ACCOUNT_MESSAGE = (
    "계정 별칭을 표시할 수 없음. "
    "원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다."
)
_INTERPRETATION_NOTICES = (
    "합성 샘플 결과",
    "탐지는 침해 확인이 아닙니다.",
    "상관관계는 인과관계가 아닙니다.",
    "로그인 성공은 공격 성공을 입증하지 않습니다.",
    "조사 사례는 확정된 사고가 아닙니다.",
)
_EMPTY_WARNINGS = (
    "지원되는 규칙으로 구성된 조사 사례가 없습니다.",
    "이 결과는 보안 문제가 없다는 의미가 아닙니다.",
)
_ERRORS = {
    "NON_EMPTY_BODY": (400, "요청 본문을 받을 수 없습니다.", "본문 없이 다시 요청하십시오.", False),
    "QUERY_NOT_ALLOWED": (400, "조회 조건을 받을 수 없습니다.", "조회 조건 없이 다시 요청하십시오.", False),
    "RATE_LIMITED": (429, "요청 횟수 한도에 도달했습니다.", "잠시 후 다시 시도하십시오.", True),
    "CONCURRENCY_LIMIT": (429, "현재 처리 가능한 요청 수를 넘었습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_TIMEOUT": (503, "분석 응답 시간이 초과되었습니다.", "잠시 후 다시 시도하십시오.", True),
    "FIXTURE_UNAVAILABLE": (503, "합성 샘플을 사용할 수 없습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_FAILED": (500, "샘플 분석을 완료하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
    "CASE_PROJECTION_FAILED": (500, "조사 사례를 구성하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
    "RESPONSE_INVALID": (500, "결과를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
}


@dataclass(frozen=True, repr=False)
class _Fixture:
    source: str
    basename: str
    sha256: str


_FIXTURES = (
    _Fixture("application", "brute_force.log", "9e9055b0033ef8555c60faac3cc3fed6c3b4fd767eb41fa6da0c236b0d9fb37c"),
    _Fixture("ssh", "ssh_auth.log", "3149324836fc5368524c9a3db4d6d25823051785a531642fa0d18f79a7268946"),
    _Fixture("access", "web_shell.log", "1f8d3666187cf2f1d026c118e21b14e9254c1d856cc8c28cf09cabbfc89215e6"),
)


class _FixtureUnavailable(ValueError):
    def __init__(self):
        super().__init__("Synthetic sample unavailable.")


class _ResponseInvalid(ValueError):
    def __init__(self):
        super().__init__("Investigation response contract failed.")


class _SampleLimit:
    """Fixed global process-local budget; no client identity is stored."""

    def __init__(self):
        self._lock = Lock()
        self._requests: deque[float] = deque(maxlen=_RATE_CAPACITY)
        self._active = 0

    def admit(self) -> str | None:
        now = time.monotonic()
        with self._lock:
            while self._requests and now - self._requests[0] >= _RATE_WINDOW_SECONDS:
                self._requests.popleft()
            if len(self._requests) >= _RATE_CAPACITY:
                return "RATE_LIMITED"
            self._requests.append(now)
            if self._active >= _CONCURRENT_CAPACITY:
                return "CONCURRENCY_LIMIT"
            self._active += 1
        return None

    def release(self) -> None:
        with self._lock:
            self._active -= 1


def _error(code: str) -> JSONResponse:
    status, message, action, retryable = _ERRORS[code]
    body = InvestigationErrorResponse(
        error_code=code,
        user_message=message,
        recovery_action=action,
        retryable=retryable,
    )
    return JSONResponse(status_code=status, content=body.model_dump())


def _fixture_bytes(spec: _Fixture) -> bytes:
    try:
        parent = _SAMPLE_DIR.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise _FixtureUnavailable()
        path = _SAMPLE_DIR / spec.basename
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise _FixtureUnavailable()
        if not 0 < metadata.st_size <= _MAX_FIXTURE_BYTES:
            raise _FixtureUnavailable()
        if not hasattr(os, "O_NOFOLLOW"):
            raise _FixtureUnavailable()
        flags = os.O_RDONLY | os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or not 0 < opened.st_size <= _MAX_FIXTURE_BYTES
            ):
                raise _FixtureUnavailable()
            content = stream.read(_MAX_FIXTURE_BYTES + 1)
        if (
            len(content) != opened.st_size
            or hashlib.sha256(content).hexdigest() != spec.sha256
        ):
            raise _FixtureUnavailable()
        return content
    except (OSError, ValueError):
        raise _FixtureUnavailable() from None


def _timestamp(value) -> Timestamp | None:
    if value is None:
        return None
    return Timestamp(display_kst=value.display_kst, display_utc=value.display_utc)


def _evidence(items) -> tuple[Evidence, ...]:
    return tuple(Evidence(label=item.label, value=item.value, unit=item.unit) for item in items)


def _text_items(items) -> tuple[TextItem, ...]:
    return tuple(TextItem(label=item.label, text=item.text) for item in items)


def _timeline(item) -> TimelineEntry:
    if item.account_alias is not None or item.account_alias_status != "ACCOUNT_REFERENCE_UNAVAILABLE":
        raise _ResponseInvalid() from None
    return TimelineEntry(
        sequence=item.sequence,
        category=item.category,
        category_label=item.category_label,
        timestamp_state=item.timestamp_state,
        timestamp_state_label=item.timestamp_state_label,
        start_time=_timestamp(item.start_time),
        end_time=_timestamp(item.end_time),
        title=item.display_title,
        fact=item.interpretation_label,
        subject=item.subject_ip,
        detection_display_name=item.detection_display_name,
        relation_display_name=item.relation_display_name,
        evidence=_evidence(item.evidence),
    )


def _case(item) -> InvestigationCase:
    row = item.row
    entries = item.timeline_entries + item.timeline_entries_without_time
    if row.account_alias is not None or row.account_alias_status != "ACCOUNT_REFERENCE_UNAVAILABLE":
        raise _ResponseInvalid() from None
    detections = tuple(dict.fromkeys(
        entry.detection_display_name for entry in entries
        if entry.detection_display_name is not None
    ))
    relations = tuple(dict.fromkeys(
        entry.relation_display_name for entry in entries
        if entry.relation_display_name is not None
    ))
    return InvestigationCase(
        review_order=row.review_order,
        case_label=row.case_label,
        subject=row.subject_ip,
        included_highest_risk=row.included_highest_risk,
        included_highest_confidence=row.included_highest_confidence,
        start_time=_timestamp(row.start_time),
        end_time=_timestamp(row.end_time),
        observation_count=row.observation_count,
        supporting_relation_count=row.supporting_relation_count,
        grouping_explanation=row.grouping_explanation,
        supported_detections=detections,
        supported_relations=relations,
        timeline_label=item.timeline_label,
        timeline=tuple(_timeline(entry) for entry in entries),
        limitations=_text_items(item.limitations),
        unverified_items=_text_items(item.unverified_items),
        next_steps=_text_items(item.next_steps),
        account_alias_state="unavailable",
        account_alias_message=_ACCOUNT_MESSAGE,
    )


def _independent(item) -> IndependentObservation:
    if item.account_alias is not None or item.account_alias_status != "ACCOUNT_REFERENCE_UNAVAILABLE":
        raise _ResponseInvalid() from None
    return IndependentObservation(
        review_order=item.review_order,
        label=item.label,
        category_label=item.category_label,
        display_type=item.display_type,
        subject=item.subject_ip,
        existing_risk_level=item.existing_risk_level,
        existing_confidence=item.existing_confidence,
        start_time=_timestamp(item.start_time),
        end_time=_timestamp(item.end_time),
        timestamp_state=item.timestamp_state,
        evidence=_evidence(item.evidence),
        reason=item.reason_text,
        account_alias_state="unavailable",
        account_alias_message=_ACCOUNT_MESSAGE,
    )


def build_sample_response(
    analysis: dict, projection: InvestigationCaseProjection
) -> InvestigationResponse:
    if type(analysis) is not dict or type(projection) is not InvestigationCaseProjection:
        raise _ResponseInvalid() from None
    results = analysis.get("results")
    if (
        type(results) is not dict
        or projection.schema_version != "1"
        or projection.account_alias_status != "ACCOUNT_REFERENCE_UNAVAILABLE"
    ):
        raise _ResponseInvalid() from None
    summary = projection.summary
    if summary.case_count != (
        summary.high_case_count + summary.medium_case_count + summary.low_case_count
    ) or summary.case_count != len(projection.cases) or (
        summary.independent_observation_count != len(projection.independent_observations)
    ):
        raise _ResponseInvalid() from None
    cases = tuple(_case(item) for item in projection.cases)
    independent = tuple(_independent(item) for item in projection.independent_observations)
    if any(case.review_order != n for n, case in enumerate(cases, 1)) or any(
        item.review_order != n for n, item in enumerate(independent, 1)
    ):
        raise _ResponseInvalid() from None
    return InvestigationResponse(
        schema_version="1",
        sample_context=SampleContext(
            label="합성 샘플 결과",
            environment_notice="실제 조직 환경의 보안 상태가 아닙니다.",
            certificate_notice="보안 점검 인증서가 아닙니다.",
        ),
        analysis_summary=AnalysisSummary(
            analyzed_subject_count=len(results),
            supported_detection_count=summary.supported_detection_observation_count,
            supported_relation_count=summary.supported_relation_observation_count,
        ),
        case_summary=CaseSummary(
            case_count=summary.case_count,
            independent_observation_count=summary.independent_observation_count,
            high_case_count=summary.high_case_count,
            medium_case_count=summary.medium_case_count,
            low_case_count=summary.low_case_count,
            relation_case_count=summary.cases_with_supported_relation_count,
            no_time_observation_count=summary.observations_without_time_count,
        ),
        cases=cases,
        independent_observations=independent,
        interpretation_notices=_INTERPRETATION_NOTICES,
        capabilities=Capabilities(
            html_report_available=False,
            llm_summary_available=False,
            linux_audit_aggregate_available=False,
            actual_log_upload_available=False,
        ),
        bounded_warnings=_EMPTY_WARNINGS if summary.case_count == 0 else (),
        report_export=ReportExport(
            available=False,
            message="HTML 보고서 다운로드는 이 단계에서 제공되지 않습니다.",
        ),
    )


def _execute(
    analyze: Callable, project: Callable
) -> InvestigationResponse:
    verified = tuple(_fixture_bytes(spec) for spec in _FIXTURES)
    with tempfile.TemporaryDirectory(prefix="investigation-sample-") as directory:
        sources = []
        for index, (spec, content) in enumerate(zip(_FIXTURES, verified), 1):
            staged = Path(directory) / f"input-{index}.log"
            with staged.open("xb") as stream:
                stream.write(content)
            sources.append({"source": spec.source, "path": str(staged)})
        analysis = analyze(sources)
        projection = project(analysis)
        try:
            return build_sample_response(analysis, projection)
        except ValidationError:
            raise _ResponseInvalid() from None


def _complete(task: asyncio.Task, limiter: _SampleLimit) -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        pass
    finally:
        limiter.release()


def create_sample_endpoint(analyze: Callable, project: Callable):
    limiter = _SampleLimit()

    async def sample_investigation(request: Request):
        if request.scope.get("query_string"):
            return _error("QUERY_NOT_ALLOWED")
        if request.headers.get("content-type"):
            return _error("NON_EMPTY_BODY")
        if request.headers.get("content-length") not in (None, "0"):
            return _error("NON_EMPTY_BODY")
        async for chunk in request.stream():
            if chunk:
                return _error("NON_EMPTY_BODY")
        rejection = limiter.admit()
        if rejection is not None:
            return _error(rejection)
        task = asyncio.create_task(asyncio.to_thread(_execute, analyze, project))
        task.add_done_callback(lambda completed: _complete(completed, limiter))
        try:
            return await asyncio.wait_for(asyncio.shield(task), _TIMEOUT_SECONDS)
        except TimeoutError:
            return _error("ANALYSIS_TIMEOUT")
        except _FixtureUnavailable:
            return _error("FIXTURE_UNAVAILABLE")
        except IncidentCaseAdapterError:
            return _error("CASE_PROJECTION_FAILED")
        except _ResponseInvalid:
            return _error("RESPONSE_INVALID")
        except Exception:
            return _error("ANALYSIS_FAILED")

    return sample_investigation
