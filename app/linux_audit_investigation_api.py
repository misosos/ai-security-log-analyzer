"""Loopback-only, bounded Linux Audit upload; separate from IP investigations."""

import asyncio
import codecs
from collections import deque
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
from threading import Lock
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.analyzer.process_execution_classification import (
    CATEGORY_IDS, DISPLAY_NAMES, PRIORITIES, LIMITATIONS, NEXT_STEPS, NOTICES,
    ProcessExecutionObservationAssembly, classify_process_execution_observations,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.local_investigation_api import _archive, _loopback_request, _stop_process
from app.models.linux_audit_investigation import (
    INTERPRETATION_NOTICES,
    LinuxAuditCapabilities, LinuxAuditCategoryObservation,
    LinuxAuditInvestigationError, LinuxAuditInvestigationResponse,
    LinuxAuditOutcomeCounts, LinuxAuditSourceContext, LinuxAuditSummary,
)
from app.parser.linux_audit import parse_linux_audit_events


# Largest documented fixture: 15,742 bytes / 68 lines / 363-byte line.
# Three varied documented fixtures total 27,602 bytes / 125 lines.
MAX_FILE_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 72 * 1024
MAX_LINE_BYTES = 1024
MAX_LINES = 512
CHUNK_BYTES = 4096
UPLOAD_TIMEOUT_SECONDS = 10.0
ANALYSIS_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 16 * 1024
RATE_CAPACITY = 6
RATE_WINDOW_SECONDS = 60.0
FIELD = "audit_file"
_ERRORS = {
    "LOCAL_ONLY": (403, "이 기능은 로컬 서버에서만 사용할 수 있습니다.", "127.0.0.1에 직접 연결하십시오.", False),
    "QUERY_NOT_ALLOWED": (400, "조회 조건을 받을 수 없습니다.", "조회 조건 없이 다시 시도하십시오.", False),
    "INVALID_MEDIA_TYPE": (415, "Linux Audit 파일의 multipart 요청이 필요합니다.", "파일을 다시 선택하십시오.", False),
    "MALFORMED_MULTIPART": (400, "업로드 형식을 확인할 수 없습니다.", "파일을 다시 선택하십시오.", False),
    "MISSING_FIELD": (422, "Linux Audit 파일이 누락되었습니다.", "파일을 선택하십시오.", False),
    "REPEATED_FIELD": (400, "파일 입력이 여러 번 전송되었습니다.", "한 파일만 선택하십시오.", False),
    "UNKNOWN_FIELD": (400, "지원하지 않는 업로드 항목이 있습니다.", "Linux Audit 파일만 선택하십시오.", False),
    "FILE_COUNT_EXCEEDED": (413, "파일 수 한도를 넘었습니다.", "한 파일만 선택하십시오.", False),
    "FILE_TOO_LARGE": (413, "파일 크기 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", False),
    "ENVELOPE_TOO_LARGE": (413, "요청 크기 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", False),
    "LINE_TOO_LONG": (413, "로그 한 줄이 길이 한도를 넘었습니다.", "입력 형식을 확인하십시오.", False),
    "LINE_COUNT_EXCEEDED": (413, "로그 줄 수 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", False),
    "EMPTY_INPUT": (400, "로그가 비었거나 공백만 있습니다.", "내용이 있는 로그를 선택하십시오.", False),
    "INVALID_UTF8": (400, "UTF-8 로그로 읽을 수 없습니다.", "UTF-8 텍스트 파일을 선택하십시오.", False),
    "BINARY_INPUT": (415, "텍스트 로그 형식을 확인할 수 없습니다.", "UTF-8 텍스트 로그를 선택하십시오.", False),
    "ARCHIVE_UNSUPPORTED": (415, "압축·보관 파일은 지원하지 않습니다.", "압축을 풀고 텍스트 로그를 선택하십시오.", False),
    "PARSER_INCOMPATIBLE": (400, "지원되는 Linux Audit 구조를 확인할 수 없습니다.", "Audit 텍스트 형식과 수집 범위를 확인하십시오.", False),
    "UPLOAD_TIMEOUT": (503, "업로드 처리 시간이 초과되었습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_TIMEOUT": (503, "분류 시간이 초과되었습니다.", "더 작은 로그로 다시 시도하십시오.", True),
    "CONCURRENCY_LIMIT": (429, "다른 Linux Audit 분석이 진행 중입니다.", "완료 후 다시 시도하십시오.", True),
    "RATE_LIMITED": (429, "Linux Audit 요청 횟수 한도에 도달했습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_FAILED": (500, "Linux Audit 로그를 분류하지 못했습니다.", "입력 형식을 확인하고 다시 시도하십시오.", True),
    "RESPONSE_INVALID": (500, "결과를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
}


class _UploadError(ValueError):
    def __init__(self, code: str):
        self.code = code if code in _ERRORS else "ANALYSIS_FAILED"
        super().__init__(self.code)


def _error(code: str) -> JSONResponse:
    status, message, recovery, retryable = _ERRORS[code]
    body = LinuxAuditInvestigationError(
        error_code=code, user_message=message, recovery_action=recovery,
        retryable=retryable, field=FIELD if code in {
            "MISSING_FIELD", "FILE_TOO_LARGE", "LINE_TOO_LONG", "LINE_COUNT_EXCEEDED",
            "EMPTY_INPUT", "INVALID_UTF8", "BINARY_INPUT", "ARCHIVE_UNSUPPORTED",
            "PARSER_INCOMPATIBLE", "REPEATED_FIELD",
        } else None,
    )
    return JSONResponse(status_code=status, content=body.model_dump())


class _Limiter:
    def __init__(self):
        self.lock = Lock()
        self.requests: deque[float] = deque(maxlen=RATE_CAPACITY)
        self.active = 0

    def admit(self) -> str | None:
        now = time.monotonic()
        with self.lock:
            while self.requests and now - self.requests[0] >= RATE_WINDOW_SECONDS:
                self.requests.popleft()
            if len(self.requests) >= RATE_CAPACITY:
                return "RATE_LIMITED"
            self.requests.append(now)
            if self.active >= 1:
                return "CONCURRENCY_LIMIT"
            self.active += 1
        return None

    def release(self) -> None:
        with self.lock:
            self.active -= 1


async def _bounded_stream(request: Request):
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdecimal() or int(declared) > MAX_ENVELOPE_BYTES):
        raise _UploadError("ENVELOPE_TOO_LARGE")
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_ENVELOPE_BYTES:
            raise _UploadError("ENVELOPE_TOO_LARGE")
        yield chunk


async def _form(request: Request):
    # Admit a second parser part only to distinguish repeated from unknown;
    # both are rejected before staging and the envelope remains bounded.
    parser = MultiPartParser(request.headers, _bounded_stream(request),
                             max_files=2, max_fields=0, max_part_size=0)
    try:
        form = await parser.parse()
    except MultiPartException as error:
        code = ("FILE_COUNT_EXCEEDED" if str(error).startswith("Too many files")
                else "UNKNOWN_FIELD" if str(error).startswith("Too many fields")
                else "MALFORMED_MULTIPART")
        raise _UploadError(code) from None
    entries = form.multi_items()
    if not entries:
        await form.close()
        raise _UploadError("MISSING_FIELD")
    if any(name != FIELD or type(upload) is not UploadFile for name, upload in entries):
        await form.close()
        raise _UploadError("UNKNOWN_FIELD")
    if len(entries) != 1:
        await form.close()
        raise _UploadError("REPEATED_FIELD")
    return form


async def _stage(upload: UploadFile, path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _UploadError("ANALYSIS_FAILED")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    prefix = bytearray()
    size = 0
    line_bytes = 0
    lines = 0
    nonblank_lines = 0
    pending = ""
    last_byte = None
    with os.fdopen(descriptor, "wb") as output:
        while True:
            chunk = await upload.read(CHUNK_BYTES)
            if type(chunk) is not bytes:
                raise _UploadError("BINARY_INPUT")
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise _UploadError("FILE_TOO_LARGE")
            prefix.extend(chunk[:max(0, 262 - len(prefix))])
            if _archive(prefix):
                raise _UploadError("ARCHIVE_UNSUPPORTED")
            if any((byte < 32 and byte not in (9, 10, 13)) or byte == 127 for byte in chunk):
                raise _UploadError("BINARY_INPUT")
            try:
                decoded = decoder.decode(chunk, final=False)
            except UnicodeDecodeError:
                raise _UploadError("INVALID_UTF8") from None
            for index, fragment in enumerate(chunk.split(b"\n")):
                line_bytes += len(fragment)
                if line_bytes > MAX_LINE_BYTES:
                    raise _UploadError("LINE_TOO_LONG")
                if index < chunk.count(b"\n"):
                    lines += 1
                    if lines > MAX_LINES:
                        raise _UploadError("LINE_COUNT_EXCEEDED")
                    line_bytes = 0
            pending += decoded
            completed = pending.split("\n")
            pending = completed.pop()
            nonblank_lines += sum(bool(line.strip()) for line in completed)
            last_byte = chunk[-1]
            output.write(chunk)
        try:
            pending += decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            raise _UploadError("INVALID_UTF8") from None
        if last_byte != 10 and size:
            lines += 1
            if lines > MAX_LINES:
                raise _UploadError("LINE_COUNT_EXCEEDED")
            nonblank_lines += bool(pending.strip())
        if not nonblank_lines:
            raise _UploadError("EMPTY_INPUT")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise _UploadError("ANALYSIS_FAILED")
    return nonblank_lines


def _project(assembly: ProcessExecutionObservationAssembly) -> LinuxAuditInvestigationResponse:
    if type(assembly) is not ProcessExecutionObservationAssembly:
        raise ValueError("invalid_linux_projection")
    summary = assembly.summary
    if (tuple(item.category_id for item in summary.categories) != CATEGORY_IDS
            or len(assembly.observations) != summary.category_observation_count
            or assembly.interpretation_notices != NOTICES):
        raise ValueError("invalid_linux_projection")
    categories = []
    for index, category in enumerate(summary.categories):
        items = tuple(item for item in assembly.observations if item.category_id == CATEGORY_IDS[index])
        if (category.display_name != DISPLAY_NAMES[index]
                or category.review_priority != PRIORITIES[index]
                or category.observation_count != len(items)
                or any(item.display_name != DISPLAY_NAMES[index]
                       or item.review_priority != PRIORITIES[index]
                       or item.limitations[0] != LIMITATIONS[index]
                       or item.next_steps != (NEXT_STEPS[index],) for item in items)):
            raise ValueError("invalid_linux_projection")
        confidence = min((item.confidence for item in items),
                         key={"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get) if items else None
        categories.append(LinuxAuditCategoryObservation(
            category_id=CATEGORY_IDS[index], display_name=DISPLAY_NAMES[index],
            observation_count=category.observation_count, review_priority=PRIORITIES[index],
            confidence=confidence,
            outcome_counts=LinuxAuditOutcomeCounts(**{
                "success": category.outcome_counts.success,
                "failure": category.outcome_counts.failure,
                "unknown": category.outcome_counts.unknown,
            }),
            limitation=LIMITATIONS[index], next_step=NEXT_STEPS[index],
        ))
    return LinuxAuditInvestigationResponse(
        schema_version="1",
        source_context=LinuxAuditSourceContext(
            kind="LOCAL_PRIVATE_UPLOAD", label="로컬 Linux Audit 분석 결과",
            storage_notice="로그와 결과를 서버에 영구 저장하지 않습니다. 비정상 종료 후 임시 파일이 남을 수 있습니다.",
        ),
        summary=LinuxAuditSummary(
            eligible_execution_count=summary.eligible_execution_count,
            classified_execution_count=summary.classified_execution_count,
            unclassified_execution_count=assembly.unclassified_count,
            category_observation_count=summary.category_observation_count,
            outcome_counts=LinuxAuditOutcomeCounts(
                success=summary.outcome_counts.success,
                failure=summary.outcome_counts.failure,
                unknown=summary.outcome_counts.unknown,
            ),
            low_priority_observation_count=sum(item.observation_count for item in categories if item.review_priority == "LOW"),
            medium_priority_observation_count=sum(item.observation_count for item in categories if item.review_priority == "MEDIUM"),
            incomplete_context_count=assembly.incomplete_context_count,
        ),
        observations=tuple(categories), interpretation_notices=INTERPRETATION_NOTICES,
        bounded_warnings=assembly.bounded_warnings,
        capabilities=LinuxAuditCapabilities(
            html_report_available=False, llm_summary_available=False,
            auth_web_case_linking_available=False,
        ),
    )


def _worker(connection, path: str, expected_lines: int) -> None:
    try:
        try:
            groups = load_linux_audit_events(path, source_instance="local-linux-audit")
            if sum(len(group.records) for group in groups) != expected_lines:
                connection.send(("error", "PARSER_INCOMPATIBLE"))
                return
            events = tuple(event for group in groups for event in parse_linux_audit_events(group)
                           if event.event_type == "process_execution_attempt")
        except Exception:
            connection.send(("error", "PARSER_INCOMPATIBLE"))
            return
        try:
            assembly = classify_process_execution_observations(events)
        except Exception:
            connection.send(("error", "ANALYSIS_FAILED"))
            return
        try:
            response = _project(assembly).model_dump_json().encode("utf-8")
            if len(response) > MAX_RESPONSE_BYTES:
                connection.send(("error", "RESPONSE_INVALID"))
                return
            connection.send(("ok", response))
        except Exception:
            connection.send(("error", "RESPONSE_INVALID"))
    except Exception:
        pass
    finally:
        connection.close()


async def _run_worker(path: str, expected_lines: int):
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(sending, path, expected_lines))
    try:
        process.start()
        sending.close()
        ready = await asyncio.wait_for(
            asyncio.to_thread(receiving.poll, ANALYSIS_TIMEOUT_SECONDS),
            timeout=ANALYSIS_TIMEOUT_SECONDS + 1.0,
        )
        if not ready:
            return _error("ANALYSIS_TIMEOUT")
        try:
            kind, value = receiving.recv()
        except (EOFError, OSError):
            return _error("ANALYSIS_FAILED")
        if kind == "error" and value in _ERRORS:
            return _error(value)
        if kind != "ok" or type(value) is not bytes or len(value) > MAX_RESPONSE_BYTES:
            return _error("RESPONSE_INVALID")
        try:
            return LinuxAuditInvestigationResponse.model_validate_json(value)
        except ValidationError:
            return _error("RESPONSE_INVALID")
    except TimeoutError:
        return _error("ANALYSIS_TIMEOUT")
    except (OSError, RuntimeError, TypeError):
        return _error("ANALYSIS_FAILED")
    finally:
        _stop_process(process)
        receiving.close()
        sending.close()


def create_linux_audit_local_endpoint():
    limiter = _Limiter()

    async def endpoint(request: Request):
        if not _loopback_request(request):
            return _error("LOCAL_ONLY")
        if request.scope.get("query_string"):
            return _error("QUERY_NOT_ALLOWED")
        if not request.headers.get("content-type", "").lower().startswith("multipart/form-data;"):
            return _error("INVALID_MEDIA_TYPE")
        rejection = limiter.admit()
        if rejection:
            return _error(rejection)
        form = None
        try:
            try:
                with tempfile.TemporaryDirectory(prefix="investigation-linux-local-") as name:
                    directory = Path(name)
                    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                        return _error("ANALYSIS_FAILED")
                    async with asyncio.timeout(UPLOAD_TIMEOUT_SECONDS):
                        form = await _form(request)
                        expected_lines = await _stage(form[FIELD], directory / "audit.log")
                    return await _run_worker(str(directory / "audit.log"), expected_lines)
            except _UploadError as error:
                return _error(error.code)
            except TimeoutError:
                return _error("UPLOAD_TIMEOUT")
            except (OSError, ValueError):
                return _error("ANALYSIS_FAILED")
        finally:
            try:
                if form is not None:
                    try:
                        await form.close()
                    except OSError:
                        pass
            finally:
                limiter.release()

    return endpoint
