"""Loopback-only, bounded upload boundary for the existing deterministic pipeline."""

import asyncio
import codecs
from collections import deque
from datetime import datetime
from ipaddress import ip_address
import multiprocessing
import os
from pathlib import Path
import re
import stat
import tempfile
from threading import Lock
import time
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.analyzer.incident_case_projection import InvestigationCaseProjection
from app.models.investigation_sample_api import (
    AnalysisSummary, CaseSummary, LocalCapabilities, LocalContext,
    LocalInvestigationErrorResponse, LocalInvestigationResponse, ReportExport,
)
from app.parser.ssh_auth import AUTHENTICATION_MESSAGE
from app.sample_investigation_api import (
    _EMPTY_WARNINGS, _case, _independent, _report_export,
)


_FIELDS = ("application_file", "ssh_file", "access_file")
_SOURCES = ("application", "ssh", "access")
_MAX_FILE_BYTES = 32 * 1024
_MAX_TOTAL_BYTES = 80 * 1024
_MAX_ENVELOPE_BYTES = 96 * 1024
_MAX_LINE_BYTES = 2048
_MAX_LINES_PER_FILE = 512
_CHUNK_BYTES = 4096
_UPLOAD_TIMEOUT_SECONDS = 10.0
_ANALYSIS_TIMEOUT_SECONDS = 10.0
_CONCURRENT_CAPACITY = 1
_RATE_CAPACITY = 6
_RATE_WINDOW_SECONDS = 60.0
_MAX_RESPONSE_BYTES = 128 * 1024
_ARCHIVE_PREFIX_BYTES = 262
_ARCHIVE_SIGNATURES = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"BZh",
    b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd",
)
_ACCESS_LINE = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+\d{3}\s+(?:\d+|-)(?:\s|$)'
)
_HOST = re.compile(r"^(?:127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?$")
_LOCAL_NOTICES = (
    "로컬 실제 로그 분석 결과",
    "탐지는 침해 확인이 아닙니다.",
    "상관관계는 인과관계가 아닙니다.",
    "로그인 성공은 공격 성공을 입증하지 않습니다.",
    "조사 사례는 확정된 사고가 아닙니다.",
)
_ERRORS = {
    "LOCAL_ONLY": (403, "이 기능은 로컬 서버에서만 사용할 수 있습니다.", "127.0.0.1에 직접 연결하십시오.", False),
    "INVALID_MEDIA_TYPE": (415, "세 로그의 multipart 요청이 필요합니다.", "세 파일을 다시 선택하십시오.", False),
    "QUERY_NOT_ALLOWED": (400, "조회 조건을 받을 수 없습니다.", "조회 조건 없이 다시 시도하십시오.", False),
    "MALFORMED_MULTIPART": (400, "업로드 형식을 확인할 수 없습니다.", "세 파일을 다시 선택하십시오.", False),
    "MISSING_FIELD": (422, "필수 로그가 누락되었습니다.", "표시된 로그 파일을 선택하십시오.", False),
    "REPEATED_FIELD": (400, "같은 로그 입력이 여러 번 전송되었습니다.", "각 로그를 한 번씩 선택하십시오.", False),
    "UNKNOWN_FIELD": (400, "지원하지 않는 업로드 항목이 있습니다.", "세 로그 파일만 선택하십시오.", False),
    "FILE_COUNT_EXCEEDED": (413, "업로드 파일 수가 한도를 넘었습니다.", "세 로그 파일만 선택하십시오.", False),
    "FILE_TOO_LARGE": (413, "로그 파일 크기가 한도를 넘었습니다.", "더 작은 파일을 선택하십시오.", False),
    "TOTAL_TOO_LARGE": (413, "로그 전체 크기가 한도를 넘었습니다.", "더 작은 파일을 선택하십시오.", False),
    "ENVELOPE_TOO_LARGE": (413, "요청 크기가 한도를 넘었습니다.", "더 작은 파일을 선택하십시오.", False),
    "ARCHIVE_UNSUPPORTED": (415, "압축·보관 파일은 지원하지 않습니다.", "압축을 풀고 텍스트 로그를 선택하십시오.", False),
    "BINARY_INPUT": (415, "텍스트 로그 형식을 확인할 수 없습니다.", "UTF-8 텍스트 로그를 선택하십시오.", False),
    "INVALID_UTF8": (400, "UTF-8 로그로 읽을 수 없습니다.", "UTF-8 텍스트 파일을 선택하십시오.", False),
    "EMPTY_INPUT": (400, "로그가 비었거나 공백만 있습니다.", "내용이 있는 로그를 선택하십시오.", False),
    "LINE_TOO_LONG": (413, "로그 한 줄이 길이 한도를 넘었습니다.", "입력 형식을 확인하십시오.", False),
    "LINE_COUNT_EXCEEDED": (413, "로그 줄 수가 한도를 넘었습니다.", "더 작은 파일을 선택하십시오.", False),
    "PARSER_INCOMPATIBLE": (400, "지원하는 로그 형식이 아닙니다.", "파일 종류와 입력칸을 확인한 뒤 다시 선택하십시오.", False),
    "UPLOAD_TIMEOUT": (503, "업로드 처리 시간이 초과되었습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_TIMEOUT": (503, "분석 시간이 초과되었습니다.", "더 작은 로그로 다시 시도하십시오.", True),
    "CONCURRENCY_LIMIT": (429, "다른 로컬 분석이 진행 중입니다.", "완료 후 다시 시도하십시오.", True),
    "RATE_LIMITED": (429, "로컬 분석 요청 횟수 한도에 도달했습니다.", "잠시 후 다시 시도하십시오.", True),
    "ANALYSIS_FAILED": (500, "로그 분석을 완료하지 못했습니다.", "입력 형식을 확인하고 다시 시도하십시오.", True),
    "CASE_PROJECTION_FAILED": (500, "조사 사례를 구성하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
    "REPORT_GENERATION_FAILED": (500, "HTML 보고서를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
    "RESPONSE_INVALID": (500, "결과를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True),
}


class _UploadError(ValueError):
    def __init__(self, code: str, field: str | None = None):
        super().__init__("Local upload contract failed.")
        self.code = code
        self.field = field if field in _FIELDS else None


def _error(code: str, field: str | None = None) -> JSONResponse:
    status, message, action, retryable = _ERRORS[code]
    response = LocalInvestigationErrorResponse(
        error_code=code, user_message=message, recovery_action=action,
        retryable=retryable, field=field if field in _FIELDS else None,
    )
    return JSONResponse(status_code=status, content=response.model_dump())


class _LocalLimit:
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


def _loopback_request(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        address = ip_address(request.client.host)
    except ValueError:
        return False
    if not address.is_loopback or getattr(address, "ipv4_mapped", None) is not None:
        return False
    hosts = request.headers.getlist("host")
    if len(hosts) != 1 or _HOST.fullmatch(hosts[0]) is None:
        return False
    origins = request.headers.getlist("origin")
    if len(origins) > 1 or (origins and origins[0] != f"{request.url.scheme}://{hosts[0]}"):
        return False
    if request.headers.get("sec-fetch-site") == "cross-site":
        return False
    if any(name in request.headers for name in (
        "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
        "x-real-ip", "via",
    )):
        return False
    return True


async def _bounded_stream(request: Request):
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdecimal() or int(declared) > _MAX_ENVELOPE_BYTES):
        raise _UploadError("ENVELOPE_TOO_LARGE") from None
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _MAX_ENVELOPE_BYTES:
            raise _UploadError("ENVELOPE_TOO_LARGE") from None
        yield chunk


async def _form(request: Request):
    parser = MultiPartParser(
        request.headers, _bounded_stream(request),
        max_files=3, max_fields=0, max_part_size=0,
    )
    try:
        form = await parser.parse()
    except MultiPartException as error:
        code = "FILE_COUNT_EXCEEDED" if str(error).startswith("Too many files") else "UNKNOWN_FIELD" if str(error).startswith("Too many fields") else "MALFORMED_MULTIPART"
        raise _UploadError(code) from None
    entries = form.multi_items()
    seen = set()
    for name, upload in entries:
        if name not in _FIELDS or type(upload) is not UploadFile:
            await form.close()
            raise _UploadError("UNKNOWN_FIELD") from None
        if name in seen:
            await form.close()
            raise _UploadError("REPEATED_FIELD", name) from None
        seen.add(name)
    if seen != set(_FIELDS):
        await form.close()
        raise _UploadError("MISSING_FIELD", next(field for field in _FIELDS if field not in seen)) from None
    if len(entries) != 3:
        await form.close()
        raise _UploadError("FILE_COUNT_EXCEEDED") from None
    return form


def _archive(prefix: bytes) -> bool:
    return any(prefix.startswith(signature) for signature in _ARCHIVE_SIGNATURES) or (
        len(prefix) >= _ARCHIVE_PREFIX_BYTES and prefix[257:262] == b"ustar"
    )


def _compatible(source: str, line: str) -> bool:
    if not line.strip():
        return True
    try:
        if source == "application":
            parts = line.split()
            if len(parts) < 4:
                return False
            datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")
            return True
        if source == "ssh":
            parts = line.split()
            if len(parts) < 3:
                return False
            datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")
            return AUTHENTICATION_MESSAGE.search(line) is not None
        match = _ACCESS_LINE.match(line)
        if match is None or len(match.group(2).split()) != 3:
            return False
        datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
        return True
    except (ValueError, IndexError):
        return False


async def _stage_file(
    upload: UploadFile, *, source: str, field: str, path: Path, total: int,
) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _UploadError("ANALYSIS_FAILED") from None
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    prefix = bytearray()
    file_size = 0
    line_bytes = 0
    line_count = 0
    text_pending = ""
    non_whitespace = False
    last_byte = None
    cr_pending = False
    with os.fdopen(descriptor, "wb") as staged:
        while True:
            chunk = await upload.read(_CHUNK_BYTES)
            if not isinstance(chunk, bytes):
                raise _UploadError("BINARY_INPUT", field) from None
            if not chunk:
                break
            file_size += len(chunk)
            total += len(chunk)
            if file_size > _MAX_FILE_BYTES:
                raise _UploadError("FILE_TOO_LARGE", field) from None
            if total > _MAX_TOTAL_BYTES:
                raise _UploadError("TOTAL_TOO_LARGE", field) from None
            prefix.extend(chunk[: max(0, _ARCHIVE_PREFIX_BYTES - len(prefix))])
            if _archive(prefix):
                raise _UploadError("ARCHIVE_UNSUPPORTED", field) from None
            if any(byte < 32 and byte not in (9, 10, 13) or byte == 127 for byte in chunk):
                raise _UploadError("BINARY_INPUT", field) from None
            if cr_pending and chunk[0] != 10:
                raise _UploadError("BINARY_INPUT", field) from None
            if any(chunk[index + 1] != 10 for index, byte in enumerate(chunk[:-1]) if byte == 13):
                raise _UploadError("BINARY_INPUT", field) from None
            cr_pending = chunk[-1] == 13
            try:
                decoded = decoder.decode(chunk, final=False)
            except UnicodeDecodeError:
                raise _UploadError("INVALID_UTF8", field) from None
            non_whitespace = non_whitespace or any(not char.isspace() for char in decoded)
            fragments = chunk.split(b"\n")
            for index, fragment in enumerate(fragments):
                line_bytes += len(fragment)
                if line_bytes > _MAX_LINE_BYTES:
                    raise _UploadError("LINE_TOO_LONG", field) from None
                if index < len(fragments) - 1:
                    line_count += 1
                    if line_count > _MAX_LINES_PER_FILE:
                        raise _UploadError("LINE_COUNT_EXCEEDED", field) from None
                    line_bytes = 0
            text_pending += decoded
            completed = text_pending.split("\n")
            text_pending = completed.pop()
            for line in completed:
                if not _compatible(source, line.rstrip("\r")):
                    raise _UploadError("PARSER_INCOMPATIBLE", field) from None
            last_byte = chunk[-1]
            staged.write(chunk)
        try:
            text_pending += decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            raise _UploadError("INVALID_UTF8", field) from None
        if cr_pending:
            raise _UploadError("BINARY_INPUT", field) from None
        if last_byte != 10 and file_size:
            line_count += 1
            if line_count > _MAX_LINES_PER_FILE:
                raise _UploadError("LINE_COUNT_EXCEEDED", field) from None
            if not _compatible(source, text_pending.rstrip("\r")):
                raise _UploadError("PARSER_INCOMPATIBLE", field) from None
        if not non_whitespace:
            raise _UploadError("EMPTY_INPUT", field) from None
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise _UploadError("ANALYSIS_FAILED") from None
    return total


async def _stage(form, directory: Path):
    total = 0
    sources = []
    for index, (field, source) in enumerate(zip(_FIELDS, _SOURCES), 1):
        upload = form[field]
        path = directory / f"input-{index}.log"
        total = await _stage_file(upload, source=source, field=field, path=path, total=total)
        sources.append({"source": source, "path": str(path)})
    return sources


def _local_response(
    analysis: dict, projection: InvestigationCaseProjection,
    report_export: ReportExport,
) -> LocalInvestigationResponse:
    if (
        type(analysis) is not dict
        or type(projection) is not InvestigationCaseProjection
        or type(report_export) is not ReportExport
    ):
        raise ValueError("Invalid local projection contract.")
    results = analysis.get("results")
    summary = projection.summary
    if (
        type(results) is not dict
        or projection.schema_version != "1"
        or projection.account_alias_status != "ACCOUNT_REFERENCE_UNAVAILABLE"
        or summary.case_count != summary.high_case_count + summary.medium_case_count + summary.low_case_count
        or summary.case_count != len(projection.cases)
        or summary.independent_observation_count != len(projection.independent_observations)
    ):
        raise ValueError("Invalid local projection contract.")
    cases = tuple(_case(item) for item in projection.cases)
    independent = tuple(_independent(item) for item in projection.independent_observations)
    if any(item.review_order != index for index, item in enumerate(cases, 1)) or any(
        item.review_order != index for index, item in enumerate(independent, 1)
    ):
        raise ValueError("Invalid local projection contract.")
    return LocalInvestigationResponse(
        schema_version="1",
        local_context=LocalContext(
            label="로컬 실제 로그 분석 결과",
            environment_notice="사용자가 제공한 로그를 이 로컬 서버에서 분석한 결과입니다.",
            interpretation_notice="탐지와 관계는 침해 확정이 아닙니다.",
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
        interpretation_notices=_LOCAL_NOTICES,
        capabilities=LocalCapabilities(
            html_report_available=True, llm_summary_available=False,
            linux_audit_aggregate_available=False, actual_log_upload_available=True,
        ),
        bounded_warnings=_EMPTY_WARNINGS if summary.case_count == 0 else (),
        report_export=report_export,
    )


def _render_local_report(projection):
    from app.analyzer.html_report import render_investigation_report_html

    return render_investigation_report_html(projection, local_upload=True)


def _worker(connection, sources, analyze: Callable, project: Callable,
            build_report_projection: Callable, render_report: Callable) -> None:
    try:
        try:
            analysis = analyze(sources)
        except (ValueError, IndexError, UnicodeError):
            connection.send(("error", "PARSER_INCOMPATIBLE"))
            return
        except Exception:
            connection.send(("error", "ANALYSIS_FAILED"))
            return
        try:
            projection = project(analysis)
        except Exception:
            connection.send(("error", "CASE_PROJECTION_FAILED"))
            return
        try:
            report_projection = build_report_projection(analysis)
            report_export = _report_export(
                render_report(report_projection), synthetic_sample=False,
            )
        except Exception:
            connection.send(("error", "REPORT_GENERATION_FAILED"))
            return
        try:
            response = _local_response(analysis, projection, report_export)
            serialized = response.model_dump_json().encode("utf-8")
            if len(serialized) > _MAX_RESPONSE_BYTES:
                connection.send(("error", "RESPONSE_INVALID"))
                return
            connection.send(("ok", serialized))
        except (ValueError, ValidationError, TypeError):
            connection.send(("error", "RESPONSE_INVALID"))
    except Exception:
        # A child-process failure never exposes a Python traceback to the HTTP client.
        pass
    finally:
        connection.close()


def _stop_process(process) -> None:
    if process.pid is None:
        return
    if process.is_alive():
        process.terminate()
    process.join(timeout=1.0)
    if process.is_alive():
        process.kill()
        process.join(timeout=1.0)


async def _run_worker(sources, analyze, project, build_report_projection, render_report):
    context = multiprocessing.get_context("spawn")
    receiving, sending = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker,
        args=(sending, sources, analyze, project, build_report_projection, render_report),
    )
    try:
        process.start()
        sending.close()
        ready = await asyncio.wait_for(
            asyncio.to_thread(receiving.poll, _ANALYSIS_TIMEOUT_SECONDS),
            timeout=_ANALYSIS_TIMEOUT_SECONDS + 1.0,
        )
        if not ready:
            return _error("ANALYSIS_TIMEOUT")
        try:
            kind, value = receiving.recv()
        except (EOFError, OSError):
            return _error("ANALYSIS_FAILED")
        if kind == "error" and value in _ERRORS:
            return _error(value)
        if kind != "ok" or type(value) is not bytes or len(value) > _MAX_RESPONSE_BYTES:
            return _error("RESPONSE_INVALID")
        try:
            response = LocalInvestigationResponse.model_validate_json(value)
        except ValidationError:
            return _error("RESPONSE_INVALID")
        return response
    except TimeoutError:
        return _error("ANALYSIS_TIMEOUT")
    except (OSError, RuntimeError, TypeError):
        return _error("ANALYSIS_FAILED")
    finally:
        _stop_process(process)
        receiving.close()
        sending.close()


def create_local_endpoint(
    analyze: Callable, project: Callable,
    build_report_projection: Callable, render_report: Callable = _render_local_report,
):
    limiter = _LocalLimit()

    async def local_investigation(request: Request):
        if not _loopback_request(request):
            return _error("LOCAL_ONLY")
        if request.scope.get("query_string"):
            return _error("QUERY_NOT_ALLOWED")
        content_type = request.headers.get("content-type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            return _error("INVALID_MEDIA_TYPE")
        rejection = limiter.admit()
        if rejection is not None:
            return _error(rejection)
        form = None
        try:
            try:
                with tempfile.TemporaryDirectory(prefix="investigation-local-") as name:
                    directory = Path(name)
                    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                        return _error("ANALYSIS_FAILED")
                    async with asyncio.timeout(_UPLOAD_TIMEOUT_SECONDS):
                        form = await _form(request)
                        sources = await _stage(form, directory)
                    return await _run_worker(
                        sources, analyze, project,
                        build_report_projection, render_report,
                    )
            except _UploadError as error:
                return _error(error.code, error.field)
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

    return local_investigation
