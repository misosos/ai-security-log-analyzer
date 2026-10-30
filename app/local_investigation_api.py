"""Loopback-only, bounded upload boundary for the existing deterministic pipeline."""

import asyncio
import codecs
from collections import deque
from datetime import datetime
import json
import multiprocessing
import os
from pathlib import Path
import re
import stat
import tempfile
from threading import Lock
import time
from typing import Callable
import unicodedata

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser

from app.analyzer.incident_case_projection import InvestigationCaseProjection
from app.detector.brute_force import is_owned_analysis_result
from app.models.investigation_sample_api import (
    AnalysisSummary, CaseSummary, LocalCapabilities, LocalContext,
    LocalInvestigationErrorResponse, LocalInvestigationResponse, ReportExport,
)
from app.models.local_text_investigation import (
    LocalTextInputScope,
    LocalTextInvestigationErrorResponse,
    LocalTextInvestigationRequest,
    LocalTextInvestigationResponse,
)
from app.investigation_role_snapshot_36_4 import AnalysisWithSourceRoleSnapshot
from app.parser.access_log import parse_access_log
from app.parser.ssh_auth import parse_ssh_auth_log
from app.local_request_security import classify_local_request
from app.sample_investigation_api import (
    _EMPTY_WARNINGS, _case, _independent, _report_export,
)
from app.public_identifiers import subject_aliases


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
_MAX_TEXT_REQUEST_BYTES = 96 * 1024
_MAX_TEXT_BYTES = 32 * 1024
_ARCHIVE_PREFIX_BYTES = 262
_ARCHIVE_SIGNATURES = (
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"BZh",
    b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd",
)
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
_TEXT_ERRORS = {
    "LOCAL_ONLY": (403, "이 기능은 로컬 서버에서만 사용할 수 있습니다.", "127.0.0.1에 직접 연결하십시오.", False, None),
    "INVALID_MEDIA_TYPE": (415, "JSON 텍스트 입력 요청이 필요합니다.", "application/json UTF-8 요청을 사용하십시오.", False, None),
    "QUERY_NOT_ALLOWED": (400, "조회 조건을 받을 수 없습니다.", "조회 조건 없이 다시 시도하십시오.", False, None),
    "INVALID_JSON": (400, "요청 본문을 읽을 수 없습니다.", "JSON 문법과 UTF-8 인코딩을 확인하십시오.", False, None),
    "INVALID_SCHEMA": (422, "요청 형식을 확인할 수 없습니다.", "필수 항목과 허용된 형식을 확인하십시오.", False, None),
    "UNKNOWN_SOURCE": (422, "지원하지 않는 로그 종류입니다.", "애플리케이션, SSH 또는 접근 로그를 선택하십시오.", False, "source"),
    "EMPTY_INPUT": (400, "로그가 비었거나 공백만 있습니다.", "내용이 있는 로그를 입력하십시오.", False, "log_text"),
    "INVALID_UTF8": (400, "UTF-8 로그로 읽을 수 없습니다.", "유효한 UTF-8 텍스트를 사용하십시오.", False, "log_text"),
    "INVALID_TEXT": (400, "로그 텍스트에 허용되지 않는 문자가 있습니다.", "제어 문자를 제거하고 UTF-8 텍스트를 확인하십시오.", False, "log_text"),
    "PARSER_INCOMPATIBLE": (400, "선택한 로그 종류와 입력 형식이 맞지 않습니다.", "로그 종류와 지원 형식을 확인하십시오.", False, "log_text"),
    "TEXT_TOO_LARGE": (413, "로그 텍스트 크기가 한도를 넘었습니다.", "더 작은 로그 범위를 선택하십시오.", False, "log_text"),
    "ENVELOPE_TOO_LARGE": (413, "요청 크기가 한도를 넘었습니다.", "더 작은 로그 범위를 선택하십시오.", False, None),
    "LINE_TOO_LONG": (413, "로그 한 줄이 길이 한도를 넘었습니다.", "입력 범위를 줄이거나 줄 형식을 확인하십시오.", False, "log_text"),
    "LINE_COUNT_EXCEEDED": (413, "로그 줄 수가 한도를 넘었습니다.", "더 작은 로그 범위를 선택하십시오.", False, "log_text"),
    "BODY_TIMEOUT": (503, "요청 본문 처리 시간이 초과되었습니다.", "잠시 후 다시 요청하십시오.", True, None),
    "ANALYSIS_TIMEOUT": (503, "분석 응답 시간이 초과되었습니다.", "더 작은 로그 범위로 다시 시도하십시오.", True, None),
    "CONCURRENCY_LIMIT": (429, "현재 처리 가능한 요청 수를 넘었습니다.", "현재 분석이 끝난 뒤 다시 시도하십시오.", True, None),
    "RATE_LIMITED": (429, "요청 횟수 한도에 도달했습니다.", "잠시 후 다시 시도하십시오.", True, None),
    "ANALYSIS_FAILED": (500, "분석을 완료하지 못했습니다.", "입력 형식을 확인한 뒤 다시 시도하십시오.", True, None),
    "CASE_PROJECTION_FAILED": (500, "조사 사례를 구성하지 못했습니다.", "잠시 후 다시 시도하십시오.", True, None),
    "REPORT_GENERATION_FAILED": (500, "HTML 보고서를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True, None),
    "RESPONSE_INVALID": (500, "결과를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", True, None),
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
    return classify_local_request(request) is None


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
            event = parse_ssh_auth_log(line, "Asia/Seoul")
            return event is not None and event.authentication is not None
        return parse_access_log(line) is not None
    except (ValueError, IndexError, TypeError, OverflowError):
        return False


class _TextInputError(ValueError):
    def __init__(self, code: str):
        super().__init__("Local text input contract failed.")
        self.code = code if code in _TEXT_ERRORS else "INVALID_SCHEMA"


def _text_error(code: str) -> JSONResponse:
    status, message, action, retryable, field = _TEXT_ERRORS[code]
    response = LocalTextInvestigationErrorResponse(
        error_code=code, user_message=message, recovery_action=action,
        retryable=retryable, field=field,
    )
    return JSONResponse(status_code=status, content=response.model_dump())


def _reject_duplicate_json_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON member.") from None
        value[key] = item
    return value


def _reject_json_constant(_value):
    raise ValueError("Invalid JSON constant.") from None


def _parse_text_request(raw: bytes) -> LocalTextInvestigationRequest:
    try:
        decoded = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise _TextInputError("INVALID_UTF8") from None
    try:
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, RecursionError):
        raise _TextInputError("INVALID_JSON") from None
    if type(value) is not dict:
        raise _TextInputError("INVALID_SCHEMA")
    if set(value) != {"schema_version", "source", "log_text"}:
        raise _TextInputError("INVALID_SCHEMA")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _TextInputError("INVALID_SCHEMA")
    if type(value["source"]) is not str:
        raise _TextInputError("INVALID_SCHEMA")
    if value["source"] not in _SOURCES:
        raise _TextInputError("UNKNOWN_SOURCE")
    if type(value["log_text"]) is not str:
        raise _TextInputError("INVALID_SCHEMA")
    try:
        request = LocalTextInvestigationRequest.model_validate(value)
    except ValidationError:
        raise _TextInputError("INVALID_SCHEMA") from None
    return request


def _validate_text(source: str, text: str) -> bytes:
    if type(source) is not str or source not in _SOURCES or type(text) is not str:
        raise _TextInputError("INVALID_SCHEMA")
    try:
        raw = text.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise _TextInputError("INVALID_UTF8") from None
    if len(raw) > _MAX_TEXT_BYTES:
        raise _TextInputError("TEXT_TOO_LARGE")
    if not text or not any(not char.isspace() for char in text):
        raise _TextInputError("EMPTY_INPUT")
    if any(
        unicodedata.category(char) == "Cc" and char not in "\t\r\n"
        for char in text
    ):
        raise _TextInputError("INVALID_TEXT")
    if "\r" in text.replace("\r\n", ""):
        raise _TextInputError("INVALID_TEXT")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if len(lines) > _MAX_LINES_PER_FILE:
        raise _TextInputError("LINE_COUNT_EXCEEDED")
    for line in lines:
        if len(line.encode("utf-8")) > _MAX_LINE_BYTES:
            raise _TextInputError("LINE_TOO_LONG")
        if not _compatible(source, line.removesuffix("\r")):
            raise _TextInputError("PARSER_INCOMPATIBLE")
    return raw


async def _bounded_json_body(request: Request) -> bytes:
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        raise _TextInputError("INVALID_JSON")
    if lengths:
        value = lengths[0]
        if not value or any(character < "0" or character > "9" for character in value):
            raise _TextInputError("INVALID_JSON")
        significant = value.lstrip("0") or "0"
        limit = str(_MAX_TEXT_REQUEST_BYTES)
        if len(significant) > len(limit) or (
            len(significant) == len(limit) and significant > limit
        ):
            raise _TextInputError("ENVELOPE_TOO_LARGE")
    body = bytearray()
    async for chunk in request.stream():
        if type(chunk) is not bytes:
            raise _TextInputError("INVALID_JSON")
        if len(body) + len(chunk) > _MAX_TEXT_REQUEST_BYTES:
            raise _TextInputError("ENVELOPE_TOO_LARGE")
        body.extend(chunk)
    return bytes(body)


def _stage_text(raw: bytes, directory: Path) -> Path:
    if not hasattr(os, "O_NOFOLLOW"):
        raise _TextInputError("ANALYSIS_FAILED") from None
    path = directory / "input-1.log"
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as staged:
            staged.write(raw)
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise _TextInputError("ANALYSIS_FAILED") from None
    try:
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError("Unexpected staging mode.")
    except OSError:
        raise _TextInputError("ANALYSIS_FAILED") from None
    return path


def _render_text_local_report(projection):
    from app.analyzer.html_report import render_investigation_report_html

    return render_investigation_report_html(
        projection, local_upload=True, partial_single_source=True,
    )


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
        (type(analysis) is not dict and not is_owned_analysis_result(analysis))
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
    aliases = subject_aliases(
        [item.row.subject_ip for item in projection.cases]
        + [item.subject_ip for item in projection.independent_observations]
    )
    import secrets
    cases = tuple(_case(item, aliases, "c_" + secrets.token_hex(12)) for item in projection.cases)
    independent = tuple(_independent(item, aliases) for item in projection.independent_observations)
    if any(item.review_order != index for index, item in enumerate(cases, 1)) or any(
        item.review_order != index for index, item in enumerate(independent, 1)
    ):
        raise ValueError("Invalid local projection contract.")
    return LocalInvestigationResponse(
        schema_version="2",
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
            analysis_run = analyze(sources)
            role_snapshot = None
            if type(analysis_run) is AnalysisWithSourceRoleSnapshot:
                analysis = analysis_run.analysis
                role_snapshot = analysis_run.source_roles
            else:
                analysis = analysis_run
        except (ValueError, IndexError, UnicodeError):
            connection.send(("error", "PARSER_INCOMPATIBLE"))
            return
        except Exception:
            connection.send(("error", "ANALYSIS_FAILED"))
            return
        try:
            projection = project(
                analysis_run
                if type(analysis_run) is AnalysisWithSourceRoleSnapshot
                else analysis
            )
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
            from app.investigation_checklist_api_36_3 import trusted_case_fields_from_projection
            bound_roles = (role_snapshot.bind_projection(projection, analysis)
                           if role_snapshot is not None else ())
            safe_case_inputs = tuple(
                trusted_case_fields_from_projection(
                    case,
                    bound_roles[index] if index < len(bound_roles) else None,
                    analysis,
                    projection,
                )
                for index, case in enumerate(projection.cases[:128])
            ) + (None,) * max(0, len(projection.cases) - 128)
            connection.send(("ok", serialized, safe_case_inputs))
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
            message = receiving.recv()
            kind, value = message[:2]
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
        safe_case_inputs = message[2] if len(message) == 3 else None
        return response, safe_case_inputs
    except TimeoutError:
        return _error("ANALYSIS_TIMEOUT")
    except (OSError, RuntimeError, TypeError):
        return _error("ANALYSIS_FAILED")
    finally:
        _stop_process(process)
        receiving.close()
        sending.close()


def create_local_admission():
    """Create the per-application admission gate shared by local analysis routes."""
    return _LocalLimit()


def create_local_endpoint(
    analyze: Callable, project: Callable,
    build_report_projection: Callable, render_report: Callable = _render_local_report,
    checklist_registry=None, admission=None,
):
    limiter = admission if admission is not None else create_local_admission()

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
                    worker_result = await _run_worker(
                        sources, analyze, project,
                        build_report_projection, render_report,
                    )
                    if (checklist_registry is not None and type(worker_result) is tuple
                            and len(worker_result) == 2
                            and isinstance(worker_result[0], LocalInvestigationResponse)
                            and type(worker_result[1]) is tuple):
                        response, safe_case_inputs = worker_result
                        if any(item is None for item in safe_case_inputs):
                            return _error("RESPONSE_INVALID")
                        return checklist_registry.attach(response, safe_case_inputs)
                    if type(worker_result) is tuple:
                        return worker_result[0]
                    return worker_result
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


def create_local_text_endpoint(
    analyze: Callable, project: Callable, build_report_projection: Callable,
    checklist_registry=None, admission=None,
):
    limiter = admission if admission is not None else create_local_admission()

    async def local_text_investigation(request: Request):
        if not _loopback_request(request):
            return _text_error("LOCAL_ONLY")
        if request.scope.get("query_string"):
            return _text_error("QUERY_NOT_ALLOWED")
        content_types = request.headers.getlist("content-type")
        if (
            len(content_types) != 1
            or re.fullmatch(
                r"application/json(?:\s*;\s*charset\s*=\s*(?:utf-8|\"utf-8\"))?\s*",
                content_types[0], re.IGNORECASE,
            ) is None
            or request.headers.get("content-encoding", "identity").lower() not in ("", "identity")
        ):
            return _text_error("INVALID_MEDIA_TYPE")
        rejection = limiter.admit()
        if rejection is not None:
            return _text_error(rejection)
        try:
            try:
                async with asyncio.timeout(_UPLOAD_TIMEOUT_SECONDS):
                    raw_body = await _bounded_json_body(request)
                text_request = _parse_text_request(raw_body)
                raw_text = _validate_text(text_request.source, text_request.log_text)
            except TimeoutError:
                return _text_error("BODY_TIMEOUT")
            except _TextInputError as error:
                return _text_error(error.code)

            with tempfile.TemporaryDirectory(prefix="investigation-local-text-") as name:
                directory = Path(name)
                if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                    return _text_error("ANALYSIS_FAILED")
                try:
                    path = _stage_text(raw_text, directory)
                except _TextInputError as error:
                    return _text_error(error.code)
                sources = [{"source": text_request.source, "path": str(path)}]
                worker_result = await _run_worker(
                    sources, analyze, project, build_report_projection,
                    _render_text_local_report,
                )
                if isinstance(worker_result, JSONResponse):
                    try:
                        error_body = json.loads(worker_result.body)
                        error_code = error_body.get("error_code")
                    except (ValueError, TypeError, AttributeError):
                        error_code = None
                    if error_code not in _TEXT_ERRORS:
                        error_code = "ANALYSIS_FAILED"
                    return _text_error(error_code)
                if (
                    type(worker_result) is not tuple
                    or len(worker_result) != 2
                    or not isinstance(worker_result[0], LocalInvestigationResponse)
                    or type(worker_result[1]) is not tuple
                ):
                    return _text_error("RESPONSE_INVALID")
                response, safe_case_inputs = worker_result
                if checklist_registry is not None:
                    if any(item is None for item in safe_case_inputs):
                        return _text_error("RESPONSE_INVALID")
                    try:
                        response = checklist_registry.attach(response, safe_case_inputs)
                    except (TypeError, ValueError):
                        return _text_error("RESPONSE_INVALID")
                try:
                    envelope = LocalTextInvestigationResponse(
                        schema_version="1",
                        input_scope=LocalTextInputScope(
                            mode="text", source=text_request.source,
                            notice_code="PARTIAL_SINGLE_SOURCE",
                        ),
                        result=response,
                    )
                    rendered = JSONResponse(
                        status_code=200,
                        content=envelope.model_dump(mode="json"),
                    )
                    if len(rendered.body) > _MAX_RESPONSE_BYTES:
                        return _text_error("RESPONSE_INVALID")
                except (ValidationError, TypeError, ValueError):
                    return _text_error("RESPONSE_INVALID")
                return rendered
        except TimeoutError:
            return _text_error("ANALYSIS_TIMEOUT")
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError):
            return _text_error("ANALYSIS_FAILED")
        finally:
            limiter.release()

    return local_text_investigation
