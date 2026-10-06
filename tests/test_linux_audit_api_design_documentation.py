from pathlib import Path


DOCUMENT = Path("docs/linux_audit_api_design.md")
SESSION_DOCUMENT = Path("docs/linux_audit_session_process_review.md")
CANARIES = {
    "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE",
}
REQUIRED_URLS = {
    "https://fastapi.tiangolo.com/tutorial/request-files/",
    "https://www.starlette.io/requests/#request-files",
    "https://docs.python.org/3/library/tempfile.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "File_Upload_Cheat_Sheet.html",
    "https://api-security.owasp.org/editions/2023/en/"
    "0xa4-unrestricted-resource-consumption/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    "https://csrc.nist.gov/pubs/sp/800/92/final",
}


def _document_text() -> str:
    return DOCUMENT.read_text(encoding="utf-8")


def test_design_document_exists_and_compares_api_options():
    text = _document_text()

    assert text.startswith("# Linux Audit API Boundary Design")
    assert "A. 기존 `/api/analyze`" in text
    assert "B. 전용 `/api/analyze-linux-audit`" in text
    assert "C. `/api/v1/analyze`" in text
    assert "V1은 후보 B를 선택한다" in text
    assert "기존 `/api/analyze`" in text
    assert "`AnalysisResponse`" in text


def test_design_document_fixes_bounded_request_and_cleanup_contracts():
    text = _document_text()

    for contract in (
        "Repeatable field: `linux_audit_files`",
        "최소 1, 최대 4",
        "각 최대 10 MiB",
        "최대 20 MiB",
        "strict UTF-8",
        "archive, gzip, remote URL 및 directory upload: 지원하지 않음",
        "api-linux-audit-1",
        "SHA-256",
        "TemporaryDirectory",
        "finally/context exit",
        "request cancellation",
    ):
        assert contract.casefold() in text.casefold()

    assert "공식 Linux Audit 표준값이 아니라" in text
    assert "client filename" in text
    assert "신뢰하지 않고" in text


def test_design_document_defines_fixed_response_and_privacy_denylist():
    text = _document_text()

    for response_field in (
        '"process_telemetry"',
        '"shared_memory_review"',
        '"session_process_review"',
        '"session_co_observation_count"',
        '"sessions_with_shared_memory_observation_count"',
    ):
        assert response_field in text

    for excluded in (
        "NormalizedEvent",
        "argv",
        "PROCTITLE",
        "raw records",
        "executable",
        "PATH/CWD",
        "UID/GID/AUID/session ID",
        "source_instance",
        "temporary path",
        "`global_correlation`",
    ):
        assert excluded in text

    assert "fixed shape" in text
    assert "generic dataclass/Pydantic serialization" in text


def test_design_document_defines_machine_readable_error_contract():
    text = _document_text()

    for status in ("400", "409", "413", "415", "422", "500"):
        assert f"| {status} |" in text

    for code in (
        "MISSING_LINUX_AUDIT_FILES",
        "LINUX_AUDIT_FILE_COUNT_EXCEEDED",
        "LINUX_AUDIT_FILE_TOO_LARGE",
        "LINUX_AUDIT_REQUEST_TOO_LARGE",
        "EMPTY_LINUX_AUDIT_FILE",
        "INVALID_LINUX_AUDIT_ENCODING",
        "UNSUPPORTED_LINUX_AUDIT_INPUT",
        "DUPLICATE_LINUX_AUDIT_FILE",
        "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
        "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
        "INTERNAL_SERVER_ERROR",
    ):
        assert code in text

    assert "traceback" in text
    assert "safe zero" in text


def test_design_document_keeps_llm_frontend_and_auth_boundaries_explicit():
    text = _document_text()

    assert "Gemini 또는 다른 LLM provider를 호출하지 않는다" in text
    assert "aggregate count도" in text
    assert "Frontend files는 현재 비어" in text
    assert "authentication, authorization" in text
    assert "기본 비활성화" in text
    assert "Detailed forensic evidence" in text
    assert "RBAC" in text
    assert "`/api/upload-test`" in text
    assert "public app과 OpenAPI schema에서 제거" in text
    assert "private test helper" in text
    assert "temporary path" in text


def test_design_document_includes_implementation_tests_and_primary_sources():
    text = _document_text()

    for planned_test in (
        "FastAPI `TestClient`",
        "file count",
        "size",
        "cleanup",
        "canary",
        "concurrent request",
        "Full regression",
    ):
        assert planned_test.casefold() in text.casefold()

    assert REQUIRED_URLS <= set(text.split())
    assert "접근일: 2026-10-06" in text
    assert "보장하지 않는다" in text


def test_design_document_records_bounded_staging_implementation_boundary():
    text = _document_text()

    for contract in (
        "app/api_uploads.py",
        "64 KiB",
        "incremental strict UTF-8",
        "EMPTY_LINUX_AUDIT_FILE",
        "UNSUPPORTED_LINUX_AUDIT_INPUT",
        "request-local set",
        "input-1.audit",
        "0600",
        "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
        "production API, CLI 또는 LLM에서 import/call하지 않으며",
    ):
        assert contract in text


def test_design_document_records_route_independent_orchestration_boundary():
    text = _document_text()

    for contract in (
        "app/analyzer/linux_audit_api.py",
        "load_normalized_logs()`를 정확히 한 번",
        "같은 normalized logs list object",
        "LinuxAuditApiAnalysis",
        "16개 non-negative integer",
        "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
        "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
        "Strict Pydantic response/error projection",
        "API, CLI, LLM 또는 Frontend에서 import/call하지 않는다",
    ):
        assert contract in text


def test_design_document_records_strict_response_projection_boundary():
    text = _document_text()

    for contract in (
        "app/models/linux_audit_api.py",
        "Pydantic v2",
        'extra="forbid"',
        "exact non-negative integer",
        'Literal["completed"]',
        "actual `UUID`",
        'model_dump(mode="json")',
        "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR",
        "known-error mapping",
        "Pydantic validation detail",
        "현재 OpenAPI",
        "default-disabled endpoint integration",
    ):
        assert contract in text


def test_document_has_no_fixture_evidence_and_related_document_links_to_it():
    text = _document_text()

    assert CANARIES.isdisjoint(text.split())
    assert "type=SYSCALL msg=audit(" not in text
    assert "type=USER_START msg=audit(" not in text
    assert "password=" not in text.casefold()
    assert "credential=" not in text.casefold()
    assert "/Users/" not in text
    assert "linux_audit_api_design.md" in SESSION_DOCUMENT.read_text(
        encoding="utf-8"
    )
