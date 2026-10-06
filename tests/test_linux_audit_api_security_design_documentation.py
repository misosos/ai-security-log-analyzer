from pathlib import Path
import re


DOCUMENT = Path("docs/linux_audit_api_security_design.md")
API_DESIGN = Path("docs/linux_audit_api_design.md")
CANARIES = {
    "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE",
}
OFFICIAL_URLS = {
    "https://fastapi.tiangolo.com/tutorial/security/",
    "https://fastapi.tiangolo.com/reference/security/",
    "https://docs.python.org/3.12/library/secrets.html#secrets.compare_digest",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Authentication_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "REST_Security_Cheat_Sheet.html",
    "https://api-security.owasp.org/editions/2023/en/"
    "0xa2-broken-authentication/",
    "https://api-security.owasp.org/editions/2023/en/"
    "0xa4-unrestricted-resource-consumption/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    "https://pages.nist.gov/800-63-4/sp800-63b.html",
    "https://csrc.nist.gov/pubs/sp/800/92/final",
    "https://www.starlette.io/requests/#request-files",
    "https://www.uvicorn.org/settings/",
    "https://www.uvicorn.org/deployment/",
}


def document_text() -> str:
    raw = DOCUMENT.read_bytes()
    assert raw.decode("utf-8").encode("utf-8") == raw
    return raw.decode("utf-8")


def test_security_design_exists_and_records_current_gap_and_v1_choice():
    text = document_text()

    assert text.startswith("# Linux Audit API Security Controls Design")
    for contract in (
        "create_app(*, enable_linux_audit_api: bool = False)",
        "feature gate는 route registration control일 뿐 authentication",
        "Static operator bearer token",
        "External OAuth2/OIDC",
        "Reverse proxy/API gateway authentication",
        "Mutual TLS",
        "explicit static operator bearer credential",
        "Custom username/password database나 자체 JWT issuer는 만들지 않는다",
    ):
        assert contract in text


def test_security_config_and_fail_closed_startup_are_explicit():
    text = document_text()

    for contract in (
        "LinuxAuditApiSecurityConfig",
        "operator_token: SecretStr",
        "principal_id: str",
        "max_concurrent_analyses: int",
        "32 random bytes",
        "43 ASCII characters",
        "SHA-256 digest",
        "secrets.compare_digest()",
        "Hashing은 weak token을 strong token으로 만들지 않는다",
        "Default credential은 없으며",
        "create_app(enable_linux_audit_api=True)",
        "Missing security configuration error",
        "Contradictory configuration error",
        "startup-only exception",
        "Random unknown credential 생성",
    ):
        assert contract.casefold() in text.casefold()

    assert "default token" in text


def test_authentication_authorization_and_errors_are_bounded():
    text = document_text()

    for contract in (
        "Authorization: Bearer <operator-token>",
        "Exactly one `Authorization` header",
        "case-insensitive `Bearer`",
        "256 bytes 이하",
        "linux-audit:analyze",
        "AuthenticatedLinuxAuditPrincipal",
        "LINUX_AUDIT_AUTHENTICATION_REQUIRED",
        "LINUX_AUDIT_ACCESS_DENIED",
        "LINUX_AUDIT_ANALYSIS_BUSY",
        "LINUX_AUDIT_RATE_LIMITED",
        "WWW-Authenticate: Bearer",
    ):
        assert contract in text

    for status in ("401", "403", "429"):
        assert f"| {status} |" in text


def test_resource_body_tls_and_proxy_boundaries_are_not_overclaimed():
    text = document_text()

    for contract in (
        "app instance가 소유",
        "non-blocking",
        "Unbounded queue",
        "worker/process/instance count",
        "distributed global limit이 아니다",
        "reverse proxy/API gateway",
        "Application-local IP rate limiter는 만들지 않는다",
        "multipart body를 만든 후 `solve_dependencies()`",
        "upstream gateway",
        "strict total-body/header/rate/connection limits",
        "Bearer credentials require HTTPS",
        "forwarded-allow-ips",
        "Client IP is not an authentication factor",
    ):
        assert contract.casefold() in text.casefold()


def test_access_audit_has_fixed_allowlist_and_sensitive_denylist():
    text = document_text()

    for category in (
        "authentication_failed",
        "authorization_failed",
        "validation_failed",
        "capacity_rejected",
        "analysis_completed",
        "internal_failed",
        "cancelled",
    ):
        assert category in text

    allowed_section = text.split("Allowed fields:", 1)[1].split(
        "Forbidden fields:", 1
    )[0]
    forbidden_section = text.split("Forbidden fields:", 1)[1].split(
        "## 13.", 1
    )[0]
    for allowed in (
        "request ID",
        "principal_id",
        "result category",
        "HTTP status",
        "file count",
        "total-size bucket",
        "duration bucket",
    ):
        assert allowed in allowed_section
    for forbidden in (
        "Bearer token",
        "token digest",
        "Filename",
        "Temporary path",
        "raw record",
        "argv",
        "Exception string",
        "full request/response headers",
    ):
        assert forbidden.casefold() in forbidden_section.casefold()


def test_privacy_threat_model_and_plans_are_complete():
    text = document_text()

    for contract in (
        "Security controls do not expand the response allowlist",
        "does not call an LLM",
        "Authentication is not consent",
        "## 15. Threat model",
        "does not prevent replay",
        "## 16. Implementation sequence",
        "## 17. Implementation test plan",
        "Default endpoint and Linux Audit security schema absent",
        "Slot releases after success",
        "Existing default OpenAPI",
        "Full regression passes before and after commit",
        "## 18. Non-goals and known limitations",
    ):
        assert contract.casefold() in text.casefold()


def test_official_sources_record_access_date_facts_and_non_guarantees():
    text = document_text()

    assert OFFICIAL_URLS <= set(text.split())
    assert "2026-10-06" in text
    assert "Fact used" in text
    assert "Does not guarantee" in text
    assert text.count("| FastAPI |") >= 2
    assert text.count("| OWASP") >= 4
    assert text.count("| NIST |") >= 2
    assert text.count("| Uvicorn |") >= 2


def test_document_contains_no_secret_fixture_canary_or_local_user_path():
    text = document_text()

    assert CANARIES.isdisjoint(text.split())
    assert "type=SYSCALL msg=audit(" not in text
    assert "type=USER_START msg=audit(" not in text
    assert "/Users/" not in text
    assert "/home/" not in text
    assert "password=" not in text.casefold()
    assert "credential=" not in text.casefold()

    bearer_values = re.findall(
        r"Authorization:\s*Bearer\s+([^\s`]+)",
        text,
        flags=re.IGNORECASE,
    )
    assert bearer_values == ["<operator-token>"]


def test_existing_api_design_links_security_design_without_claiming_implementation():
    text = API_DESIGN.read_text(encoding="utf-8")

    assert "[Linux Audit API Security Controls Design]" in text
    assert "(linux_audit_api_security_design.md)" in text
    assert "control 구현이나 production enablement를 의미하지 않는다" in text
