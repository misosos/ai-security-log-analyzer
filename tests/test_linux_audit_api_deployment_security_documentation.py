from pathlib import Path
import re


DOCUMENT = Path("docs/linux_audit_api_deployment_security.md")
SECURITY_DESIGN = Path("docs/linux_audit_api_security_design.md")
API_DESIGN = Path("docs/linux_audit_api_design.md")
KNOWN_CANARIES = {
    "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_CAPACITY_SECRET_DO_NOT_EXPOSE",
    "SYNTHETIC_UPLOAD_TEST_SECRET_DO_NOT_EXPOSE",
}
OFFICIAL_URLS = {
    "https://fastapi.tiangolo.com/deployment/https/",
    "https://fastapi.tiangolo.com/advanced/behind-a-proxy/",
    "https://fastapi.tiangolo.com/deployment/concepts/",
    "https://fastapi.tiangolo.com/deployment/server-workers/",
    "https://fastapi.tiangolo.com/deployment/docker/",
    "https://www.uvicorn.org/settings/",
    "https://docs.python.org/3/library/os.html",
    "https://docs.python.org/3/library/stat.html",
    "https://docs.python.org/3/library/pathlib.html",
    "https://nginx.org/en/docs/http/configuring_https_servers.html",
    "https://nginx.org/en/docs/http/ngx_http_core_module.html",
    "https://nginx.org/en/docs/http/ngx_http_proxy_module.html",
    "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html",
    "https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html",
    "https://infosec.mozilla.org/guidelines/web_security",
    "https://ssl-config.mozilla.org/",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Transport_Layer_Security_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "REST_Security_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "File_Upload_Cheat_Sheet.html",
    "https://api-security.owasp.org/editions/2023/en/"
    "0xa4-unrestricted-resource-consumption/",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Logging_Cheat_Sheet.html",
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Secrets_Management_Cheat_Sheet.html",
    "https://csrc.nist.gov/pubs/sp/800/92/final",
    "https://csrc.nist.gov/Projects/Key-Management/"
    "Key-Management-Guidelines",
    "https://systemd.io/CREDENTIALS/",
    "https://www.freedesktop.org/software/systemd/man/"
    "journald.conf.html",
    "https://www.freedesktop.org/software/systemd/man/"
    "journalctl.html",
}


def document_bytes() -> bytes:
    assert DOCUMENT.is_file()
    raw = DOCUMENT.read_bytes()
    assert raw.decode("utf-8").encode("utf-8") == raw
    return raw


def document_text() -> str:
    return document_bytes().decode("utf-8")


def test_document_records_current_gap_default_disabled_and_gate_boundary():
    text = document_text()

    assert text.startswith(
        "# Linux Audit API Production Deployment Security Contract"
    )
    for contract in (
        "default-disabled",
        "feature gate is not authentication",
        "README.md",
        "no Dockerfile",
        "no `.env.example`",
        "Production activation remains prohibited",
        "design and acceptance plan",
    ):
        assert contract.casefold() in text.casefold()


def test_selected_topology_tls_binding_and_proxy_trust_are_explicit():
    text = document_text()

    for option in (
        "A. Public Uvicorn",
        "B. Loopback Uvicorn behind Nginx",
        "C. Uvicorn behind Caddy",
        "D. Containerized app behind ingress/API gateway",
    ):
        assert option in text

    for contract in (
        "public Nginx TLS listener",
        "loopback-only Uvicorn, one worker",
        "Uvicorn must never be publicly bound",
        "TLS 1.3 is preferred",
        "TLS 1.2 is the minimum",
        "Public plaintext HTTP is disabled",
        "HSTS",
        "explicit `forwarded-allow-ips`",
        "Wildcard trust is prohibited",
        "removes inbound `Forwarded` and `X-Forwarded-*`",
        "exact `server_name`",
        "Client IP is not an authentication factor",
    ):
        assert contract.casefold() in text.casefold()


def test_edge_body_header_timeout_connection_and_rate_contracts_are_bounded():
    text = document_text()

    assert "24 MiB" in text
    assert "20 MiB" in text
    assert text.index("24 MiB") < text.index(
        "application's 20 MiB content ceiling"
    )
    for contract in (
        "V1 operational defaults",
        "not Linux Audit standards",
        "2 × 8 KiB",
        "Header read timeout",
        "Body read inactivity timeout",
        "Absolute request budget",
        "Keep-alive idle timeout",
        "Endpoint connections being processed",
        "EDGE_REQUEST_BODY_TOO_LARGE",
        "average of 6 requests per minute",
        "burst of 2",
        "nodelay",
        "EDGE_REQUEST_RATE_LIMITED",
        "Client-IP keying is not used",
        "multiple proxies do not share state",
    ):
        assert contract.casefold() in text.casefold()


def test_worker_capacity_formula_and_initial_recommendation_are_exact():
    text = document_text()

    for contract in (
        "effective concurrent analyses",
        "Uvicorn worker count",
        "max_concurrent_analyses per app instance",
        "replica count",
        "one Uvicorn worker",
        "one replica",
        "max_concurrent_analyses=1",
        "giving effective capacity 1",
        "process-local capacity is never described as fleet-global",
        "threadpool is also process-local",
    ):
        assert contract.casefold() in text.casefold()


def test_secret_delivery_rotation_and_revocation_are_fail_closed():
    text = document_text()

    for contract in (
        "systemd service credential",
        "$CREDENTIALS_DIRECTORY",
        "mode `0400`",
        "never an environment value or command-line argument",
        "at most 44 bytes",
        "exactly 43 ASCII Base64URL characters",
        "decoded length other than 32 bytes",
        "Missing/invalid credentials fail before traffic is accepted",
        "coordinated restart/redeployment",
        "Emergency revocation",
        "no dual-token grace period",
        "no token expiry",
        "no distributed revocation",
        "Static bearer credentials remain replayable",
    ):
        assert contract.casefold() in text.casefold()


def test_secret_bootstrap_implementation_and_residual_limits_are_recorded():
    text = document_text()

    for contract in (
        "load_linux_audit_api_security_config()",
        "app/bootstrap/linux_audit_api.py",
        "caller-supplied absolute `pathlib.Path`",
        "never reads an environment variable",
        "exact permission mode of `0400` or `0600`",
        "rejects relative paths, symlinks, directories, FIFOs, sockets",
        "`O_RDONLY` plus `O_CLOEXEC` and `O_NOFOLLOW` when the host exposes",
        "Pre-open and open device/inode identities must match",
        "do not eliminate TOCTOU",
        "128-byte file ceiling",
        "application operational bound",
        "strict ASCII",
        "exactly one final LF",
        "fixed machine codes and messages",
        "cannot be securely zeroized",
        "No route or `create_app()` integration",
        "deployment entry point remains responsible",
    ):
        assert contract.casefold() in text.casefold()


def test_audit_sink_and_retention_policy_are_explicit_and_non_universal():
    text = document_text()

    for sink in (
        "Local JSON Lines file",
        "syslog/journald",
        "Remote security collector",
        "native structured journald adapter",
    ):
        assert sink.casefold() in text.casefold()

    for contract in (
        "explicitly to bounded journald fields",
        "It will not accept generic dictionaries",
        "Sink initialization verifies",
        "LINUX_AUDIT_ACCESS_AUDIT_FAILED",
        "does not guarantee durable media",
        "No universal retention number is defined",
        "Retention",
        "Access roles",
        "Integrity",
        "Backups",
        "Deletion",
        "Incident hold",
        "Production activation is prohibited until this policy is supplied",
        "request-scoped and are not retained",
    ):
        assert contract.casefold() in text.casefold()


def test_implemented_journald_sink_contract_is_bounded_and_route_independent():
    text = document_text()

    for contract in (
        "app/security/linux_audit_api_journald.py",
        "exact immutable `LinuxAuditApiAccessAuditEvent`",
        "fixed journald allowlist",
        "LINUX_AUDIT_EVENT_SCHEMA_VERSION",
        "LINUX_AUDIT_DURATION_BUCKET",
        "maximum UTF-8 length of 256 bytes",
        "limited to 4096 bytes",
        "V1 application operational bounds",
        "fails with a fixed bounded initialization error",
        "There is no logger, syslog, file, stdout/stderr, memory or network fallback",
        "not yet wired into `create_app()`",
        "there is no event queue and no automatic retry",
        "cannot guarantee termination of an already-running blocking send",
        "does not claim exactly-once delivery",
        "`close()` is explicit, bounded and idempotent",
        "does not claim to flush, fsync, persist, forward or delete",
        "does not prove journald acceptance",
        "forwarding is a separate host policy",
    ):
        assert contract.casefold() in text.casefold()

    for url in (
        "https://systemd.io/JOURNAL_NATIVE_PROTOCOL/",
        "https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml",
        "https://docs.python.org/3/library/asyncio-task.html",
    ):
        assert url in text


def test_liveness_readiness_startup_and_shutdown_are_distinct():
    text = document_text()

    for contract in (
        "only a lightweight liveness signal",
        "separate internal readiness contract",
        "security configuration was prepared successfully",
        "audit sink completed startup initialization",
        "does not upload a file",
        "Any config, sink or contradictory feature-state error terminates startup",
        "There is no development bypass",
        "60-second operational drain budget",
        "five-second budget",
        "Cancellation continues to release limiter capacity",
        "abrupt kill",
        "cannot guarantee cleanup or terminal audit persistence",
    ):
        assert contract.casefold() in text.casefold()


def test_activation_checklist_reference_plan_acceptance_and_threats_exist():
    text = document_text()

    checklist = text.split(
        "## 13. Production activation checklist",
        1,
    )[1].split("## 14.", 1)[0]
    assert checklist.count("- [ ]") >= 18
    for contract in (
        "TLS proxy",
        "Uvicorn is loopback/private only",
        "trusted proxy allowlist",
        "Rotation, emergency revocation",
        "audit sink initializes",
        "Retention",
        "privacy-canary acceptance",
        "Incident-response contact",
    ):
        assert contract.casefold() in checklist.casefold()

    for section in (
        "## 14. Later reference implementation plan",
        "## 15. Deployment acceptance-test plan",
        "## 16. Threat model and ownership",
        "## 17. Non-goals and known limitations",
    ):
        assert section in text

    for threat in (
        "Plaintext bearer interception",
        "Public Uvicorn exposure",
        "Spoofed forwarded headers",
        "Oversized multipart body",
        "Slow upload",
        "Request flood",
        "Worker/replica multiplication",
        "Secret in argv/environment/log",
        "Stale token after rotation",
        "Audit-log tampering",
        "Audit storage exhaustion",
        "Over-retention",
        "Failed deletion",
        "Proxy misconfiguration",
        "Health/readiness disclosure",
        "Abrupt termination",
        "Compromised proxy or host",
    ):
        assert threat in text


def test_official_sources_record_exact_urls_facts_limits_and_access_date():
    text = document_text()

    assert OFFICIAL_URLS <= set(text.split())
    assert "2026-10-07" in text
    assert "Fact used" in text
    assert "Does not guarantee" in text
    assert text.count("| FastAPI |") >= 5
    assert text.count("| Nginx |") >= 5
    assert text.count("| OWASP") >= 6
    assert text.count("| NIST |") >= 2
    assert text.count("| systemd |") >= 3
    assert text.count("| Python Software Foundation |") >= 3


def test_documents_link_the_deployment_contract_without_claiming_implementation():
    for path in (SECURITY_DESIGN, API_DESIGN):
        text = path.read_text(encoding="utf-8")
        assert "[Linux Audit API Production Deployment Security Contract]" in text
        assert "(linux_audit_api_deployment_security.md)" in text

    security_text = SECURITY_DESIGN.read_text(encoding="utf-8")
    api_text = API_DESIGN.read_text(encoding="utf-8")
    assert "design-only" in security_text
    assert "proxy, bootstrap, secret loader" in api_text


def test_document_has_no_secret_canary_raw_fixture_or_real_local_path():
    text = document_text()

    assert KNOWN_CANARIES.isdisjoint(text.split())
    assert "type=SYSCALL msg=audit(" not in text
    assert "type=USER_START msg=audit(" not in text
    assert "/Users/" not in text
    assert "/home/" not in text
    assert "password=" not in text.casefold()
    assert "authorization: bearer" not in text.casefold()

    likely_literal_secrets = re.findall(
        r"(?<![A-Za-z0-9_/-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_/-])",
        text,
    )
    assert likely_literal_secrets == []
