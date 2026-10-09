from pathlib import Path
import re

from app.api import app
from app.api_uploads import (
    LINUX_AUDIT_MAX_FILE_COUNT,
    LINUX_AUDIT_MAX_FILE_SIZE_BYTES,
    LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES,
)
from app.deployment.asgi import (
    CREDENTIALS_DIRECTORY_ENVIRONMENT_VARIABLE,
    LINUX_AUDIT_API_CREDENTIAL_FILENAME,
    MAX_CONCURRENT_ANALYSES_ENVIRONMENT_VARIABLE,
    PRINCIPAL_ID_ENVIRONMENT_VARIABLE,
)


SYSTEMD_UNIT = Path(
    "deploy/systemd/ai-security-log-analyzer.service"
)
NGINX_CONFIG = Path(
    "deploy/nginx/ai-security-log-analyzer.conf"
)
API_PATH = "/api/analyze-linux-audit"
READINESS_PATH = "/internal/readiness"


def _utf8_text(path: Path) -> str:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    assert text.encode("utf-8") == raw
    assert raw.endswith(b"\n")
    return text


def _directive_values(text: str, name: str) -> list[str]:
    prefix = f"{name}="
    return [
        line[len(prefix) :]
        for line in text.splitlines()
        if line.startswith(prefix)
    ]


def _location_block(text: str, location: str) -> str:
    start = text.index(f"location {location} {{")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError("unterminated location block")


def test_reference_artifacts_are_utf8_fixed_files():
    assert SYSTEMD_UNIT.is_file()
    assert NGINX_CONFIG.is_file()
    _utf8_text(SYSTEMD_UNIT)
    _utf8_text(NGINX_CONFIG)


def test_systemd_unit_uses_exact_factory_on_loopback_with_one_worker():
    text = _utf8_text(SYSTEMD_UNIT)
    exec_start = _directive_values(text, "ExecStart")

    assert exec_start == [
        "/opt/ai-security-log-analyzer/.venv/bin/uvicorn "
        "app.deployment.asgi:create_linux_audit_api_app --factory "
        "--host 127.0.0.1 --port 8000 --workers 1 --proxy-headers "
        "--forwarded-allow-ips 127.0.0.1 --lifespan on "
        "--limit-concurrency 16 --timeout-keep-alive 15 "
        "--timeout-graceful-shutdown 60 --no-access-log"
    ]
    assert "--reload" not in text
    assert "--forwarded-allow-ips *" not in text
    assert "0.0.0.0" not in text
    assert "ExecStart=/bin/" not in text
    assert "sh -c" not in text


def test_systemd_unit_has_dedicated_identity_and_bounded_service_policy():
    text = _utf8_text(SYSTEMD_UNIT)

    for section in ("[Unit]", "[Service]", "[Install]"):
        assert section in text
    for contract in (
        "User=ai-security-log-analyzer",
        "Group=ai-security-log-analyzer",
        "WorkingDirectory=/opt/ai-security-log-analyzer",
        "Type=exec",
        "UMask=0077",
        "Restart=on-failure",
        "RestartSec=10s",
        "StartLimitIntervalSec=300",
        "StartLimitBurst=3",
        "TimeoutStartSec=30s",
        "TimeoutStopSec=75s",
        "KillSignal=SIGTERM",
        "StandardOutput=journal",
        "StandardError=journal",
    ):
        assert contract in text


def test_systemd_unit_uses_only_reviewed_compatible_hardening():
    text = _utf8_text(SYSTEMD_UNIT)

    for directive in (
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX AF_INET",
        "SystemCallArchitectures=native",
    ):
        assert directive in text
    assert "PrivateNetwork=" not in text
    assert "MemoryMax=" not in text
    assert "TasksMax=" not in text


def test_systemd_credential_and_environment_match_application_contracts():
    text = _utf8_text(SYSTEMD_UNIT)
    load_credential = _directive_values(text, "LoadCredential")
    environment = _directive_values(text, "Environment")

    assert load_credential == [
        f"{LINUX_AUDIT_API_CREDENTIAL_FILENAME}:"
        "/etc/ai-security-log-analyzer/"
        f"{LINUX_AUDIT_API_CREDENTIAL_FILENAME}"
    ]
    assert environment == [
        f"{PRINCIPAL_ID_ENVIRONMENT_VARIABLE}=reference-operator",
        f"{MAX_CONCURRENT_ANALYSES_ENVIRONMENT_VARIABLE}=1",
    ]
    assert CREDENTIALS_DIRECTORY_ENVIRONMENT_VARIABLE not in text
    assert "TOKEN=" not in text
    assert "BEARER=" not in text
    assert "EnvironmentFile=" not in text


def test_nginx_public_listener_is_tls_only_with_reserved_name():
    text = _utf8_text(NGINX_CONFIG)

    assert "listen 443 ssl default_server;" in text
    assert "listen 443 ssl;" in text
    assert not re.search(r"\blisten\s+80\b", text)
    assert "server_name linux-audit-api.example.invalid;" in text
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in text
    assert "ssl_reject_handshake on;" in text
    assert "server_tokens off;" in text
    assert "fullchain.pem" in text
    assert "privkey.pem" in text


def test_nginx_resource_limits_are_exact_and_non_queueing():
    text = _utf8_text(NGINX_CONFIG)
    protected = _location_block(text, f"= {API_PATH}")

    for directive in (
        "client_max_body_size 24m;",
        "client_body_buffer_size 128k;",
        "client_header_buffer_size 1k;",
        "large_client_header_buffers 2 8k;",
        "client_header_timeout 10s;",
        "client_body_timeout 15s;",
        "keepalive_timeout 15s;",
        "keepalive_requests 100;",
        "limit_req_zone $server_name zone=linux_audit_rate:1m rate=6r/m;",
        "limit_conn_zone $server_name zone=linux_audit_connections:1m;",
        "limit_req_status 429;",
        "limit_conn_status 429;",
        "proxy_connect_timeout 2s;",
        "proxy_send_timeout 30s;",
        "proxy_read_timeout 120s;",
    ):
        assert directive in text
    assert "limit_req zone=linux_audit_rate burst=2 nodelay;" in protected
    assert "limit_conn linux_audit_connections 4;" in protected
    assert "proxy_request_buffering on;" in protected
    assert "proxy_buffering on;" in protected
    assert "proxy_cache off;" in protected
    assert "Retry-After" not in text


def test_nginx_proxies_only_the_exact_post_analysis_route():
    text = _utf8_text(NGINX_CONFIG)
    protected = _location_block(text, f"= {API_PATH}")
    fallback = _location_block(text, "/")

    assert text.count("proxy_pass ") == 1
    assert "if ($request_method != POST)" in protected
    assert "return 405;" in protected
    assert "proxy_pass http://127.0.0.1:8000;" in protected
    assert "return 404" in fallback
    for forbidden in (
        "/api/analyze {",
        "/api/health {",
        f"{READINESS_PATH} {{",
        "/docs {",
        "/openapi.json {",
    ):
        assert forbidden not in text


def test_nginx_overwrites_forwarded_headers_and_preserves_bearer_header():
    text = _utf8_text(NGINX_CONFIG)
    protected = _location_block(text, f"= {API_PATH}")

    for directive in (
        "proxy_set_header Host linux-audit-api.example.invalid;",
        "proxy_set_header Authorization $http_authorization;",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Forwarded-Proto https;",
        "proxy_set_header X-Forwarded-Host linux-audit-api.example.invalid;",
        "proxy_set_header X-Forwarded-Port 443;",
        'proxy_set_header Forwarded "";',
        'proxy_set_header X-Real-IP "";',
    ):
        assert directive in protected
    assert "$proxy_add_x_forwarded_for" not in text
    assert "proxy_set_header X-Forwarded-For *" not in text


def test_nginx_access_log_excludes_credentials_queries_and_bodies():
    text = _utf8_text(NGINX_CONFIG)
    log_format = text.split("log_format linux_audit_access", 1)[1].split(
        ";", 1
    )[0]

    assert "$uri" in log_format
    for forbidden in (
        "$request_uri",
        "$args",
        "$http_authorization",
        "$request_body",
        "$http_cookie",
    ):
        assert forbidden not in log_format
    assert 'add_header Cache-Control "no-store" always;' in text


def test_nginx_edge_errors_are_fixed_bounded_json():
    text = _utf8_text(NGINX_CONFIG)

    assert "error_page 413 = @edge_body_too_large;" in text
    assert "error_page 429 = @edge_rate_limited;" in text
    assert "EDGE_REQUEST_BODY_TOO_LARGE" in text
    assert "EDGE_REQUEST_RATE_LIMITED" in text
    assert "METHOD_NOT_ALLOWED" in text
    assert "NOT_FOUND" in text
    assert "default_type application/json;" in text


def test_cross_layer_limits_routes_and_capacity_are_consistent():
    systemd = _utf8_text(SYSTEMD_UNIT)
    nginx = _utf8_text(NGINX_CONFIG)

    assert 24 * 1024 * 1024 > LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES
    assert LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES == 20 * 1024 * 1024
    assert LINUX_AUDIT_MAX_FILE_SIZE_BYTES == 10 * 1024 * 1024
    assert LINUX_AUDIT_MAX_FILE_COUNT == 4
    assert f"location = {API_PATH} {{" in nginx
    assert READINESS_PATH not in nginx
    assert "--workers 1" in systemd
    assert f"{MAX_CONCURRENT_ANALYSES_ENVIRONMENT_VARIABLE}=1" in systemd
    assert "limit_conn linux_audit_connections 4;" in nginx


def test_default_application_routes_and_openapi_remain_unchanged():
    route_paths = {
        route.path for route in app.routes if route.path.startswith("/api/")
    }
    schema = app.openapi()

    assert route_paths == {
        "/api/health", "/api/analyze", "/api/v1/investigations/sample", "/api/v1/investigations"
    }
    assert set(schema["paths"]) == route_paths
    assert API_PATH not in schema["paths"]
    assert READINESS_PATH not in schema["paths"]


def test_reference_artifacts_contain_no_literal_secret_or_private_evidence():
    combined = _utf8_text(SYSTEMD_UNIT) + _utf8_text(NGINX_CONFIG)

    assert "Authorization: Bearer" not in combined
    assert "/Users/" not in combined
    assert "/home/" not in combined
    assert "type=SYSCALL msg=audit(" not in combined
    assert "PROCTITLE=" not in combined
    assert "SYNTHETIC_" not in combined
    assert not re.search(
        r"(?<![A-Za-z0-9_/-])[A-Za-z0-9_-]{43}"
        r"(?![A-Za-z0-9_/-])",
        combined,
    )
