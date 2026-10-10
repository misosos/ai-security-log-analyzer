import base64
from dataclasses import FrozenInstanceError, fields
import json
from pathlib import Path
import traceback

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.api as api_module
import app.security.linux_audit_api as security_module
from app.security.linux_audit_api import (
    LINUX_AUDIT_ANALYZE_PERMISSION,
    AuthenticatedLinuxAuditPrincipal,
    LinuxAuditApiAuthenticationError,
    LinuxAuditApiAccessAuditSink,
    LinuxAuditApiAuthorizationError,
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
    PreparedLinuxAuditApiSecurity,
    authenticate_linux_audit_token,
    authorize_linux_audit_analysis,
    prepare_linux_audit_api_security,
)


ENDPOINT = "/api/analyze-linux-audit"
FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
TOKEN_BYTES = bytes(range(32))
OTHER_TOKEN_BYTES = bytes(reversed(range(32)))
OPERATOR_TOKEN = base64.urlsafe_b64encode(TOKEN_BYTES).rstrip(
    b"="
).decode("ascii")
OTHER_TOKEN = base64.urlsafe_b64encode(OTHER_TOKEN_BYTES).rstrip(
    b"="
).decode("ascii")
AUTH_HEADERS = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


class RecordingAuditSink(LinuxAuditApiAccessAuditSink):
    def __init__(self):
        self.events = []

    async def emit(self, event):
        self.events.append(event)


def valid_config(**changes):
    values = {
        "operator_token": SecretStr(OPERATOR_TOKEN),
        "principal_id": "operator-1",
        "max_concurrent_analyses": 1,
    }
    values.update(changes)
    return LinuxAuditApiSecurityConfig(**values)


def secured_app():
    return api_module.create_app(
        enable_linux_audit_api=True,
        linux_audit_api_security=valid_config(),
        linux_audit_api_audit_sink=RecordingAuditSink(),
    )


def fixture_files():
    return {
        "linux_audit_files": (
            "input.audit",
            FIXTURE.read_bytes(),
            "text/plain",
        )
    }


def assert_auth_error(response, *, status, code, message):
    assert response.status_code == status
    assert response.json() == {
        "error": {"code": code, "message": message}
    }
    assert "detail" not in response.json()


def test_security_config_is_frozen_exact_and_has_a_safe_repr():
    config = valid_config()

    assert type(config) is LinuxAuditApiSecurityConfig
    assert tuple(item.name for item in fields(config)) == (
        "operator_token",
        "principal_id",
        "max_concurrent_analyses",
    )
    assert OPERATOR_TOKEN not in repr(config)
    assert "operator_token" not in repr(config)
    with pytest.raises(FrozenInstanceError):
        config.principal_id = "changed"


def test_valid_config_prepares_digest_only_and_exact_permission():
    config = valid_config(max_concurrent_analyses=4)
    prepared = prepare_linux_audit_api_security(config)

    assert type(prepared) is PreparedLinuxAuditApiSecurity
    assert prepared.principal_id == "operator-1"
    assert prepared.max_concurrent_analyses == 4
    assert prepared.permissions == frozenset((
        LINUX_AUDIT_ANALYZE_PERMISSION,
    ))
    assert type(prepared.permissions) is frozenset
    assert type(prepared._operator_token_digest) is bytes
    assert len(prepared._operator_token_digest) == 32
    assert OPERATOR_TOKEN not in repr(prepared)
    assert prepared._operator_token_digest.hex() not in repr(prepared)
    assert "_operator_token_digest" not in repr(prepared)
    assert config.operator_token.get_secret_value() == OPERATOR_TOKEN


def test_prepare_requires_exact_config_and_secret_carrier_types():
    class ConfigSubclass(LinuxAuditApiSecurityConfig):
        pass

    for invalid in (
        object(),
        ConfigSubclass(
            SecretStr(OPERATOR_TOKEN),
            "operator-1",
            1,
        ),
        LinuxAuditApiSecurityConfig(
            OPERATOR_TOKEN,
            "operator-1",
            1,
        ),
    ):
        with pytest.raises(LinuxAuditApiSecurityConfigurationError):
            prepare_linux_audit_api_security(invalid)


def test_token_validation_accepts_only_canonical_32_byte_base64url():
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    final_index = alphabet.index(OPERATOR_TOKEN[-1])
    noncanonical = OPERATOR_TOKEN[:-1] + alphabet[final_index ^ 1]
    assert base64.urlsafe_b64decode(noncanonical + "=") == TOKEN_BYTES

    invalid_tokens = (
        "",
        " ",
        OPERATOR_TOKEN[:-1],
        OPERATOR_TOKEN + "A",
        OPERATOR_TOKEN + "=",
        "!" + OPERATOR_TOKEN[1:],
        "é" + OPERATOR_TOKEN[1:],
        "\x00" + OPERATOR_TOKEN[1:],
        noncanonical,
    )
    for token in invalid_tokens:
        config = valid_config(operator_token=SecretStr(token))
        with pytest.raises(LinuxAuditApiSecurityConfigurationError) as caught:
            prepare_linux_audit_api_security(config)
        if len(token) >= 8:
            assert token not in str(caught.value)
            assert token not in repr(caught.value)


@pytest.mark.parametrize(
    "principal_id",
    ("A", "operator-1", "a" * 64, "A.b_c-9"),
)
def test_principal_allowlist_accepts_bounded_ascii(principal_id):
    prepared = prepare_linux_audit_api_security(
        valid_config(principal_id=principal_id)
    )
    assert prepared.principal_id == principal_id


@pytest.mark.parametrize(
    "principal_id",
    ("", ".operator", "_operator", "-operator", "a" * 65, "a b", "é"),
)
def test_principal_allowlist_rejects_invalid_values(principal_id):
    with pytest.raises(LinuxAuditApiSecurityConfigurationError):
        prepare_linux_audit_api_security(
            valid_config(principal_id=principal_id)
        )


@pytest.mark.parametrize("limit", (1, 4))
def test_concurrency_boundary_is_validated_for_limiter_enforcement(limit):
    prepared = prepare_linux_audit_api_security(
        valid_config(max_concurrent_analyses=limit)
    )
    assert prepared.max_concurrent_analyses == limit


@pytest.mark.parametrize("limit", (0, 5, -1, True, False, "1", 1.0))
def test_invalid_concurrency_values_are_rejected(limit):
    with pytest.raises(LinuxAuditApiSecurityConfigurationError):
        prepare_linux_audit_api_security(
            valid_config(max_concurrent_analyses=limit)
        )


def test_factory_is_fail_closed_and_keeps_the_default_app_disabled():
    assert set(api_module.app.openapi()["paths"]) == {
        "/api/health",
        "/api/analyze",
        "/api/v1/investigations/sample",
        "/api/v1/investigations",
        "/api/v1/investigations/linux-audit",
    }
    assert "securitySchemes" not in api_module.app.openapi().get(
        "components", {}
    )

    for create in (
        lambda: api_module.create_app(enable_linux_audit_api=True),
        lambda: api_module.create_app(
            linux_audit_api_security=valid_config()
        ),
        lambda: api_module.create_app(
            enable_linux_audit_api=True,
            linux_audit_api_security=object(),
        ),
    ):
        with pytest.raises(LinuxAuditApiSecurityConfigurationError) as caught:
            create()
        assert str(caught.value) == (
            "Linux Audit API security configuration is invalid."
        )


def test_factory_instances_are_isolated_and_enabled_openapi_is_secured():
    first = secured_app()
    second = secured_app()
    disabled = api_module.create_app()

    for configured in (first, second):
        schema = configured.openapi()
        operation = schema["paths"][ENDPOINT]["post"]
        assert operation["security"] == [
            {"LinuxAuditOperatorBearer": []}
        ]
        assert set(schema["components"]["securitySchemes"]) == {
            "LinuxAuditOperatorBearer"
        }
        serialized = json.dumps(schema, sort_keys=True)
        assert OPERATOR_TOKEN not in serialized
        assert "operator-1" not in serialized
        assert "digest" not in serialized.casefold()

    assert first is not second
    assert first.router is not second.router
    assert ENDPOINT not in disabled.openapi()["paths"]
    assert "securitySchemes" not in disabled.openapi().get("components", {})


@pytest.mark.parametrize(
    "headers",
    (
        None,
        {"Authorization": f"Basic {OPERATOR_TOKEN}"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer malformed"},
        {"Authorization": f"Bearer {OTHER_TOKEN}"},
        {"Authorization": f" Bearer {OPERATOR_TOKEN}"},
        {"Authorization": f"Bearer  {OPERATOR_TOKEN}"},
        {"Authorization": f"Bearer {OPERATOR_TOKEN} "},
        {"Authorization": "Bearer " + "A" * 300},
    ),
)
def test_authentication_failures_have_one_fixed_401_contract(headers):
    response = TestClient(secured_app()).post(
        ENDPOINT,
        headers=headers,
    )

    assert_auth_error(
        response,
        status=401,
        code="LINUX_AUDIT_AUTHENTICATION_REQUIRED",
        message="Authentication is required.",
    )
    assert response.headers["www-authenticate"] == "Bearer"
    outputs = (response.text, repr(response.headers))
    for secret in (OPERATOR_TOKEN, OTHER_TOKEN):
        assert all(secret not in output for output in outputs)


def test_duplicate_authorization_headers_are_rejected():
    response = TestClient(secured_app()).post(
        ENDPOINT,
        headers=[
            ("Authorization", f"Bearer {OPERATOR_TOKEN}"),
            ("Authorization", f"Bearer {OPERATOR_TOKEN}"),
        ],
    )

    assert_auth_error(
        response,
        status=401,
        code="LINUX_AUDIT_AUTHENTICATION_REQUIRED",
        message="Authentication is required.",
    )


def test_valid_bearer_reaches_existing_validation_and_fixture_success():
    client = TestClient(secured_app(), headers=AUTH_HEADERS)
    missing_file = client.post(ENDPOINT)
    assert missing_file.status_code == 422
    assert missing_file.json()["error"]["code"] == (
        "MISSING_LINUX_AUDIT_FILES"
    )

    success = client.post(ENDPOINT, files=fixture_files())
    assert success.status_code == 200
    assert success.json()["status"] == "completed"
    assert success.json()["process_telemetry"]["observation_count"] == 4
    serialized = success.text
    assert OPERATOR_TOKEN not in serialized
    assert "operator-1" not in serialized
    assert "permissions" not in serialized


def test_unauthenticated_request_never_invokes_handler_layers_or_uuid(
    monkeypatch,
):
    calls = []

    def fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("unauthenticated request reached handler layer")

    monkeypatch.setattr(api_module, "stage_linux_audit_uploads", fail)
    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        fail,
    )
    monkeypatch.setattr(
        api_module,
        "build_linux_audit_api_response",
        fail,
    )
    monkeypatch.setattr(api_module.uuid, "uuid4", fail)

    response = TestClient(secured_app()).post(
        ENDPOINT,
        files=fixture_files(),
    )
    assert response.status_code == 401
    assert calls == []


def test_authorization_is_separate_exact_and_has_a_fixed_403(monkeypatch):
    allowed = AuthenticatedLinuxAuditPrincipal(
        principal_id="operator-1",
        permissions=frozenset((LINUX_AUDIT_ANALYZE_PERMISSION,)),
    )
    assert authorize_linux_audit_analysis(allowed) is allowed

    for permissions in (frozenset(), frozenset(("*",)), frozenset((
        "linux-audit:detail",
    ))):
        with pytest.raises(LinuxAuditApiAuthorizationError):
            authorize_linux_audit_analysis(
                AuthenticatedLinuxAuditPrincipal(
                    principal_id="operator-1",
                    permissions=permissions,
                )
            )

    def deny(principal):
        raise LinuxAuditApiAuthorizationError()

    monkeypatch.setattr(
        security_module,
        "authorize_linux_audit_analysis",
        deny,
    )
    response = TestClient(secured_app(), headers=AUTH_HEADERS).post(
        ENDPOINT,
        files=fixture_files(),
    )
    assert_auth_error(
        response,
        status=403,
        code="LINUX_AUDIT_ACCESS_DENIED",
        message="Access is denied.",
    )
    assert "www-authenticate" not in response.headers
    assert "operator-1" not in response.text


def test_startup_and_request_hash_once_and_compare_fixed_digests(monkeypatch):
    original_sha256 = security_module.hashlib.sha256
    original_compare = security_module.secrets.compare_digest
    hashed_inputs = []
    compared = []

    def track_sha256(value):
        hashed_inputs.append(value)
        return original_sha256(value)

    def track_compare(first, second):
        compared.append((first, second))
        return original_compare(first, second)

    monkeypatch.setattr(security_module.hashlib, "sha256", track_sha256)
    monkeypatch.setattr(
        security_module.secrets,
        "compare_digest",
        track_compare,
    )
    configured = secured_app()
    assert hashed_inputs == [TOKEN_BYTES]

    response = TestClient(configured, headers=AUTH_HEADERS).post(ENDPOINT)
    assert response.status_code == 422
    assert hashed_inputs == [TOKEN_BYTES, TOKEN_BYTES]
    assert len(compared) == 1
    assert all(type(value) is bytes and len(value) == 32 for value in compared[0])


def test_direct_authentication_does_not_compare_raw_strings(monkeypatch):
    prepared = prepare_linux_audit_api_security(valid_config())
    compared = []
    original_compare = security_module.secrets.compare_digest

    def track(first, second):
        compared.append((first, second))
        return original_compare(first, second)

    monkeypatch.setattr(security_module.secrets, "compare_digest", track)
    principal = authenticate_linux_audit_token(prepared, OPERATOR_TOKEN)

    assert principal == AuthenticatedLinuxAuditPrincipal(
        principal_id="operator-1",
        permissions=frozenset((LINUX_AUDIT_ANALYZE_PERMISSION,)),
    )
    assert OPERATOR_TOKEN not in repr(principal)
    assert compared and all(
        type(value) is bytes
        for pair in compared
        for value in pair
    )


def test_secret_is_absent_from_startup_error_traceback_and_logs(caplog):
    invalid_token = OPERATOR_TOKEN + "="
    config = valid_config(operator_token=SecretStr(invalid_token))

    try:
        api_module.create_app(
            enable_linux_audit_api=True,
            linux_audit_api_security=config,
        )
    except LinuxAuditApiSecurityConfigurationError as error:
        outputs = (
            str(error),
            repr(error),
            traceback.format_exc(),
            caplog.text,
            repr(config),
        )
    else:
        raise AssertionError("invalid security config was accepted")

    assert all(invalid_token not in output for output in outputs)
    assert all(OPERATOR_TOKEN not in output for output in outputs)


def test_tampered_security_errors_collapse_to_projection_error():
    for error in (
        LinuxAuditApiAuthenticationError(),
        LinuxAuditApiAuthorizationError(),
    ):
        error.message = "private tampered value"
        projected = api_module.project_linux_audit_api_error(error)
        assert projected.status_code == 500
        assert projected.body.error.code == (
            "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
        )
        assert "private" not in projected.body.model_dump_json()
