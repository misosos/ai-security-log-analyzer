import asyncio
import base64
from collections.abc import Mapping
import inspect
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.api as api_module
import app.deployment.asgi as asgi_module
import app.deployment.linux_audit_api as deployment_module
import app.security.linux_audit_api_journald as journald_module
from app.deployment.asgi import (
    LinuxAuditApiDeploymentError,
    _parse_linux_audit_api_deployment_environment,
    create_linux_audit_api_app,
)
from app.deployment.linux_audit_api import (
    LinuxAuditApiProductionBootstrapError,
    LinuxAuditApiReadiness,
    get_linux_audit_api_readiness,
)
from app.security.linux_audit_api import LinuxAuditApiSecurityConfig


TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
CREDENTIAL_FILENAME = "linux-audit-api-operator-token"
READINESS_PATH = "/internal/readiness"
PRIVATE_CANARY = "PRIVATE_DEPLOYMENT_ENTRYPOINT_DO_NOT_EXPOSE"


class RecordingTransport(journald_module._JournaldTransport):
    def __init__(self):
        self.close_calls = 0

    def submit(self, _fields):
        return None

    def close(self):
        self.close_calls += 1


class TrackingEnvironment(Mapping):
    def __init__(self, values):
        self._values = dict(values)
        self.requested = []

    def __getitem__(self, key):
        raise AssertionError("environment must be read with explicit get")

    def __iter__(self):
        raise AssertionError("environment must not be enumerated")

    def __len__(self):
        raise AssertionError("environment size must not be inspected")

    def get(self, key, default=None):
        self.requested.append(key)
        return self._values.get(key, default)


def deployment_environment(directory, **changes):
    values = {
        "CREDENTIALS_DIRECTORY": str(directory),
        "LINUX_AUDIT_API_PRINCIPAL_ID": "production-operator",
        "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES": "1",
    }
    values.update(changes)
    return values


def write_secret(directory):
    directory.mkdir(mode=0o700)
    path = directory / CREDENTIAL_FILENAME
    path.write_text(TOKEN, encoding="ascii")
    path.chmod(0o400)
    return path


def patch_sink_factory(monkeypatch):
    transport = RecordingTransport()
    sink = journald_module._create_linux_audit_api_journald_sink_for_transport(
        transport
    )
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink,
    )
    return transport


def assert_deployment_error(call, code):
    with pytest.raises(LinuxAuditApiDeploymentError) as captured:
        call()
    assert captured.value.code == code
    assert captured.value.message == str(captured.value)
    return captured.value


def readiness_endpoint(application):
    return next(
        route.endpoint
        for route in application.routes
        if getattr(route, "path", None) == READINESS_PATH
    )


def test_import_and_reload_have_no_factory_side_effects():
    code = (
        "import importlib, sys\n"
        "import app.deployment.asgi as module\n"
        "importlib.reload(module)\n"
        "assert not hasattr(module, 'app')\n"
        "assert 'app.api' not in sys.modules\n"
        "assert 'app.deployment.linux_audit_api' not in sys.modules\n"
        "try:\n"
        "    module.create_linux_audit_api_app()\n"
        "except module.LinuxAuditApiDeploymentError:\n"
        "    pass\n"
        "else:\n"
        "    raise AssertionError('missing config was accepted')\n"
        "assert 'app.api' not in sys.modules\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path.cwd(),
        env={"PYTHONPATH": str(Path.cwd())},
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


def test_environment_parser_reads_only_three_allowlisted_values(tmp_path):
    values = deployment_environment(tmp_path)
    values.update(
        {
            "LINUX_AUDIT_API_TOKEN": PRIVATE_CANARY,
            "LINUX_AUDIT_API_CREDENTIAL_FILENAME": "overridden",
            "AUTHORIZATION": PRIVATE_CANARY,
            "UNRELATED": PRIVATE_CANARY,
        }
    )
    environment = TrackingEnvironment(values)

    config = _parse_linux_audit_api_deployment_environment(environment)

    assert environment.requested == [
        "CREDENTIALS_DIRECTORY",
        "LINUX_AUDIT_API_PRINCIPAL_ID",
        "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES",
    ]
    assert config.secret_file == tmp_path / CREDENTIAL_FILENAME
    assert config.principal_id == "production-operator"
    assert config.max_concurrent_analyses == 1
    assert values["LINUX_AUDIT_API_TOKEN"] == PRIVATE_CANARY


@pytest.mark.parametrize(
    "missing",
    (
        "CREDENTIALS_DIRECTORY",
        "LINUX_AUDIT_API_PRINCIPAL_ID",
        "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES",
    ),
)
def test_each_required_environment_value_must_be_present(tmp_path, missing):
    values = deployment_environment(tmp_path)
    del values[missing]

    assert_deployment_error(
        lambda: _parse_linux_audit_api_deployment_environment(values),
        "MISSING_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION",
    )


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("CREDENTIALS_DIRECTORY", ""),
        ("LINUX_AUDIT_API_PRINCIPAL_ID", ""),
        ("LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES", ""),
        ("CREDENTIALS_DIRECTORY", None),
        ("LINUX_AUDIT_API_PRINCIPAL_ID", 1),
        ("LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES", 1),
    ),
)
def test_environment_values_require_exact_nonempty_strings(
    tmp_path,
    name,
    value,
):
    values = deployment_environment(tmp_path)
    values[name] = value
    expected = (
        "MISSING_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        if value is None
        else "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
    )

    assert_deployment_error(
        lambda: _parse_linux_audit_api_deployment_environment(values),
        expected,
    )


@pytest.mark.parametrize(
    "value",
    (
        "relative",
        "~/credentials",
        " /private/credentials",
        "/private/credentials ",
        "/private/cred\nentials",
        "/private/cred\rentials",
        "/private/cred\x00entials",
    ),
)
def test_credentials_directory_requires_strict_absolute_value(value):
    values = deployment_environment(Path("/private/credentials"))
    values["CREDENTIALS_DIRECTORY"] = value

    assert_deployment_error(
        lambda: _parse_linux_audit_api_deployment_environment(values),
        "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION",
    )


@pytest.mark.parametrize(
    "value",
    (
        "/private/first:/private/second",
        "/private/$CREDENTIALS",
        "/private/cred*",
    ),
)
def test_path_list_shell_and_glob_syntax_is_kept_literal(value):
    values = deployment_environment(Path("/private/credentials"))
    values["CREDENTIALS_DIRECTORY"] = value

    config = _parse_linux_audit_api_deployment_environment(values)

    assert config.secret_file == Path(value) / CREDENTIAL_FILENAME


@pytest.mark.parametrize("value", ("1", "2", "3", "4"))
def test_canonical_concurrency_values_are_accepted(tmp_path, value):
    values = deployment_environment(
        tmp_path,
        LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES=value,
    )

    config = _parse_linux_audit_api_deployment_environment(values)

    assert config.max_concurrent_analyses == int(value)


@pytest.mark.parametrize(
    "value",
    (
        "0",
        "5",
        "-1",
        "+1",
        "01",
        "1.0",
        "1e0",
        "true",
        "False",
        "١",
        "１",
        " 1",
        "1 ",
    ),
)
def test_noncanonical_concurrency_values_are_rejected(tmp_path, value):
    values = deployment_environment(
        tmp_path,
        LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES=value,
    )

    assert_deployment_error(
        lambda: _parse_linux_audit_api_deployment_environment(values),
        "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION",
    )


def test_parser_rejects_non_mapping_without_repr_leakage():
    error = assert_deployment_error(
        lambda: _parse_linux_audit_api_deployment_environment(
            PRIVATE_CANARY
        ),
        "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION",
    )

    assert PRIVATE_CANARY not in str(error)
    assert PRIVATE_CANARY not in repr(error)


def test_public_factory_is_zero_argument_and_delegates_exactly_once(
    tmp_path,
    monkeypatch,
):
    values = deployment_environment(tmp_path)
    expected = FastAPI()
    calls = []
    monkeypatch.setattr(asgi_module.os, "environ", values)

    def construct(config):
        calls.append(config)
        return expected

    monkeypatch.setattr(
        asgi_module,
        "_construct_linux_audit_api_production_app",
        construct,
    )

    result = create_linux_audit_api_app()

    assert tuple(inspect.signature(create_linux_audit_api_app).parameters) == ()
    assert result is expected
    assert len(calls) == 1
    assert calls[0].secret_file == tmp_path / CREDENTIAL_FILENAME


def test_repeated_factory_calls_reread_environment_and_are_isolated(
    tmp_path,
    monkeypatch,
):
    values = deployment_environment(tmp_path)
    applications = [FastAPI(), FastAPI()]
    calls = []
    monkeypatch.setattr(asgi_module.os, "environ", values)
    monkeypatch.setattr(
        asgi_module,
        "_construct_linux_audit_api_production_app",
        lambda config: calls.append(config) or applications[len(calls) - 1],
    )

    first = create_linux_audit_api_app()
    values["LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES"] = "2"
    second = create_linux_audit_api_app()

    assert first is applications[0]
    assert second is applications[1]
    assert [item.max_concurrent_analyses for item in calls] == [1, 2]


def test_production_construction_failure_is_bounded_without_fallback(
    tmp_path,
    monkeypatch,
    capsys,
    caplog,
):
    values = deployment_environment(tmp_path)
    monkeypatch.setattr(asgi_module.os, "environ", values)

    def fail(_config):
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        )

    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_production_app",
        fail,
    )

    error = assert_deployment_error(
        create_linux_audit_api_app,
        "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED",
    )

    rendered = f"{error!s} {error!r}"
    assert str(tmp_path) not in rendered
    assert CREDENTIAL_FILENAME not in rendered
    assert "production-operator" not in rendered
    assert PRIVATE_CANARY not in rendered
    assert capsys.readouterr() == ("", "")
    assert caplog.text == ""


@pytest.mark.parametrize("principal", (" invalid", "invalid/value", "é"))
def test_principal_validation_is_delegated_to_existing_contract(
    tmp_path,
    monkeypatch,
    principal,
):
    credential_directory = tmp_path / "credentials"
    write_secret(credential_directory)
    values = deployment_environment(
        credential_directory,
        LINUX_AUDIT_API_PRINCIPAL_ID=principal,
    )
    sink_calls = []
    monkeypatch.setattr(asgi_module.os, "environ", values)
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink_calls.append(True),
    )

    assert_deployment_error(
        create_linux_audit_api_app,
        "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED",
    )
    assert sink_calls == []


def test_production_readiness_route_lifecycle_and_openapi_isolation(
    tmp_path,
    monkeypatch,
):
    credential_directory = tmp_path / "credentials"
    write_secret(credential_directory)
    transport = patch_sink_factory(monkeypatch)
    monkeypatch.setattr(
        asgi_module.os,
        "environ",
        deployment_environment(credential_directory),
    )

    application = create_linux_audit_api_app()

    assert READINESS_PATH not in application.openapi()["paths"]
    assert READINESS_PATH not in api_module.app.openapi()["paths"]
    assert READINESS_PATH not in api_module.create_app().openapi()["paths"]
    initial = asyncio.run(readiness_endpoint(application)())
    assert initial.status_code == 503
    assert initial.body == b'{"status":"not_ready"}'
    assert initial.headers["cache-control"] == "no-store"
    assert get_linux_audit_api_readiness(application).phase == "starting"
    assert transport.close_calls == 0

    with TestClient(application) as client:
        ready = client.get(READINESS_PATH)
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}
        assert ready.headers["cache-control"] == "no-store"
        for method in (client.post, client.put, client.delete):
            assert method(READINESS_PATH).status_code == 405
        assert get_linux_audit_api_readiness(application).ready is True

    stopped = asyncio.run(readiness_endpoint(application)())
    assert stopped.status_code == 503
    assert stopped.body == b'{"status":"not_ready"}'
    assert get_linux_audit_api_readiness(application).phase == "stopped"
    assert transport.close_calls == 1


@pytest.mark.parametrize("phase", ("starting", "stopping", "stopped", "failed"))
def test_every_not_ready_phase_returns_the_same_bounded_503(
    tmp_path,
    monkeypatch,
    phase,
):
    credential_directory = tmp_path / "credentials"
    write_secret(credential_directory)
    transport = patch_sink_factory(monkeypatch)
    monkeypatch.setattr(
        asgi_module.os,
        "environ",
        deployment_environment(credential_directory),
    )
    application = create_linux_audit_api_app()
    endpoint = readiness_endpoint(application)
    monkeypatch.setattr(
        deployment_module,
        "get_linux_audit_api_readiness",
        lambda _application: LinuxAuditApiReadiness(
            phase=phase,
            ready=False,
        ),
    )

    response = asyncio.run(endpoint())

    assert response.status_code == 503
    assert response.body == b'{"status":"not_ready"}'
    assert response.headers["cache-control"] == "no-store"
    assert transport.close_calls == 0

    async def close_owned_sink():
        manager = application.router.lifespan_context(application)
        await manager.__aenter__()
        await manager.__aexit__(None, None, None)

    asyncio.run(close_owned_sink())
    assert transport.close_calls == 1


def test_separate_production_apps_have_isolated_readiness(
    tmp_path,
    monkeypatch,
):
    credential_directory = tmp_path / "credentials"
    write_secret(credential_directory)
    transports = [RecordingTransport(), RecordingTransport()]
    sinks = [
        journald_module._create_linux_audit_api_journald_sink_for_transport(
            transport
        )
        for transport in transports
    ]
    iterator = iter(sinks)
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: next(iterator),
    )
    monkeypatch.setattr(
        asgi_module.os,
        "environ",
        deployment_environment(credential_directory),
    )
    first = create_linux_audit_api_app()
    second = create_linux_audit_api_app()

    async def scenario():
        first_lifespan = first.router.lifespan_context(first)
        second_lifespan = second.router.lifespan_context(second)
        await first_lifespan.__aenter__()
        assert (await readiness_endpoint(first)()).status_code == 200
        assert (await readiness_endpoint(second)()).status_code == 503
        await second_lifespan.__aenter__()
        await first_lifespan.__aexit__(None, None, None)
        assert (await readiness_endpoint(first)()).status_code == 503
        assert (await readiness_endpoint(second)()).status_code == 200
        await second_lifespan.__aexit__(None, None, None)

    asyncio.run(scenario())

    assert [transport.close_calls for transport in transports] == [1, 1]


def test_default_app_and_direct_enabled_app_do_not_gain_readiness_route():
    assert READINESS_PATH not in api_module.app.openapi()["paths"]
    sink = journald_module._create_linux_audit_api_journald_sink_for_transport(
        RecordingTransport()
    )
    security = LinuxAuditApiSecurityConfig(
        operator_token=SecretStr(TOKEN),
        principal_id="direct-operator",
        max_concurrent_analyses=1,
    )
    for direct in (
        api_module.create_app(),
        api_module.create_app(
            enable_linux_audit_api=True,
            linux_audit_api_security=security,
            linux_audit_api_audit_sink=sink,
        ),
    ):
        assert all(
            getattr(route, "path", None) != READINESS_PATH
            for route in direct.routes
        )


def test_error_contract_does_not_copy_unknown_code_or_private_values():
    error = LinuxAuditApiDeploymentError(PRIVATE_CANARY)

    assert error.code == "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED"
    assert PRIVATE_CANARY not in str(error)
    assert PRIVATE_CANARY not in repr(error)
