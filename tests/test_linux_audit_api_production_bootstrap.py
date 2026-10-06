import asyncio
import base64
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api as api_module
import app.deployment.linux_audit_api as deployment_module
import app.security.linux_audit_api_journald as journald_module
from app.deployment.linux_audit_api import (
    LinuxAuditApiProductionBootstrapError,
    LinuxAuditApiProductionConfig,
    LinuxAuditApiReadiness,
    create_linux_audit_api_production_app,
    get_linux_audit_api_readiness,
)


TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"}
ENDPOINT = "/api/analyze-linux-audit"
FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
PRIVATE_CANARY = "PRIVATE_PRODUCTION_BOOTSTRAP_DO_NOT_EXPOSE"


class RecordingTransport(journald_module._JournaldTransport):
    def __init__(self, *, close_error=None):
        self.submissions = []
        self.close_calls = 0
        self.close_error = close_error

    def submit(self, fields):
        self.submissions.append(dict(fields))

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class BlockingCloseTransport(RecordingTransport):
    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()

    def close(self):
        self.close_calls += 1
        self.entered.set()
        try:
            self.release.wait()
        finally:
            self.finished.set()


def write_secret(tmp_path, content=None):
    path = tmp_path / "private-production-credential"
    path.write_bytes(content if content is not None else TOKEN.encode("ascii"))
    path.chmod(0o400)
    return path


def production_config(path, **changes):
    values = {
        "secret_file": path,
        "principal_id": "production-operator",
        "max_concurrent_analyses": 1,
    }
    values.update(changes)
    return LinuxAuditApiProductionConfig(**values)


def create_test_sink(transport=None):
    transport = transport or RecordingTransport()
    sink = journald_module._create_linux_audit_api_journald_sink_for_transport(
        transport
    )
    return sink, transport


def patch_sink_factory(monkeypatch, transport=None):
    sink, transport = create_test_sink(transport)
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink,
    )
    return sink, transport


def assert_bootstrap_error(call, code):
    with pytest.raises(LinuxAuditApiProductionBootstrapError) as captured:
        call()
    assert captured.value.code == code
    assert captured.value.message == str(captured.value)
    return captured.value


def test_production_config_is_frozen_exact_and_has_bounded_repr(tmp_path):
    path = tmp_path / PRIVATE_CANARY
    config = production_config(path, principal_id=PRIVATE_CANARY)

    assert tuple(item.name for item in fields(config)) == (
        "secret_file",
        "principal_id",
        "max_concurrent_analyses",
    )
    assert repr(config) == "LinuxAuditApiProductionConfig()"
    assert str(path) not in repr(config)
    assert path.name not in repr(config)
    assert PRIVATE_CANARY not in repr(config)
    with pytest.raises(FrozenInstanceError):
        config.principal_id = "changed"


def test_factory_requires_exact_config_type_without_side_effects(monkeypatch):
    class ConfigSubclass(LinuxAuditApiProductionConfig):
        pass

    calls = []
    monkeypatch.setattr(
        deployment_module,
        "load_linux_audit_api_security_config",
        lambda _config: calls.append("secret"),
    )
    invalid = ConfigSubclass(Path("/private/secret"), "operator", 1)

    for value in (object(), invalid):
        error = assert_bootstrap_error(
            lambda value=value: create_linux_audit_api_production_app(value),
            "INVALID_LINUX_AUDIT_API_PRODUCTION_CONFIG",
        )
        assert PRIVATE_CANARY not in repr(error)
    assert calls == []


@pytest.mark.parametrize(
    "secret_file",
    (Path("relative-secret"), "/absolute-but-not-a-path"),
)
def test_secret_path_contract_is_delegated_without_sink_creation(
    monkeypatch,
    secret_file,
):
    sink_calls = []
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink_calls.append(True),
    )

    assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(secret_file)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )
    assert sink_calls == []


def test_factory_composes_each_existing_boundary_exactly_once(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    sink, transport = create_test_sink()
    calls = {"secret": 0, "sink": 0, "app": 0}
    original_loader = deployment_module.load_linux_audit_api_security_config
    original_app_factory = deployment_module.create_app

    def load_once(config):
        calls["secret"] += 1
        return original_loader(config)

    def sink_once():
        calls["sink"] += 1
        return sink

    def app_once(**kwargs):
        calls["app"] += 1
        assert kwargs["enable_linux_audit_api"] is True
        assert kwargs["linux_audit_api_audit_sink"] is sink
        return original_app_factory(**kwargs)

    monkeypatch.setattr(
        deployment_module,
        "load_linux_audit_api_security_config",
        load_once,
    )
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        sink_once,
    )
    monkeypatch.setattr(deployment_module, "create_app", app_once)

    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    assert type(application) is FastAPI
    assert calls == {"secret": 1, "sink": 1, "app": 1}
    assert get_linux_audit_api_readiness(application) == (
        LinuxAuditApiReadiness(phase="starting", ready=False)
    )
    assert transport.close_calls == 0


@pytest.mark.parametrize(
    "change",
    (
        {"principal_id": " invalid"},
        {"max_concurrent_analyses": True},
        {"max_concurrent_analyses": 0},
        {"max_concurrent_analyses": 5},
    ),
)
def test_existing_security_validation_is_authoritative(
    tmp_path,
    monkeypatch,
    change,
):
    path = write_secret(tmp_path)
    sink_calls = []
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink_calls.append(True),
    )

    assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(path, **change)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )
    assert sink_calls == []


@pytest.mark.parametrize(
    "content",
    (None, b"malformed", b"\xff" + b"A" * 42),
)
def test_missing_or_malformed_secret_fails_before_sink(
    tmp_path,
    monkeypatch,
    content,
):
    path = tmp_path / "missing-secret"
    if content is not None:
        path = write_secret(tmp_path, content)
    sink_calls = []
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink_calls.append(True),
    )

    error = assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(path)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )

    assert sink_calls == []
    for rendered in (str(error), repr(error)):
        assert str(path) not in rendered
        assert path.name not in rendered
        assert TOKEN not in rendered


def test_unsafe_secret_file_fails_before_sink(tmp_path, monkeypatch):
    directory = tmp_path / "private-credential-directory"
    directory.mkdir(mode=0o700)
    sink_calls = []
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: sink_calls.append(True),
    )

    assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(directory)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )
    assert sink_calls == []


def test_journald_unavailable_fails_without_default_app_fallback(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    app_calls = []

    def unavailable():
        raise journald_module.LinuxAuditApiJournaldSinkError(
            "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED"
        )

    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        unavailable,
    )
    monkeypatch.setattr(
        deployment_module,
        "create_app",
        lambda **_kwargs: app_calls.append(True),
    )

    assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(path)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )
    assert app_calls == []


def test_app_construction_failure_closes_initialized_sink(
    tmp_path,
    monkeypatch,
    capsys,
    caplog,
):
    path = write_secret(tmp_path)
    sink, transport = patch_sink_factory(monkeypatch)

    def fail_app(**_kwargs):
        raise RuntimeError(PRIVATE_CANARY)

    monkeypatch.setattr(deployment_module, "create_app", fail_app)

    error = assert_bootstrap_error(
        lambda: create_linux_audit_api_production_app(
            production_config(path)
        ),
        "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED",
    )

    assert transport.close_calls == 1
    assert PRIVATE_CANARY not in str(error)
    assert PRIVATE_CANARY not in repr(error)
    assert capsys.readouterr() == ("", "")
    assert PRIVATE_CANARY not in caplog.text
    with pytest.raises(journald_module.LinuxAuditApiJournaldSinkError):
        asyncio.run(sink.emit(object()))


def test_readiness_lifecycle_and_close_ownership(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    _, transport = patch_sink_factory(monkeypatch)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    async def scenario():
        assert get_linux_audit_api_readiness(application).phase == "starting"
        manager = application.router.lifespan_context(application)
        await manager.__aenter__()
        assert get_linux_audit_api_readiness(application) == (
            LinuxAuditApiReadiness(phase="ready", ready=True)
        )
        assert transport.close_calls == 0
        await manager.__aexit__(None, None, None)

    asyncio.run(scenario())

    assert get_linux_audit_api_readiness(application) == (
        LinuxAuditApiReadiness(phase="stopped", ready=False)
    )
    assert transport.close_calls == 1


def test_shutdown_marks_not_ready_before_bounded_sink_close(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    transport = BlockingCloseTransport()
    patch_sink_factory(monkeypatch, transport)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    async def scenario():
        manager = application.router.lifespan_context(application)
        await manager.__aenter__()
        shutdown = asyncio.create_task(
            manager.__aexit__(None, None, None)
        )
        assert await asyncio.to_thread(transport.entered.wait, 1)
        assert get_linux_audit_api_readiness(application) == (
            LinuxAuditApiReadiness(phase="stopping", ready=False)
        )
        transport.release.set()
        await shutdown

    asyncio.run(scenario())

    assert get_linux_audit_api_readiness(application).phase == "stopped"
    assert transport.close_calls == 1


def test_shutdown_failure_is_bounded_and_marks_failed(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    transport = RecordingTransport(
        close_error=journald_module._JournaldTransportError(PRIVATE_CANARY)
    )
    patch_sink_factory(monkeypatch, transport)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    async def scenario():
        manager = application.router.lifespan_context(application)
        await manager.__aenter__()
        with pytest.raises(LinuxAuditApiProductionBootstrapError) as captured:
            await manager.__aexit__(None, None, None)
        return captured.value

    error = asyncio.run(scenario())

    assert error.code == "LINUX_AUDIT_API_PRODUCTION_SHUTDOWN_FAILED"
    assert PRIVATE_CANARY not in str(error)
    assert get_linux_audit_api_readiness(application).phase == "failed"
    assert transport.close_calls == 1


def test_shutdown_cancellation_propagates_and_remains_not_ready(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    transport = BlockingCloseTransport()
    patch_sink_factory(monkeypatch, transport)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    async def scenario():
        manager = application.router.lifespan_context(application)
        await manager.__aenter__()
        shutdown = asyncio.create_task(
            manager.__aexit__(None, None, None)
        )
        assert await asyncio.to_thread(transport.entered.wait, 1)
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shutdown
        assert get_linux_audit_api_readiness(application).phase == "failed"
        transport.release.set()
        assert await asyncio.to_thread(transport.finished.wait, 1)

    asyncio.run(scenario())

    assert transport.close_calls == 1


def test_repeated_lifespan_entry_is_rejected_without_second_close(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    _, transport = patch_sink_factory(monkeypatch)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )

    async def scenario():
        first = application.router.lifespan_context(application)
        await first.__aenter__()
        await first.__aexit__(None, None, None)
        second = application.router.lifespan_context(application)
        with pytest.raises(LinuxAuditApiProductionBootstrapError):
            await second.__aenter__()

    asyncio.run(scenario())

    assert get_linux_audit_api_readiness(application).phase == "failed"
    assert transport.close_calls == 1


def test_readiness_snapshot_is_frozen_fixed_and_rejects_unrelated_apps(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    patch_sink_factory(monkeypatch)
    application = create_linux_audit_api_production_app(
        production_config(path)
    )
    snapshot = get_linux_audit_api_readiness(application)

    assert tuple(item.name for item in fields(snapshot)) == ("phase", "ready")
    assert repr(snapshot) == (
        "LinuxAuditApiReadiness(phase='starting', ready=False)"
    )
    assert PRIVATE_CANARY not in repr(snapshot)
    with pytest.raises(FrozenInstanceError):
        snapshot.ready = True
    assert_bootstrap_error(
        lambda: get_linux_audit_api_readiness(api_module.app),
        "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR",
    )
    assert_bootstrap_error(
        lambda: get_linux_audit_api_readiness(object()),
        "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR",
    )


@pytest.mark.parametrize(
    ("phase", "ready"),
    (
        ("starting", True),
        ("ready", False),
        ("unknown", False),
        (1, False),
        ("ready", 1),
    ),
)
def test_readiness_snapshot_rejects_invalid_runtime_contract(phase, ready):
    assert_bootstrap_error(
        lambda: LinuxAuditApiReadiness(phase=phase, ready=ready),
        "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR",
    )


def test_separate_production_apps_have_isolated_readiness_and_sinks(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    pairs = [create_test_sink(), create_test_sink()]
    iterator = iter(pair[0] for pair in pairs)
    monkeypatch.setattr(
        deployment_module,
        "create_linux_audit_api_journald_sink",
        lambda: next(iterator),
    )
    first = create_linux_audit_api_production_app(production_config(path))
    second = create_linux_audit_api_production_app(production_config(path))

    async def scenario():
        first_lifespan = first.router.lifespan_context(first)
        second_lifespan = second.router.lifespan_context(second)
        await first_lifespan.__aenter__()
        assert get_linux_audit_api_readiness(first).ready is True
        assert get_linux_audit_api_readiness(second).ready is False
        await second_lifespan.__aenter__()
        await first_lifespan.__aexit__(None, None, None)
        assert get_linux_audit_api_readiness(first).phase == "stopped"
        assert get_linux_audit_api_readiness(second).phase == "ready"
        await second_lifespan.__aexit__(None, None, None)

    asyncio.run(scenario())

    assert pairs[0][1].close_calls == 1
    assert pairs[1][1].close_calls == 1


def test_production_app_endpoint_and_default_app_contracts_are_isolated(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    _, transport = patch_sink_factory(monkeypatch)
    production_app = create_linux_audit_api_production_app(
        production_config(path)
    )

    assert ENDPOINT not in api_module.app.openapi()["paths"]
    assert "/api/readiness" not in production_app.openapi()["paths"]
    assert ENDPOINT in production_app.openapi()["paths"]
    with TestClient(production_app) as client:
        unauthorized = client.post(ENDPOINT)
        success = client.post(
            ENDPOINT,
            headers=AUTH_HEADERS,
            files={
                "linux_audit_files": (
                    "private.audit",
                    FIXTURE.read_bytes(),
                    "text/plain",
                )
            },
        )
        assert transport.close_calls == 0

    assert unauthorized.status_code == 401
    assert unauthorized.json() == {
        "error": {
            "code": "LINUX_AUDIT_AUTHENTICATION_REQUIRED",
            "message": "Authentication is required.",
        }
    }
    assert success.status_code == 200
    assert set(success.json()) == {
        "analysis_id",
        "status",
        "process_telemetry",
        "shared_memory_review",
        "session_process_review",
    }
    assert success.json()["status"] == "completed"
    assert len(transport.submissions) == 2
    assert get_linux_audit_api_readiness(production_app).phase == "stopped"
    assert transport.close_calls == 1


def test_core_factory_has_no_environment_or_analysis_side_effect(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    patch_sink_factory(monkeypatch)
    config = production_config(path)
    before = (config.secret_file, config.principal_id, config.max_concurrent_analyses)

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", PRIVATE_CANARY)
    monkeypatch.setenv("LINUX_AUDIT_API_TOKEN", PRIVATE_CANARY)
    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        lambda *_args: pytest.fail("analysis ran during construction"),
    )

    application = create_linux_audit_api_production_app(config)

    assert get_linux_audit_api_readiness(application).phase == "starting"
    assert before == (
        config.secret_file,
        config.principal_id,
        config.max_concurrent_analyses,
    )
