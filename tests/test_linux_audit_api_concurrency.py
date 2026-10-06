import asyncio
import base64
from contextlib import asynccontextmanager
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.analyzer.llm as llm_module
import app.api as api_module
import app.api_uploads as uploads_module
import app.security.linux_audit_api as security_module
from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
)
from app.models.linux_audit_api import (
    LinuxAuditResponseProjectionError,
    project_linux_audit_api_error,
)
from app.security.linux_audit_api import (
    LinuxAuditAnalysisBusyError,
    LinuxAuditAnalysisLimiter,
    LinuxAuditAnalysisLimiterContractError,
    LinuxAuditApiAuthorizationError,
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
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
PRIVACY_CANARY = "SYNTHETIC_CAPACITY_SECRET_DO_NOT_EXPOSE"
PRINCIPAL_CANARY = "SYNTHETIC_CAPACITY_OPERATOR"


def security_config(capacity, *, principal_id="operator-1"):
    return LinuxAuditApiSecurityConfig(
        operator_token=SecretStr(OPERATOR_TOKEN),
        principal_id=principal_id,
        max_concurrent_analyses=capacity,
    )


def secured_app(capacity=1, *, principal_id="operator-1"):
    return api_module.create_app(
        enable_linux_audit_api=True,
        linux_audit_api_security=security_config(
            capacity,
            principal_id=principal_id,
        ),
    )


def fixture_files(*, canary=False):
    filename = (
        f"../../{PRIVACY_CANARY}.audit"
        if canary
        else "input.audit"
    )
    content_type = (
        f"application/{PRIVACY_CANARY}"
        if canary
        else "text/plain"
    )
    return {
        "linux_audit_files": (
            filename,
            (
                PRIVACY_CANARY.encode("ascii")
                if canary
                else FIXTURE.read_bytes()
            ),
            content_type,
        )
    }


async def async_post(client, *, headers=AUTH_HEADERS, canary=False):
    return await client.post(
        ENDPOINT,
        headers=headers,
        files=fixture_files(canary=canary),
    )


def assert_busy_response(response):
    assert response.status_code == 429
    assert response.json() == {
        "error": {
            "code": "LINUX_AUDIT_ANALYSIS_BUSY",
            "message": (
                "Linux Audit analysis capacity is unavailable."
            ),
        }
    }
    assert "detail" not in response.json()
    assert "retry-after" not in response.headers


@pytest.mark.parametrize("capacity", (None, True, False, 0, -1, 5, "1"))
def test_limiter_rejects_non_v1_capacity(capacity):
    with pytest.raises(LinuxAuditApiSecurityConfigurationError):
        LinuxAuditAnalysisLimiter(capacity)


def test_limiter_capacity_boundaries_and_single_use_lease():
    async def scenario():
        for capacity in (1, 2, 4):
            limiter = LinuxAuditAnalysisLimiter(capacity)
            leases = [limiter.acquire() for _ in range(capacity)]
            for lease in leases:
                assert await lease.__aenter__() is None

            busy = limiter.acquire()
            with pytest.raises(LinuxAuditAnalysisBusyError):
                await busy.__aenter__()

            for lease in reversed(leases):
                assert await lease.__aexit__(None, None, None) is False

            with pytest.raises(LinuxAuditAnalysisLimiterContractError):
                await leases[0].__aenter__()
            with pytest.raises(LinuxAuditAnalysisLimiterContractError):
                await leases[0].__aexit__(None, None, None)

            async with limiter.acquire():
                pass

    asyncio.run(scenario())


def test_limiter_releases_after_exception_and_cancellation():
    async def scenario():
        limiter = LinuxAuditAnalysisLimiter(1)
        with pytest.raises(RuntimeError, match="primary failure"):
            async with limiter.acquire():
                raise RuntimeError("primary failure")

        corrupted = LinuxAuditAnalysisLimiter(1)
        with pytest.raises(RuntimeError, match="primary failure") as caught:
            async with corrupted.acquire():
                object.__setattr__(
                    corrupted,
                    "_LinuxAuditAnalysisLimiter__in_use",
                    0,
                )
                raise RuntimeError("primary failure")
        assert caught.value.__notes__ == [
            "Linux Audit analysis capacity state is invalid."
        ]

        entered = asyncio.Event()
        never = asyncio.Event()

        async def holder():
            async with limiter.acquire():
                entered.set()
                await never.wait()

        task = asyncio.create_task(holder())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        async with limiter.acquire():
            pass

        started = False

        async def cancelled_before_start():
            nonlocal started
            async with limiter.acquire():
                started = True

        pending = asyncio.create_task(cancelled_before_start())
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert started is False
        async with limiter.acquire():
            pass

    asyncio.run(scenario())


def test_each_enabled_app_owns_one_distinct_configured_limiter(monkeypatch):
    original = api_module.LinuxAuditAnalysisLimiter
    created = []

    class TrackedLimiter(original):

        def __init__(self, capacity):
            super().__init__(capacity)
            created.append((capacity, self))

    monkeypatch.setattr(
        api_module,
        "LinuxAuditAnalysisLimiter",
        TrackedLimiter,
    )
    first = secured_app(1)
    second = secured_app(2)
    disabled = api_module.create_app()

    assert [capacity for capacity, _ in created] == [1, 2]
    assert created[0][1] is not created[1][1]
    assert repr(created[0][1]) == "LinuxAuditAnalysisLimiter()"
    assert ENDPOINT in first.openapi()["paths"]
    assert ENDPOINT in second.openapi()["paths"]
    assert ENDPOINT not in disabled.openapi()["paths"]


def test_capacity_one_rejects_without_queue_or_handler_work(
    monkeypatch,
    caplog,
):
    original_threadpool = api_module.run_in_threadpool
    original_stage = api_module.stage_linux_audit_uploads
    entered = asyncio.Event()
    release = asyncio.Event()
    stage_calls = []
    analysis_calls = []
    uuid_calls = []

    @asynccontextmanager
    async def tracked_stage(files):
        stage_calls.append(files)
        async with original_stage(files) as staged_inputs:
            yield staged_inputs

    async def blocked_threadpool(func, *args, **kwargs):
        analysis_calls.append(args)
        entered.set()
        await release.wait()
        return await original_threadpool(func, *args, **kwargs)

    original_uuid = api_module.uuid.uuid4

    def tracked_uuid():
        uuid_calls.append(True)
        return original_uuid()

    monkeypatch.setattr(api_module, "stage_linux_audit_uploads", tracked_stage)
    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)
    monkeypatch.setattr(api_module.uuid, "uuid4", tracked_uuid)

    def fail_llm(*args, **kwargs):
        raise AssertionError("capacity path must not call an LLM")

    monkeypatch.setattr(llm_module.genai, "Client", fail_llm)

    async def scenario():
        transport = httpx.ASGITransport(
            app=secured_app(1, principal_id=PRINCIPAL_CANARY)
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            first = asyncio.create_task(async_post(client))
            await entered.wait()

            busy = await async_post(client, canary=True)
            assert_busy_response(busy)
            assert PRIVACY_CANARY not in busy.text
            assert OPERATOR_TOKEN not in busy.text
            assert PRINCIPAL_CANARY not in busy.text
            assert all(
                PRIVACY_CANARY not in value
                for value in busy.headers.values()
            )
            assert release.is_set() is False
            assert len(stage_calls) == 1
            assert len(analysis_calls) == 1
            assert uuid_calls == []
            assert PRIVACY_CANARY not in caplog.text
            assert OPERATOR_TOKEN not in caplog.text
            assert PRINCIPAL_CANARY not in caplog.text

            release.set()
            assert (await first).status_code == 200
            assert (await async_post(client)).status_code == 200

    asyncio.run(scenario())


def test_endpoint_cancellation_releases_temp_files_and_capacity(
    monkeypatch,
    tmp_path,
):
    original_threadpool = api_module.run_in_threadpool
    original_temporary_directory = (
        uploads_module.tempfile.TemporaryDirectory
    )
    entered = asyncio.Event()
    never = asyncio.Event()
    directories = []

    def tracked_temporary_directory(*args, **kwargs):
        kwargs["dir"] = tmp_path
        temporary_directory = original_temporary_directory(*args, **kwargs)
        directories.append(Path(temporary_directory.name))
        return temporary_directory

    async def blocked_threadpool(func, *args, **kwargs):
        entered.set()
        await never.wait()

    monkeypatch.setattr(
        uploads_module.tempfile,
        "TemporaryDirectory",
        tracked_temporary_directory,
    )
    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)

    async def scenario():
        transport = httpx.ASGITransport(app=secured_app(1))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            request = asyncio.create_task(async_post(client))
            await entered.wait()
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request

            assert directories
            assert all(not directory.exists() for directory in directories)

            monkeypatch.setattr(
                api_module,
                "run_in_threadpool",
                original_threadpool,
            )
            later = await async_post(client)
            assert later.status_code == 200

    asyncio.run(scenario())


def test_capacity_two_admits_two_and_rejects_third(monkeypatch):
    original_threadpool = api_module.run_in_threadpool
    release = asyncio.Event()
    both_entered = asyncio.Event()
    call_count = 0

    async def blocked_threadpool(func, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            both_entered.set()
        await release.wait()
        return await original_threadpool(func, *args, **kwargs)

    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)

    async def scenario():
        transport = httpx.ASGITransport(app=secured_app(2))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            first = asyncio.create_task(async_post(client))
            second = asyncio.create_task(async_post(client))
            await both_entered.wait()
            third = await async_post(client)
            assert_busy_response(third)
            assert call_count == 2

            release.set()
            assert (await first).status_code == 200
            assert (await second).status_code == 200
            assert (await async_post(client)).status_code == 200

    asyncio.run(scenario())


def test_authentication_and_authorization_precede_busy_state(monkeypatch):
    original_threadpool = api_module.run_in_threadpool
    original_authorize = security_module.authorize_linux_audit_analysis
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_threadpool(func, *args, **kwargs):
        entered.set()
        await release.wait()
        return await original_threadpool(func, *args, **kwargs)

    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)

    async def scenario():
        transport = httpx.ASGITransport(app=secured_app(1))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            holder = asyncio.create_task(async_post(client))
            await entered.wait()

            missing = await async_post(client, headers={})
            invalid = await async_post(
                client,
                headers={"Authorization": f"Bearer {OTHER_TOKEN}"},
            )
            assert missing.status_code == invalid.status_code == 401

            def deny(principal):
                raise LinuxAuditApiAuthorizationError()

            monkeypatch.setattr(
                security_module,
                "authorize_linux_audit_analysis",
                deny,
            )
            denied = await async_post(client)
            assert denied.status_code == 403
            monkeypatch.setattr(
                security_module,
                "authorize_linux_audit_analysis",
                original_authorize,
            )

            busy = await async_post(client)
            assert_busy_response(busy)
            release.set()
            assert (await holder).status_code == 200

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "failure_stage",
    ("staging", "analysis", "projection", "unexpected", "uuid"),
)
def test_every_failure_path_releases_capacity(
    failure_stage,
    monkeypatch,
):
    client = TestClient(secured_app(1), headers=AUTH_HEADERS)

    if failure_stage == "staging":
        failed = client.post(
            ENDPOINT,
            files={
                "linux_audit_files": (
                    "invalid.audit",
                    b"\xff",
                    "text/plain",
                )
            },
        )
        assert failed.status_code == 400
    else:
        target = (
            "build_linux_audit_api_response"
            if failure_stage == "projection"
            else "analyze_staged_linux_audit_inputs"
        )
        if failure_stage == "uuid":
            target = None
            original = api_module.uuid.uuid4

            def fail_uuid():
                raise RuntimeError("private response construction failure")

            monkeypatch.setattr(api_module.uuid, "uuid4", fail_uuid)
        else:
            original = getattr(api_module, target)

            def fail(*args, **kwargs):
                if failure_stage == "analysis":
                    raise LinuxAuditAnalysisValidationError(
                        "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR"
                    )
                if failure_stage == "projection":
                    raise LinuxAuditResponseProjectionError()
                raise RuntimeError("private unexpected failure")

            monkeypatch.setattr(api_module, target, fail)

        failed = client.post(ENDPOINT, files=fixture_files())
        assert failed.status_code == 500
        if target is None:
            monkeypatch.setattr(api_module.uuid, "uuid4", original)
        else:
            monkeypatch.setattr(api_module, target, original)

    success = client.post(ENDPOINT, files=fixture_files())
    assert success.status_code == 200
    assert success.json()["process_telemetry"]["observation_count"] == 4


def test_separate_apps_do_not_share_exhaustion(monkeypatch):
    original_threadpool = api_module.run_in_threadpool
    first_entered = asyncio.Event()
    release = asyncio.Event()
    call_count = 0

    async def block_first(func, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            first_entered.set()
            await release.wait()
        return await original_threadpool(func, *args, **kwargs)

    monkeypatch.setattr(api_module, "run_in_threadpool", block_first)

    async def scenario():
        first_transport = httpx.ASGITransport(app=secured_app(1))
        second_transport = httpx.ASGITransport(app=secured_app(1))
        async with (
            httpx.AsyncClient(
                transport=first_transport,
                base_url="http://first",
            ) as first_client,
            httpx.AsyncClient(
                transport=second_transport,
                base_url="http://second",
            ) as second_client,
        ):
            holder = asyncio.create_task(async_post(first_client))
            await first_entered.wait()
            assert_busy_response(await async_post(first_client))
            independent = await async_post(second_client)
            assert independent.status_code == 200
            release.set()
            assert (await holder).status_code == 200

    asyncio.run(scenario())


def test_busy_projection_rejects_tampering_and_discloses_no_canary(
    monkeypatch,
    caplog,
):
    error = LinuxAuditAnalysisBusyError()
    error.message = f"private {PRIVACY_CANARY}"
    projected = project_linux_audit_api_error(error)
    assert projected.status_code == 500
    assert projected.body.error.code == (
        "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
    )
    assert PRIVACY_CANARY not in projected.body.model_dump_json()
    assert PRIVACY_CANARY not in repr(LinuxAuditAnalysisLimiter(1))
    assert PRIVACY_CANARY not in repr(LinuxAuditAnalysisBusyError())
    assert PRIVACY_CANARY not in repr(
        LinuxAuditAnalysisLimiterContractError()
    )

    def fail_llm(*args, **kwargs):
        raise AssertionError("capacity path must not call an LLM")

    monkeypatch.setattr(llm_module.genai, "Client", fail_llm)
    configured = secured_app(
        1,
        principal_id=PRINCIPAL_CANARY,
    )
    schema = json.dumps(configured.openapi(), sort_keys=True)
    assert PRIVACY_CANARY not in schema
    assert OPERATOR_TOKEN not in schema
    assert PRINCIPAL_CANARY not in schema
    assert PRIVACY_CANARY not in caplog.text
