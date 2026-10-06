import asyncio
import base64
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

import app.api as api_module
import app.api_uploads as uploads_module
import app.security.linux_audit_api as security_module
from app.models.linux_audit_api import (
    LinuxAuditResponseProjectionError,
    project_linux_audit_api_error,
)
from app.security.linux_audit_api import (
    LinuxAuditApiAccessAuditContractError,
    LinuxAuditApiAccessAuditEvent,
    LinuxAuditApiAccessAuditFailedError,
    LinuxAuditApiAccessAuditRecorder,
    LinuxAuditApiAccessAuditSink,
    LinuxAuditApiAuthorizationError,
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
)


ENDPOINT = "/api/analyze-linux-audit"
FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"}
AUDIT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ANALYSIS_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


class RecordingAuditSink(LinuxAuditApiAccessAuditSink):
    def __init__(self, *, failure=None):
        self.events = []
        self.failure = failure

    async def emit(self, event):
        self.events.append(event)
        if self.failure is not None:
            raise self.failure


def security_config(capacity=1):
    return LinuxAuditApiSecurityConfig(
        operator_token=SecretStr(TOKEN),
        principal_id="audit-operator",
        max_concurrent_analyses=capacity,
    )


def enabled_app(sink, *, capacity=1):
    return api_module.create_app(
        enable_linux_audit_api=True,
        linux_audit_api_security=security_config(capacity),
        linux_audit_api_audit_sink=sink,
    )


def fixture_files(content=None):
    return {
        "linux_audit_files": (
            "private-name.audit",
            FIXTURE.read_bytes() if content is None else content,
            "text/private-content-type",
        )
    }


def event(**changes):
    values = {
        "audit_event_id": AUDIT_ID,
        "analysis_id": ANALYSIS_ID,
        "timestamp": NOW,
        "principal_id": "audit-operator",
        "endpoint": ENDPOINT,
        "method": "POST",
        "result_category": "analysis_completed",
        "http_status": 200,
        "file_count": 1,
        "upload_size_bucket": "under_1_mib",
        "duration_bucket": "under_1s",
    }
    values.update(changes)
    return LinuxAuditApiAccessAuditEvent(**values)


def test_audit_event_is_frozen_fixed_shape_and_has_safe_repr():
    audit_event = event()

    assert tuple(item.name for item in fields(audit_event)) == (
        "audit_event_id",
        "analysis_id",
        "timestamp",
        "principal_id",
        "endpoint",
        "method",
        "result_category",
        "http_status",
        "file_count",
        "upload_size_bucket",
        "duration_bucket",
    )
    assert repr(audit_event) == "LinuxAuditApiAccessAuditEvent()"
    assert "audit-operator" not in repr(audit_event)
    with pytest.raises(FrozenInstanceError):
        audit_event.http_status = 500


@pytest.mark.parametrize(
    "timestamp",
    (
        datetime(2026, 10, 6, 12, 0),
        datetime(2026, 10, 6, 12, 0, tzinfo=timezone(timedelta(hours=1))),
        "2026-10-06T12:00:00Z",
    ),
)
def test_audit_event_requires_exact_timezone_aware_utc(timestamp):
    with pytest.raises(LinuxAuditApiAccessAuditContractError):
        event(timestamp=timestamp)


@pytest.mark.parametrize(
    "changes",
    (
        {"audit_event_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
        {"analysis_id": None},
        {"endpoint": "/api/other"},
        {"method": "GET"},
        {"result_category": "malicious"},
        {"http_status": True},
        {"file_count": True},
        {"file_count": -1},
        {"upload_size_bucket": "exact"},
        {"duration_bucket": "fast"},
    ),
)
def test_audit_event_rejects_invalid_fixed_fields(changes):
    with pytest.raises(LinuxAuditApiAccessAuditContractError):
        event(**changes)


@pytest.mark.parametrize(
    "changes",
    (
        {
            "result_category": "authentication_failed",
            "http_status": 401,
            "analysis_id": None,
            "principal_id": "audit-operator",
            "file_count": None,
            "upload_size_bucket": "unknown",
        },
        {
            "result_category": "authorization_failed",
            "http_status": 403,
            "analysis_id": None,
            "principal_id": None,
            "file_count": None,
            "upload_size_bucket": "unknown",
        },
        {
            "result_category": "capacity_rejected",
            "http_status": 429,
            "analysis_id": None,
            "file_count": None,
            "upload_size_bucket": "unknown",
        },
        {
            "result_category": "validation_failed",
            "http_status": 500,
            "analysis_id": None,
        },
        {
            "result_category": "internal_failed",
            "http_status": 200,
            "analysis_id": None,
        },
        {
            "result_category": "cancelled",
            "http_status": 200,
            "analysis_id": None,
        },
    ),
)
def test_category_status_principal_and_analysis_invariants(changes):
    with pytest.raises(LinuxAuditApiAccessAuditContractError):
        event(**changes)


@pytest.mark.parametrize(
    ("size_bytes", "expected"),
    (
        (0, "under_1_mib"),
        (1024 * 1024 - 1, "under_1_mib"),
        (1024 * 1024, "1_to_10_mib"),
        (10 * 1024 * 1024, "1_to_10_mib"),
        (10 * 1024 * 1024 + 1, "over_10_mib"),
    ),
)
def test_upload_size_bucket_boundaries(size_bytes, expected):
    assert security_module._upload_size_bucket(size_bytes) == expected


@pytest.mark.parametrize(
    ("seconds", "expected"),
    (
        (0, "under_1s"),
        (0.999, "under_1s"),
        (1, "1_to_5s"),
        (4.999, "1_to_5s"),
        (5, "over_5s"),
        (5.001, "over_5s"),
    ),
)
def test_duration_bucket_boundaries(seconds, expected):
    assert security_module._duration_bucket(seconds) == expected


def test_recorder_emits_once_with_injected_clocks_and_bounded_state():
    sink = RecordingAuditSink()
    recorder = LinuxAuditApiAccessAuditRecorder(
        sink,
        audit_event_id=AUDIT_ID,
        started_at=10.0,
        utc_now=lambda: NOW,
        monotonic=lambda: 11.0,
    )
    recorder.set_principal_id("audit-operator")
    recorder.set_file_count(2)
    recorder.set_upload_size_bytes(1024 * 1024)

    asyncio.run(recorder.emit(
        result_category="analysis_completed",
        http_status=200,
        analysis_id=ANALYSIS_ID,
    ))

    assert sink.events == [event(
        file_count=2,
        upload_size_bucket="1_to_10_mib",
        duration_bucket="1_to_5s",
    )]
    with pytest.raises(LinuxAuditApiAccessAuditContractError):
        asyncio.run(recorder.emit(
            result_category="analysis_completed",
            http_status=200,
            analysis_id=ANALYSIS_ID,
        ))


def test_factory_requires_explicit_valid_sink_only_when_enabled():
    assert ENDPOINT not in api_module.create_app().openapi()["paths"]

    for kwargs in (
        {
            "enable_linux_audit_api": True,
            "linux_audit_api_security": security_config(),
        },
        {"linux_audit_api_audit_sink": RecordingAuditSink()},
        {
            "enable_linux_audit_api": True,
            "linux_audit_api_security": security_config(),
            "linux_audit_api_audit_sink": object(),
        },
    ):
        with pytest.raises(LinuxAuditApiSecurityConfigurationError):
            api_module.create_app(**kwargs)

    first_sink = RecordingAuditSink()
    second_sink = RecordingAuditSink()
    first = enabled_app(first_sink)
    second = enabled_app(second_sink)
    assert first is not second
    assert first_sink is not second_sink


def test_authentication_and_authorization_failures_emit_once(monkeypatch):
    authentication_sink = RecordingAuditSink()
    response = TestClient(enabled_app(authentication_sink)).post(ENDPOINT)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert len(authentication_sink.events) == 1
    authentication_event = authentication_sink.events[0]
    assert authentication_event.result_category == "authentication_failed"
    assert authentication_event.principal_id is None
    assert authentication_event.file_count is None
    assert authentication_event.analysis_id is None

    def deny(principal):
        raise LinuxAuditApiAuthorizationError()

    monkeypatch.setattr(
        security_module,
        "authorize_linux_audit_analysis",
        deny,
    )
    authorization_sink = RecordingAuditSink()
    response = TestClient(enabled_app(authorization_sink)).post(
        ENDPOINT,
        headers=AUTH_HEADERS,
        files=fixture_files(),
    )
    assert response.status_code == 403
    assert len(authorization_sink.events) == 1
    authorization_event = authorization_sink.events[0]
    assert authorization_event.result_category == "authorization_failed"
    assert authorization_event.principal_id == "audit-operator"
    assert authorization_event.file_count is None


def test_validation_no_eligible_success_and_internal_categories(monkeypatch):
    validation_sink = RecordingAuditSink()
    invalid = TestClient(
        enabled_app(validation_sink),
        headers=AUTH_HEADERS,
    ).post(ENDPOINT, files=fixture_files(b"\xff"))
    assert invalid.status_code == 400
    assert [item.result_category for item in validation_sink.events] == [
        "validation_failed"
    ]
    assert validation_sink.events[0].file_count == 1
    assert validation_sink.events[0].upload_size_bucket == "unknown"

    no_event_sink = RecordingAuditSink()
    no_event = TestClient(
        enabled_app(no_event_sink),
        headers=AUTH_HEADERS,
    ).post(ENDPOINT, files=fixture_files(b"not an audit record\n"))
    assert no_event.status_code == 422
    assert no_event_sink.events[0].result_category == "validation_failed"
    assert no_event_sink.events[0].upload_size_bucket == "under_1_mib"

    success_sink = RecordingAuditSink()
    success = TestClient(
        enabled_app(success_sink),
        headers=AUTH_HEADERS,
    ).post(ENDPOINT, files=fixture_files())
    assert success.status_code == 200
    assert len(success_sink.events) == 1
    completed = success_sink.events[0]
    assert completed.result_category == "analysis_completed"
    assert str(completed.analysis_id) == success.json()["analysis_id"]
    assert completed.http_status == 200

    def fail_analysis(staged_inputs):
        raise RuntimeError("PRIVATE_INTERNAL_EXCEPTION")

    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        fail_analysis,
    )
    internal_sink = RecordingAuditSink()
    internal = TestClient(
        enabled_app(internal_sink),
        headers=AUTH_HEADERS,
    ).post(ENDPOINT, files=fixture_files())
    assert internal.status_code == 500
    assert internal_sink.events[0].result_category == "internal_failed"
    assert internal_sink.events[0].analysis_id is None
    assert "PRIVATE_INTERNAL_EXCEPTION" not in internal.text


def test_projection_failure_is_internal_and_audited_once(monkeypatch):
    def fail_projection(*args, **kwargs):
        raise LinuxAuditResponseProjectionError()

    monkeypatch.setattr(
        api_module,
        "build_linux_audit_api_response",
        fail_projection,
    )
    sink = RecordingAuditSink()
    response = TestClient(
        enabled_app(sink),
        headers=AUTH_HEADERS,
    ).post(ENDPOINT, files=fixture_files())

    assert response.status_code == 500
    assert len(sink.events) == 1
    assert sink.events[0].result_category == "internal_failed"


def test_sink_failure_replaces_success_and_validation_without_recursion():
    for files in (fixture_files(), None):
        sink = RecordingAuditSink(failure=RuntimeError("PRIVATE_SINK"))
        client = TestClient(enabled_app(sink), headers=AUTH_HEADERS)
        response = client.post(ENDPOINT, files=files)

        assert response.status_code == 500
        assert response.json() == {
            "error": {
                "code": "LINUX_AUDIT_ACCESS_AUDIT_FAILED",
                "message": (
                    "Linux Audit access audit could not be completed."
                ),
            }
        }
        assert len(sink.events) == 1
        assert "PRIVATE_SINK" not in response.text


def test_sink_failure_cleans_staging_and_releases_capacity(
    monkeypatch,
    tmp_path,
):
    original = uploads_module.tempfile.TemporaryDirectory
    directories = []

    def tracked_temporary_directory(*args, **kwargs):
        kwargs["dir"] = tmp_path
        temporary_directory = original(*args, **kwargs)
        directories.append(Path(temporary_directory.name))
        return temporary_directory

    monkeypatch.setattr(
        uploads_module.tempfile,
        "TemporaryDirectory",
        tracked_temporary_directory,
    )
    sink = RecordingAuditSink(failure=RuntimeError("PRIVATE_SINK"))
    client = TestClient(enabled_app(sink), headers=AUTH_HEADERS)

    failed = client.post(ENDPOINT, files=fixture_files())
    assert failed.status_code == 500
    assert directories
    assert all(not directory.exists() for directory in directories)

    sink.failure = None
    later = client.post(ENDPOINT, files=fixture_files())
    assert later.status_code == 200
    assert all(not directory.exists() for directory in directories)


def test_audit_failure_has_strict_projection_and_tampering_fails_closed():
    projected = project_linux_audit_api_error(
        LinuxAuditApiAccessAuditFailedError()
    )
    assert projected.status_code == 500
    assert projected.body.model_dump(mode="json") == {
        "error": {
            "code": "LINUX_AUDIT_ACCESS_AUDIT_FAILED",
            "message": "Linux Audit access audit could not be completed.",
        }
    }

    tampered = LinuxAuditApiAccessAuditFailedError()
    tampered.message = "user controlled"
    collapsed = project_linux_audit_api_error(tampered)
    assert collapsed.body.error.code == (
        "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
    )


def test_capacity_rejection_emits_once_before_staging(monkeypatch):
    entered = asyncio.Event()
    release = asyncio.Event()
    original = api_module.run_in_threadpool

    async def blocked_threadpool(func, *args, **kwargs):
        entered.set()
        await release.wait()
        return await original(func, *args, **kwargs)

    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)
    sink = RecordingAuditSink()

    async def scenario():
        transport = httpx.ASGITransport(app=enabled_app(sink))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers=AUTH_HEADERS,
        ) as client:
            first = asyncio.create_task(client.post(
                ENDPOINT,
                files=fixture_files(),
            ))
            await entered.wait()
            busy = await client.post(ENDPOINT, files=fixture_files())
            assert busy.status_code == 429
            assert len(sink.events) == 1
            assert sink.events[0].result_category == "capacity_rejected"
            assert sink.events[0].upload_size_bucket == "unknown"
            release.set()
            assert (await first).status_code == 200

    asyncio.run(scenario())
    assert [item.result_category for item in sink.events] == [
        "capacity_rejected",
        "analysis_completed",
    ]


def test_cancellation_attempts_one_event_and_preserves_cancellation(
    monkeypatch,
):
    entered = asyncio.Event()
    never = asyncio.Event()

    async def blocked_threadpool(func, *args, **kwargs):
        entered.set()
        await never.wait()

    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)
    sink = RecordingAuditSink()

    async def scenario():
        transport = httpx.ASGITransport(app=enabled_app(sink))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers=AUTH_HEADERS,
        ) as client:
            pending = asyncio.create_task(client.post(
                ENDPOINT,
                files=fixture_files(),
            ))
            await entered.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending

    asyncio.run(scenario())
    assert len(sink.events) == 1
    assert sink.events[0].result_category == "cancelled"
    assert sink.events[0].http_status == 499
    assert sink.events[0].analysis_id is None


def test_cancellation_is_preserved_when_sink_fails(monkeypatch):
    entered = asyncio.Event()
    never = asyncio.Event()

    async def blocked_threadpool(func, *args, **kwargs):
        entered.set()
        await never.wait()

    monkeypatch.setattr(api_module, "run_in_threadpool", blocked_threadpool)
    sink = RecordingAuditSink(failure=RuntimeError("PRIVATE_SINK"))

    async def scenario():
        transport = httpx.ASGITransport(app=enabled_app(sink))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers=AUTH_HEADERS,
        ) as client:
            pending = asyncio.create_task(client.post(
                ENDPOINT,
                files=fixture_files(),
            ))
            await entered.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError) as caught:
                await pending
            assert caught.value.__notes__ == [
                "Linux Audit access audit emission failed."
            ]

    asyncio.run(scenario())
    assert len(sink.events) == 1


def test_audit_schema_and_private_values_are_absent_from_openapi_and_response():
    sink = RecordingAuditSink()
    app = enabled_app(sink)
    schema_text = json.dumps(app.openapi(), sort_keys=True)
    response = TestClient(app, headers=AUTH_HEADERS).post(
        ENDPOINT,
        files=fixture_files(),
    )
    response_text = response.text + repr(response.headers)

    assert response.status_code == 200
    for private in (
        TOKEN,
        "audit-operator",
        "private-name.audit",
        "text/private-content-type",
        "LinuxAuditApiAccessAuditEvent",
        "audit_event_id",
        "duration_bucket",
        "file_count",
    ):
        assert private not in schema_text
        assert private not in response_text
    assert repr(sink.events[0]) == "LinuxAuditApiAccessAuditEvent()"
