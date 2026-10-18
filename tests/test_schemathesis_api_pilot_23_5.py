"""Bounded, in-process HTTP properties; no external schema, logs, or reports."""

import asyncio
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient
from hypothesis import given, settings, strategies as st
import schemathesis
from schemathesis.python.asgi import ASGIClient

from app import api as api_module
from app.api import create_app
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.service import LiveMonitoringService


ACCOUNT = "SYNTH_ACCOUNT_23_5"
IP = "198.51.100.235"
PATH = "/synthetic/SYNTH_PATH_23_5"
QUERY = "SYNTH_QUERY_23_5"
FILENAME = "SYNTH_FILENAME_23_5.log"
RAW = "SYNTH_RAW_LINE_23_5"
EXCEPTION = "SYNTH_EXCEPTION_23_5"
CANARIES = (ACCOUNT, IP, PATH, QUERY, FILENAME, RAW, EXCEPTION)
DEFAULT_SCHEMA = schemathesis.openapi.from_dict(create_app().openapi())
SAMPLE_FILES = Path(__file__).resolve().parents[1] / "sample_logs"


@contextmanager
def _no_external_network():
    def deny(*_args, **_kwargs):
        raise AssertionError("external network attempted")

    with patch.object(socket.socket, "connect", deny), patch.object(socket.socket, "connect_ex", deny), patch.object(socket, "create_connection", deny):
        yield


def _safe(response):
    content = response.content.decode("utf-8", "replace")
    headers = str(dict(response.headers))
    for canary in CANARIES:
        assert canary not in content
        assert canary not in headers
    assert "Traceback" not in content
    assert "/private/tmp/" not in content
    assert response.status_code < 500


def _loopback_scope(app):
    """Schemathesis uses testclient as ASGI peer; model local transport explicitly."""
    async def wrapped(scope, receive, send):
        local_scope = dict(scope)
        local_scope["client"] = ("127.0.0.1", 50000)
        await app(local_scope, receive, send)
    return wrapped


@given(st.data())
@settings(max_examples=6, database=None, deadline=timedelta(seconds=2))
def test_sample_openapi_generated_no_input_contract(data):
    app = create_app()
    case = data.draw(DEFAULT_SCHEMA["/api/v1/investigations/sample"]["POST"].as_strategy())
    with _no_external_network(), ASGIClient(app, base_url="http://127.0.0.1:8000") as client:
        response = case.call_and_validate(session=client, base_url="http://127.0.0.1:8000")
    assert response.status_code == 200
    assert response.json()["schema_version"] == "1"
    assert response.json()["sample_context"]["label"] == "합성 샘플 결과"
    _safe(response)


@given(st.data())
@settings(max_examples=6, database=None, deadline=timedelta(seconds=2))
def test_live_status_openapi_generated_closed_schema(data):
    with TemporaryDirectory(prefix="schema-live-23-5-") as directory:
        path = Path(directory) / "synthetic.log"
        path.write_bytes(b"past line\n")
        session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
        worker = LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), 16, 4096)
        service = LiveMonitoringService(worker)
        app = create_app(live_monitoring_service=service)
        schema = schemathesis.openapi.from_dict(app.openapi())
        case = data.draw(schema["/api/v1/live/status"]["GET"].as_strategy())
        try:
            with _no_external_network(), ASGIClient(_loopback_scope(app), base_url="http://127.0.0.1:8000") as client:
                response = case.call_and_validate(session=client, base_url="http://127.0.0.1:8000")
            assert response.status_code == 200, response.json().get("error_code")
            assert response.headers["cache-control"] == ["no-store"]
            assert response.headers["x-content-type-options"] == ["nosniff"]
            assert response.json()["latest_detection_revision"] == 0
            assert response.json()["available_event_count"] == 0
            _safe(response)
        finally:
            asyncio.run(service.close())


def test_live_disabled_and_manual_negative_runtime_contract():
    app = create_app()
    assert "/api/v1/live/status" not in app.openapi()["paths"]
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        disabled = client.get("/api/v1/live/status")
        assert disabled.status_code == 404
        assert disabled.json()["error_code"] == "LIVE_MONITORING_NOT_ENABLED"
        for request in (
            lambda: client.post("/api/v1/investigations/sample", content=RAW),
            lambda: client.post("/api/v1/investigations/sample?x=" + QUERY),
            lambda: client.post("/api/v1/investigations/sample", data={"x": RAW}),
            lambda: client.post("/api/v1/investigations/sample", files={"x": (FILENAME, RAW)}),
            lambda: client.post("/api/v1/investigations/sample", headers={"Content-Type": "application/json"}),
        ):
            response = request()
            assert response.status_code == 400
            _safe(response)


def test_active_status_manual_query_body_and_method_boundaries():
    with TemporaryDirectory(prefix="schema-status-boundary-23-5-") as directory:
        path = Path(directory) / "synthetic.log"
        path.write_bytes(b"past line\n")
        session = open_live_tail_session(LiveMonitorConfig("application", path.resolve()))
        worker = LiveProcessingWorker(session, LiveDetectionAccumulator("application", 64, 65536), 16, 4096)
        service = LiveMonitoringService(worker)
        try:
            with TestClient(create_app(live_monitoring_service=service),
                            base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
                query = client.get("/api/v1/live/status?cursor=" + QUERY)
                body = client.request("GET", "/api/v1/live/status", content=RAW)
                method = client.post("/api/v1/live/status")
            assert (query.status_code, query.json()["error_code"]) == (400, "LIVE_INVALID_LAST_EVENT_ID")
            # Current read-only endpoint ignores a GET body; OpenAPI does not describe it.
            assert body.status_code == 200
            assert method.status_code == 405
            for response in (query, body, method):
                for canary in CANARIES:
                    assert canary not in response.text
        finally:
            asyncio.run(service.close())


@given(st.data())
@settings(max_examples=4, database=None, deadline=timedelta(seconds=2))
def test_legacy_openapi_generated_bounded_missing_fields(data):
    app = create_app()
    case = data.draw(DEFAULT_SCHEMA["/api/analyze"]["POST"].as_strategy())
    # The generated multipart body is arbitrary; this pilot covers the schema's
    # missing-field boundary, not automatic fuzzing of valid three-file uploads.
    case.body = {"application_file": "synthetic"}
    with _no_external_network(), ASGIClient(app, base_url="http://127.0.0.1:8000") as client:
        response = case.call(session=client, base_url="http://127.0.0.1:8000")
    assert response.status_code == 422
    case.validate_response(response)
    assert app.openapi()["paths"]["/api/analyze"]["post"]["deprecated"] is True
    _safe(response)


def test_legacy_valid_three_file_projection_and_cleanup():
    with TemporaryDirectory(prefix="schema-legacy-23-5-") as directory:
        created = []
        original = api_module.tempfile.NamedTemporaryFile

        def tracked(*args, **kwargs):
            kwargs["dir"] = directory
            result = original(*args, **kwargs)
            created.append(Path(result.name))
            return result

        files = {
            "application_file": (FILENAME, (SAMPLE_FILES / "brute_force.log").read_bytes(), "text/plain"),
            "ssh_file": ("synthetic-ssh.log", (SAMPLE_FILES / "ssh_auth.log").read_bytes(), "text/plain"),
            "access_file": ("synthetic-access.log", (SAMPLE_FILES / "web_shell.log").read_bytes(), "text/plain"),
        }
        with patch.object(api_module.tempfile, "NamedTemporaryFile", tracked):
            with TestClient(create_app(), base_url="http://127.0.0.1:8000") as client:
                response = client.post("/api/analyze", files=files)
        assert response.status_code == 200
        assert response.headers["Deprecation"] == "true"
        assert created and all(not path.exists() for path in created)
        _safe(response)
