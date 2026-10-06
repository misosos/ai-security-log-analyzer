import asyncio
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import app.analyzer.llm as llm_module
import app.api as api_module
import app.api_uploads as uploads_module
from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
)
from app.models.linux_audit_api import (
    LinuxAuditResponseProjectionError,
)


ENDPOINT = "/api/analyze-linux-audit"
FIXTURE_DIR = Path("sample_logs")
SHARED_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_shared_memory_execution_contract_synthetic.log"
)
SESSION_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_session_process_co_observation_contract_synthetic.log"
)
LINKED_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
ANALYSIS_ID = UUID("12345678-1234-5678-9abc-def012345678")
CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"


def enabled_app():
    return api_module.create_app(enable_linux_audit_api=True)


def multipart_file(
    content: bytes,
    *,
    filename: str = "input.audit",
    content_type: str = "text/plain",
):
    return (
        "linux_audit_files",
        (filename, content, content_type),
    )


def fixture_files(*paths):
    return [
        multipart_file(
            path.read_bytes(),
            filename=f"fixture-{index}.audit",
        )
        for index, path in enumerate(paths, start=1)
    ]


def assert_error(response, *, status_code, code, message):
    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "error": {"code": code, "message": message}
    }
    assert "detail" not in response.json()


def track_request_directories(monkeypatch, tmp_path):
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
    return directories


def test_default_app_is_disabled_and_does_not_invoke_linux_audit_helpers(
    monkeypatch,
):
    calls = []

    def fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("disabled route invoked a Linux Audit helper")

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
    client = TestClient(api_module.app)
    files = [multipart_file(
        CANARY.encode(),
        filename=f"../../{CANARY}.audit",
        content_type=f"application/{CANARY}",
    )]

    for response in (
        client.post(ENDPOINT, files=files),
        client.get(ENDPOINT),
    ):
        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}
        assert CANARY not in response.text
        assert all(CANARY not in value for value in response.headers.values())

    schema = api_module.app.openapi()
    assert set(schema["paths"]) == {"/api/health", "/api/analyze"}
    assert ENDPOINT not in schema["paths"]
    assert not any(
        "LinuxAudit" in name
        for name in schema.get("components", {}).get("schemas", {})
    )
    assert calls == []


@pytest.mark.parametrize("value", [None, 0, 1, "false", object()])
def test_feature_gate_requires_an_exact_bool(value):
    with pytest.raises(TypeError, match="must be a bool"):
        api_module.create_app(enable_linux_audit_api=value)


def test_enabled_route_and_openapi_are_exact_and_app_instances_are_isolated():
    first = enabled_app()
    second = enabled_app()

    for configured_app in (first, second):
        route_paths = [
            route.path
            for route in configured_app.routes
            if route.path.startswith("/api/")
        ]
        assert route_paths.count("/api/health") == 1
        assert route_paths.count("/api/analyze") == 1
        assert route_paths.count(ENDPOINT) == 1

        schema = configured_app.openapi()
        assert set(schema["paths"]) == {
            "/api/health",
            "/api/analyze",
            ENDPOINT,
        }
        endpoint_schema = schema["paths"][ENDPOINT]
        assert set(endpoint_schema) == {"post"}
        operation = endpoint_schema["post"]
        assert operation["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"].endswith("/LinuxAuditAnalysisResponse")
        for status_code in ("400", "409", "413", "415", "422", "500"):
            assert operation["responses"][status_code]["content"][
                "application/json"
            ]["schema"]["$ref"].endswith(
                "/LinuxAuditApiErrorResponse"
            )
        request_schema = operation["requestBody"]["content"][
            "multipart/form-data"
        ]["schema"]["$ref"].split("/")[-1]
        request_properties = schema["components"]["schemas"][
            request_schema
        ]["properties"]
        assert set(request_properties) == {"linux_audit_files"}
        assert CANARY not in json.dumps(schema, sort_keys=True)

    assert first is not second
    assert first.router is not second.router
    assert TestClient(first).get("/api/health").json() == {"status": "ok"}
    assert TestClient(first).get(ENDPOINT).status_code == 405


def test_missing_or_zero_files_use_the_bounded_error_envelope():
    client = TestClient(enabled_app())

    for response in (
        client.post(ENDPOINT),
        client.post(ENDPOINT, files={}),
        client.post(
            ENDPOINT,
            files={
                "application_file": (
                    "application.log",
                    b"not a Linux Audit endpoint field",
                    "text/plain",
                )
            },
        ),
    ):
        assert_error(
            response,
            status_code=422,
            code="MISSING_LINUX_AUDIT_FILES",
            message="At least one Linux Audit file is required.",
        )


def test_file_count_limit_maps_to_413_before_analysis():
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=[multipart_file(str(index).encode()) for index in range(5)],
    )

    assert_error(
        response,
        status_code=413,
        code="LINUX_AUDIT_FILE_COUNT_EXCEEDED",
        message="Linux Audit file count limit exceeded.",
    )


def test_per_file_and_total_size_limits_map_to_413(monkeypatch):
    client = TestClient(enabled_app())
    monkeypatch.setattr(
        uploads_module,
        "LINUX_AUDIT_MAX_FILE_SIZE_BYTES",
        4,
    )
    monkeypatch.setattr(
        uploads_module,
        "LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES",
        20,
    )
    file_response = client.post(
        ENDPOINT,
        files=[multipart_file(b"12345")],
    )
    assert_error(
        file_response,
        status_code=413,
        code="LINUX_AUDIT_FILE_TOO_LARGE",
        message="A Linux Audit file exceeds the size limit.",
    )

    monkeypatch.setattr(
        uploads_module,
        "LINUX_AUDIT_MAX_FILE_SIZE_BYTES",
        10,
    )
    monkeypatch.setattr(
        uploads_module,
        "LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES",
        8,
    )
    request_response = client.post(
        ENDPOINT,
        files=[multipart_file(b"aaaaa"), multipart_file(b"bbbbb")],
    )
    assert_error(
        request_response,
        status_code=413,
        code="LINUX_AUDIT_REQUEST_TOO_LARGE",
        message="Linux Audit upload size limit exceeded.",
    )


@pytest.mark.parametrize(
    ("content", "status_code", "code", "message"),
    [
        (
            b"",
            400,
            "EMPTY_LINUX_AUDIT_FILE",
            "A Linux Audit file is empty or contains only whitespace.",
        ),
        (
            b" \n\t",
            400,
            "EMPTY_LINUX_AUDIT_FILE",
            "A Linux Audit file is empty or contains only whitespace.",
        ),
        (
            b"\xff",
            400,
            "INVALID_LINUX_AUDIT_ENCODING",
            "Linux Audit input must be valid UTF-8.",
        ),
        (
            b"plain\x00binary",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
        (
            b"PK\x03\x04archive",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
        (
            b"\x1f\x8barchive",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
        (
            b"BZharchive",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
        (
            b"\xfd7zXZ\x00archive",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
        (
            b"a" * 257 + b"ustar" + b"tail",
            415,
            "UNSUPPORTED_LINUX_AUDIT_INPUT",
            "Linux Audit input format is not supported.",
        ),
    ],
)
def test_content_validation_errors_use_fixed_envelopes(
    content,
    status_code,
    code,
    message,
):
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=[multipart_file(
            content,
            filename=f"../../{CANARY}.zip",
            content_type=f"application/{CANARY}",
        )],
    )

    assert_error(
        response,
        status_code=status_code,
        code=code,
        message=message,
    )
    assert CANARY not in response.text
    assert all(CANARY not in value for value in response.headers.values())


def test_duplicate_and_all_malformed_inputs_use_fixed_envelopes():
    client = TestClient(enabled_app())
    duplicate = b"same nonempty content"
    duplicate_response = client.post(
        ENDPOINT,
        files=[
            multipart_file(duplicate, filename="first.audit"),
            multipart_file(duplicate, filename="second.txt"),
        ],
    )
    assert_error(
        duplicate_response,
        status_code=409,
        code="DUPLICATE_LINUX_AUDIT_FILE",
        message="Duplicate Linux Audit input is not allowed.",
    )

    malformed_response = client.post(
        ENDPOINT,
        files=[multipart_file(f"malformed {CANARY}\n".encode())],
    )
    assert_error(
        malformed_response,
        status_code=422,
        code="NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
        message="No eligible Linux Audit events were found.",
    )
    assert CANARY not in malformed_response.text


@pytest.mark.parametrize(
    ("stage", "error_factory", "expected_code", "expected_message"),
    [
        (
            "analysis",
            lambda: LinuxAuditAnalysisValidationError(
                "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR"
            ),
            "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
            "Linux Audit analysis could not be completed.",
        ),
        (
            "projection",
            LinuxAuditResponseProjectionError,
            "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR",
            "Linux Audit response could not be created.",
        ),
    ],
)
def test_analysis_and_projection_failures_use_existing_bounded_mapping(
    stage,
    error_factory,
    expected_code,
    expected_message,
    monkeypatch,
):
    def fail(*args, **kwargs):
        raise error_factory()

    monkeypatch.setattr(
        api_module,
        (
            "analyze_staged_linux_audit_inputs"
            if stage == "analysis"
            else "build_linux_audit_api_response"
        ),
        fail,
    )
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=fixture_files(LINKED_FIXTURE),
    )

    assert_error(
        response,
        status_code=500,
        code=expected_code,
        message=expected_message,
    )


def test_uuid_is_not_generated_before_staging_and_analysis_succeed(
    monkeypatch,
):
    uuid_calls = []

    def unexpected_uuid():
        uuid_calls.append(True)
        raise AssertionError("UUID must not be generated for failed analysis")

    monkeypatch.setattr(api_module.uuid, "uuid4", unexpected_uuid)
    missing = TestClient(enabled_app()).post(ENDPOINT)
    assert missing.status_code == 422

    def fail_analysis(staged_inputs):
        raise LinuxAuditAnalysisValidationError(
            "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR"
        )

    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        fail_analysis,
    )
    failed_analysis = TestClient(enabled_app()).post(
        ENDPOINT,
        files=fixture_files(LINKED_FIXTURE),
    )
    assert failed_analysis.status_code == 500
    assert uuid_calls == []


def test_unexpected_internal_error_is_fixed_and_contains_no_private_text(
    monkeypatch,
):
    def fail(staged_inputs):
        raise RuntimeError(
            f"{CANARY}: path=/private/tmp/private raw=private"
        )

    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        fail,
    )
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=fixture_files(LINKED_FIXTURE),
    )

    assert_error(
        response,
        status_code=500,
        code="INTERNAL_SERVER_ERROR",
        message="The request could not be completed.",
    )
    assert CANARY not in response.text
    assert "private" not in response.text.casefold()


def test_success_calls_each_layer_once_in_threadpool_and_cleans_up(
    monkeypatch,
    tmp_path,
):
    directories = track_request_directories(monkeypatch, tmp_path)
    original_stage = api_module.stage_linux_audit_uploads
    original_analysis = api_module.analyze_staged_linux_audit_inputs
    original_builder = api_module.build_linux_audit_api_response
    original_threadpool = api_module.run_in_threadpool
    calls = {"staging": 0, "analysis": 0, "projection": 0, "threadpool": 0}
    captured_uploads = []
    staged_paths = []
    thread_ids = {}

    @asynccontextmanager
    async def tracked_stage(files):
        calls["staging"] += 1
        captured_uploads.extend(files)
        async with original_stage(files) as staged_inputs:
            staged_paths.extend(item.path for item in staged_inputs)
            assert all(path.exists() for path in staged_paths)
            yield staged_inputs

    def tracked_analysis(staged_inputs):
        calls["analysis"] += 1
        thread_ids["worker"] = threading.get_ident()
        assert all(item.path.exists() for item in staged_inputs)
        return original_analysis(staged_inputs)

    def tracked_builder(analysis, *, analysis_id):
        calls["projection"] += 1
        assert all(path.exists() for path in staged_paths)
        return original_builder(analysis, analysis_id=analysis_id)

    async def tracked_threadpool(func, *args, **kwargs):
        calls["threadpool"] += 1
        thread_ids["event_loop"] = threading.get_ident()
        return await original_threadpool(func, *args, **kwargs)

    monkeypatch.setattr(api_module, "stage_linux_audit_uploads", tracked_stage)
    monkeypatch.setattr(
        api_module,
        "analyze_staged_linux_audit_inputs",
        tracked_analysis,
    )
    monkeypatch.setattr(
        api_module,
        "build_linux_audit_api_response",
        tracked_builder,
    )
    monkeypatch.setattr(api_module, "run_in_threadpool", tracked_threadpool)
    monkeypatch.setattr(api_module.uuid, "uuid4", lambda: ANALYSIS_ID)
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=[multipart_file(
            LINKED_FIXTURE.read_bytes(),
            filename=f"../../{CANARY}.audit",
            content_type=f"application/{CANARY}",
        )],
    )

    assert response.status_code == 200
    assert calls == {
        "staging": 1,
        "analysis": 1,
        "projection": 1,
        "threadpool": 1,
    }
    assert thread_ids["worker"] != thread_ids["event_loop"]
    assert response.json()["analysis_id"] == str(ANALYSIS_ID)
    assert all(not path.exists() for path in staged_paths)
    assert all(not directory.exists() for directory in directories)
    assert all(upload.file.closed for upload in captured_uploads)
    assert CANARY not in response.text
    assert all(CANARY not in value for value in response.headers.values())


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (
            (SHARED_FIXTURE,),
            {
                "process": (14, 12, 1, 1),
                "shared": 6,
                "session": (0, 0, 0, 0, 0, 0, 0),
            },
        ),
        (
            (SESSION_FIXTURE,),
            {
                "process": (18, 16, 1, 1),
                "shared": 0,
                "session": (2, 5, 3, 1, 1, 0, 0),
            },
        ),
        (
            (LINKED_FIXTURE,),
            {
                "process": (4, 3, 1, 0),
                "shared": 2,
                "session": (1, 3, 2, 1, 0, 1, 1),
            },
        ),
        (
            (SESSION_FIXTURE, LINKED_FIXTURE),
            {
                "process": (22, 19, 2, 1),
                "shared": 2,
                "session": (3, 8, 5, 2, 1, 1, 1),
            },
        ),
    ],
)
def test_enabled_endpoint_fixture_acceptance(
    paths,
    expected,
    monkeypatch,
):
    monkeypatch.setattr(api_module.uuid, "uuid4", lambda: ANALYSIS_ID)
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=fixture_files(*paths),
    )

    assert response.status_code == 200
    body = response.json()
    process = body["process_telemetry"]
    session = body["session_process_review"]
    assert set(body) == {
        "analysis_id",
        "status",
        "process_telemetry",
        "shared_memory_review",
        "session_process_review",
    }
    assert body["analysis_id"] == str(ANALYSIS_ID)
    assert body["status"] == "completed"
    assert (
        process["observation_count"],
        process["outcome_counts"]["success"],
        process["outcome_counts"]["failure"],
        process["outcome_counts"]["unknown"],
    ) == expected["process"]
    assert body["shared_memory_review"]["observation_count"] == (
        expected["shared"]
    )
    assert (
        session["session_co_observation_count"],
        session["process_observation_count"],
        session["outcome_counts"]["success"],
        session["outcome_counts"]["failure"],
        session["outcome_counts"]["unknown"],
        session["shared_memory_observation_count"],
        session["sessions_with_shared_memory_observation_count"],
    ) == expected["session"]
    assert "results" not in body
    assert "global_correlation" not in body
    assert "ai_summary" not in body


@pytest.mark.parametrize("failure_stage", ["analysis", "projection", "unexpected"])
def test_cleanup_is_preserved_for_every_post_staging_failure(
    failure_stage,
    monkeypatch,
    tmp_path,
):
    directories = track_request_directories(monkeypatch, tmp_path)

    def fail(*args, **kwargs):
        if failure_stage == "analysis":
            raise LinuxAuditAnalysisValidationError(
                "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR"
            )
        if failure_stage == "projection":
            raise LinuxAuditResponseProjectionError()
        raise RuntimeError(f"private {CANARY}")

    monkeypatch.setattr(
        api_module,
        (
            "build_linux_audit_api_response"
            if failure_stage == "projection"
            else "analyze_staged_linux_audit_inputs"
        ),
        fail,
    )
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=fixture_files(LINKED_FIXTURE),
    )

    assert response.status_code == 500
    assert all(not directory.exists() for directory in directories)
    assert CANARY not in response.text


def test_staging_failure_and_cancellation_cleanup(monkeypatch, tmp_path):
    directories = track_request_directories(monkeypatch, tmp_path)
    invalid_response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=[multipart_file(b"\xff")],
    )
    assert invalid_response.status_code == 400
    assert all(not directory.exists() for directory in directories)

    original_stage = api_module.stage_linux_audit_uploads
    staged_paths = []

    @asynccontextmanager
    async def tracked_stage(files):
        async with original_stage(files) as staged_inputs:
            staged_paths.extend(item.path for item in staged_inputs)
            yield staged_inputs

    async def cancel(func, *args, **kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(api_module, "stage_linux_audit_uploads", tracked_stage)
    monkeypatch.setattr(api_module, "run_in_threadpool", cancel)

    async def invoke():
        upload = uploads_module.UploadFile(
            file=LINKED_FIXTURE.open("rb"),
            filename="input.audit",
        )
        try:
            with pytest.raises(asyncio.CancelledError):
                await api_module.analyze_linux_audit_logs([upload])
        finally:
            await upload.close()

    asyncio.run(invoke())
    assert staged_paths
    assert all(not path.exists() for path in staged_paths)
    assert all(not directory.exists() for directory in directories)


def test_concurrent_requests_have_isolated_staging_and_deterministic_counts(
    monkeypatch,
    tmp_path,
):
    directories = track_request_directories(monkeypatch, tmp_path)
    monkeypatch.setattr(api_module.uuid, "uuid4", lambda: ANALYSIS_ID)
    configured_app = enabled_app()

    def request(path):
        return TestClient(configured_app).post(
            ENDPOINT,
            files=fixture_files(path),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(request, LINKED_FIXTURE)
        second = executor.submit(request, SESSION_FIXTURE)
        responses = (first.result(), second.result())

    assert [response.status_code for response in responses] == [200, 200]
    assert {
        response.json()["process_telemetry"]["observation_count"]
        for response in responses
    } == {4, 18}
    assert len(directories) == 2
    assert len(set(directories)) == 2
    assert all(not directory.exists() for directory in directories)


def test_success_privacy_canary_and_existing_llm_boundary(
    monkeypatch,
):
    def fail_llm(*args, **kwargs):
        raise AssertionError("Linux Audit endpoint must not call an LLM")

    monkeypatch.setattr(llm_module.genai, "Client", fail_llm)
    monkeypatch.setattr(api_module, "analyze", fail_llm)
    monkeypatch.setattr(api_module.uuid, "uuid4", lambda: ANALYSIS_ID)
    response = TestClient(enabled_app()).post(
        ENDPOINT,
        files=[multipart_file(
            SHARED_FIXTURE.read_bytes(),
            filename=f"../../{CANARY}.audit",
            content_type=f"application/{CANARY}",
        )],
    )

    assert response.status_code == 200
    assert CANARY not in response.text
    assert CANARY not in response.json()["analysis_id"]
    assert all(CANARY not in value for value in response.headers.values())
