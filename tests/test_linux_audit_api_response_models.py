import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from io import BytesIO
import json
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.datastructures import UploadFile

import app.analyzer.llm as llm_module
from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
    LinuxAuditApiAnalysis,
    analyze_staged_linux_audit_inputs,
)
from app.analyzer.pipeline import load_normalized_logs
from app.api import app
from app.api_uploads import (
    LinuxAuditUploadValidationError,
    stage_linux_audit_uploads,
)
from app.models.linux_audit_api import (
    CompletenessCountsResponse,
    LinuxAuditAnalysisResponse,
    LinuxAuditApiErrorDetail,
    LinuxAuditApiErrorResponse,
    LinuxAuditResponseProjectionError,
    OutcomeCountsResponse,
    ProcessTelemetryResponse,
    ProjectedLinuxAuditApiError,
    SessionProcessReviewResponse,
    SharedMemoryReviewResponse,
    build_linux_audit_api_response,
    project_linux_audit_api_error,
)


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

EXPECTED_RESPONSE_FIELDS = {
    "analysis_id",
    "status",
    "process_telemetry",
    "shared_memory_review",
    "session_process_review",
}

ERROR_CONTRACTS = {
    "MISSING_LINUX_AUDIT_FILES": (
        422,
        "At least one Linux Audit file is required.",
    ),
    "LINUX_AUDIT_FILE_COUNT_EXCEEDED": (
        413,
        "Linux Audit file count limit exceeded.",
    ),
    "LINUX_AUDIT_FILE_TOO_LARGE": (
        413,
        "A Linux Audit file exceeds the size limit.",
    ),
    "LINUX_AUDIT_REQUEST_TOO_LARGE": (
        413,
        "Linux Audit upload size limit exceeded.",
    ),
    "EMPTY_LINUX_AUDIT_FILE": (
        400,
        "A Linux Audit file is empty or contains only whitespace.",
    ),
    "INVALID_LINUX_AUDIT_ENCODING": (
        400,
        "Linux Audit input must be valid UTF-8.",
    ),
    "UNSUPPORTED_LINUX_AUDIT_INPUT": (
        415,
        "Linux Audit input format is not supported.",
    ),
    "DUPLICATE_LINUX_AUDIT_FILE": (
        409,
        "Duplicate Linux Audit input is not allowed.",
    ),
    "NO_ELIGIBLE_LINUX_AUDIT_EVENTS": (
        422,
        "No eligible Linux Audit events were found.",
    ),
    "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR": (
        500,
        "Linux Audit analysis could not be completed.",
    ),
    "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR": (
        500,
        "Linux Audit response could not be created.",
    ),
}


def valid_analysis(**changes):
    values = {
        "process_observation_count": 4,
        "process_outcome_success_count": 3,
        "process_outcome_failure_count": 1,
        "process_outcome_unknown_count": 0,
        "argv_complete_count": 4,
        "argv_incomplete_count": 0,
        "path_complete_count": 4,
        "path_incomplete_count": 0,
        "shared_memory_privileged_execution_observation_count": 2,
        "session_co_observation_count": 1,
        "session_process_observation_count": 3,
        "session_process_outcome_success_count": 2,
        "session_process_outcome_failure_count": 1,
        "session_process_outcome_unknown_count": 0,
        "session_linked_shared_memory_observation_count": 1,
        "sessions_with_shared_memory_observation_count": 1,
    }
    values.update(changes)
    return LinuxAuditApiAnalysis(**values)


def zero_analysis():
    return LinuxAuditApiAnalysis(
        process_observation_count=0,
        process_outcome_success_count=0,
        process_outcome_failure_count=0,
        process_outcome_unknown_count=0,
        argv_complete_count=0,
        argv_incomplete_count=0,
        path_complete_count=0,
        path_incomplete_count=0,
        shared_memory_privileged_execution_observation_count=0,
        session_co_observation_count=0,
        session_process_observation_count=0,
        session_process_outcome_success_count=0,
        session_process_outcome_failure_count=0,
        session_process_outcome_unknown_count=0,
        session_linked_shared_memory_observation_count=0,
        sessions_with_shared_memory_observation_count=0,
    )


def assert_projection_error(call):
    with pytest.raises(LinuxAuditResponseProjectionError) as caught:
        call()

    error = caught.value
    assert error.code == "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
    assert error.status_code == 500
    assert error.message == "Linux Audit response could not be created."
    assert str(error) == error.message
    assert set(vars(error)) == {"code", "status_code", "message"}
    return error


async def project_uploaded_files(*paths):
    uploads = tuple(
        UploadFile(BytesIO(path.read_bytes()))
        for path in paths
    )
    directories = []
    async with stage_linux_audit_uploads(uploads) as staged_inputs:
        directories.extend(item.path.parent for item in staged_inputs)
        analysis = analyze_staged_linux_audit_inputs(staged_inputs)
        response = build_linux_audit_api_response(
            analysis,
            analysis_id=ANALYSIS_ID,
        )
    return analysis, response, tuple(directories)


def fixture_projection(*paths):
    return asyncio.run(project_uploaded_files(*paths))


def test_models_have_exact_frozen_fields_and_forbid_extras():
    outcome = OutcomeCountsResponse(success=1, failure=0, unknown=0)
    completeness = CompletenessCountsResponse(complete=1, incomplete=0)
    process = ProcessTelemetryResponse(
        observation_count=1,
        outcome_counts=outcome,
        argv_completeness_counts=completeness,
        path_completeness_counts=completeness,
    )
    shared = SharedMemoryReviewResponse(observation_count=0)
    session = SessionProcessReviewResponse(
        session_co_observation_count=0,
        process_observation_count=0,
        outcome_counts=OutcomeCountsResponse(
            success=0,
            failure=0,
            unknown=0,
        ),
        shared_memory_observation_count=0,
        sessions_with_shared_memory_observation_count=0,
    )
    response = LinuxAuditAnalysisResponse(
        analysis_id=ANALYSIS_ID,
        status="completed",
        process_telemetry=process,
        shared_memory_review=shared,
        session_process_review=session,
    )

    assert tuple(OutcomeCountsResponse.model_fields) == (
        "success",
        "failure",
        "unknown",
    )
    assert tuple(CompletenessCountsResponse.model_fields) == (
        "complete",
        "incomplete",
    )
    assert tuple(ProcessTelemetryResponse.model_fields) == (
        "observation_count",
        "outcome_counts",
        "argv_completeness_counts",
        "path_completeness_counts",
    )
    assert tuple(SharedMemoryReviewResponse.model_fields) == (
        "observation_count",
    )
    assert tuple(SessionProcessReviewResponse.model_fields) == (
        "session_co_observation_count",
        "process_observation_count",
        "outcome_counts",
        "shared_memory_observation_count",
        "sessions_with_shared_memory_observation_count",
    )
    assert set(LinuxAuditAnalysisResponse.model_fields) == (
        EXPECTED_RESPONSE_FIELDS
    )

    with pytest.raises(ValidationError):
        OutcomeCountsResponse(
            success=1,
            failure=0,
            unknown=0,
            evidence="forbidden",
        )
    with pytest.raises(ValidationError):
        LinuxAuditAnalysisResponse(
            **response.model_dump(),
            raw_records=[],
        )
    with pytest.raises(ValidationError):
        response.status = "failed"


@pytest.mark.parametrize("invalid", [True, "1", 1.0, -1])
def test_counts_are_strict_non_negative_integers(invalid):
    with pytest.raises(ValidationError):
        OutcomeCountsResponse(
            success=invalid,
            failure=0,
            unknown=0,
        )


def test_status_uuid_and_canonical_deterministic_json_contract():
    response = build_linux_audit_api_response(
        valid_analysis(),
        analysis_id=ANALYSIS_ID,
    )
    first_dump = response.model_dump(mode="json")
    second_dump = response.model_dump(mode="json")

    assert first_dump == second_dump
    assert first_dump["analysis_id"] == str(ANALYSIS_ID)
    assert first_dump["status"] == "completed"
    assert response.model_dump_json() == response.model_dump_json()
    assert json.loads(response.model_dump_json()) == first_dump

    assert_projection_error(
        lambda: build_linux_audit_api_response(
            valid_analysis(),
            analysis_id=str(ANALYSIS_ID),
        )
    )
    with pytest.raises(ValidationError):
        LinuxAuditAnalysisResponse(
            **{
                **response.model_dump(),
                "analysis_id": str(ANALYSIS_ID),
            }
        )
    with pytest.raises(ValidationError):
        LinuxAuditAnalysisResponse(
            **{
                **response.model_dump(),
                "status": "failed",
            }
        )

    zero = build_linux_audit_api_response(
        zero_analysis(),
        analysis_id=ANALYSIS_ID,
    ).model_dump(mode="json")
    assert zero["process_telemetry"] == {
        "observation_count": 0,
        "outcome_counts": {"success": 0, "failure": 0, "unknown": 0},
        "argv_completeness_counts": {"complete": 0, "incomplete": 0},
        "path_completeness_counts": {"complete": 0, "incomplete": 0},
    }
    assert zero["shared_memory_review"] == {"observation_count": 0}
    assert zero["session_process_review"] == {
        "session_co_observation_count": 0,
        "process_observation_count": 0,
        "outcome_counts": {"success": 0, "failure": 0, "unknown": 0},
        "shared_memory_observation_count": 0,
        "sessions_with_shared_memory_observation_count": 0,
    }


def test_success_projection_is_explicit_fixed_and_does_not_mutate_input():
    analysis = valid_analysis()
    before = deepcopy(analysis)

    response = build_linux_audit_api_response(
        analysis,
        analysis_id=ANALYSIS_ID,
    )

    assert analysis == before
    assert response.model_dump(mode="json") == {
        "analysis_id": str(ANALYSIS_ID),
        "status": "completed",
        "process_telemetry": {
            "observation_count": 4,
            "outcome_counts": {
                "success": 3,
                "failure": 1,
                "unknown": 0,
            },
            "argv_completeness_counts": {
                "complete": 4,
                "incomplete": 0,
            },
            "path_completeness_counts": {
                "complete": 4,
                "incomplete": 0,
            },
        },
        "shared_memory_review": {"observation_count": 2},
        "session_process_review": {
            "session_co_observation_count": 1,
            "process_observation_count": 3,
            "outcome_counts": {
                "success": 2,
                "failure": 1,
                "unknown": 0,
            },
            "shared_memory_observation_count": 1,
            "sessions_with_shared_memory_observation_count": 1,
        },
    }

    source = Path("app/models/linux_audit_api.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "asdict(",
        "vars(analysis",
        "analysis.__dict__",
        "model_validate(analysis",
    ):
        assert forbidden not in source


@pytest.mark.parametrize(
    "analysis",
    [
        object(),
        valid_analysis(process_observation_count=True),
        valid_analysis(process_observation_count=-1),
        valid_analysis(process_observation_count=5),
        valid_analysis(argv_complete_count=3),
        valid_analysis(path_complete_count=3),
        valid_analysis(
            shared_memory_privileged_execution_observation_count=5
        ),
        valid_analysis(session_process_observation_count=4),
        valid_analysis(session_process_observation_count=5),
        valid_analysis(
            session_linked_shared_memory_observation_count=4
        ),
        valid_analysis(
            shared_memory_privileged_execution_observation_count=0
        ),
        valid_analysis(
            sessions_with_shared_memory_observation_count=2
        ),
        valid_analysis(
            session_linked_shared_memory_observation_count=0
        ),
        valid_analysis(
            session_co_observation_count=0,
        ),
    ],
)
def test_success_projection_rejects_type_count_and_cross_invariant_failures(
    analysis,
):
    assert_projection_error(
        lambda: build_linux_audit_api_response(
            analysis,
            analysis_id=ANALYSIS_ID,
        )
    )


def test_nested_models_enforce_their_own_count_invariants():
    with pytest.raises(ValidationError):
        ProcessTelemetryResponse(
            observation_count=2,
            outcome_counts=OutcomeCountsResponse(
                success=1,
                failure=0,
                unknown=0,
            ),
            argv_completeness_counts=CompletenessCountsResponse(
                complete=2,
                incomplete=0,
            ),
            path_completeness_counts=CompletenessCountsResponse(
                complete=2,
                incomplete=0,
            ),
        )
    with pytest.raises(ValidationError):
        SessionProcessReviewResponse(
            session_co_observation_count=0,
            process_observation_count=1,
            outcome_counts=OutcomeCountsResponse(
                success=1,
                failure=0,
                unknown=0,
            ),
            shared_memory_observation_count=0,
            sessions_with_shared_memory_observation_count=0,
        )


def test_error_models_are_exact_frozen_and_exclude_http_status():
    detail = LinuxAuditApiErrorDetail(
        code="EMPTY_LINUX_AUDIT_FILE",
        message="A Linux Audit file is empty or contains only whitespace.",
    )
    body = LinuxAuditApiErrorResponse(error=detail)

    assert body.model_dump(mode="json") == {
        "error": {
            "code": "EMPTY_LINUX_AUDIT_FILE",
            "message": (
                "A Linux Audit file is empty or contains only whitespace."
            ),
        }
    }
    assert "status_code" not in body.model_dump_json()
    with pytest.raises(ValidationError):
        LinuxAuditApiErrorDetail(code="UNKNOWN", message="unknown")
    with pytest.raises(ValidationError):
        LinuxAuditApiErrorDetail(
            code="EMPTY_LINUX_AUDIT_FILE",
            message="   ",
        )
    with pytest.raises(ValidationError):
        LinuxAuditApiErrorDetail(
            code="EMPTY_LINUX_AUDIT_FILE",
            message="tampered",
        )
    with pytest.raises(ValidationError):
        LinuxAuditApiErrorDetail(
            code="EMPTY_LINUX_AUDIT_FILE",
            message=400,
        )
    with pytest.raises(ValidationError):
        LinuxAuditApiErrorResponse(error=detail, path="forbidden")
    with pytest.raises(ValidationError):
        body.error = detail


@pytest.mark.parametrize("code", tuple(ERROR_CONTRACTS))
def test_all_known_errors_project_to_fixed_status_and_envelope(code):
    if code in {
        "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
        "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
    }:
        error = LinuxAuditAnalysisValidationError(code)
    elif code == "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR":
        error = LinuxAuditResponseProjectionError()
    else:
        error = LinuxAuditUploadValidationError(code)

    projected = project_linux_audit_api_error(error)
    expected_status, expected_message = ERROR_CONTRACTS[code]

    assert type(projected) is ProjectedLinuxAuditApiError
    assert projected.status_code == expected_status
    assert projected.body.model_dump(mode="json") == {
        "error": {"code": code, "message": expected_message}
    }
    assert "status_code" not in projected.body.model_dump(mode="json")
    with pytest.raises(FrozenInstanceError):
        projected.status_code = 200


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("code", f"{CANARY}-tampered"),
        ("code", []),
        ("status_code", f"{CANARY}-tampered"),
        ("message", f"{CANARY}-tampered"),
    ],
)
def test_tampered_known_errors_become_fixed_projection_error(
    attribute,
    value,
):
    error = LinuxAuditUploadValidationError("EMPTY_LINUX_AUDIT_FILE")
    setattr(error, attribute, value)

    projected = project_linux_audit_api_error(error)
    serialized = projected.body.model_dump_json()

    assert projected.status_code == 500
    assert json.loads(serialized) == {
        "error": {
            "code": "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR",
            "message": "Linux Audit response could not be created.",
        }
    }
    assert CANARY not in serialized
    assert CANARY not in repr(projected)


def test_unknown_exception_and_subclass_text_are_not_copied():
    class UploadErrorSubclass(LinuxAuditUploadValidationError):
        pass

    for error in (
        RuntimeError(f"private path and raw data: {CANARY}"),
        UploadErrorSubclass("EMPTY_LINUX_AUDIT_FILE"),
    ):
        projected = project_linux_audit_api_error(error)
        output = projected.body.model_dump_json()
        assert projected.status_code == 500
        assert CANARY not in output
        assert CANARY not in repr(projected)
        assert "private path" not in output

    missing_attribute = LinuxAuditUploadValidationError(
        "EMPTY_LINUX_AUDIT_FILE"
    )
    del missing_attribute.code
    projected = project_linux_audit_api_error(missing_attribute)
    assert projected.body.error.code == (
        "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
    )


def test_json_schema_is_fixed_and_contains_no_privacy_fields_or_canary():
    schema = LinuxAuditAnalysisResponse.model_json_schema()
    serialized = json.dumps(schema, sort_keys=True)
    property_names = set(schema["properties"])

    assert set(schema["properties"]) == EXPECTED_RESPONSE_FIELDS
    assert schema["additionalProperties"] is False
    for definition in schema["$defs"].values():
        assert definition["additionalProperties"] is False
        property_names.update(definition.get("properties", {}))

    assert CANARY not in serialized
    for forbidden_field in (
        "raw_records",
        "argv",
        "executable",
        "source_instance",
        "event_id",
        "timestamp",
        "path",
        "filename",
        "risk",
        "severity",
        "confidence",
        "verdict",
    ):
        assert forbidden_field not in property_names


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            SHARED_FIXTURE,
            {
                "process": (14, 12, 1, 1),
                "shared": 6,
                "session": (0, 0, 0, 0, 0, 0, 0),
            },
        ),
        (
            SESSION_FIXTURE,
            {
                "process": (18, 16, 1, 1),
                "shared": 0,
                "session": (2, 5, 3, 1, 1, 0, 0),
            },
        ),
        (
            LINKED_FIXTURE,
            {
                "process": (4, 3, 1, 0),
                "shared": 2,
                "session": (1, 3, 2, 1, 0, 1, 1),
            },
        ),
    ],
)
def test_fixture_projection_through_staging_analysis_and_json(path, expected):
    analysis, response, directories = fixture_projection(path)
    data = response.model_dump(mode="json")
    process = data["process_telemetry"]
    session = data["session_process_review"]

    assert response.analysis_id == ANALYSIS_ID
    assert (
        process["observation_count"],
        process["outcome_counts"]["success"],
        process["outcome_counts"]["failure"],
        process["outcome_counts"]["unknown"],
    ) == expected["process"]
    assert data["shared_memory_review"]["observation_count"] == (
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
    assert json.loads(response.model_dump_json()) == data
    assert all(not directory.exists() for directory in directories)
    assert all(
        type(getattr(analysis, field.name)) is int
        for field in fields(analysis)
    )


def test_combined_fixture_projection_is_deterministic_and_scope_isolated():
    first = fixture_projection(SESSION_FIXTURE, LINKED_FIXTURE)
    second = fixture_projection(SESSION_FIXTURE, LINKED_FIXTURE)
    data = first[1].model_dump(mode="json")
    session = data["session_process_review"]

    assert first[1] == second[1]
    assert data["process_telemetry"]["observation_count"] == 22
    assert data["shared_memory_review"]["observation_count"] == 2
    assert session["session_co_observation_count"] == 3
    assert session["process_observation_count"] == 8
    assert session["outcome_counts"] == {
        "success": 5,
        "failure": 2,
        "unknown": 1,
    }
    assert session["shared_memory_observation_count"] == 1
    assert session["sessions_with_shared_memory_observation_count"] == 1
    assert all(
        not directory.exists()
        for directory in (*first[2], *second[2])
    )


def test_privacy_canary_stays_internal_and_never_enters_projection():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "path": SHARED_FIXTURE,
        "source_instance": CANARY,
    }])
    event = next(
        item
        for item in logs
        if item.linux_audit.event_id.endswith(":2014")
    )
    event_before = deepcopy(event)
    assert CANARY in event.process_execution.argv
    assert CANARY in repr(event.process_execution.raw_records)
    assert CANARY in event.raw

    analysis, response, _ = fixture_projection(SHARED_FIXTURE)
    outputs = (
        repr(analysis),
        repr(response),
        json.dumps(response.model_dump(mode="json"), sort_keys=True),
        response.model_dump_json(),
        json.dumps(response.model_json_schema(), sort_keys=True),
    )
    assert all(CANARY not in output for output in outputs)
    assert event == event_before


def test_projection_failure_inside_staging_still_cleans_directory():
    async def run():
        upload = UploadFile(BytesIO(LINKED_FIXTURE.read_bytes()))
        directories = []
        with pytest.raises(LinuxAuditResponseProjectionError):
            async with stage_linux_audit_uploads((upload,)) as inputs:
                directories.append(inputs[0].path.parent)
                analysis = analyze_staged_linux_audit_inputs(inputs)
                build_linux_audit_api_response(
                    replace(analysis, process_observation_count=-1),
                    analysis_id=ANALYSIS_ID,
                )
        return directories

    directories = asyncio.run(run())
    assert all(not directory.exists() for directory in directories)


def test_existing_openapi_health_api_cli_and_llm_boundaries(monkeypatch):
    def fail_llm(*args, **kwargs):
        raise AssertionError("LLM provider boundary was crossed")

    monkeypatch.setattr(llm_module.genai, "Client", fail_llm)
    response = build_linux_audit_api_response(
        valid_analysis(),
        analysis_id=ANALYSIS_ID,
    )
    assert response.status == "completed"

    schema = app.openapi()
    assert set(schema["paths"]) == {"/api/health", "/api/analyze"}
    assert "/api/analyze-linux-audit" not in schema["paths"]
    assert not any(
        "LinuxAudit" in name
        for name in schema.get("components", {}).get("schemas", {})
    )
    health = TestClient(app).get("/api/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    api_source = Path("app/api.py").read_text(encoding="utf-8")
    cli_source = Path("app/main.py").read_text(encoding="utf-8")
    assert "models.linux_audit_api" not in api_source
    assert "build_linux_audit_api_response" not in api_source
    assert "models.linux_audit_api" not in cli_source
