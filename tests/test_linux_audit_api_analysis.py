import asyncio
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from io import BytesIO
import json
from pathlib import Path

import pytest
from starlette.datastructures import UploadFile

import app.analyzer.linux_audit_api as analysis_module
import app.analyzer.llm as llm_module
from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
    LinuxAuditApiAnalysis,
    analyze_staged_linux_audit_inputs,
)
from app.analyzer.pipeline import load_normalized_logs
from app.api import app
from app.api_uploads import (
    StagedLinuxAuditInput,
    stage_linux_audit_uploads,
)
from app.correlation.session_process import SessionProcessReviewSummary
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionReviewSummary,
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
CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"

RESULT_FIELDS = (
    "process_observation_count",
    "process_outcome_success_count",
    "process_outcome_failure_count",
    "process_outcome_unknown_count",
    "argv_complete_count",
    "argv_incomplete_count",
    "path_complete_count",
    "path_incomplete_count",
    "shared_memory_privileged_execution_observation_count",
    "session_co_observation_count",
    "session_process_observation_count",
    "session_process_outcome_success_count",
    "session_process_outcome_failure_count",
    "session_process_outcome_unknown_count",
    "session_linked_shared_memory_observation_count",
    "sessions_with_shared_memory_observation_count",
)


def staged(path=SHARED_FIXTURE, source_instance="api-linux-audit-1"):
    return StagedLinuxAuditInput(
        path=path,
        source_instance=source_instance,
        size_bytes=path.stat().st_size,
    )


def assert_contract_error(call):
    with pytest.raises(LinuxAuditAnalysisValidationError) as caught:
        call()

    error = caught.value
    assert error.code == "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR"
    assert error.status_code == 500
    assert error.message == "Linux Audit analysis could not be completed."
    assert str(error) == error.message
    assert set(vars(error)) == {"code", "status_code", "message"}
    return error


def valid_aggregate(count=0):
    return {
        "observation_count": count,
        "outcome_counts": {
            "success": count,
            "failure": 0,
            "unknown": 0,
        },
        "argv_completeness_counts": {
            "complete": count,
            "incomplete": 0,
        },
        "path_completeness_counts": {
            "complete": count,
            "incomplete": 0,
        },
    }


async def analyze_uploaded_contents(*contents):
    uploads = tuple(UploadFile(BytesIO(content)) for content in contents)
    directories = []
    async with stage_linux_audit_uploads(uploads) as staged_inputs:
        directories.extend(item.path.parent for item in staged_inputs)
        result = analyze_staged_linux_audit_inputs(staged_inputs)
    return result, tuple(directories)


def analyze_uploaded_files(*paths):
    return asyncio.run(
        analyze_uploaded_contents(
            *(path.read_bytes() for path in paths)
        )
    )


def test_result_is_frozen_exact_fixed_scalar_allowlist():
    result, _ = analyze_uploaded_files(LINKED_FIXTURE)

    assert tuple(field.name for field in fields(result)) == RESULT_FIELDS
    assert all(
        type(getattr(result, field_name)) is int
        and getattr(result, field_name) >= 0
        for field_name in RESULT_FIELDS
    )
    assert not any(
        isinstance(getattr(result, field_name), (dict, list, tuple))
        for field_name in RESULT_FIELDS
    )
    with pytest.raises(FrozenInstanceError):
        result.process_observation_count = 0


@pytest.mark.parametrize("value", [[], None, "staged", ()])
def test_invalid_or_empty_top_level_contract_is_bounded(value):
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs(value)
    )


@pytest.mark.parametrize(
    "item",
    [
        object(),
        StagedLinuxAuditInput("not-a-path", "source", 1),
        StagedLinuxAuditInput(SHARED_FIXTURE, "", 1),
        StagedLinuxAuditInput(SHARED_FIXTURE, 7, 1),
        StagedLinuxAuditInput(SHARED_FIXTURE, "source", True),
        StagedLinuxAuditInput(SHARED_FIXTURE, "source", 0),
        StagedLinuxAuditInput(SHARED_FIXTURE, "source", -1),
    ],
)
def test_invalid_staged_item_contract_is_bounded(item):
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((item,))
    )


def test_duplicate_source_instance_and_path_are_rejected():
    first = staged(SHARED_FIXTURE, "same-source")
    same_source = staged(SESSION_FIXTURE, "same-source")
    same_path = staged(SHARED_FIXTURE, "other-source")

    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((first, same_source))
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((first, same_path))
    )


def test_source_projection_order_single_load_and_producer_object_identity(
    monkeypatch,
):
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "path": LINKED_FIXTURE,
        "source_instance": "fixture-source",
    }])
    logs_before = deepcopy(logs)
    source_configs_seen = []
    log_object_ids = []
    shared_objects = ()
    original_aggregate = (
        analysis_module.aggregate_process_execution_observations
    )
    original_collect_shared = (
        analysis_module.collect_shared_memory_execution_observations
    )
    original_summarize_shared = (
        analysis_module.summarize_shared_memory_execution_observations
    )
    original_collect_sessions = (
        analysis_module.collect_session_process_co_observations
    )
    original_summarize_sessions = (
        analysis_module.summarize_session_process_co_observations
    )
    calls = {
        "loader": 0,
        "aggregate": 0,
        "shared_collector": 0,
        "shared_summary": 0,
        "session_collector": 0,
        "session_summary": 0,
    }

    def loader(configs):
        calls["loader"] += 1
        source_configs_seen.extend(configs)
        return logs

    def aggregate(events):
        calls["aggregate"] += 1
        log_object_ids.append(id(events))
        return original_aggregate(events)

    def collect_shared(events):
        nonlocal shared_objects
        calls["shared_collector"] += 1
        log_object_ids.append(id(events))
        shared_objects = original_collect_shared(events)
        return shared_objects

    def summarize_shared(observations):
        calls["shared_summary"] += 1
        assert observations is shared_objects
        return original_summarize_shared(observations)

    def collect_sessions(events):
        calls["session_collector"] += 1
        log_object_ids.append(id(events))
        return original_collect_sessions(events)

    def summarize_sessions(relations, observations):
        calls["session_summary"] += 1
        assert observations is shared_objects
        return original_summarize_sessions(relations, observations)

    monkeypatch.setattr(analysis_module, "load_normalized_logs", loader)
    monkeypatch.setattr(
        analysis_module,
        "aggregate_process_execution_observations",
        aggregate,
    )
    monkeypatch.setattr(
        analysis_module,
        "collect_shared_memory_execution_observations",
        collect_shared,
    )
    monkeypatch.setattr(
        analysis_module,
        "summarize_shared_memory_execution_observations",
        summarize_shared,
    )
    monkeypatch.setattr(
        analysis_module,
        "collect_session_process_co_observations",
        collect_sessions,
    )
    monkeypatch.setattr(
        analysis_module,
        "summarize_session_process_co_observations",
        summarize_sessions,
    )

    inputs = (
        staged(SHARED_FIXTURE, "api-linux-audit-1"),
        staged(SESSION_FIXTURE, "api-linux-audit-2"),
    )
    before = tuple(inputs)
    result = analyze_staged_linux_audit_inputs(inputs)

    assert source_configs_seen == [
        {
            "source": "linux_audit",
            "path": SHARED_FIXTURE,
            "source_instance": "api-linux-audit-1",
        },
        {
            "source": "linux_audit",
            "path": SESSION_FIXTURE,
            "source_instance": "api-linux-audit-2",
        },
    ]
    assert calls == {name: 1 for name in calls}
    assert set(log_object_ids) == {id(logs)}
    assert inputs == before
    assert logs == logs_before
    assert result.session_linked_shared_memory_observation_count == 1


@pytest.mark.parametrize("loader_result", [(), [object()]])
def test_loader_runtime_contract_failure_is_bounded(
    loader_result,
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_module,
        "load_normalized_logs",
        lambda configs: loader_result,
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )


@pytest.mark.parametrize(
    "aggregate",
    [
        {},
        {**valid_aggregate(), "unexpected": 0},
        {**valid_aggregate(), "observation_count": True},
        {**valid_aggregate(), "observation_count": -1},
        {
            **valid_aggregate(1),
            "outcome_counts": {"success": 0, "failure": 0},
        },
        {
            **valid_aggregate(1),
            "argv_completeness_counts": {
                "complete": 0,
                "incomplete": 0,
            },
        },
    ],
)
def test_process_aggregate_exact_shape_scalar_and_invariants(
    aggregate,
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_module,
        "aggregate_process_execution_observations",
        lambda logs: aggregate,
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )


@pytest.mark.parametrize(
    "summary",
    [
        object(),
        SharedMemoryExecutionReviewSummary(True),
        SharedMemoryExecutionReviewSummary(-1),
        SharedMemoryExecutionReviewSummary(15),
    ],
)
def test_shared_summary_contract_and_cross_count_invariant(
    summary,
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_module,
        "summarize_shared_memory_execution_observations",
        lambda observations: summary,
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )


@pytest.mark.parametrize(
    "summary",
    [
        object(),
        SessionProcessReviewSummary(1, 1, True, 0, 0, 0, 0),
        SessionProcessReviewSummary(1, 2, 1, 0, 0, 0, 0),
        SessionProcessReviewSummary(0, 1, 1, 0, 0, 0, 0),
        SessionProcessReviewSummary(1, 15, 15, 0, 0, 0, 0),
        SessionProcessReviewSummary(1, 1, 1, 0, 0, 2, 1),
        SessionProcessReviewSummary(1, 1, 1, 0, 0, 1, 0),
        SessionProcessReviewSummary(1, 1, 1, 0, 0, 0, 1),
    ],
)
def test_session_summary_contract_and_cross_summary_invariants(
    summary,
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_module,
        "summarize_session_process_co_observations",
        lambda relations, observations: summary,
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )


@pytest.mark.parametrize(
    "producer_name",
    [
        "aggregate_process_execution_observations",
        "collect_shared_memory_execution_observations",
        "summarize_shared_memory_execution_observations",
        "collect_session_process_co_observations",
        "summarize_session_process_co_observations",
    ],
)
def test_producer_type_and_value_failures_are_bounded(
    producer_name,
    monkeypatch,
):
    def fail(*args, **kwargs):
        raise ValueError(f"private path: {CANARY}")

    monkeypatch.setattr(analysis_module, producer_name, fail)
    error = assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )
    assert CANARY not in repr(error)


@pytest.mark.parametrize(
    ("producer_name", "invalid_value"),
    [
        ("collect_shared_memory_execution_observations", []),
        (
            "collect_shared_memory_execution_observations",
            (object(),),
        ),
        ("collect_session_process_co_observations", []),
        ("collect_session_process_co_observations", (object(),)),
    ],
)
def test_collector_exact_tuple_item_contract_is_validated(
    producer_name,
    invalid_value,
    monkeypatch,
):
    monkeypatch.setattr(
        analysis_module,
        producer_name,
        lambda logs: invalid_value,
    )
    assert_contract_error(
        lambda: analyze_staged_linux_audit_inputs((staged(),))
    )


def test_all_malformed_is_rejected_but_lifecycle_only_is_valid(tmp_path):
    malformed = tmp_path / "malformed.audit"
    malformed.write_text("not an audit record\n", encoding="utf-8")

    with pytest.raises(LinuxAuditAnalysisValidationError) as caught:
        analyze_staged_linux_audit_inputs((staged(malformed),))
    assert caught.value.code == "NO_ELIGIBLE_LINUX_AUDIT_EVENTS"
    assert caught.value.status_code == 422
    assert caught.value.message == (
        "No eligible Linux Audit events were found."
    )

    lifecycle = tmp_path / "lifecycle.audit"
    lifecycle.write_text(
        "type=USER_START msg=audit(1710000000.000:1): "
        "pid=1 uid=0 auid=1000 ses=1 "
        "msg='op=PAM:session_open acct=test exe=/usr/sbin/sshd "
        "hostname=node addr=192.0.2.1 terminal=ssh res=success'\n",
        encoding="utf-8",
    )
    result = analyze_staged_linux_audit_inputs((staged(lifecycle),))
    assert result.process_observation_count == 0
    assert result.session_process_observation_count == 0


def test_partially_malformed_input_succeeds_without_raw_line_projection(
    tmp_path,
):
    malformed_line = "PRIVATE_MALFORMED_RAW_CANARY"
    path = tmp_path / "partial.audit"
    path.write_text(
        f"{malformed_line}\n"
        + LINKED_FIXTURE.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = analyze_staged_linux_audit_inputs((staged(path),))

    assert result.process_observation_count == 4
    assert malformed_line not in repr(result)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            SHARED_FIXTURE,
            (14, 12, 1, 1, 13, 1, 13, 1, 6, 0, 0, 0, 0, 0, 0, 0),
        ),
        (
            SESSION_FIXTURE,
            (18, 16, 1, 1, 18, 0, 18, 0, 0, 2, 5, 3, 1, 1, 0, 0),
        ),
        (
            LINKED_FIXTURE,
            (4, 3, 1, 0, 4, 0, 4, 0, 2, 1, 3, 2, 1, 0, 1, 1),
        ),
    ],
)
def test_existing_fixture_acceptance_through_upload_staging(path, expected):
    result, directories = analyze_uploaded_files(path)

    assert tuple(getattr(result, name) for name in RESULT_FIELDS) == expected
    assert all(not directory.exists() for directory in directories)


def test_multiple_uploaded_files_preserve_scope_and_combined_counts():
    first, first_directories = analyze_uploaded_files(
        SESSION_FIXTURE,
        LINKED_FIXTURE,
    )
    second, second_directories = analyze_uploaded_files(
        SESSION_FIXTURE,
        LINKED_FIXTURE,
    )

    assert first == second
    assert first.process_observation_count == 22
    assert first.session_co_observation_count == 3
    assert first.session_process_observation_count == 8
    assert (
        first.session_process_outcome_success_count,
        first.session_process_outcome_failure_count,
        first.session_process_outcome_unknown_count,
    ) == (5, 2, 1)
    assert first.shared_memory_privileged_execution_observation_count == 2
    assert first.session_linked_shared_memory_observation_count == 1
    assert first.sessions_with_shared_memory_observation_count == 1
    assert all(
        not directory.exists()
        for directory in (*first_directories, *second_directories)
    )


def test_privacy_canary_stays_internal_without_mutation_or_llm_call(
    monkeypatch,
):
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "path": SHARED_FIXTURE,
        "source_instance": CANARY,
    }])
    canary_event = next(
        event
        for event in logs
        if event.linux_audit.event_id.endswith(":2014")
    )
    original_raw = canary_event.raw
    assert CANARY in canary_event.process_execution.argv
    assert CANARY in repr(canary_event.process_execution.raw_records)
    assert CANARY in canary_event.raw

    def fail_llm(*args, **kwargs):
        raise AssertionError("LLM provider boundary was crossed")

    monkeypatch.setattr(llm_module, "generate_security_summary", fail_llm)
    monkeypatch.setattr(llm_module, "generate_overall_summary", fail_llm)
    result = analyze_staged_linux_audit_inputs((staged(),))
    serialized = json.dumps(
        {name: getattr(result, name) for name in RESULT_FIELDS},
        sort_keys=True,
    )

    assert CANARY not in repr(result)
    assert CANARY not in serialized
    assert canary_event.raw == original_raw


def test_failed_orchestration_still_cleans_staging_directory():
    async def run():
        upload = UploadFile(BytesIO(b"not an audit record\n"))
        directories = []
        with pytest.raises(LinuxAuditAnalysisValidationError) as caught:
            async with stage_linux_audit_uploads((upload,)) as inputs:
                directories.append(inputs[0].path.parent)
                analyze_staged_linux_audit_inputs(inputs)
        assert caught.value.code == "NO_ELIGIBLE_LINUX_AUDIT_EVENTS"
        return directories

    directories = asyncio.run(run())
    assert all(not directory.exists() for directory in directories)


def test_existing_api_routes_openapi_and_new_helper_isolation():
    assert set(app.openapi()["paths"]) == {"/api/health", "/api/analyze"}
    assert "/api/analyze-linux-audit" not in app.openapi()["paths"]

    api_source = Path("app/api.py").read_text(encoding="utf-8")
    assert "linux_audit_api" not in api_source
    assert "analyze_staged_linux_audit_inputs" not in api_source
    assert "linux_audit_api" not in Path("app/main.py").read_text(
        encoding="utf-8"
    )
