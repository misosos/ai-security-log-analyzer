from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from app.analyzer.llm import serialize_value
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.detector.shared_memory_execution import (
    DETECTION_TYPE,
    detect_shared_memory_privileged_execution,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze
from app.models.schemas import (
    NormalizedEvent,
    ProcessExecutionContext,
)
from app.parser.linux_audit import parse_linux_audit_events


FIXTURE_DIR = Path("sample_logs")
CONTRACT_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_shared_memory_execution_contract_synthetic.log"
)
SCOPE_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_shared_memory_execution_scope_synthetic.log"
)
CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"


def process_context(**changes):
    context = ProcessExecutionContext(
        outcome="success",
        architecture_raw="c000003e",
        syscall_raw="59",
        architecture_name=None,
        syscall_name=None,
        exit_code=0,
        process_id=3001,
        parent_process_id=3000,
        real_user_id=0,
        effective_user_id=0,
        saved_user_id=0,
        filesystem_user_id=0,
        real_group_id=0,
        effective_group_id=0,
        saved_group_id=0,
        filesystem_group_id=0,
        command_name="telemetry-probe",
        executable="/dev/shm/telemetry-probe",
        terminal="pts0",
        audit_rule_key="shared-memory-observation",
        argument_count=1,
        argv=("/dev/shm/telemetry-probe",),
        argv_complete=True,
        incomplete_argument_indexes=(),
        working_directory=None,
        paths=(),
        paths_complete=True,
        proctitle_raw=None,
        proctitle_arguments=None,
        raw_records=("synthetic raw evidence",),
    )
    return replace(context, **changes)


def process_event(context=None, **changes):
    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 26, tzinfo=timezone.utc),
        event_type="process_execution_attempt",
        source="linux_audit",
        user=None,
        src_ip=None,
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw="synthetic syscall evidence",
        process_execution=context or process_context(),
    )
    return replace(event, **changes)


def fixture_events(path=CONTRACT_FIXTURE, source_instance="phase-3w-c"):
    return [
        normalized
        for group in load_linux_audit_events(
            path,
            source_instance=source_instance,
        )
        for normalized in parse_linux_audit_events(group)
        if normalized.event_type == "process_execution_attempt"
    ]


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


@pytest.mark.parametrize(
    "executable",
    [
        "/dev/shm/telemetry-probe",
        "/run/shm/audit-observation",
        "/dev/shm/nested/fixture-runner",
        "/run/shm/nested/fixture-runner",
    ],
)
def test_positive_paths_produce_bounded_detection(executable):
    event = process_event(process_context(executable=executable))

    result = detect_shared_memory_privileged_execution(event)

    assert result.is_detected is True
    assert result.detection_type == DETECTION_TYPE
    assert [evidence.type for evidence in result.evidence] == [
        "shared_memory_executable_path",
        "effective_user_id",
        "syscall_outcome",
    ]
    assert [evidence.value for evidence in result.evidence] == [
        executable,
        0,
        "success",
    ]
    assert all(
        evidence.source == "linux_audit"
        and evidence.timestamp == event.timestamp
        for evidence in result.evidence
    )


def test_phase_3w_b_positive_fixtures_match_with_allowlisted_evidence():
    events = fixture_events()

    for serial in (2001, 2002):
        result = detect_shared_memory_privileged_execution(
            event_by_serial(events, serial)
        )

        assert result.is_detected is True
        assert len(result.evidence) == 3
        assert {evidence.type for evidence in result.evidence} == {
            "shared_memory_executable_path",
            "effective_user_id",
            "syscall_outcome",
        }


@pytest.mark.parametrize(
    ("event_change", "context_change"),
    [
        ({"event_type": "authentication_attempt"}, {}),
        ({"source": "application"}, {}),
        ({"process_execution": None}, {}),
        ({}, {"outcome": "failure"}),
        ({}, {"outcome": "unknown"}),
        ({}, {"outcome": "unexpected"}),
        ({}, {"effective_user_id": None}),
        ({}, {"effective_user_id": 1000}),
        ({}, {"executable": None}),
    ],
)
def test_missing_or_mismatched_required_evidence_is_a_safe_non_match(
    event_change,
    context_change,
):
    context = process_context(**context_change)
    event = process_event(context, **event_change)

    result = detect_shared_memory_privileged_execution(event)

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []


@pytest.mark.parametrize(
    "effective_user_id",
    [False, True, "0", 0.0, -1, 1, [], {}],
)
def test_effective_user_id_requires_exact_integer_zero(effective_user_id):
    event = process_event(process_context(
        effective_user_id=effective_user_id,
    ))

    assert detect_shared_memory_privileged_execution(
        event
    ).is_detected is False


@pytest.mark.parametrize(
    "executable",
    [None, "", "   ", b"/dev/shm/file", [], {}],
)
def test_executable_requires_a_non_empty_string(executable):
    event = process_event(process_context(executable=executable))

    assert detect_shared_memory_privileged_execution(
        event
    ).is_detected is False


@pytest.mark.parametrize(
    "executable",
    [
        "/dev/shm",
        "/dev/shm/",
        "/run/shm",
        "/run/shm/",
        "/dev/shm-backup/file",
        "/dev/shm_backup/file",
        "/run/shm-backup/file",
        "/run/shm_backup/file",
        "/tmp/file",
        "/var/tmp/file",
        "/var/run/file",
        "/var/lock/file",
        "dev/shm/file",
        "/opt/dev/shm/file",
    ],
)
def test_path_boundary_rejects_broad_relative_or_similar_paths(executable):
    event = process_event(process_context(executable=executable))

    assert detect_shared_memory_privileged_execution(
        event
    ).is_detected is False


def test_dot_segments_are_preserved_as_observed_without_canonicalization():
    executable = "/dev/shm/../fixture-runner"
    event = process_event(process_context(executable=executable))

    result = detect_shared_memory_privileged_execution(event)

    assert result.is_detected is True
    assert result.evidence[0].value == executable


def test_non_event_and_unexpected_context_object_are_safe_non_matches():
    invalid_context_event = process_event(process_execution={})

    for value in (None, {}, [], invalid_context_event):
        result = detect_shared_memory_privileged_execution(value)
        assert result.is_detected is False
        assert result.detection_type is None
        assert result.evidence == []


def test_optional_evidence_does_not_change_required_condition_result():
    events = fixture_events()

    for serial in (2011, 2012, 2013):
        event = event_by_serial(events, serial)
        result = detect_shared_memory_privileged_execution(event)

        assert result.is_detected is True
        assert len(result.evidence) == 3
        assert {
            evidence.type for evidence in result.evidence
        } == {
            "shared_memory_executable_path",
            "effective_user_id",
            "syscall_outcome",
        }


@pytest.mark.parametrize(
    "serial",
    [2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010],
)
def test_phase_3w_b_negative_and_missing_boundaries_do_not_match(serial):
    event = event_by_serial(fixture_events(), serial)

    result = detect_shared_memory_privileged_execution(event)

    assert result.is_detected is False
    assert result.detection_type is None
    assert result.evidence == []


def test_scope_order_and_repeated_invocation_are_deterministic_and_pure():
    events = fixture_events(SCOPE_FIXTURE)
    original = deepcopy(events)

    forward = {
        (
            event.linux_audit.source_instance,
            event.linux_audit.node,
            event.linux_audit.event_id,
        ): detect_shared_memory_privileged_execution(event)
        for event in events
    }
    reverse = {
        (
            event.linux_audit.source_instance,
            event.linux_audit.node,
            event.linux_audit.event_id,
        ): detect_shared_memory_privileged_execution(event)
        for event in reversed(events)
    }

    assert forward == reverse
    assert all(result.is_detected is True for result in forward.values())
    assert events == original
    assert all(
        detect_shared_memory_privileged_execution(event)
        == detect_shared_memory_privileged_execution(event)
        for event in events
    )


def test_privacy_canary_is_not_copied_into_detection_or_external_outputs(
    capsys,
):
    events = fixture_events(CONTRACT_FIXTURE, CANARY)
    event = event_by_serial(events, 2014)
    original = deepcopy(event)
    context = event.process_execution

    assert CANARY in repr(context)
    assert CANARY in event.raw

    result = detect_shared_memory_privileged_execution(event)
    assert result.is_detected is True
    assert CANARY not in repr(result)
    assert [evidence.type for evidence in result.evidence] == [
        "shared_memory_executable_path",
        "effective_user_id",
        "syscall_outcome",
    ]

    aggregate = aggregate_process_execution_observations(events)
    analysis = analyze([{
        "source": "linux_audit",
        "path": CONTRACT_FIXTURE,
        "source_instance": CANARY,
    }])
    print_analysis_result(
        analysis,
        process_execution_aggregate=aggregate,
    )
    cli_output = capsys.readouterr().out
    api_output = build_analysis_response(
        analysis,
        total_sources=1,
    ).model_dump()
    llm_output = serialize_value(analysis)

    assert CANARY not in cli_output
    assert CANARY not in json.dumps(api_output, sort_keys=True)
    assert CANARY not in json.dumps(llm_output, sort_keys=True)
    assert event == original


def test_detection_wording_stays_bounded_to_observed_telemetry():
    result = detect_shared_memory_privileged_execution(process_event())
    prohibited = {
        "malware",
        "fileless malware",
        "compromise",
        "privilege escalation",
        "attack success",
        "exploit",
        "confirmed attack",
        "benign",
        "safe",
    }
    observed_wording = " ".join((
        result.detection_type,
        *(evidence.type for evidence in result.evidence),
    )).lower()

    assert all(term not in observed_wording for term in prohibited)
