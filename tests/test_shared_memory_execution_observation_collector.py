from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import app.detector.shared_memory_execution as detector_module
from app.analyzer.llm import serialize_value
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.detector.shared_memory_execution import (
    DETECTION_TYPE,
    SharedMemoryExecutionObservation,
    collect_shared_memory_execution_observations,
    detect_shared_memory_privileged_execution,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import _analyze_normalized_logs
from app.models.schemas import (
    Evidence,
    LinuxAuditContext,
    LinuxAuditPathContext,
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


def fixture_events(path=CONTRACT_FIXTURE, source_instance="phase-3w-e"):
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


def valid_event(**scope_changes):
    context = ProcessExecutionContext(
        outcome="success",
        architecture_raw="c000003e",
        syscall_raw="59",
        architecture_name=None,
        syscall_name=None,
        exit_code=0,
        process_id=4001,
        parent_process_id=4000,
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
        terminal=None,
        audit_rule_key=None,
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
    linux_audit = LinuxAuditContext(
        event_id="1792000000.001:3001",
        record_types=("SYSCALL", "EXECVE"),
        executable=context.executable,
        source_instance="collector-fixture",
        node="collector-node",
    )
    linux_audit = replace(linux_audit, **scope_changes)
    return NormalizedEvent(
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
        linux_audit=linux_audit,
        process_execution=context,
    )


def positive_result(event):
    return detect_shared_memory_privileged_execution(event)


def test_observation_is_a_frozen_scalar_projection():
    event = valid_event()
    observation = collect_shared_memory_execution_observations([event])[0]

    assert tuple(field.name for field in fields(observation)) == (
        "timestamp",
        "source",
        "event_type",
        "source_instance",
        "node",
        "event_id",
        "detection_type",
        "shared_memory_executable_path",
        "effective_user_id",
        "syscall_outcome",
    )
    assert observation == SharedMemoryExecutionObservation(
        timestamp=event.timestamp,
        source="linux_audit",
        event_type="process_execution_attempt",
        source_instance="collector-fixture",
        node="collector-node",
        event_id="1792000000.001:3001",
        detection_type=DETECTION_TYPE,
        shared_memory_executable_path="/dev/shm/telemetry-probe",
        effective_user_id=0,
        syscall_outcome="success",
    )
    assert all(
        not isinstance(getattr(observation, field.name), (list, dict))
        for field in fields(observation)
    )
    with pytest.raises(FrozenInstanceError):
        observation.event_id = "changed"


class SinglePassIterable:
    def __init__(self, values):
        self.values = values
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("iterable consumed more than once")
        yield from self.values


def test_empty_mixed_and_generator_inputs_are_single_pass():
    positive = valid_event()
    negative = replace(positive, event_type="authentication_attempt")
    values = SinglePassIterable([None, negative, positive, {}, positive])

    assert collect_shared_memory_execution_observations([]) == ()
    observations = collect_shared_memory_execution_observations(values)

    assert values.iterations == 1
    assert len(observations) == 2
    assert observations[0] == observations[1]


def test_contract_fixture_projects_only_positive_boundaries_in_input_order():
    events = fixture_events()
    observations = collect_shared_memory_execution_observations(events)

    assert [observation.event_id.rsplit(":", 1)[1] for observation in observations] == [
        "2001",
        "2002",
        "2011",
        "2012",
        "2013",
        "2014",
    ]
    assert [
        observation.shared_memory_executable_path
        for observation in observations[:2]
    ] == [
        "/dev/shm/telemetry-probe",
        "/run/shm/audit-observation",
    ]
    assert all(
        event_by_serial(events, serial).process_execution.argv_complete is False
        for serial in (2011,)
    )
    assert event_by_serial(events, 2012).process_execution.paths == ()
    assert event_by_serial(events, 2013).process_execution.paths_complete is False
    assert not {
        str(serial) for serial in range(2003, 2011)
    }.intersection(
        observation.event_id.rsplit(":", 1)[1]
        for observation in observations
    )


def test_scope_projection_preserves_optional_values_and_reference_parts():
    event = valid_event(source_instance=None, node=None)
    observation = collect_shared_memory_execution_observations([event])[0]

    assert observation.source_instance is None
    assert observation.node is None
    assert (
        observation.source_instance,
        observation.node,
        observation.event_id,
        observation.detection_type,
    ) == (None, None, "1792000000.001:3001", DETECTION_TYPE)

    scoped = fixture_events(SCOPE_FIXTURE, "scope-a")
    other_source = fixture_events(SCOPE_FIXTURE, "scope-b")
    observations = collect_shared_memory_execution_observations(
        [*scoped, *other_source]
    )
    references = {
        (
            item.source_instance,
            item.node,
            item.event_id,
            item.detection_type,
        )
        for item in observations
    }

    assert len(observations) == 8
    assert len(references) == 8
    assert {
        (item.source_instance, item.node)
        for item in observations
        if item.event_id == "1791000020.001:2020"
    } == {
        ("scope-a", "shared-memory-node-a"),
        ("scope-a", "shared-memory-node-b"),
        ("scope-b", "shared-memory-node-a"),
        ("scope-b", "shared-memory-node-b"),
    }


def test_input_order_and_duplicate_occurrences_are_preserved():
    first = valid_event(event_id="1792000002.001:3002")
    second = valid_event(event_id="1792000001.001:3001")

    forward = collect_shared_memory_execution_observations(
        [first, second, first]
    )
    reverse = collect_shared_memory_execution_observations(
        [second, first]
    )

    assert [item.event_id for item in forward] == [
        "1792000002.001:3002",
        "1792000001.001:3001",
        "1792000002.001:3002",
    ]
    assert [item.event_id for item in reverse] == [
        "1792000001.001:3001",
        "1792000002.001:3002",
    ]
    assert forward[0] == forward[2]
    assert collect_shared_memory_execution_observations(
        [first, second, first]
    ) == forward


def test_positive_evidence_order_does_not_affect_projection(monkeypatch):
    event = valid_event()
    result = positive_result(event)
    result.evidence.reverse()
    monkeypatch.setattr(
        detector_module,
        "detect_shared_memory_privileged_execution",
        lambda item: result,
    )

    observation = collect_shared_memory_execution_observations([event])[0]

    assert observation.shared_memory_executable_path == (
        "/dev/shm/telemetry-probe"
    )
    assert observation.effective_user_id == 0
    assert observation.syscall_outcome == "success"


@pytest.mark.parametrize(
    "violation",
    [
        "missing",
        "duplicate",
        "unexpected",
        "detection_type",
        "executable",
        "effective_user_id",
        "outcome",
        "source",
        "timestamp",
        "time_range",
    ],
)
def test_malformed_positive_detection_is_an_explicit_contract_error(
    monkeypatch,
    violation,
):
    event = valid_event()
    result = positive_result(event)

    if violation == "missing":
        result.evidence = result.evidence[:2]
    elif violation == "duplicate":
        result.evidence = [result.evidence[0], result.evidence[0], result.evidence[2]]
    elif violation == "unexpected":
        result.evidence[0].type = "unexpected"
    elif violation == "detection_type":
        result.detection_type = "Different Observation"
    elif violation == "executable":
        result.evidence[0].value = "/dev/shm/different"
    elif violation == "effective_user_id":
        result.evidence[1].value = False
    elif violation == "outcome":
        result.evidence[2].value = "failure"
    elif violation == "source":
        result.evidence[0].source = "application"
    elif violation == "timestamp":
        result.evidence[0].timestamp += timedelta(seconds=1)
    elif violation == "time_range":
        result.evidence[0].time_range = (event.timestamp, event.timestamp)

    monkeypatch.setattr(
        detector_module,
        "detect_shared_memory_privileged_execution",
        lambda item: result,
    )

    with pytest.raises(ValueError):
        collect_shared_memory_execution_observations([event])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("linux_audit", None),
        ("event_id", None),
        ("event_id", "   "),
        ("source_instance", 123),
        ("node", []),
    ],
)
def test_invalid_positive_event_scope_is_an_explicit_contract_error(
    field,
    value,
):
    event = valid_event()
    if field == "linux_audit":
        event = replace(event, linux_audit=value)
    else:
        event = replace(
            event,
            linux_audit=replace(event.linux_audit, **{field: value}),
        )

    with pytest.raises(ValueError):
        collect_shared_memory_execution_observations([event])


def test_projection_is_independent_from_mutable_detection_result(monkeypatch):
    event = valid_event()
    original = deepcopy(event)
    result = positive_result(event)
    monkeypatch.setattr(
        detector_module,
        "detect_shared_memory_privileged_execution",
        lambda item: result,
    )

    observations = collect_shared_memory_execution_observations([event])
    result.detection_type = "mutated"
    result.evidence[0].value = "mutated"
    result.evidence.clear()

    assert observations[0].detection_type == DETECTION_TYPE
    assert observations[0].shared_memory_executable_path == (
        "/dev/shm/telemetry-probe"
    )
    assert event == original
    assert event.process_execution.raw_records == original.process_execution.raw_records
    with pytest.raises(TypeError):
        observations[0] = observations[0]


def test_private_canary_is_excluded_and_scope_canary_stays_internal(capsys):
    private_path = LinuxAuditPathContext(
        item=0,
        name=f"/private/{CANARY}",
        nametype="NORMAL",
        inode=1,
        device="00:00",
        mode="0100600",
        owner_user_id=0,
        owner_group_id=0,
    )
    base = valid_event()
    private_context = replace(
        base.process_execution,
        command_name=CANARY,
        audit_rule_key=CANARY,
        argv=(base.process_execution.executable, CANARY),
        argument_count=2,
        working_directory=f"/work/{CANARY}",
        paths=(private_path,),
        proctitle_raw=CANARY,
        proctitle_arguments=(CANARY,),
        raw_records=(f"raw={CANARY}",),
    )
    private_event = replace(
        base,
        raw=f"raw={CANARY}",
        process_execution=private_context,
    )
    original = deepcopy(private_event)

    private_observation = collect_shared_memory_execution_observations(
        [private_event]
    )[0]
    assert CANARY in repr(private_event.process_execution)
    assert CANARY not in repr(private_observation)

    scope_event = replace(
        base,
        linux_audit=replace(
            base.linux_audit,
            source_instance=CANARY,
            node=CANARY,
        ),
    )
    scope_observation = collect_shared_memory_execution_observations(
        [scope_event]
    )[0]
    assert scope_observation.source_instance == CANARY
    assert scope_observation.node == CANARY

    analysis = _analyze_normalized_logs([scope_event])
    aggregate = aggregate_process_execution_observations([scope_event])
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
    assert set(analysis) == {"results", "global_correlation"}
    assert private_event == original
