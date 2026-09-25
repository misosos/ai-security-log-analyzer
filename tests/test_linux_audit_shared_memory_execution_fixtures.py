from copy import deepcopy
import json
from pathlib import Path

import pytest

from app.analyzer.llm import serialize_value
from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze
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


def load_groups(path=CONTRACT_FIXTURE, source_instance="phase-3w-b"):
    return load_linux_audit_events(
        path,
        source_instance=source_instance,
    )


def process_events(path=CONTRACT_FIXTURE, source_instance="phase-3w-b"):
    return [
        normalized
        for group in load_groups(path, source_instance)
        for normalized in parse_linux_audit_events(group)
        if normalized.event_type == "process_execution_attempt"
    ]


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


def semantic_process_values(event):
    context = event.process_execution
    return (
        context.outcome,
        context.effective_user_id,
        context.executable,
        context.argv,
        context.argv_complete,
        context.working_directory,
        tuple((path.item, path.name) for path in context.paths),
        context.paths_complete,
        context.proctitle_arguments,
        event.linux_audit.audit_session_id,
    )


def test_contract_fixture_loads_and_normalizes_every_intended_group():
    groups = load_groups()
    events = process_events()

    assert len(groups) == 14
    assert len(events) == 14
    assert all(event.source == "linux_audit" for event in events)
    assert all(event.process_execution is not None for event in events)
    assert all(
        event.linux_audit.source_instance == "phase-3w-b"
        for event in events
    )
    assert {
        group.event_id for group in groups
    } == {
        event.linux_audit.event_id for event in events
    }
    assert all(
        context_record in {
            record.raw for record in group.records
        }
        for group, event in zip(groups, events, strict=True)
        for context_record in event.process_execution.raw_records
    )


@pytest.mark.parametrize(
    ("serial", "executable"),
    [
        (2001, "/dev/shm/telemetry-probe"),
        (2002, "/run/shm/audit-observation"),
    ],
)
def test_positive_contract_preserves_exact_observed_evidence(
    serial,
    executable,
):
    event = event_by_serial(process_events(), serial)
    context = event.process_execution

    assert context.outcome == "success"
    assert context.effective_user_id == 0
    assert context.executable == executable
    assert context.argv_complete is True


@pytest.mark.parametrize(
    ("serial", "outcome", "effective_user_id", "executable"),
    [
        (2003, "success", 0, "/usr/bin/fixture-runner"),
        (2004, "success", 1000, "/dev/shm/telemetry-probe"),
        (2005, "failure", 0, "/dev/shm/telemetry-probe"),
        (2006, "unknown", 0, "/run/shm/audit-observation"),
        (2007, "success", 0, "/tmp/fixture-runner"),
        (2008, "success", 0, "/dev/shm-backup/fixture-runner"),
        (2009, "success", 0, "/run/shm_backup/fixture-runner"),
        (2010, "success", 0, None),
    ],
)
def test_negative_boundaries_preserve_the_condition_that_is_not_met(
    serial,
    outcome,
    effective_user_id,
    executable,
):
    context = event_by_serial(process_events(), serial).process_execution

    assert context.outcome == outcome
    assert context.effective_user_id == effective_user_id
    assert context.executable == executable


def test_incomplete_argv_remains_a_process_event_with_bounded_uncertainty():
    event = event_by_serial(process_events(), 2011)
    context = event.process_execution

    assert context.outcome == "success"
    assert context.effective_user_id == 0
    assert context.executable == "/dev/shm/telemetry-probe"
    assert context.argv == ("/dev/shm/telemetry-probe", None)
    assert context.argv_complete is False
    assert context.incomplete_argument_indexes == (1,)


def test_optional_record_absence_does_not_remove_core_process_observation():
    event = event_by_serial(process_events(), 2012)
    context = event.process_execution

    assert context.executable == "/run/shm/audit-observation"
    assert context.working_directory is None
    assert context.paths == ()
    assert context.paths_complete is True
    assert context.proctitle_raw is None
    assert context.proctitle_arguments is None


def test_optional_conflicts_remain_ambiguous_without_removing_core_event():
    event = event_by_serial(process_events(), 2013)
    context = event.process_execution

    assert context.outcome == "success"
    assert context.effective_user_id == 0
    assert context.executable == "/run/shm/audit-observation"
    assert context.working_directory is None
    assert len(context.paths) == 2
    assert context.paths_complete is False
    assert context.proctitle_raw is None
    assert context.proctitle_arguments is None
    assert len(context.raw_records) == 8


def test_scope_fixture_isolates_node_source_event_and_preserves_sessions():
    first = process_events(SCOPE_FIXTURE, "fixture-feed-a")
    second = process_events(SCOPE_FIXTURE, "fixture-feed-b")

    assert len(first) == len(second) == 4
    assert {
        (
            event.linux_audit.source_instance,
            event.linux_audit.node,
            event.linux_audit.event_id,
        )
        for event in (*first, *second)
    } == {
        (source, node, event_id)
        for source in ("fixture-feed-a", "fixture-feed-b")
        for node, event_id in (
            ("shared-memory-node-a", "1791000020.001:2020"),
            ("shared-memory-node-b", "1791000020.001:2020"),
            ("shared-memory-node-a", "1791000021.002:2021"),
            ("shared-memory-node-a", "1791000022.003:2022"),
        )
    }
    assert [
        event.linux_audit.audit_session_id for event in first
    ] == [521, 521, 522, 522]


def test_record_order_permutation_and_repeated_parsing_are_deterministic():
    first_groups = load_groups(SCOPE_FIXTURE)
    before = deepcopy(first_groups)
    first = process_events(SCOPE_FIXTURE)
    second = process_events(SCOPE_FIXTURE)

    node_a = next(
        event for event in first
        if event.linux_audit.event_id == "1791000020.001:2020"
        and event.linux_audit.node == "shared-memory-node-a"
    )
    node_b = next(
        event for event in first
        if event.linux_audit.event_id == "1791000020.001:2020"
        and event.linux_audit.node == "shared-memory-node-b"
    )

    assert semantic_process_values(node_a) == semantic_process_values(node_b)
    assert first == second
    assert first_groups == before


def test_loader_ignores_a_malformed_line_without_losing_valid_groups(
    tmp_path,
):
    path = tmp_path / "shared-memory-with-malformed-line.log"
    path.write_text(
        CONTRACT_FIXTURE.read_text(encoding="utf-8")
        + "not-an-audit-record\n",
        encoding="utf-8",
    )

    assert len(load_groups(path)) == 14
    assert len(process_events(path)) == 14


def test_privacy_canary_stays_internal_and_external_boundaries_remain_clean(
    capsys,
):
    source_instance = CANARY
    events = process_events(CONTRACT_FIXTURE, source_instance)
    event = event_by_serial(events, 2014)
    original = deepcopy(event)
    context = event.process_execution

    assert CANARY in context.argv
    assert CANARY in context.proctitle_arguments
    assert CANARY in repr(context.raw_records)
    assert CANARY in context.working_directory
    assert CANARY in context.paths[0].name
    assert context.command_name == CANARY
    assert context.audit_rule_key == CANARY
    assert event.linux_audit.node == CANARY
    assert event.linux_audit.source_instance == CANARY
    assert CANARY in event.raw

    aggregate = aggregate_process_execution_observations(events)
    analysis = analyze([{
        "source": "linux_audit",
        "path": CONTRACT_FIXTURE,
        "source_instance": source_instance,
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

    assert CANARY not in repr(aggregate)
    assert CANARY not in cli_output
    assert CANARY not in json.dumps(api_output, sort_keys=True)
    assert CANARY not in json.dumps(llm_output, sort_keys=True)
    assert event == original
