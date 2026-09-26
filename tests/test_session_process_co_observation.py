from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
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
from app.correlation.session_process import (
    SessionProcessCoObservation,
    collect_session_process_co_observations,
)
from app.detector.shared_memory_execution import (
    collect_shared_memory_execution_observations,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze, main
from app.models.schemas import NormalizedEvent
from app.parser.linux_audit import parse_linux_audit_events


FIXTURE_DIR = Path("sample_logs")
CONTRACT_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_session_process_co_observation_contract_synthetic.log"
)
SCOPE_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_session_process_co_observation_scope_synthetic.log"
)
SHARED_MEMORY_FIXTURE = (
    FIXTURE_DIR
    / "linux_audit_shared_memory_execution_contract_synthetic.log"
)
SOURCE_INSTANCE = "session-process-collector"
CANARY = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"


def fixture_events(path=CONTRACT_FIXTURE, source_instance=SOURCE_INSTANCE):
    return tuple(
        normalized
        for group in load_linux_audit_events(
            path,
            source_instance=source_instance,
        )
        for normalized in parse_linux_audit_events(group)
    )


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


def session_events(events, session_id):
    return tuple(
        event
        for event in events
        if event.linux_audit.audit_session_id == session_id
    )


def valid_triplet():
    events = fixture_events()
    return tuple(
        deepcopy(event_by_serial(events, serial))
        for serial in (3001, 3002, 3003)
    )


def replace_audit(event, **changes):
    return replace(
        event,
        linux_audit=replace(event.linux_audit, **changes),
    )


class SinglePassIterable:
    def __init__(self, values):
        self.values = values
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("iterable consumed more than once")
        yield from self.values


def test_relation_is_a_frozen_fixed_immutable_projection():
    relation = collect_session_process_co_observations(valid_triplet())[0]

    assert tuple(field.name for field in fields(relation)) == (
        "source_instance",
        "node",
        "audit_session_id",
        "audit_user_id",
        "session_start_timestamp",
        "session_start_event_id",
        "session_end_timestamp",
        "session_end_event_id",
        "process_observation_count",
        "process_outcome_success_count",
        "process_outcome_failure_count",
        "process_outcome_unknown_count",
        "process_event_ids",
    )
    assert all(
        not isinstance(getattr(relation, field.name), (dict, list))
        for field in fields(relation)
    )
    with pytest.raises(FrozenInstanceError):
        relation.audit_session_id = 999


def test_empty_mixed_generator_input_is_single_pass_and_safely_filtered():
    start, process, end = valid_triplet()
    values = SinglePassIterable([
        None,
        {},
        replace(process, source="other"),
        start,
        process,
        end,
    ])

    assert collect_session_process_co_observations(()) == ()
    relations = collect_session_process_co_observations(values)

    assert values.iterations == 1
    assert len(relations) == 1


def test_contract_fixture_produces_expected_single_and_multiple_relations():
    relations = collect_session_process_co_observations(fixture_events())

    assert len(relations) == 2
    first, second = relations
    assert first == SessionProcessCoObservation(
        source_instance=SOURCE_INSTANCE,
        node="session-process-contract",
        audit_session_id=601,
        audit_user_id=1601,
        session_start_timestamp=event_by_serial(
            fixture_events(),
            3001,
        ).timestamp,
        session_start_event_id="1792000000.000:3001",
        session_end_timestamp=event_by_serial(
            fixture_events(),
            3003,
        ).timestamp,
        session_end_event_id="1792000002.000:3003",
        process_observation_count=1,
        process_outcome_success_count=1,
        process_outcome_failure_count=0,
        process_outcome_unknown_count=0,
        process_event_ids=("1792000001.000:3002",),
    )
    assert second.process_observation_count == 4
    assert (
        second.process_outcome_success_count,
        second.process_outcome_failure_count,
        second.process_outcome_unknown_count,
    ) == (2, 1, 1)
    assert second.process_event_ids == (
        "1792000010.000:3011",
        "1792000011.000:3012",
        "1792000011.000:3013",
        "1792000012.000:3014",
    )


def test_process_timestamp_interval_is_inclusive_at_both_boundaries():
    events = fixture_events()
    relation = collect_session_process_co_observations(
        session_events(events, 602)
    )[0]

    assert relation.process_event_ids[0].endswith(":3011")
    assert relation.process_event_ids[-1].endswith(":3014")
    assert event_by_serial(events, 3011).timestamp == (
        relation.session_start_timestamp
    )
    assert event_by_serial(events, 3014).timestamp == (
        relation.session_end_timestamp
    )


@pytest.mark.parametrize("session_id", range(603, 612))
def test_incomplete_ambiguous_or_empty_lifecycle_does_not_create_relation(
    session_id,
):
    events = fixture_events()

    assert collect_session_process_co_observations(
        session_events(events, session_id)
    ) == ()


@pytest.mark.parametrize(
    "serials",
    [
        (3110, 3111, 3112),
        (3120, 3121, 3122),
        (3130, 3131, 3132),
        (3140, 3141, 3142),
        (3150, 3151, 3152),
    ],
)
def test_missing_unset_identity_or_node_is_not_joinable(serials):
    events = fixture_events()

    assert collect_session_process_co_observations(
        tuple(event_by_serial(events, serial) for serial in serials)
    ) == ()


def test_scope_fixture_separates_node_session_and_audit_user_boundaries():
    relations = collect_session_process_co_observations(
        fixture_events(SCOPE_FIXTURE, "scope-source")
    )

    assert len(relations) == 2
    assert {
        (
            relation.source_instance,
            relation.node,
            relation.audit_session_id,
            relation.audit_user_id,
        )
        for relation in relations
    } == {
        ("scope-source", "session-reuse-a", 705, 1705),
        ("scope-source", "session-reuse-b", 705, 1705),
    }
    assert all(relation.process_observation_count == 1 for relation in relations)


def test_same_event_and_session_values_remain_isolated_by_source_and_node():
    first = valid_triplet()
    second = tuple(
        replace_audit(
            event,
            source_instance="other-source",
            node="other-node",
        )
        for event in first
    )

    relations = collect_session_process_co_observations((*second, *first))

    assert len(relations) == 2
    assert {relation.source_instance for relation in relations} == {
        SOURCE_INSTANCE,
        "other-source",
    }
    assert {relation.node for relation in relations} == {
        "session-process-contract",
        "other-node",
    }
    assert relations[0].process_event_ids == relations[1].process_event_ids


def test_pid_uid_executable_terminal_and_optional_evidence_are_not_join_keys():
    start, process, end = valid_triplet()
    changed_context = replace(
        process.process_execution,
        process_id=9999,
        parent_process_id=9998,
        real_user_id=7,
        effective_user_id=8,
        executable=None,
        terminal="different-terminal",
        argument_count=2,
        argv=("/usr/bin/telemetry-probe", None),
        argv_complete=False,
        incomplete_argument_indexes=(1,),
        working_directory=None,
        paths=(),
        paths_complete=False,
        proctitle_raw=None,
        proctitle_arguments=None,
    )
    process = replace(
        replace_audit(
            process,
            process_user_id=77,
            executable=None,
            terminal="different-terminal",
        ),
        user="different-user",
        process_execution=changed_context,
    )

    relation = collect_session_process_co_observations(
        (start, process, end)
    )[0]

    assert relation.process_observation_count == 1
    assert relation.process_event_ids == (process.linux_audit.event_id,)


def test_duplicate_and_same_timestamp_processes_are_preserved_deterministically():
    events = fixture_events()
    start = event_by_serial(events, 3010)
    first = event_by_serial(events, 3012)
    second = event_by_serial(events, 3013)
    end = event_by_serial(events, 3015)
    ordered = (start, first, first, second, end)

    relation = collect_session_process_co_observations(ordered)[0]

    assert relation.process_observation_count == 3
    assert relation.process_event_ids == (
        first.linux_audit.event_id,
        first.linux_audit.event_id,
        second.linux_audit.event_id,
    )
    assert relation.process_outcome_failure_count == 2
    assert relation.process_outcome_unknown_count == 1
    assert collect_session_process_co_observations(reversed(ordered)) == (
        relation,
    )


def test_reversed_fixture_order_and_repeated_calls_are_deterministic():
    events = fixture_events()
    expected = collect_session_process_co_observations(events)

    assert collect_session_process_co_observations(reversed(events)) == expected
    assert collect_session_process_co_observations(events) == expected


@pytest.mark.parametrize(
    "change",
    [
        {"source_instance": None},
        {"source_instance": "   "},
        {"node": None},
        {"node": ""},
        {"audit_session_id": False},
        {"audit_session_id": -1},
        {"audit_user_id": "1601"},
        {"audit_user_id": -1},
        {"event_id": "   "},
    ],
)
def test_malformed_scope_values_are_safely_excluded(change):
    start, process, end = valid_triplet()
    process = replace_audit(process, **change)

    assert collect_session_process_co_observations(
        (start, process, end)
    ) == ()


def test_naive_timestamp_and_invalid_runtime_context_are_safely_excluded():
    start, process, end = valid_triplet()
    naive_start = replace(
        start,
        timestamp=start.timestamp.replace(tzinfo=None),
    )
    naive_process = replace(
        process,
        timestamp=process.timestamp.replace(tzinfo=None),
    )
    invalid_context = replace(process, process_execution={})
    invalid_lifecycle = replace(start, authentication={})

    assert collect_session_process_co_observations(
        (naive_start, process, end)
    ) == ()
    assert collect_session_process_co_observations(
        (start, naive_process, end)
    ) == ()
    assert collect_session_process_co_observations(
        (start, invalid_context, end)
    ) == ()
    assert collect_session_process_co_observations(
        (invalid_lifecycle, process, end)
    ) == ()


@pytest.mark.parametrize("outcome", ["failure", "unknown", "unexpected"])
def test_non_success_lifecycle_endpoint_is_not_eligible(outcome):
    start, process, end = valid_triplet()
    start = replace(
        start,
        authentication=replace(start.authentication, outcome=outcome),
    )

    assert collect_session_process_co_observations(
        (start, process, end)
    ) == ()


def test_unexpected_process_outcome_is_counted_as_unknown():
    start, process, end = valid_triplet()
    process = replace(
        process,
        process_execution=replace(
            process.process_execution,
            outcome="unexpected",
        ),
    )

    relation = collect_session_process_co_observations(
        (start, process, end)
    )[0]

    assert relation.process_observation_count == 1
    assert relation.process_outcome_success_count == 0
    assert relation.process_outcome_failure_count == 0
    assert relation.process_outcome_unknown_count == 1


def test_outcome_count_invariant_holds_for_every_fixture_relation():
    relations = collect_session_process_co_observations(fixture_events())

    assert all(
        relation.process_observation_count
        == relation.process_outcome_success_count
        + relation.process_outcome_failure_count
        + relation.process_outcome_unknown_count
        for relation in relations
    )


def test_privacy_canary_is_not_projected_or_exposed_to_existing_consumers(
    capsys,
):
    events = fixture_events()
    process = event_by_serial(events, 3002)
    before = deepcopy(events)

    assert CANARY in process.process_execution.argv
    assert any(CANARY in raw for raw in process.process_execution.raw_records)

    relations = collect_session_process_co_observations(events)
    serialized_relations = serialize_value(relations)
    analysis = analyze([
        {
            "source": "linux_audit",
            "path": str(CONTRACT_FIXTURE),
            "source_instance": SOURCE_INSTANCE,
        }
    ])
    aggregate = aggregate_process_execution_observations(events)
    print_analysis_result(
        analysis,
        process_execution_aggregate=aggregate,
    )
    main(["--linux-audit", str(CONTRACT_FIXTURE)])
    cli_output = capsys.readouterr().out
    api_response = build_analysis_response(analysis, total_sources=1)
    llm_payload = serialize_value(analysis)

    assert CANARY not in repr(relations)
    assert CANARY not in json.dumps(serialized_relations, default=str)
    assert CANARY not in cli_output
    assert CANARY not in json.dumps(api_response.model_dump(), default=str)
    assert CANARY not in json.dumps(llm_payload, default=str)
    assert events == before
    assert set(analysis) == {"results", "global_correlation"}


def test_existing_shared_memory_collector_and_analysis_contract_are_unchanged():
    shared_memory_events = fixture_events(
        SHARED_MEMORY_FIXTURE,
        "shared-memory-regression",
    )
    observations = collect_shared_memory_execution_observations(
        shared_memory_events
    )
    analysis = analyze()

    assert len(observations) == 6
    assert set(analysis) == {"results", "global_correlation"}
    assert "session_process_co_observation" not in analysis
