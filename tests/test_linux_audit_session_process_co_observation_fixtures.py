from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

from app.analyzer.llm import serialize_value
from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.detector.shared_memory_execution import (
    collect_shared_memory_execution_observations,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze
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
SOURCE_INSTANCE = "session-process-contract"
CANARY = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"


def load_groups(path=CONTRACT_FIXTURE, source_instance=SOURCE_INSTANCE):
    return load_linux_audit_events(path, source_instance=source_instance)


def normalized_events(path=CONTRACT_FIXTURE, source_instance=SOURCE_INSTANCE):
    return tuple(
        event
        for group in load_groups(path, source_instance)
        for event in parse_linux_audit_events(group)
    )


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


def events_for_session(events, session_id):
    return tuple(
        event
        for event in events
        if event.linux_audit.audit_session_id == session_id
    )


def observable_values(event):
    audit = event.linux_audit
    process = event.process_execution
    return (
        event.timestamp,
        event.event_type,
        event.source,
        audit.source_instance,
        audit.node,
        audit.event_id,
        audit.audit_session_id,
        audit.audit_user_id,
        None if process is None else process.outcome,
    )


def test_contract_fixture_preserves_every_group_and_normalized_event():
    groups = load_groups()
    events = normalized_events()

    assert len(groups) == 50
    assert len(events) == 50
    assert Counter(event.event_type for event in events) == {
        "process_execution_attempt": 18,
        "session_start": 16,
        "session_end": 16,
    }
    assert {group.event_id for group in groups} == {
        event.linux_audit.event_id for event in events
    }
    assert all(event.source == "linux_audit" for event in events)
    assert all(
        event.linux_audit.source_instance == SOURCE_INSTANCE
        for event in events
    )


def test_complete_lifecycle_preserves_strict_join_fields_and_roles():
    events = normalized_events()
    start = event_by_serial(events, 3001)
    process = event_by_serial(events, 3002)
    end = event_by_serial(events, 3003)
    expected_key = (
        SOURCE_INSTANCE,
        "session-process-contract",
        601,
        1601,
    )

    assert (start.event_type, process.event_type, end.event_type) == (
        "session_start",
        "process_execution_attempt",
        "session_end",
    )
    assert all(
        (
            event.linux_audit.source_instance,
            event.linux_audit.node,
            event.linux_audit.audit_session_id,
            event.linux_audit.audit_user_id,
        )
        == expected_key
        for event in (start, process, end)
    )
    assert (
        start.authentication.outcome
        == end.authentication.outcome
        == "success"
    )
    assert start.timestamp < process.timestamp < end.timestamp
    assert process.process_execution is not None

    # These observed values are deliberately not part of the strict join key.
    assert start.user == "fixture-account-a"
    assert process.user is None
    assert start.linux_audit.process_user_id != (
        process.linux_audit.process_user_id
    )
    assert start.linux_audit.terminal == process.linux_audit.terminal
    assert start.linux_audit.executable != process.linux_audit.executable


def test_multiple_process_outcomes_and_inclusive_timestamp_edges_are_preserved():
    events = normalized_events()
    start = event_by_serial(events, 3010)
    process_events = tuple(
        event_by_serial(events, serial)
        for serial in (3011, 3012, 3013, 3014)
    )
    end = event_by_serial(events, 3015)

    assert [event.process_execution.outcome for event in process_events] == [
        "success",
        "failure",
        "unknown",
        "success",
    ]
    assert process_events[0].timestamp == start.timestamp
    assert process_events[-1].timestamp == end.timestamp
    assert process_events[1].timestamp == process_events[2].timestamp
    assert all(
        start.timestamp <= event.timestamp <= end.timestamp
        for event in process_events
    )


def test_lifecycle_negative_and_ambiguous_boundaries_remain_observable():
    events = normalized_events()

    assert Counter(event.event_type for event in events_for_session(events, 603)) == {
        "process_execution_attempt": 1,
        "session_end": 1,
    }
    assert Counter(event.event_type for event in events_for_session(events, 604)) == {
        "session_start": 1,
        "process_execution_attempt": 1,
    }
    assert Counter(event.event_type for event in events_for_session(events, 605)) == {
        "session_start": 2,
        "process_execution_attempt": 1,
        "session_end": 1,
    }
    assert Counter(event.event_type for event in events_for_session(events, 606)) == {
        "session_start": 1,
        "process_execution_attempt": 1,
        "session_end": 2,
    }

    equal = events_for_session(events, 607)
    assert len({event.timestamp for event in equal}) == 1

    reversed_lifecycle = events_for_session(events, 608)
    reversed_start = next(
        event for event in reversed_lifecycle
        if event.event_type == "session_start"
    )
    reversed_end = next(
        event for event in reversed_lifecycle
        if event.event_type == "session_end"
    )
    assert reversed_start.timestamp > reversed_end.timestamp

    before = events_for_session(events, 609)
    assert next(
        event for event in before
        if event.event_type == "process_execution_attempt"
    ).timestamp < next(
        event for event in before if event.event_type == "session_start"
    ).timestamp

    after = events_for_session(events, 610)
    assert next(
        event for event in after
        if event.event_type == "process_execution_attempt"
    ).timestamp > next(
        event for event in after if event.event_type == "session_end"
    ).timestamp

    no_process = events_for_session(events, 611)
    assert {event.event_type for event in no_process} == {
        "session_start",
        "session_end",
    }


def test_missing_and_unset_session_user_and_node_values_normalize_safely():
    events = normalized_events()

    for serial in (3110, 3111, 3112, 3120, 3121, 3122):
        assert event_by_serial(
            events,
            serial,
        ).linux_audit.audit_session_id is None

    for serial in (3130, 3131, 3132, 3140, 3141, 3142):
        assert event_by_serial(
            events,
            serial,
        ).linux_audit.audit_user_id is None

    for serial in (3150, 3151, 3152):
        assert event_by_serial(events, serial).linux_audit.node is None


def test_scope_fixture_keeps_node_session_and_audit_user_boundaries_separate():
    groups = load_groups(SCOPE_FIXTURE, "scope-a")
    events = normalized_events(SCOPE_FIXTURE, "scope-a")

    assert len(groups) == 16
    assert len(events) == 14

    split_groups = [
        group for group in groups
        if group.event_id.endswith(":4002")
    ]
    assert {group.node for group in split_groups} == {
        "session-scope-a",
        "session-scope-b",
    }
    assert not any(
        event.linux_audit.event_id.endswith(":4002")
        for event in events
    )

    assert event_by_serial(
        events,
        4011,
    ).linux_audit.audit_session_id == 703
    assert {
        event_by_serial(events, serial).linux_audit.audit_session_id
        for serial in (4010, 4012)
    } == {702}

    assert event_by_serial(
        events,
        4021,
    ).linux_audit.audit_user_id == 1704
    assert {
        event_by_serial(events, serial).linux_audit.audit_user_id
        for serial in (4020, 4022)
    } == {1703}

    reused = events_for_session(events, 705)
    assert Counter(event.linux_audit.node for event in reused) == {
        "session-reuse-a": 3,
        "session-reuse-b": 3,
    }
    assert Counter(event.event_type for event in reused) == {
        "session_start": 2,
        "process_execution_attempt": 2,
        "session_end": 2,
    }


def test_same_raw_scope_values_are_isolated_by_source_instance():
    first = normalized_events(SCOPE_FIXTURE, "scope-source-a")
    second = normalized_events(SCOPE_FIXTURE, "scope-source-b")

    assert {event.linux_audit.source_instance for event in first} == {
        "scope-source-a"
    }
    assert {event.linux_audit.source_instance for event in second} == {
        "scope-source-b"
    }
    assert [
        (
            event.linux_audit.node,
            event.linux_audit.event_id,
            event.linux_audit.audit_session_id,
            event.linux_audit.audit_user_id,
        )
        for event in first
    ] == [
        (
            event.linux_audit.node,
            event.linux_audit.event_id,
            event.linux_audit.audit_session_id,
            event.linux_audit.audit_user_id,
        )
        for event in second
    ]
    assert [observable_values(event) for event in first] != [
        observable_values(event) for event in second
    ]


def test_repeated_reversed_and_duplicate_parsing_is_deterministic(tmp_path):
    groups = load_groups(SCOPE_FIXTURE)
    before = deepcopy(groups)
    first = normalized_events(SCOPE_FIXTURE)
    second = normalized_events(SCOPE_FIXTURE)

    assert [observable_values(event) for event in first] == [
        observable_values(event) for event in second
    ]
    assert groups == before

    reversed_fixture = tmp_path / "reversed.log"
    reversed_fixture.write_text(
        "".join(reversed(SCOPE_FIXTURE.read_text().splitlines(keepends=True))),
        encoding="utf-8",
    )
    reversed_events = normalized_events(reversed_fixture)
    assert [observable_values(event) for event in reversed_events] == [
        observable_values(event) for event in first
    ]

    duplicated = tuple(
        event
        for _ in range(2)
        for group in load_groups(SCOPE_FIXTURE)
        for event in parse_linux_audit_events(group)
    )
    assert len(duplicated) == len(first) * 2
    assert [observable_values(event) for event in duplicated[: len(first)]] == [
        observable_values(event) for event in duplicated[len(first) :]
    ]


def test_privacy_canary_remains_internal_and_external_contracts_are_unchanged(
    capsys,
):
    event = event_by_serial(normalized_events(), 3002)
    process_before = deepcopy(event.process_execution)

    assert CANARY in event.process_execution.argv
    assert any(CANARY in raw for raw in event.process_execution.raw_records)

    aggregate = aggregate_process_execution_observations((event,))
    result = analyze(
        [
            {
                "source": "linux_audit",
                "path": str(CONTRACT_FIXTURE),
                "source_instance": SOURCE_INSTANCE,
            }
        ]
    )
    print_analysis_result(
        result,
        process_execution_aggregate=aggregate,
    )
    cli_output = capsys.readouterr().out
    response = build_analysis_response(result, total_sources=1)
    llm_payload = serialize_value(result)

    assert CANARY not in repr(aggregate)
    assert CANARY not in cli_output
    assert CANARY not in json.dumps(response.model_dump(), default=str)
    assert CANARY not in json.dumps(llm_payload, default=str)
    assert set(result) == {"results", "global_correlation"}
    assert event.process_execution == process_before


def test_existing_shared_memory_fixture_and_detector_contract_are_unchanged():
    events = load_normalized_logs(
        [
            {
                "source": "linux_audit",
                "path": str(SHARED_MEMORY_FIXTURE),
                "source_instance": "shared-memory-regression",
            }
        ]
    )
    observations = collect_shared_memory_execution_observations(events)

    assert len(
        [
            event
            for event in events
            if event.event_type == "process_execution_attempt"
        ]
    ) == 14
    assert len(observations) == 6
