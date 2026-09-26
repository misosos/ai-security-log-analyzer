from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta
import json
from pathlib import Path

import pytest

from app.analyzer.llm import serialize_value
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.correlation.session_process import (
    SessionProcessReviewSummary,
    collect_session_process_co_observations,
    summarize_session_process_co_observations,
)
from app.detector.shared_memory_execution import (
    collect_shared_memory_execution_observations,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze
from app.parser.linux_audit import parse_linux_audit_events


CONTRACT_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_process_co_observation_contract_synthetic.log"
)
SOURCE_INSTANCE = "session-process-summary"
CANARY = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"


def fixture_events():
    return tuple(
        normalized
        for group in load_linux_audit_events(
            CONTRACT_FIXTURE,
            source_instance=SOURCE_INSTANCE,
        )
        for normalized in parse_linux_audit_events(group)
    )


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


def fixture_relations():
    return collect_session_process_co_observations(fixture_events())


def connected_fixture_products():
    events = list(fixture_events())
    process_index = next(
        index
        for index, event in enumerate(events)
        if event.linux_audit.event_id.endswith(":3002")
    )
    process = events[process_index]
    process_context = replace(
        process.process_execution,
        executable="/dev/shm/telemetry-probe",
        effective_user_id=0,
    )
    events[process_index] = replace(
        process,
        linux_audit=replace(
            process.linux_audit,
            executable=process_context.executable,
        ),
        process_execution=process_context,
    )
    immutable_events = tuple(events)
    return (
        immutable_events,
        collect_session_process_co_observations(immutable_events),
        collect_shared_memory_execution_observations(immutable_events),
    )


def observation_for(relation, event_id=None, **changes):
    _, _, observations = connected_fixture_products()
    observation = observations[0]
    values = {
        "source_instance": relation.source_instance,
        "node": relation.node,
        "event_id": event_id or relation.process_event_ids[0],
    }
    values.update(changes)
    return replace(observation, **values)


def test_summary_is_a_frozen_fixed_non_negative_integer_projection():
    summary = summarize_session_process_co_observations((), ())

    assert tuple(field.name for field in fields(summary)) == (
        "session_co_observation_count",
        "process_observation_count",
        "process_outcome_success_count",
        "process_outcome_failure_count",
        "process_outcome_unknown_count",
        "shared_memory_privileged_execution_observation_count",
        "sessions_with_shared_memory_privileged_execution_count",
    )
    assert summary == SessionProcessReviewSummary(0, 0, 0, 0, 0, 0, 0)
    assert all(
        type(getattr(summary, field.name)) is int
        and getattr(summary, field.name) >= 0
        for field in fields(summary)
    )
    with pytest.raises(FrozenInstanceError):
        summary.process_observation_count = 1


def test_actual_collectors_connect_one_fixture_process_by_bounded_key():
    events, relations, observations = connected_fixture_products()
    before = deepcopy(events)

    summary = summarize_session_process_co_observations(
        relations,
        observations,
    )

    assert len(relations) == 2
    assert len(observations) == 1
    assert summary == SessionProcessReviewSummary(
        session_co_observation_count=2,
        process_observation_count=5,
        process_outcome_success_count=3,
        process_outcome_failure_count=1,
        process_outcome_unknown_count=1,
        shared_memory_privileged_execution_observation_count=1,
        sessions_with_shared_memory_privileged_execution_count=1,
    )
    assert events == before


def test_multiple_relations_aggregate_counts_and_only_matching_sessions():
    first, second = fixture_relations()
    observations = (
        observation_for(first),
        observation_for(second, second.process_event_ids[0]),
        observation_for(second, second.process_event_ids[1]),
    )

    summary = summarize_session_process_co_observations(
        (second, first),
        tuple(reversed(observations)),
    )

    assert summary.process_observation_count == 5
    assert (
        summary.process_outcome_success_count,
        summary.process_outcome_failure_count,
        summary.process_outcome_unknown_count,
    ) == (3, 1, 1)
    assert summary.shared_memory_privileged_execution_observation_count == 3
    assert summary.sessions_with_shared_memory_privileged_execution_count == 2


def test_unmatched_inputs_do_not_create_sessions_or_processes():
    relation = fixture_relations()[0]
    unmatched = observation_for(
        relation,
        event_id="unmatched-event",
    )

    relation_only = summarize_session_process_co_observations(
        (relation,),
        (),
    )
    observation_only = summarize_session_process_co_observations(
        (),
        (unmatched,),
    )

    assert relation_only.session_co_observation_count == 1
    assert relation_only.process_observation_count == 1
    assert relation_only.shared_memory_privileged_execution_observation_count == 0
    assert observation_only == SessionProcessReviewSummary(0, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize(
    "change",
    [
        {"source_instance": "other-source"},
        {"node": "other-node"},
        {"event_id": "other-event"},
    ],
)
def test_source_node_and_event_id_mismatch_do_not_connect(change):
    relation = fixture_relations()[0]
    observation = observation_for(relation, **change)

    summary = summarize_session_process_co_observations(
        (relation,),
        (observation,),
    )

    assert summary.shared_memory_privileged_execution_observation_count == 0
    assert summary.sessions_with_shared_memory_privileged_execution_count == 0


def test_same_event_id_in_other_source_or_node_is_not_a_match():
    relation = fixture_relations()[0]
    source_mismatch = observation_for(
        relation,
        source_instance="other-source",
    )
    node_mismatch = observation_for(relation, node="other-node")

    summary = summarize_session_process_co_observations(
        (relation,),
        (source_mismatch, node_mismatch),
    )

    assert summary.shared_memory_privileged_execution_observation_count == 0


def test_duplicate_matching_uses_multiset_minimum_without_deduplication():
    relation = fixture_relations()[0]
    event_id = relation.process_event_ids[0]
    duplicated_relation = replace(
        relation,
        process_observation_count=3,
        process_outcome_success_count=3,
        process_event_ids=(event_id, event_id, event_id),
    )
    observation = observation_for(relation)

    one_observation = summarize_session_process_co_observations(
        (duplicated_relation,),
        (observation,),
    )
    four_observations = summarize_session_process_co_observations(
        (duplicated_relation,),
        (observation, observation, observation, observation),
    )

    assert one_observation.shared_memory_privileged_execution_observation_count == 1
    assert four_observations.shared_memory_privileged_execution_observation_count == 3
    assert four_observations.process_observation_count == 3
    assert four_observations.sessions_with_shared_memory_privileged_execution_count == 1


def test_ambiguous_cross_relation_process_key_is_rejected():
    first = fixture_relations()[0]
    second = replace(
        first,
        audit_session_id=first.audit_session_id + 1,
        session_start_event_id="other-start",
        session_end_event_id="other-end",
    )

    with pytest.raises(ValueError, match="ambiguous"):
        summarize_session_process_co_observations((first, second), ())


def test_input_order_permutations_produce_the_same_summary():
    relations = fixture_relations()
    observations = tuple(
        observation_for(relation, event_id=event_id)
        for relation in relations
        for event_id in relation.process_event_ids[:1]
    )
    expected = summarize_session_process_co_observations(
        relations,
        observations,
    )

    assert summarize_session_process_co_observations(
        tuple(reversed(relations)),
        tuple(reversed(observations)),
    ) == expected
    assert summarize_session_process_co_observations(
        relations,
        observations,
    ) == expected


@pytest.mark.parametrize(
    ("relations", "observations"),
    [
        ([], ()),
        ({}, ()),
        ((item for item in ()), ()),
        ((), []),
        ((), {}),
        ((), (item for item in ())),
    ],
)
def test_invalid_top_level_container_raises_type_error(
    relations,
    observations,
):
    with pytest.raises(TypeError):
        summarize_session_process_co_observations(relations, observations)


def test_invalid_tuple_item_raises_value_error():
    relation = fixture_relations()[0]
    observation = observation_for(relation)

    with pytest.raises(ValueError):
        summarize_session_process_co_observations((None,), ())
    with pytest.raises(ValueError):
        summarize_session_process_co_observations(
            (relation,),
            ({}, observation),
        )


@pytest.mark.parametrize(
    "change",
    [
        {"source_instance": ""},
        {"node": "   "},
        {"audit_session_id": False},
        {"audit_user_id": -1},
        {"session_start_event_id": ""},
        {"session_end_event_id": "   "},
        {"process_observation_count": True},
        {"process_observation_count": -1},
        {"process_outcome_success_count": -1},
        {"process_event_ids": []},
        {"process_event_ids": ("",)},
    ],
)
def test_invalid_relation_scalar_contract_is_rejected(change):
    relation = replace(fixture_relations()[0], **change)

    with pytest.raises(ValueError):
        summarize_session_process_co_observations((relation,), ())


def test_broken_relation_invariants_are_rejected():
    relation = fixture_relations()[0]

    broken_outcomes = replace(
        relation,
        process_outcome_success_count=0,
    )
    broken_cardinality = replace(
        relation,
        process_event_ids=("one", "two"),
    )
    reversed_lifecycle = replace(
        relation,
        session_start_timestamp=relation.session_end_timestamp,
        session_end_timestamp=relation.session_start_timestamp,
    )

    for broken in (
        broken_outcomes,
        broken_cardinality,
        reversed_lifecycle,
    ):
        with pytest.raises(ValueError):
            summarize_session_process_co_observations((broken,), ())


@pytest.mark.parametrize(
    "change",
    [
        {"source": "other"},
        {"source": True},
        {"timestamp": datetime(2025, 1, 1)},
        {"event_type": "other"},
        {"source_instance": None},
        {"node": ""},
        {"event_id": "   "},
        {"detection_type": "other"},
        {"shared_memory_executable_path": "/tmp/file"},
        {"effective_user_id": False},
        {"effective_user_id": 1},
        {"syscall_outcome": "failure"},
    ],
)
def test_invalid_shared_memory_observation_contract_is_rejected(change):
    relation = fixture_relations()[0]
    observation = observation_for(relation, **change)

    with pytest.raises(ValueError):
        summarize_session_process_co_observations(
            (relation,),
            (observation,),
        )


def test_privacy_canary_is_not_copied_and_inputs_are_not_mutated():
    events = fixture_events()
    process = event_by_serial(events, 3002)
    relation = replace(
        fixture_relations()[0],
        source_instance=CANARY,
        node=CANARY,
        session_start_event_id=CANARY,
        session_end_event_id=CANARY,
        process_event_ids=(CANARY,),
    )
    observation = observation_for(
        relation,
        event_id=CANARY,
        shared_memory_executable_path=f"/dev/shm/{CANARY}",
    )
    before = deepcopy((relation, observation, events))

    assert CANARY in process.process_execution.argv
    assert any(CANARY in raw for raw in process.process_execution.raw_records)

    summary = summarize_session_process_co_observations(
        (relation,),
        (observation,),
    )

    assert CANARY not in repr(summary)
    assert CANARY not in json.dumps(serialize_value(summary), default=str)
    assert (relation, observation, events) == before


def test_existing_analysis_api_cli_and_llm_contracts_do_not_receive_summary(
    capsys,
):
    analysis = analyze()
    print_analysis_result(analysis)
    cli_output = capsys.readouterr().out
    api_response = build_analysis_response(analysis, total_sources=3)
    llm_payload = serialize_value(analysis)

    assert set(analysis) == {"results", "global_correlation"}
    assert "session_process_review" not in analysis
    assert "SessionProcessReviewSummary" not in cli_output
    assert "session_co_observation_count" not in cli_output
    assert "session_co_observation_count" not in json.dumps(
        api_response.model_dump(),
        default=str,
    )
    assert "session_co_observation_count" not in json.dumps(
        llm_payload,
        default=str,
    )
