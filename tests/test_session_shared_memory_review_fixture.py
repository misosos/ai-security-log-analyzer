from collections import Counter
from copy import deepcopy
from dataclasses import fields
import json
from pathlib import Path

from app.analyzer.llm import serialize_value
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.correlation.session_process import (
    collect_session_process_co_observations,
    summarize_session_process_co_observations,
)
from app.detector.shared_memory_execution import (
    collect_shared_memory_execution_observations,
    summarize_shared_memory_execution_observations,
)
from app.loader.linux_audit_loader import load_linux_audit_events
from app.main import analyze
from app.parser.linux_audit import parse_linux_audit_events


FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_shared_memory_review_contract_synthetic.log"
)
EXISTING_SESSION_FIXTURE = Path(
    "sample_logs/"
    "linux_audit_session_process_co_observation_contract_synthetic.log"
)
SOURCE_INSTANCE = "session-shared-memory-review"
CANARY = "SYNTHETIC_SESSION_PROCESS_SECRET_DO_NOT_EXPOSE"


def fixture_events(path=FIXTURE, source_instance=SOURCE_INSTANCE):
    groups = load_linux_audit_events(
        path,
        source_instance=source_instance,
    )
    events = tuple(
        event
        for group in groups
        for event in parse_linux_audit_events(group)
    )
    return groups, events


def event_by_serial(events, serial):
    return next(
        event
        for event in events
        if event.linux_audit.event_id.endswith(f":{serial}")
    )


def review_products(events):
    shared = collect_shared_memory_execution_observations(events)
    relations = collect_session_process_co_observations(events)
    summary = summarize_session_process_co_observations(
        relations,
        shared,
    )
    return shared, relations, summary


def test_fixture_produces_bounded_session_linked_review_contract():
    groups, events = fixture_events()
    before = deepcopy(events)
    shared, relations, summary = review_products(events)
    shared_summary = summarize_shared_memory_execution_observations(shared)

    assert len(groups) == len(events) == 6
    assert Counter(event.event_type for event in events) == {
        "session_start": 1,
        "session_end": 1,
        "process_execution_attempt": 4,
    }
    assert len(relations) == 1
    relation = relations[0]
    assert relation.process_observation_count == 3
    assert (
        relation.process_outcome_success_count,
        relation.process_outcome_failure_count,
        relation.process_outcome_unknown_count,
    ) == (2, 1, 0)
    assert relation.process_observation_count == (
        relation.process_outcome_success_count
        + relation.process_outcome_failure_count
        + relation.process_outcome_unknown_count
    )
    assert (
        shared_summary
        .shared_memory_privileged_execution_observation_count
    ) == 2
    assert summary.shared_memory_privileged_execution_observation_count == 1
    assert summary.sessions_with_shared_memory_privileged_execution_count == 1
    assert (
        shared_summary
        .shared_memory_privileged_execution_observation_count
        > summary.shared_memory_privileged_execution_observation_count
    )
    assert events == before


def test_fixture_preserves_positive_ordinary_negative_and_outside_boundaries():
    _, events = fixture_events()
    shared, relations, summary = review_products(events)
    positive = event_by_serial(events, 4002)
    ordinary = event_by_serial(events, 4003)
    failed = event_by_serial(events, 4004)
    outside = event_by_serial(events, 4006)
    relation = relations[0]

    expected_scope = (
        SOURCE_INSTANCE,
        "session-shared-memory-review",
        701,
        1701,
    )
    assert all(
        (
            event.linux_audit.source_instance,
            event.linux_audit.node,
            event.linux_audit.audit_session_id,
            event.linux_audit.audit_user_id,
        ) == expected_scope
        for event in (positive, ordinary, failed)
    )
    assert positive.process_execution.outcome == "success"
    assert positive.process_execution.effective_user_id == 0
    assert positive.process_execution.executable == (
        "/dev/shm/session-review-probe"
    )
    assert ordinary.process_execution.executable == (
        "/usr/bin/session-review-fixture"
    )
    assert failed.process_execution.outcome == "failure"
    assert outside.linux_audit.audit_session_id == 702
    assert outside.linux_audit.audit_user_id == 1702
    assert tuple(observation.event_id for observation in shared) == (
        positive.linux_audit.event_id,
        outside.linux_audit.event_id,
    )
    shared_event_ids = {
        observation.event_id for observation in shared
    }
    assert ordinary.linux_audit.event_id not in shared_event_ids
    assert failed.linux_audit.event_id not in shared_event_ids
    assert outside.linux_audit.event_id not in relation.process_event_ids
    assert summary.process_observation_count == 3


def test_fixture_is_deterministic_under_reversal_and_preserves_duplicates():
    _, events = fixture_events()
    expected = review_products(events)[2]
    reversed_summary = review_products(tuple(reversed(events)))[2]

    assert reversed_summary == expected

    ordinary = event_by_serial(events, 4003)
    duplicated_events = (*events, ordinary)
    shared, relations, duplicated_summary = review_products(
        duplicated_events
    )

    assert len(shared) == 2
    assert relations[0].process_observation_count == 4
    assert relations[0].process_event_ids.count(
        ordinary.linux_audit.event_id
    ) == 2
    assert duplicated_summary.process_observation_count == 4
    assert duplicated_summary.process_outcome_success_count == 3
    assert (
        duplicated_summary
        .shared_memory_privileged_execution_observation_count
    ) == 1


def test_fixture_canary_stays_internal_and_summary_is_count_only(capsys):
    _, events = fixture_events()
    original = deepcopy(events)
    shared, relations, summary = review_products(events)
    positive = event_by_serial(events, 4002)

    assert CANARY in repr(positive.process_execution.argv)
    assert CANARY in repr(positive.process_execution.raw_records)
    assert all(
        type(getattr(summary, field.name)) is int
        for field in fields(summary)
    )
    assert CANARY not in repr(summary)
    assert CANARY not in json.dumps(
        serialize_value(summary),
        sort_keys=True,
    )

    analysis = analyze([])
    print_analysis_result(
        analysis,
        process_execution_aggregate=(
            aggregate_process_execution_observations(events)
        ),
    )
    cli_output = capsys.readouterr().out
    api_output = build_analysis_response(
        analysis,
        total_sources=0,
    ).model_dump()
    llm_output = serialize_value(analysis)

    assert CANARY not in cli_output
    assert CANARY not in json.dumps(api_output, sort_keys=True)
    assert CANARY not in json.dumps(llm_output, sort_keys=True)
    assert "session_process_review_summary" not in analysis
    assert "session_process_review_summary" not in api_output
    assert "session_process_review_summary" not in llm_output
    assert events == original
    assert relations == collect_session_process_co_observations(events)
    assert shared == collect_shared_memory_execution_observations(events)


def test_existing_session_fixture_remains_without_shared_memory_observations():
    _, events = fixture_events(
        EXISTING_SESSION_FIXTURE,
        source_instance="existing-session-fixture",
    )
    shared, relations, summary = review_products(events)

    assert len(relations) == 2
    assert summary.process_observation_count == 5
    assert (
        summary.process_outcome_success_count,
        summary.process_outcome_failure_count,
        summary.process_outcome_unknown_count,
    ) == (3, 1, 1)
    assert shared == ()
    assert summary.shared_memory_privileged_execution_observation_count == 0
    assert summary.sessions_with_shared_memory_privileged_execution_count == 0
