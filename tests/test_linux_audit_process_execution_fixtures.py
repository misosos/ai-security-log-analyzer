from collections import Counter
from pathlib import Path

import pytest

from app.loader.linux_audit_loader import load_linux_audit_events


FIXTURE_DIR = Path("sample_logs")


def fixture_lines(name):
    return tuple(
        line
        for line in (FIXTURE_DIR / name).read_text(
            encoding="utf-8",
        ).splitlines()
        if line.strip()
    )


def record_type_counts(event):
    return Counter(record.record_type for record in event.records)


@pytest.mark.parametrize(
    ("name", "event_count", "expected_counts"),
    [
        (
            "linux_audit_exec_success_rhel_source_derived.log",
            1,
            Counter({
                "PATH": 3,
                "SYSCALL": 1,
                "EXECVE": 1,
                "CWD": 1,
                "PROCTITLE": 1,
            }),
        ),
        (
            "linux_audit_exec_failure_structurally_derived.log",
            1,
            Counter({"SYSCALL": 1, "EXECVE": 1}),
        ),
        (
            "linux_audit_exec_split_argument_structurally_derived.log",
            1,
            Counter({"EXECVE": 2, "SYSCALL": 1}),
        ),
        (
            "linux_audit_exec_encoded_arguments_structurally_derived.log",
            1,
            Counter({"SYSCALL": 1, "EXECVE": 1}),
        ),
        (
            "linux_audit_exec_optional_records_missing.log",
            1,
            Counter({"SYSCALL": 1, "EXECVE": 1}),
        ),
    ],
)
def test_process_execution_fixture_records_remain_in_their_event(
    name,
    event_count,
    expected_counts,
):
    events = load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance="phase-3q-fixture-source",
    )

    assert len(events) == event_count
    assert record_type_counts(events[0]) == expected_counts
    assert events[0].source_instance == "phase-3q-fixture-source"
    assert {record.raw for record in events[0].records} == set(
        fixture_lines(name)
    )
    assert all(
        record.event_id == events[0].event_id
        and record.node == events[0].node
        and record.source_instance == events[0].source_instance
        for record in events[0].records
    )


def test_interleaved_fixture_isolates_event_id_and_node():
    name = "linux_audit_exec_interleaved_scope_isolation.log"
    events = load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance="phase-3q-interleaved",
    )

    assert [
        (event.event_id, event.node)
        for event in events
    ] == [
        ("1790400005.006:806", "fixture-node-a"),
        ("1790400005.006:806", "fixture-node-b"),
        ("1790400006.007:807", "fixture-node-a"),
    ]
    assert all(
        record_type_counts(event)
        == Counter({"SYSCALL": 1, "EXECVE": 1})
        for event in events
    )
    assert {
        record.raw
        for event in events
        for record in event.records
    } == set(fixture_lines(name))


def test_loader_preserves_configured_source_scope_for_same_raw_event():
    path = FIXTURE_DIR / "linux_audit_exec_optional_records_missing.log"

    first = load_linux_audit_events(path, source_instance="fixture-feed-a")
    second = load_linux_audit_events(path, source_instance="fixture-feed-b")

    assert first[0].event_id == second[0].event_id
    assert first[0].node == second[0].node
    assert first[0].source_instance == "fixture-feed-a"
    assert second[0].source_instance == "fixture-feed-b"
    assert {
        (event.source_instance, event.node, event.event_id)
        for event in (*first, *second)
    } == {
        (
            "fixture-feed-a",
            "fixture-exec-minimal",
            "1790400004.005:805",
        ),
        (
            "fixture-feed-b",
            "fixture-exec-minimal",
            "1790400004.005:805",
        ),
    }


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "linux_audit_exec_incomplete_arguments_synthetic.log",
            {
                "1790400007.008:808": Counter({
                    "SYSCALL": 1,
                    "EXECVE": 1,
                }),
                "1790400008.009:809": Counter({
                    "SYSCALL": 1,
                    "EXECVE": 1,
                }),
            },
        ),
        (
            "linux_audit_exec_duplicate_fields_synthetic.log",
            {
                "1790400009.010:810": Counter({
                    "EXECVE": 2,
                    "PATH": 2,
                    "SYSCALL": 1,
                }),
                "1790400010.011:811": Counter({
                    "EXECVE": 2,
                    "SYSCALL": 1,
                }),
            },
        ),
        (
            "linux_audit_exec_required_records_ambiguous_synthetic.log",
            {
                "1790400011.012:812": Counter({
                    "SYSCALL": 2,
                    "EXECVE": 1,
                }),
                "1790400012.013:813": Counter({"EXECVE": 1}),
                "1790400013.014:814": Counter({"SYSCALL": 1}),
            },
        ),
    ],
)
def test_ambiguous_fixture_raw_records_remain_grouped_without_collapse(
    name,
    expected,
):
    events = load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance="phase-3q-ambiguity",
    )

    assert {
        event.event_id: record_type_counts(event)
        for event in events
    } == expected
    assert sum(len(event.records) for event in events) == len(
        fixture_lines(name)
    )
    assert {
        record.raw
        for event in events
        for record in event.records
    } == set(fixture_lines(name))
