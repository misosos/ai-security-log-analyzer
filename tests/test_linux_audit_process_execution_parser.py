from copy import deepcopy
from pathlib import Path

import pytest

from app.analyzer.llm import serialize_value
from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks,
    load_normalized_logs,
)
from app.analyzer.report import print_analysis_result
from app.api import build_analysis_response
from app.loader.linux_audit_loader import (
    GroupedAuditEvent,
    load_linux_audit_events,
    parse_audit_record,
)
from app.parser.linux_audit import parse_linux_audit_events


FIXTURE_DIR = Path("sample_logs")


def fixture_events(name, source_instance="phase-3s-c"):
    return load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance=source_instance,
    )


def parse_fixture(name, source_instance="phase-3s-c"):
    return [
        normalized
        for event in fixture_events(name, source_instance)
        for normalized in parse_linux_audit_events(event)
    ]


def audit_record(record_type, fields, node="integration-node"):
    record = parse_audit_record(
        f"node={node} type={record_type} "
        "msg=audit(1790700000.001:1001): "
        f"{fields}",
        source_instance="integration-source",
    )
    assert record is not None
    return record


def grouped_event(*records):
    ordered = tuple(sorted(
        records,
        key=lambda record: (record.record_type, record.raw),
    ))
    first = ordered[0]
    return GroupedAuditEvent(
        event_id=first.event_id,
        timestamp=first.timestamp,
        serial=first.serial,
        records=ordered,
        source_instance=first.source_instance,
        node=first.node,
    )


def valid_syscall(**replacements):
    fields = {
        "arch": "c000003e",
        "syscall": "59",
        "success": "yes",
        "exit": "0",
        "items": "0",
        "ppid": "6100",
        "pid": "6101",
        "auid": "1000",
        "uid": "1001",
        "gid": "1002",
        "euid": "1001",
        "suid": "1001",
        "fsuid": "1001",
        "egid": "1002",
        "sgid": "1002",
        "fsgid": "1002",
        "tty": "pts0",
        "ses": "81",
        "comm": '"example"',
        "exe": '"/usr/bin/example"',
        "hostname": "fixture-client",
        "key": '"fixture-exec"',
    }
    fields.update(replacements)
    return " ".join(f"{key}={value}" for key, value in fields.items())


def process_group(syscall=None, execve='argc=1 a0="/usr/bin/example"'):
    records = []
    if syscall is not None:
        records.append(audit_record("SYSCALL", syscall))
    if execve is not None:
        records.append(audit_record("EXECVE", execve))
    return grouped_event(*records)


def test_success_fixture_emits_one_bounded_process_execution_event():
    grouped = fixture_events(
        "linux_audit_exec_success_rhel_source_derived.log"
    )[0]

    parsed = parse_linux_audit_events(grouped)

    assert len(parsed) == 1
    event = parsed[0]
    syscall = next(
        record for record in grouped.records
        if record.record_type == "SYSCALL"
    )
    assert event.timestamp == grouped.timestamp
    assert event.event_type == "process_execution_attempt"
    assert event.source == "linux_audit"
    assert event.user is None
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.application is None
    assert event.protocol is None
    assert event.user_agent is None
    assert event.http is None
    assert event.authentication is None
    assert event.raw == syscall.raw
    assert event.process_execution.outcome == "success"
    assert event.process_execution.raw_records == tuple(
        record.raw for record in grouped.records
    )


def test_process_event_linux_audit_context_preserves_bounded_identity():
    event = parse_linux_audit_events(process_group(valid_syscall()))[0]

    assert event.linux_audit.event_id == "1790700000.001:1001"
    assert event.linux_audit.record_types == ("EXECVE", "SYSCALL")
    assert event.linux_audit.source_instance == "integration-source"
    assert event.linux_audit.node == "integration-node"
    assert event.linux_audit.executable == "/usr/bin/example"
    assert event.linux_audit.process_user_id == 1001
    assert event.linux_audit.audit_user_id == 1000
    assert event.linux_audit.audit_session_id == 81
    assert event.linux_audit.terminal == "pts0"
    assert event.linux_audit.hostname == "fixture-client"
    assert event.linux_audit.operation is None


def test_process_event_preserves_unset_audit_identity_as_none():
    syscall = valid_syscall(auid="4294967295", ses="-1", uid="1001")

    event = parse_linux_audit_events(process_group(syscall))[0]

    assert event.linux_audit.process_user_id == 1001
    assert event.linux_audit.audit_user_id is None
    assert event.linux_audit.audit_session_id is None


@pytest.mark.parametrize(
    ("fixture", "outcome", "complete"),
    [
        (
            "linux_audit_exec_failure_structurally_derived.log",
            "failure",
            True,
        ),
        (
            "linux_audit_exec_optional_records_missing.log",
            "success",
            True,
        ),
        (
            "linux_audit_exec_incomplete_arguments_synthetic.log",
            "success",
            False,
        ),
    ],
)
def test_qualifying_fixture_groups_emit_one_event_each(
    fixture,
    outcome,
    complete,
):
    parsed = parse_fixture(fixture)

    assert parsed
    assert all(
        event.event_type == "process_execution_attempt"
        for event in parsed
    )
    assert all(event.process_execution.outcome == outcome for event in parsed)
    assert any(
        event.process_execution.argv_complete is complete
        for event in parsed
    )


def test_split_and_encoded_fixtures_emit_one_event_per_group():
    for fixture in (
        "linux_audit_exec_split_argument_structurally_derived.log",
        "linux_audit_exec_encoded_arguments_structurally_derived.log",
    ):
        grouped = fixture_events(fixture)
        parsed = parse_fixture(fixture)

        assert len(grouped) == 1
        assert len(parsed) == 1
        assert parsed[0].process_execution is not None


def test_optional_evidence_ambiguity_does_not_remove_process_event():
    syscall_with_path = valid_syscall(items="2")
    optional_groups = (
        grouped_event(
            audit_record("SYSCALL", valid_syscall()),
            audit_record("EXECVE", 'argc=1 a0="example"'),
            audit_record("CWD", 'cwd="/opt/first"'),
            audit_record("CWD", 'cwd="/opt/second"'),
        ),
        grouped_event(
            audit_record("SYSCALL", syscall_with_path),
            audit_record("EXECVE", 'argc=1 a0="example"'),
            audit_record("PATH", 'item=0 name="/first"'),
            audit_record("PATH", 'item=0 name="/duplicate"'),
        ),
        grouped_event(
            audit_record("SYSCALL", valid_syscall()),
            audit_record("EXECVE", 'argc=1 a0="example"'),
            audit_record("PROCTITLE", "proctitle=6F6E65"),
            audit_record("PROCTITLE", "proctitle=74776F"),
        ),
    )

    parsed = [parse_linux_audit_events(event) for event in optional_groups]

    assert all(len(events) == 1 for events in parsed)
    assert all(
        events[0].event_type == "process_execution_attempt"
        for events in parsed
    )


def test_required_record_ambiguity_groups_emit_no_process_events():
    parsed = parse_fixture(
        "linux_audit_exec_required_records_ambiguous_synthetic.log"
    )

    assert parsed == []


@pytest.mark.parametrize(
    ("syscall", "execve"),
    [
        (None, 'argc=1 a0="/usr/bin/example"'),
        (valid_syscall(), None),
        (valid_syscall(pid="invalid"), 'argc=1 a0="example"'),
        (valid_syscall(), 'a0="example"'),
        (valid_syscall(), 'argc=1 argc=2 a0="example"'),
    ],
)
def test_non_candidates_emit_no_process_event(syscall, execve):
    assert parse_linux_audit_events(process_group(syscall, execve)) == []


def test_multiple_syscall_records_emit_no_process_event():
    event = grouped_event(
        audit_record("SYSCALL", valid_syscall()),
        audit_record("SYSCALL", valid_syscall(success="no", exit="-2")),
        audit_record("EXECVE", 'argc=1 a0="example"'),
    )

    assert parse_linux_audit_events(event) == []


def test_existing_user_event_precedes_process_event_without_semantic_change():
    user = audit_record(
        "USER_AUTH",
        "pid=6101 uid=0 auid=1000 ses=81 "
        "msg='op=PAM:authentication acct=training-user "
        "exe=/usr/sbin/sshd hostname=remote-a "
        "addr=198.51.100.80 terminal=ssh res=success'",
    )
    event = grouped_event(
        user,
        audit_record("SYSCALL", valid_syscall()),
        audit_record("EXECVE", 'argc=1 a0="/usr/bin/example"'),
    )

    parsed = parse_linux_audit_events(event)

    assert [item.event_type for item in parsed] == [
        "authentication_attempt",
        "process_execution_attempt",
    ]
    authentication = parsed[0]
    assert authentication.user == "training-user"
    assert authentication.src_ip == "198.51.100.80"
    assert authentication.authentication.outcome == "success"
    assert authentication.process_execution is None


def test_core_ambiguity_suppresses_only_process_event():
    event = grouped_event(
        audit_record(
            "USER_AUTH",
            "pid=6101 uid=0 auid=1000 ses=81 "
            "msg='op=PAM:authentication acct=training-user "
            "exe=/usr/sbin/sshd hostname=remote-a "
            "addr=198.51.100.80 terminal=ssh res=success'",
        ),
        audit_record("SYSCALL", valid_syscall()),
        audit_record("SYSCALL", valid_syscall(success="no", exit="-2")),
        audit_record("EXECVE", 'argc=1 a0="/usr/bin/example"'),
    )

    parsed = parse_linux_audit_events(event)

    assert [item.event_type for item in parsed] == [
        "authentication_attempt",
    ]
    assert parsed[0].process_execution is None


def test_loader_ordering_makes_reversed_raw_input_semantically_stable(tmp_path):
    fixture = (
        FIXTURE_DIR / "linux_audit_exec_success_rhel_source_derived.log"
    )
    lines = fixture.read_text(encoding="utf-8").splitlines()
    reversed_fixture = tmp_path / "reversed-process-event.log"
    reversed_fixture.write_text(
        "\n".join(reversed(lines)),
        encoding="utf-8",
    )

    original = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "ordering-source",
        "path": fixture,
    }])
    reversed_events = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "ordering-source",
        "path": reversed_fixture,
    }])

    assert reversed_events == original


def test_parser_is_deterministic_and_does_not_mutate_group():
    grouped = fixture_events(
        "linux_audit_exec_success_rhel_source_derived.log"
    )[0]
    before_records = grouped.records
    before_fields = tuple(dict(record.fields) for record in grouped.records)
    before_raw = tuple(record.raw for record in grouped.records)

    first = parse_linux_audit_events(grouped)
    second = parse_linux_audit_events(grouped)

    assert first == second
    assert grouped.records == before_records
    assert tuple(dict(record.fields) for record in grouped.records) == (
        before_fields
    )
    assert tuple(record.raw for record in grouped.records) == before_raw


def test_interleaved_fixture_preserves_node_isolation():
    events = fixture_events(
        "linux_audit_exec_interleaved_scope_isolation.log"
    )
    parsed = [
        parse_linux_audit_events(event)[0]
        for event in events
    ]

    assert len(parsed) == 3
    assert [
        (event.linux_audit.node, event.linux_audit.event_id)
        for event in parsed
    ] == [
        ("fixture-node-a", "1790400005.006:806"),
        ("fixture-node-b", "1790400005.006:806"),
        ("fixture-node-a", "1790400006.007:807"),
    ]


def test_same_raw_event_preserves_source_instance_isolation():
    fixture = "linux_audit_exec_optional_records_missing.log"

    first = parse_fixture(fixture, source_instance="feed-a")[0]
    second = parse_fixture(fixture, source_instance="feed-b")[0]

    assert first.linux_audit.event_id == second.linux_audit.event_id
    assert first.linux_audit.node == second.linux_audit.node
    assert first.linux_audit.source_instance == "feed-a"
    assert second.linux_audit.source_instance == "feed-b"


def test_process_only_pipeline_isolated_from_detection_correlation_and_risk():
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "phase-3s-c-pipeline",
        "path": (
            FIXTURE_DIR
            / "linux_audit_exec_success_rhel_source_derived.log"
        ),
    }])

    assert len(logs) == 1
    assert logs[0].event_type == "process_execution_attempt"
    detections = detect_attacks(logs)
    correlated = correlate_attacks(logs, detections)
    assessed = assess_risk(deepcopy(correlated))

    assert detections == {}
    assert correlated["results"] == {}
    assert correlated["global_correlation"] == {
        "multi_ip_authentication": [],
        "distributed_authentication_to_success": [],
        "linux_audit_session_lifecycle": [],
        "linux_audit_login_start_co_observation": [],
    }
    assert assessed == correlated


def test_process_event_is_not_projected_to_api_cli_or_llm(capsys):
    logs = load_normalized_logs([{
        "source": "linux_audit",
        "source_instance": "phase-3s-c-exposure",
        "path": (
            FIXTURE_DIR
            / "linux_audit_exec_success_rhel_source_derived.log"
        ),
    }])
    assert logs[0].process_execution.argv == (
        "/usr/bin/example",
        "--check",
    )

    analysis = correlate_attacks(logs, detect_attacks(logs))
    analysis = assess_risk(analysis)
    response = build_analysis_response(analysis, total_sources=1)
    print_analysis_result(analysis)
    serialized_analysis = serialize_value(analysis)

    assert response.results == []
    assert response.global_correlation == analysis["global_correlation"]
    assert capsys.readouterr().out == ""
    assert "process_execution" not in str(serialized_analysis)
    assert "/usr/bin/example" not in str(serialized_analysis)
