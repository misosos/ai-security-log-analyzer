from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from app.loader.linux_audit_loader import load_linux_audit_events
from app.models.schemas import (
    AuthenticationContext,
    HttpContext,
    LinuxAuditContext,
    LinuxAuditPathContext,
    NormalizedEvent,
    ProcessExecutionContext,
)
from app.parser.linux_audit import parse_linux_audit_events


def path_context(**overrides):
    values = {
        "item": 0,
        "name": "/usr/bin/example",
        "nametype": "NORMAL",
        "inode": 1001,
        "device": "fd:01",
        "mode": "0100755",
        "owner_user_id": 0,
        "owner_group_id": 0,
    }
    values.update(overrides)
    return LinuxAuditPathContext(**values)


def process_context(paths=()):
    return ProcessExecutionContext(
        outcome="success",
        architecture_raw="c000003e",
        syscall_raw="59",
        architecture_name="x86_64",
        syscall_name="execve",
        exit_code=0,
        process_id=4101,
        parent_process_id=4100,
        real_user_id=1000,
        effective_user_id=1000,
        saved_user_id=1000,
        filesystem_user_id=1000,
        real_group_id=1000,
        effective_group_id=1000,
        saved_group_id=None,
        filesystem_group_id=1000,
        command_name="example",
        executable="/usr/bin/example",
        terminal="pts0",
        audit_rule_key="fixture-exec",
        argument_count=3,
        argv=("/usr/bin/example", None, "--check"),
        argv_complete=False,
        incomplete_argument_indexes=(1,),
        working_directory="/opt/fixture",
        paths=paths,
        paths_complete=True,
        proctitle_raw=(
            "2F7573722F62696E2F6578616D706C65002D2D636865636B"
        ),
        proctitle_arguments=("/usr/bin/example", "--check"),
        raw_records=(
            "type=EXECVE msg=audit(1790400000.001:801): argc=3",
            "type=SYSCALL msg=audit(1790400000.001:801): success=yes",
        ),
    )


def normalized_event(**overrides):
    values = {
        "timestamp": datetime(2026, 9, 18, tzinfo=timezone.utc),
        "event_type": "fixture_event",
        "source": "fixture",
        "user": None,
        "src_ip": None,
        "dst_ip": None,
        "application": None,
        "protocol": None,
        "user_agent": None,
        "raw": "fixture record",
    }
    values.update(overrides)
    return NormalizedEvent(**values)


def test_linux_audit_path_context_supports_observed_and_missing_fields():
    observed = path_context()
    missing = path_context(
        item=None,
        name=None,
        nametype=None,
        inode=None,
        device=None,
        mode=None,
        owner_user_id=None,
        owner_group_id=None,
    )

    assert observed.name == "/usr/bin/example"
    assert observed.nametype == "NORMAL"
    assert missing.item is None
    assert missing.owner_group_id is None

    with pytest.raises(FrozenInstanceError):
        observed.name = "/tmp/changed"


def test_process_execution_context_preserves_nested_evidence_and_is_frozen():
    paths = (
        path_context(),
        path_context(item=1, name="/usr/libexec/example-runtime"),
    )
    context = process_context(paths=paths)

    assert context.paths == paths
    assert context.argv == ("/usr/bin/example", None, "--check")
    assert context.incomplete_argument_indexes == (1,)
    assert context.raw_records == (
        "type=EXECVE msg=audit(1790400000.001:801): argc=3",
        "type=SYSCALL msg=audit(1790400000.001:801): success=yes",
    )

    with pytest.raises(FrozenInstanceError):
        context.outcome = "failure"


def test_normalized_event_defaults_and_existing_contexts_remain_compatible():
    event = normalized_event(
        http=HttpContext(
            method="GET",
            path="/health",
            status_code=200,
            response_size=2,
        ),
        authentication=AuthenticationContext(outcome="success"),
        linux_audit=LinuxAuditContext(
            event_id="1790400000.001:801",
            record_types=("USER_LOGIN",),
        ),
    )

    assert event.http.path == "/health"
    assert event.authentication.outcome == "success"
    assert event.linux_audit.event_id == "1790400000.001:801"
    assert event.process_execution is None


def test_normalized_event_accepts_process_execution_context():
    context = process_context(paths=(path_context(),))

    event = normalized_event(process_execution=context)

    assert event.process_execution is context


def test_existing_linux_audit_parser_leaves_process_execution_unset():
    grouped_events = load_linux_audit_events(
        "sample_logs/linux_audit_user_login.log",
        source_instance="schema-compatibility-test",
    )

    parsed = [
        event
        for grouped_event in grouped_events
        for event in parse_linux_audit_events(grouped_event)
    ]

    assert parsed
    assert all(event.process_execution is None for event in parsed)
