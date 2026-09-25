from pathlib import Path

import pytest

from app.loader.linux_audit_loader import (
    GroupedAuditEvent,
    load_linux_audit_events,
    parse_audit_record,
)
from app.parser.linux_audit import (
    _build_process_execution_context,
    parse_linux_audit_events,
)


FIXTURE_DIR = Path("sample_logs")
DEFAULT_SYSCALL = (
    "arch=c000003e syscall=59 success=yes exit=0 items=0 "
    "ppid=5100 pid=5101 auid=1000 uid=1000 gid=1000 "
    "euid=1001 suid=1002 fsuid=1003 egid=1001 sgid=1002 "
    "fsgid=1003 tty=pts0 comm=\"example\" "
    "exe=\"/usr/bin/example\" key=\"fixture-exec\""
)
DEFAULT_EXECVE = 'argc=1 a0="/usr/bin/example"'


def grouped_event(syscall=DEFAULT_SYSCALL, execve=DEFAULT_EXECVE, extra=()):
    specifications = []
    if syscall is not None:
        specifications.append(("SYSCALL", syscall))
    if execve is not None:
        if isinstance(execve, str):
            execve = (execve,)
        specifications.extend(("EXECVE", value) for value in execve)
    specifications.extend(extra)

    records = []
    for record_type, fields in specifications:
        record = parse_audit_record(
            "node=builder-fixture "
            f"type={record_type} "
            "msg=audit(1790600000.001:901): "
            f"{fields}",
            source_instance="phase-3s-b",
        )
        assert record is not None
        records.append(record)
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


def fixture_event(name, event_id=None):
    events = load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance="phase-3s-b",
    )
    if event_id is None:
        assert len(events) == 1
        return events[0]
    return next(event for event in events if event.event_id == event_id)


def test_canonical_fixture_builds_bounded_process_execution_context():
    event = fixture_event(
        "linux_audit_exec_success_rhel_source_derived.log"
    )

    context = _build_process_execution_context(event)

    assert context is not None
    assert context.outcome == "success"
    assert context.architecture_raw == "c000003e"
    assert context.syscall_raw == "59"
    assert context.architecture_name is None
    assert context.syscall_name is None
    assert context.exit_code == 0
    assert context.process_id == 4101
    assert context.parent_process_id == 4100
    assert (
        context.real_user_id,
        context.effective_user_id,
        context.saved_user_id,
        context.filesystem_user_id,
    ) == (1000, 1000, 1000, 1000)
    assert (
        context.real_group_id,
        context.effective_group_id,
        context.saved_group_id,
        context.filesystem_group_id,
    ) == (1000, 1000, 1000, 1000)
    assert context.command_name == "example"
    assert context.executable == "/usr/bin/example"
    assert context.terminal == "pts0"
    assert context.audit_rule_key == "fixture-exec"
    assert context.argv == ("/usr/bin/example", "--check")
    assert context.argv_complete is True
    assert context.working_directory == "/opt/fixture"
    assert [path.item for path in context.paths] == [0, 1, 2]
    assert [path.name for path in context.paths] == [
        "/usr/bin/example",
        "/usr/libexec/example-runtime",
        "/lib64/ld-linux-x86-64.so.2",
    ]
    assert context.paths_complete is True
    assert context.proctitle_raw == (
        "2F7573722F62696E2F6578616D706C65002D2D636865636B"
    )
    assert context.proctitle_arguments == (
        "/usr/bin/example",
        "--check",
    )
    assert context.raw_records == tuple(
        record.raw for record in event.records
    )


def test_failed_and_optional_record_fixtures_remain_candidates():
    failed = _build_process_execution_context(fixture_event(
        "linux_audit_exec_failure_structurally_derived.log"
    ))
    optional_missing = _build_process_execution_context(fixture_event(
        "linux_audit_exec_optional_records_missing.log"
    ))

    assert failed is not None
    assert failed.outcome == "failure"
    assert failed.exit_code == -2
    assert optional_missing is not None
    assert optional_missing.working_directory is None
    assert optional_missing.paths == ()
    assert optional_missing.paths_complete is True
    assert optional_missing.proctitle_raw is None
    assert optional_missing.proctitle_arguments is None


def test_split_and_incomplete_argv_fixtures_are_candidates():
    split = _build_process_execution_context(fixture_event(
        "linux_audit_exec_split_argument_structurally_derived.log"
    ))
    incomplete = _build_process_execution_context(fixture_event(
        "linux_audit_exec_incomplete_arguments_synthetic.log",
        "1790400007.008:808",
    ))

    assert split is not None
    assert split.argv == ("/usr/bin/example", "longargument")
    assert split.argv_complete is True
    assert incomplete is not None
    assert incomplete.argv == (
        "/usr/bin/example",
        None,
        "orphan-index",
    )
    assert incomplete.argv_complete is False
    assert incomplete.incomplete_argument_indexes == (1,)


def test_candidate_cardinality_and_argument_count_rejections():
    required = "linux_audit_exec_required_records_ambiguous_synthetic.log"
    duplicate = "linux_audit_exec_duplicate_fields_synthetic.log"

    assert _build_process_execution_context(fixture_event(
        required, "1790400011.012:812"
    )) is None
    assert _build_process_execution_context(fixture_event(
        required, "1790400012.013:813"
    )) is None
    assert _build_process_execution_context(fixture_event(
        required, "1790400013.014:814"
    )) is None
    assert _build_process_execution_context(fixture_event(
        duplicate, "1790400009.010:810"
    )) is None
    assert _build_process_execution_context(
        grouped_event(execve='a0="example"')
    ) is None


@pytest.mark.parametrize(
    "field",
    ["arch", "syscall", "pid", "ppid"],
)
def test_missing_required_syscall_field_rejects_candidate(field):
    syscall = " ".join(
        token for token in DEFAULT_SYSCALL.split()
        if not token.startswith(f"{field}=")
    )

    assert _build_process_execution_context(
        grouped_event(syscall=syscall)
    ) is None


@pytest.mark.parametrize("field", ["pid", "ppid"])
@pytest.mark.parametrize("value", ["invalid", "-1"])
def test_invalid_or_negative_required_process_id_rejects(field, value):
    syscall = DEFAULT_SYSCALL.replace(
        f"{field}={'5101' if field == 'pid' else '5100'}",
        f"{field}={value}",
    )

    assert _build_process_execution_context(
        grouped_event(syscall=syscall)
    ) is None


def test_raw_architecture_and_syscall_are_preserved_without_name_guessing():
    syscall = DEFAULT_SYSCALL.replace(
        "arch=c000003e syscall=59",
        "arch=fixture-arch syscall=fixture-call",
    )

    context = _build_process_execution_context(grouped_event(syscall=syscall))

    assert context is not None
    assert context.architecture_raw == "fixture-arch"
    assert context.syscall_raw == "fixture-call"
    assert context.architecture_name is None
    assert context.syscall_name is None


@pytest.mark.parametrize(
    ("success", "exit_value", "outcome", "exit_code"),
    [
        ("yes", "0", "success", 0),
        ("no", "-13", "failure", -13),
        ("unexpected", "7", "unknown", 7),
        (None, None, "unknown", None),
        ("yes", "invalid", "success", None),
        ("no", "0", "failure", 0),
    ],
)
def test_outcome_and_exit_remain_independent_observations(
    success,
    exit_value,
    outcome,
    exit_code,
):
    tokens = [
        token for token in DEFAULT_SYSCALL.split()
        if not token.startswith(("success=", "exit="))
    ]
    if success is not None:
        tokens.append(f"success={success}")
    if exit_value is not None:
        tokens.append(f"exit={exit_value}")

    context = _build_process_execution_context(
        grouped_event(syscall=" ".join(tokens))
    )

    assert context is not None
    assert context.outcome == outcome
    assert context.exit_code == exit_code


def test_identity_fields_preserve_numeric_values_and_unset_as_none():
    syscall = DEFAULT_SYSCALL.replace(
        "uid=1000 gid=1000 euid=1001 suid=1002 fsuid=1003 "
        "egid=1001 sgid=1002 fsgid=1003",
        "uid=10 gid=20 euid=11 suid=invalid fsuid=4294967295 "
        "egid=21 sgid=-1 fsgid=4294967295",
    )

    context = _build_process_execution_context(grouped_event(syscall=syscall))

    assert context is not None
    assert context.real_user_id == 10
    assert context.effective_user_id == 11
    assert context.saved_user_id is None
    assert context.filesystem_user_id is None
    assert context.real_group_id == 20
    assert context.effective_group_id == 21
    assert context.saved_group_id is None
    assert context.filesystem_group_id is None


def test_string_fields_are_independent_and_special_markers_become_none():
    independent = DEFAULT_SYSCALL.replace(
        'comm="example" exe="/usr/bin/example"',
        'comm="wrapper" exe="/opt/fixture/program"',
    )
    independent_event = grouped_event(
        syscall=independent,
        execve='argc=1 a0="different-argv-zero"',
    )
    marker_syscall = DEFAULT_SYSCALL.replace(
        'tty=pts0 comm="example" exe="/usr/bin/example" '
        'key="fixture-exec"',
        'tty=? comm="(null)" exe=(none) key=(null)',
    )

    context = _build_process_execution_context(independent_event)
    markers = _build_process_execution_context(
        grouped_event(syscall=marker_syscall)
    )

    assert context is not None
    assert context.command_name == "wrapper"
    assert context.executable == "/opt/fixture/program"
    assert context.argv == ("different-argv-zero",)
    assert markers is not None
    assert markers.command_name is None
    assert markers.executable is None
    assert markers.terminal is None
    assert markers.audit_rule_key is None


def test_cwd_optional_duplicate_and_conflict_policy():
    absent = _build_process_execution_context(grouped_event())
    single = _build_process_execution_context(grouped_event(extra=(
        ("CWD", 'cwd="/opt/fixture"'),
    )))
    duplicate = _build_process_execution_context(grouped_event(extra=(
        ("CWD", 'cwd="/opt/fixture"'),
        ("CWD", 'cwd="/opt/fixture"'),
    )))
    conflict = _build_process_execution_context(grouped_event(extra=(
        ("CWD", 'cwd="/opt/a"'),
        ("CWD", 'cwd="/opt/b"'),
    )))
    invalid = _build_process_execution_context(grouped_event(extra=(
        ("CWD", "cwd=FF"),
    )))

    assert absent.working_directory is None
    assert single.working_directory == "/opt/fixture"
    assert duplicate.working_directory == "/opt/fixture"
    assert conflict.working_directory is None
    assert invalid.working_directory is None


def test_path_fields_are_typed_and_sorted_by_numeric_item():
    syscall = DEFAULT_SYSCALL.replace("items=0", "items=2")
    event = grouped_event(syscall=syscall, extra=(
        (
            "PATH",
            'item=1 name="/opt/second" inode=102 dev=fd:01 '
            "mode=0100644 ouid=1001 ogid=1002 nametype=NORMAL",
        ),
        (
            "PATH",
            'item=0 name="/opt/first" inode=101 dev=fd:02 '
            "mode=0100755 ouid=1000 ogid=1000 nametype=CREATE",
        ),
    ))

    context = _build_process_execution_context(event)

    assert context is not None
    assert [path.item for path in context.paths] == [0, 1]
    first, second = context.paths
    assert (
        first.name,
        first.nametype,
        first.inode,
        first.device,
        first.mode,
        first.owner_user_id,
        first.owner_group_id,
    ) == (
        "/opt/first",
        "CREATE",
        101,
        "fd:02",
        "0100755",
        1000,
        1000,
    )
    assert second.name == "/opt/second"
    assert context.paths_complete is True


@pytest.mark.parametrize(
    ("items", "paths", "expected_complete"),
    [
        ("0", (), True),
        (None, (), False),
        ("2", (("PATH", 'item=0 name="/a"'),), False),
        (
            "2",
            (
                ("PATH", 'item=0 name="/a"'),
                ("PATH", 'item=0 name="/a"'),
            ),
            False,
        ),
        (
            "2",
            (
                ("PATH", 'item=0 name="/a"'),
                ("PATH", 'item=2 name="/c"'),
            ),
            False,
        ),
        ("1", (("PATH", 'item=invalid name="/a"'),), False),
        ("1", (("PATH", "item=0 name=FF"),), False),
    ],
)
def test_path_completeness_is_bounded_by_items_and_safe_parsing(
    items,
    paths,
    expected_complete,
):
    syscall_tokens = [
        token for token in DEFAULT_SYSCALL.split()
        if not token.startswith("items=")
    ]
    if items is not None:
        syscall_tokens.append(f"items={items}")

    context = _build_process_execution_context(grouped_event(
        syscall=" ".join(syscall_tokens),
        extra=paths,
    ))

    assert context is not None
    assert context.paths_complete is expected_complete
    assert len(context.paths) == len(paths)


def test_duplicate_path_records_are_preserved_not_deduplicated():
    syscall = DEFAULT_SYSCALL.replace("items=0", "items=2")
    event = grouped_event(syscall=syscall, extra=(
        ("PATH", 'item=0 name="/same"'),
        ("PATH", 'item=0 name="/same"'),
    ))

    context = _build_process_execution_context(event)

    assert context is not None
    assert len(context.paths) == 2
    assert context.paths[0] == context.paths[1]
    assert context.paths_complete is False


def test_proctitle_optional_hex_nul_and_trailing_nul_policy():
    absent = _build_process_execution_context(grouped_event())
    present = _build_process_execution_context(grouped_event(extra=(
        ("PROCTITLE", "proctitle=6F6E650074776F00"),
    )))

    assert absent.proctitle_raw is None
    assert absent.proctitle_arguments is None
    assert present.proctitle_raw == "6F6E650074776F00"
    assert present.proctitle_arguments == ("one", "two")


@pytest.mark.parametrize(
    "raw_value",
    ["ABC", "not-hex", "FF"],
)
def test_invalid_proctitle_keeps_raw_value_without_decoded_arguments(
    raw_value,
):
    context = _build_process_execution_context(grouped_event(extra=(
        ("PROCTITLE", f"proctitle={raw_value}"),
    )))

    assert context.proctitle_raw == raw_value
    assert context.proctitle_arguments is None
    assert context.argv == ("/usr/bin/example",)


def test_duplicate_and_conflicting_proctitle_policy():
    duplicate = _build_process_execution_context(grouped_event(extra=(
        ("PROCTITLE", "proctitle=6F6E65"),
        ("PROCTITLE", "proctitle=6F6E65"),
    )))
    conflict = _build_process_execution_context(grouped_event(extra=(
        ("PROCTITLE", "proctitle=6F6E65"),
        ("PROCTITLE", "proctitle=74776F"),
    )))

    assert duplicate.proctitle_raw == "6F6E65"
    assert duplicate.proctitle_arguments == ("one",)
    assert conflict.proctitle_raw is None
    assert conflict.proctitle_arguments is None


def test_conflicting_fragment_fixture_keeps_incomplete_context():
    event = fixture_event(
        "linux_audit_exec_duplicate_fields_synthetic.log",
        "1790400010.011:811",
    )

    context = _build_process_execution_context(event)

    assert context is not None
    assert context.argv == ("/usr/bin/example", None)
    assert context.argv_complete is False
    assert context.incomplete_argument_indexes == (1,)


def test_invalid_path_item_sorts_after_valid_item_without_deduplication():
    syscall = DEFAULT_SYSCALL.replace("items=0", "items=2")
    event = grouped_event(syscall=syscall, extra=(
        ("PATH", 'item=invalid name="/invalid-item"'),
        ("PATH", 'item=0 name="/valid-item"'),
    ))

    context = _build_process_execution_context(event)

    assert context is not None
    assert [path.item for path in context.paths] == [0, None]
    assert [path.name for path in context.paths] == [
        "/valid-item",
        "/invalid-item",
    ]
    assert context.paths_complete is False


def test_builder_is_not_connected_to_production_parser_output():
    event = fixture_event(
        "linux_audit_exec_success_rhel_source_derived.log"
    )

    assert _build_process_execution_context(event) is not None
    assert parse_linux_audit_events(event) == []


def test_raw_records_include_auxiliary_and_duplicates_without_mutation():
    event = grouped_event(extra=(
        ("AUX", "detail=fixture"),
        ("CWD", 'cwd="/opt/fixture"'),
        ("CWD", 'cwd="/opt/fixture"'),
    ))
    before_records = event.records
    before_fields = tuple(dict(record.fields) for record in event.records)

    context = _build_process_execution_context(event)

    assert context is not None
    assert context.raw_records == tuple(
        record.raw for record in event.records
    )
    assert sum("type=CWD" in raw for raw in context.raw_records) == 2
    assert any("type=AUX" in raw for raw in context.raw_records)
    assert event.records == before_records
    assert tuple(dict(record.fields) for record in event.records) == before_fields
