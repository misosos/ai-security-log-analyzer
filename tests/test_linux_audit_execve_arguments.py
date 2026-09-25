from itertools import permutations
from pathlib import Path

import pytest

from app.loader.linux_audit_loader import (
    load_linux_audit_events,
    parse_audit_record,
)
from app.parser.linux_audit import _assemble_execve_arguments


FIXTURE_DIR = Path("sample_logs")


def execve_record(fields, serial=900):
    record = parse_audit_record(
        f"type=EXECVE msg=audit(1790500000.001:{serial}): {fields}"
    )
    assert record is not None
    return record


def assemble(fields):
    return _assemble_execve_arguments((execve_record(fields),))


def fixture_event(name, event_id=None):
    events = load_linux_audit_events(
        FIXTURE_DIR / name,
        source_instance="phase-3s-a",
    )
    if event_id is None:
        assert len(events) == 1
        return events[0]
    return next(event for event in events if event.event_id == event_id)


def test_source_derived_and_encoded_fixtures_decode_bounded_arguments():
    source_derived = fixture_event(
        "linux_audit_exec_success_rhel_source_derived.log"
    )
    encoded = fixture_event(
        "linux_audit_exec_encoded_arguments_structurally_derived.log"
    )

    source_result = _assemble_execve_arguments(source_derived.records)
    encoded_result = _assemble_execve_arguments(encoded.records)

    assert source_result.argument_count == 2
    assert source_result.argv == ("/usr/bin/example", "--check")
    assert source_result.argv_complete is True
    assert source_result.incomplete_argument_indexes == ()

    assert encoded_result.argument_count == 4
    assert encoded_result.argv == (
        "/usr/bin/example",
        "ordinary",
        "line\nbreak",
        "",
    )
    assert encoded_result.argv_complete is True


def test_argument_indexes_are_numeric_not_lexical():
    fields = ["argc=11"]
    fields.extend(
        f'a{index}="argument-{index}"'
        for index in (10, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3)
    )

    result = assemble(" ".join(fields))

    assert result.argv == tuple(
        f"argument-{index}" for index in range(11)
    )
    assert result.argv_complete is True


def test_split_fixture_assembles_by_fragment_index_not_record_order():
    event = fixture_event(
        "linux_audit_exec_split_argument_structurally_derived.log"
    )
    before = tuple(record.raw for record in event.records)
    results = {
        _assemble_execve_arguments(records)
        for records in permutations(event.records)
    }

    assert len(results) == 1
    result = results.pop()
    assert result.argument_count == 2
    assert result.argv == ("/usr/bin/example", "longargument")
    assert result.argv_complete is True
    assert tuple(record.raw for record in event.records) == before


def test_fragment_indexes_are_numeric_not_lexical():
    indexes = (10, 2, 1, 0, 9, 8, 7, 6, 5, 4, 3)
    fragments = " ".join(
        f"a1[{index}]={byte_value:02X}"
        for index, byte_value in (
            (index, ord("a") + index) for index in indexes
        )
    )

    result = assemble(
        f'argc=2 a0="example" a1_len=22 {fragments}'
    )

    assert result.argv == ("example", "abcdefghijk")
    assert result.argv_complete is True


@pytest.mark.parametrize(
    ("fields", "expected_value"),
    [
        (
            'argc=2 a0="example" a1_len=22 '
            "a1[0]=68656C6C6F a1[1]=20776F726C64",
            "hello world",
        ),
        (
            'argc=2 a0="example" a1_len=10 '
            "a1[0]=68656C6C6F a1[0]=68656C6C6F",
            "hello",
        ),
    ],
)
def test_fragment_assembly_supports_numeric_order_and_marks_duplicates(
    fields,
    expected_value,
):
    result = assemble(fields)

    assert result.argv == ("example", expected_value)
    assert result.incomplete_argument_indexes == (
        () if "[1]" in fields else (1,)
    )
    assert result.argv_complete is ("[1]" in fields)


@pytest.mark.parametrize(
    "fields",
    [
        'argc=2 a0="example" a1_len=20 a1[0]=68656C6C6F',
        (
            'argc=2 a0="example" a1_len=20 '
            "a1[0]=68656C6C6F a1[2]=776F726C64"
        ),
        (
            'argc=2 a0="example" a1_len=10 '
            "a1[0]=68656C6C6F a1[0]=776F726C64"
        ),
    ],
)
def test_fragment_length_gap_or_conflict_is_incomplete(fields):
    result = assemble(fields)

    assert result.argv == ("example", None)
    assert result.argv_complete is False
    assert result.incomplete_argument_indexes == (1,)


@pytest.mark.parametrize(
    "fields",
    [
        'a0="example"',
        'argc=invalid a0="example"',
        'argc=-1 a0="example"',
        'argc=1 argc=2 a0="example"',
    ],
)
def test_missing_invalid_negative_or_conflicting_argc_fails_safely(fields):
    result = assemble(fields)

    assert result.argument_count is None
    assert result.argv == ()
    assert result.argv_complete is False
    assert result.incomplete_argument_indexes == ()


def test_zero_and_identical_duplicate_argc_remain_distinguishable():
    zero = assemble("argc=0")
    duplicate = assemble('argc=1 argc=1 a0="example"')

    assert zero.argument_count == 0
    assert zero.argv == ()
    assert zero.argv_complete is True
    assert duplicate.argument_count == 1
    assert duplicate.argv == ("example",)
    assert duplicate.argv_complete is False
    assert duplicate.incomplete_argument_indexes == ()


def test_incomplete_fixture_marks_missing_argument_index():
    event = fixture_event(
        "linux_audit_exec_incomplete_arguments_synthetic.log",
        "1790400007.008:808",
    )

    result = _assemble_execve_arguments(event.records)

    assert result.argument_count == 3
    assert result.argv == ("/usr/bin/example", None, "orphan-index")
    assert result.argv_complete is False
    assert result.incomplete_argument_indexes == (1,)


@pytest.mark.parametrize(
    ("fields", "expected_argv", "expected_incomplete"),
    [
        (
            'argc=2 a0="example" a1="same" a1="same"',
            ("example", "same"),
            (1,),
        ),
        (
            'argc=2 a0="example" a1="first" a1="second"',
            ("example", None),
            (1,),
        ),
        (
            'argc=2 a0="example" a1="whole" '
            "a1_len=10 a1[0]=77686F6C65",
            ("example", None),
            (1,),
        ),
        (
            'argc=1 a0="example" a2="outside"',
            ("example",),
            (),
        ),
    ],
)
def test_duplicate_conflicting_and_out_of_range_evidence_is_not_complete(
    fields,
    expected_argv,
    expected_incomplete,
):
    result = assemble(fields)

    assert result.argv == expected_argv
    assert result.argv_complete is False
    assert result.incomplete_argument_indexes == expected_incomplete


@pytest.mark.parametrize(
    "encoded",
    [
        "ABC",
        "not-hex",
        "FF",
        "610062",
    ],
)
def test_invalid_or_unsafe_encoded_bytes_are_not_replaced(encoded):
    result = assemble(f'argc=1 a0={encoded}')

    assert result.argv == (None,)
    assert result.argv_complete is False
    assert result.incomplete_argument_indexes == (0,)


def test_ambiguity_fixtures_preserve_conflicts_and_ignore_syscall_pointers():
    duplicate_argc = fixture_event(
        "linux_audit_exec_duplicate_fields_synthetic.log",
        "1790400009.010:810",
    )
    conflicting_fragment = fixture_event(
        "linux_audit_exec_duplicate_fields_synthetic.log",
        "1790400010.011:811",
    )
    multiple_syscalls = fixture_event(
        "linux_audit_exec_required_records_ambiguous_synthetic.log",
        "1790400011.012:812",
    )

    assert _assemble_execve_arguments(
        duplicate_argc.records
    ).argument_count is None
    assert _assemble_execve_arguments(
        conflicting_fragment.records
    ).argv == ("/usr/bin/example", None)

    syscall_result = _assemble_execve_arguments(multiple_syscalls.records)
    assert syscall_result.argv == ("/usr/bin/example",)
    assert syscall_result.argv_complete is True


def test_large_unsubstantiated_argc_does_not_allocate_amplified_argv():
    result = assemble("argc=1000000000")

    assert result.argument_count is None
    assert result.argv == ()
    assert result.argv_complete is False
