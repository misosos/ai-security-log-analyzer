from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_address
import re

from app.models.schemas import (
    AuthenticationContext,
    LinuxAuditContext,
    NormalizedEvent,
)


UNKNOWN_VALUES = {
    "",
    "?",
    "(unknown)",
    "unknown",
    "unset",
    "none",
    "(none)",
}
UNSET_AUDIT_ID = 4294967295
SEMANTIC_RECORDS = {
    "USER_AUTH": "authentication_attempt",
    "USER_ACCT": "account_authorization_attempt",
    "USER_LOGIN": "login_establishment",
    "USER_START": "session_start",
    "USER_END": "session_end",
}
SEMANTIC_RECORD_ORDER = {
    "USER_AUTH": 0,
    "USER_ACCT": 1,
    "USER_LOGIN": 2,
    "USER_START": 3,
    "USER_END": 4,
}


EXECVE_FIELD = re.compile(
    r'(?<!\S)'
    r'(?P<name>argc|a\d+(?:_len|\[\d+\])?)='
    r'(?P<value>"[^"]*"|\S+)'
)
EXECVE_ARGUMENT = re.compile(r"^a(?P<argument>\d+)$")
EXECVE_ARGUMENT_LENGTH = re.compile(
    r"^a(?P<argument>\d+)_len$"
)
EXECVE_ARGUMENT_FRAGMENT = re.compile(
    r"^a(?P<argument>\d+)\[(?P<fragment>\d+)\]$"
)


@dataclass(frozen=True)
class _SerializedExecveValue:
    value: str
    quoted: bool


@dataclass(frozen=True)
class _ExecveArgumentAssembly:
    argument_count: int | None
    argv: tuple[str | None, ...]
    argv_complete: bool
    incomplete_argument_indexes: tuple[int, ...]


def _serialized_execve_value(raw_value):
    if raw_value.startswith('"') and raw_value.endswith('"'):
        return _SerializedExecveValue(
            value=raw_value[1:-1],
            quoted=True,
        )

    return _SerializedExecveValue(
        value=raw_value,
        quoted=False,
    )


def _decode_execve_value(serialized):
    if serialized.quoted:
        return serialized.value

    value = serialized.value

    if (
        not value
        or len(value) % 2
        or re.fullmatch(r"[0-9A-Fa-f]+", value) is None
    ):
        return None

    try:
        decoded = bytes.fromhex(value)
        if b"\x00" in decoded:
            return None
        return decoded.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def _parse_non_negative_decimal(values):
    parsed = []

    for value in values:
        if re.fullmatch(r"\d+", value) is None:
            return None, False
        parsed.append(int(value))

    if not parsed or len(set(parsed)) != 1:
        return None, False

    return parsed[0], len(parsed) == 1


def _execve_fields(record):
    if record.record_type != "EXECVE":
        return ()

    return tuple(
        (match.group("name"), match.group("value"))
        for match in EXECVE_FIELD.finditer(record.raw)
    )


def _assemble_fragmented_execve_argument(
    fragment_values,
    length_values,
):
    declared_length, length_unique = _parse_non_negative_decimal(
        length_values
    )
    duplicated = not length_unique

    if declared_length is None or not fragment_values:
        return None, True

    fragment_indexes = sorted(fragment_values)
    if fragment_indexes != list(range(fragment_indexes[-1] + 1)):
        return None, True

    fragments = []
    quoted = None

    for fragment_index in fragment_indexes:
        observed = fragment_values[fragment_index]
        duplicated = duplicated or len(observed) != 1

        if len(set(observed)) != 1:
            return None, True

        fragment = observed[0]
        if quoted is None:
            quoted = fragment.quoted
        elif quoted != fragment.quoted:
            return None, True
        fragments.append(fragment.value)

    joined = "".join(fragments)
    serialized_length = (
        len(joined.encode("utf-8")) if quoted else len(joined)
    )
    if serialized_length != declared_length:
        return None, True

    decoded = _decode_execve_value(
        _SerializedExecveValue(joined, quoted)
    )
    if decoded is None:
        return None, True

    return decoded, duplicated


def _assemble_execve_arguments(records):
    argc_values = []
    whole_values = defaultdict(list)
    length_values = defaultdict(list)
    fragment_values = defaultdict(lambda: defaultdict(list))
    execve_records = tuple(
        record for record in records if record.record_type == "EXECVE"
    )

    for record in execve_records:
        for name, raw_value in _execve_fields(record):
            if name == "argc":
                argc_values.append(raw_value)
                continue

            match = EXECVE_ARGUMENT.fullmatch(name)
            if match is not None:
                whole_values[int(match.group("argument"))].append(
                    _serialized_execve_value(raw_value)
                )
                continue

            match = EXECVE_ARGUMENT_LENGTH.fullmatch(name)
            if match is not None:
                length_values[int(match.group("argument"))].append(
                    raw_value
                )
                continue

            match = EXECVE_ARGUMENT_FRAGMENT.fullmatch(name)
            if match is not None:
                fragment_values[
                    int(match.group("argument"))
                ][int(match.group("fragment"))].append(
                    _serialized_execve_value(raw_value)
                )

    argument_count, argc_unique = _parse_non_negative_decimal(
        argc_values
    )
    raw_size = sum(len(record.raw) for record in execve_records)

    if argument_count is None or argument_count > raw_size:
        return _ExecveArgumentAssembly(
            argument_count=None,
            argv=(),
            argv_complete=False,
            incomplete_argument_indexes=(),
        )

    argv = []
    incomplete = set()
    observed_indexes = (
        set(whole_values)
        | set(length_values)
        | set(fragment_values)
    )

    for argument_index in range(argument_count):
        whole = whole_values.get(argument_index, ())
        fragments = fragment_values.get(argument_index, {})
        lengths = length_values.get(argument_index, ())

        if whole and (fragments or lengths):
            argv.append(None)
            incomplete.add(argument_index)
            continue

        if whole:
            decoded = tuple(
                _decode_execve_value(value) for value in whole
            )
            if None in decoded or len(set(decoded)) != 1:
                argv.append(None)
                incomplete.add(argument_index)
                continue

            argv.append(decoded[0])
            if len(whole) != 1:
                incomplete.add(argument_index)
            continue

        if fragments or lengths:
            decoded, is_incomplete = (
                _assemble_fragmented_execve_argument(
                    fragments,
                    lengths,
                )
            )
            argv.append(decoded)
            if is_incomplete:
                incomplete.add(argument_index)
            continue

        argv.append(None)
        incomplete.add(argument_index)

    has_out_of_range_evidence = any(
        index >= argument_count for index in observed_indexes
    )
    argv_complete = (
        argc_unique
        and not incomplete
        and not has_out_of_range_evidence
    )

    return _ExecveArgumentAssembly(
        argument_count=argument_count,
        argv=tuple(argv),
        argv_complete=argv_complete,
        incomplete_argument_indexes=tuple(sorted(incomplete)),
    )


def _known_text(value):
    if value is None or value.lower() in UNKNOWN_VALUES:
        return None

    return value


def _numeric_id(value):
    try:
        numeric_value = int(value)
    except (TypeError, ValueError):
        return None

    if numeric_value < 0 or numeric_value >= UNSET_AUDIT_ID:
        return None

    return numeric_value


def _remote_address(value):
    value = _known_text(value)

    if value is None:
        return None

    try:
        address = ip_address(value)
    except ValueError:
        return None

    if address.is_loopback or address.is_unspecified:
        return None

    return value


def _outcome(value):
    if value == "success":
        return "success"
    if value == "failed":
        return "failure"

    return "unknown"


def _normalize_semantic_record(record, event, record_types):
    fields = record.fields

    return NormalizedEvent(
        timestamp=event.timestamp,
        event_type=SEMANTIC_RECORDS[record.record_type],
        source="linux_audit",
        user=_known_text(fields.get("acct")),
        src_ip=_remote_address(fields.get("addr")),
        dst_ip=None,
        application=None,
        protocol=None,
        user_agent=None,
        raw=record.raw,
        authentication=AuthenticationContext(
            outcome=_outcome(fields.get("res")),
            method=None,
            service=None,
        ),
        linux_audit=LinuxAuditContext(
            event_id=event.event_id,
            record_types=record_types,
            operation=_known_text(fields.get("op")),
            executable=_known_text(fields.get("exe")),
            process_user_id=_numeric_id(fields.get("uid")),
            audit_user_id=_numeric_id(fields.get("auid")),
            audit_session_id=_numeric_id(fields.get("ses")),
            terminal=_known_text(fields.get("terminal")),
            hostname=_known_text(fields.get("hostname")),
            source_instance=event.source_instance,
            node=event.node,
        ),
    )


def parse_linux_audit_events(event):
    record_types = tuple(
        record.record_type
        for record in event.records
    )
    semantic_records = sorted(
        (
            record
            for record in event.records
            if record.record_type in SEMANTIC_RECORDS
        ),
        key=lambda record: (
            SEMANTIC_RECORD_ORDER[record.record_type],
            record.raw,
        ),
    )

    return [
        _normalize_semantic_record(
            record,
            event,
            record_types,
        )
        for record in semantic_records
    ]
