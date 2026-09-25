from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_address
import re

from app.models.schemas import (
    AuthenticationContext,
    LinuxAuditContext,
    LinuxAuditPathContext,
    NormalizedEvent,
    ProcessExecutionContext,
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


AUDIT_FIELD = re.compile(
    r'(?<!\S)'
    r'(?P<name>[A-Za-z0-9_.\-\[\]]+)='
    r'(?P<value>"[^"]*"|\S+)'
)


def _record_field_values(record, field_name):
    return tuple(
        _serialized_execve_value(match.group("value"))
        for match in AUDIT_FIELD.finditer(record.raw)
        if match.group("name") == field_name
    )


def _non_negative_decimal(value):
    if value is None or re.fullmatch(r"\d+", value) is None:
        return None
    return int(value)


def _signed_decimal(value):
    if value is None or re.fullmatch(r"-?\d+", value) is None:
        return None
    return int(value)


def _single_raw_text(record, field_name, required=False):
    values = _record_field_values(record, field_name)
    if not values:
        return None, not required
    if len(values) != 1 or not values[0].value:
        return None, False
    return values[0].value, True


def _single_numeric_field(record, field_name, converter):
    values = _record_field_values(record, field_name)
    if not values:
        return None, True
    if len(values) != 1:
        return None, False
    parsed = converter(values[0].value)
    return parsed, parsed is not None


def _decode_audit_string(serialized):
    if serialized.value.lower() in UNKNOWN_VALUES | {"(null)"}:
        return None, True
    decoded = _decode_execve_value(serialized)
    return decoded, decoded is not None


def _single_encoded_field(record, field_name):
    values = _record_field_values(record, field_name)
    if not values:
        return None, True
    if len(values) != 1:
        return None, False
    return _decode_audit_string(values[0])


def _single_optional_text(record, field_name):
    value, valid = _single_raw_text(record, field_name)
    if not valid or value is None:
        return None, valid
    if value.lower() in UNKNOWN_VALUES | {"(null)"}:
        return None, True
    return value, True


def _normalize_process_outcome(value):
    if value == "yes":
        return "success"
    if value == "no":
        return "failure"
    return "unknown"


def _normalize_cwd(records):
    if not records:
        return None
    observed = []
    for record in records:
        value, valid = _single_encoded_field(record, "cwd")
        if not valid:
            return None
        observed.append(value)
    if len(set(observed)) != 1:
        return None
    return observed[0]


def _normalize_path(record):
    item, item_valid = _single_numeric_field(
        record, "item", _non_negative_decimal
    )
    name, name_valid = _single_encoded_field(record, "name")
    nametype, nametype_valid = _single_optional_text(
        record, "nametype"
    )
    inode, inode_valid = _single_numeric_field(
        record, "inode", _non_negative_decimal
    )
    device, device_valid = _single_optional_text(record, "dev")
    mode, mode_valid = _single_optional_text(record, "mode")
    owner_user_id, owner_user_id_valid = _single_numeric_field(
        record, "ouid", _numeric_id
    )
    owner_group_id, owner_group_id_valid = _single_numeric_field(
        record, "ogid", _numeric_id
    )
    return (
        LinuxAuditPathContext(
            item=item,
            name=name,
            nametype=nametype,
            inode=inode,
            device=device,
            mode=mode,
            owner_user_id=owner_user_id,
            owner_group_id=owner_group_id,
        ),
        all((
            item_valid,
            name_valid,
            nametype_valid,
            inode_valid,
            device_valid,
            mode_valid,
            owner_user_id_valid,
            owner_group_id_valid,
        )),
    )


def _normalize_paths(path_records, syscall_record):
    normalized = []
    structurally_valid = True
    for record in path_records:
        path, valid = _normalize_path(record)
        normalized.append((path, record.raw))
        structurally_valid = structurally_valid and valid
    normalized.sort(key=lambda item: (
        item[0].item is None,
        item[0].item if item[0].item is not None else 0,
        item[1],
    ))
    paths = tuple(path for path, _ in normalized)

    items, items_valid = _single_numeric_field(
        syscall_record, "items", _non_negative_decimal
    )
    path_items = [path.item for path in paths]
    paths_complete = (
        items_valid
        and items is not None
        and structurally_valid
        and len(paths) == items
        and path_items == list(range(items))
    )
    return paths, paths_complete


def _decode_proctitle_arguments(serialized):
    if serialized.quoted:
        return None
    raw_value = serialized.value
    if (
        not raw_value
        or len(raw_value) % 2
        or re.fullmatch(r"[0-9A-Fa-f]+", raw_value) is None
    ):
        return None
    try:
        components = bytes.fromhex(raw_value).split(b"\x00")
        while components and components[-1] == b"":
            components.pop()
        return tuple(component.decode("utf-8") for component in components)
    except (UnicodeDecodeError, ValueError):
        return None


def _normalize_proctitle(records):
    if not records:
        return None, None
    observed = []
    for record in records:
        values = _record_field_values(record, "proctitle")
        if len(values) != 1:
            return None, None
        observed.append(values[0])
    if len(set(observed)) != 1:
        return None, None
    serialized = observed[0]
    return serialized.value, _decode_proctitle_arguments(serialized)


def _build_process_execution_context(event):
    syscall_records = tuple(
        record for record in event.records
        if record.record_type == "SYSCALL"
    )
    execve_records = tuple(
        record for record in event.records
        if record.record_type == "EXECVE"
    )
    if len(syscall_records) != 1 or not execve_records:
        return None

    syscall_record = syscall_records[0]
    architecture_raw, architecture_valid = _single_raw_text(
        syscall_record, "arch", required=True
    )
    syscall_raw, syscall_valid = _single_raw_text(
        syscall_record, "syscall", required=True
    )
    process_id, process_id_valid = _single_numeric_field(
        syscall_record, "pid", _non_negative_decimal
    )
    parent_process_id, parent_process_id_valid = _single_numeric_field(
        syscall_record, "ppid", _non_negative_decimal
    )
    if not all((
        architecture_valid,
        syscall_valid,
        process_id_valid,
        parent_process_id_valid,
        process_id is not None,
        parent_process_id is not None,
    )):
        return None

    arguments = _assemble_execve_arguments(execve_records)
    if arguments.argument_count is None:
        return None

    success, _ = _single_raw_text(syscall_record, "success")
    exit_code, _ = _single_numeric_field(
        syscall_record, "exit", _signed_decimal
    )
    command_name, _ = _single_encoded_field(syscall_record, "comm")
    executable, _ = _single_encoded_field(syscall_record, "exe")
    terminal, _ = _single_optional_text(syscall_record, "tty")
    audit_rule_key, _ = _single_encoded_field(syscall_record, "key")

    cwd_records = tuple(
        record for record in event.records if record.record_type == "CWD"
    )
    path_records = tuple(
        record for record in event.records if record.record_type == "PATH"
    )
    proctitle_records = tuple(
        record for record in event.records
        if record.record_type == "PROCTITLE"
    )
    paths, paths_complete = _normalize_paths(
        path_records, syscall_record
    )
    proctitle_raw, proctitle_arguments = _normalize_proctitle(
        proctitle_records
    )

    return ProcessExecutionContext(
        outcome=_normalize_process_outcome(success),
        architecture_raw=architecture_raw,
        syscall_raw=syscall_raw,
        architecture_name=None,
        syscall_name=None,
        exit_code=exit_code,
        process_id=process_id,
        parent_process_id=parent_process_id,
        real_user_id=_numeric_id(syscall_record.fields.get("uid")),
        effective_user_id=_numeric_id(syscall_record.fields.get("euid")),
        saved_user_id=_numeric_id(syscall_record.fields.get("suid")),
        filesystem_user_id=_numeric_id(syscall_record.fields.get("fsuid")),
        real_group_id=_numeric_id(syscall_record.fields.get("gid")),
        effective_group_id=_numeric_id(syscall_record.fields.get("egid")),
        saved_group_id=_numeric_id(syscall_record.fields.get("sgid")),
        filesystem_group_id=_numeric_id(syscall_record.fields.get("fsgid")),
        command_name=command_name,
        executable=executable,
        terminal=terminal,
        audit_rule_key=audit_rule_key,
        argument_count=arguments.argument_count,
        argv=arguments.argv,
        argv_complete=arguments.argv_complete,
        incomplete_argument_indexes=(
            arguments.incomplete_argument_indexes
        ),
        working_directory=_normalize_cwd(cwd_records),
        paths=paths,
        paths_complete=paths_complete,
        proctitle_raw=proctitle_raw,
        proctitle_arguments=proctitle_arguments,
        raw_records=tuple(record.raw for record in event.records),
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
