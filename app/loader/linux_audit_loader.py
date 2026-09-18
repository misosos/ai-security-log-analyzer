from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import shlex


AUDIT_PREAMBLE = re.compile(
    r"^type=(?P<record_type>[A-Z0-9_]+) "
    r"msg=audit\("
    r"(?P<seconds>\d+)\."
    r"(?P<fraction>\d+):"
    r"(?P<serial>\d+)"
    r"\):\s*(?P<payload>.*)$"
)


@dataclass(frozen=True)
class AuditRecord:
    record_type: str
    event_id: str
    timestamp: datetime
    serial: int
    fields: dict[str, str]
    raw: str


@dataclass(frozen=True)
class GroupedAuditEvent:
    event_id: str
    timestamp: datetime
    serial: int
    records: tuple[AuditRecord, ...]


def _parse_key_values(text):
    fields = {}

    try:
        tokens = shlex.split(text)
    except ValueError:
        return None

    for token in tokens:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)

        if key == "msg":
            nested_fields = _parse_key_values(value)

            if nested_fields is None:
                return None

            fields.update(nested_fields)
        else:
            fields[key] = value

    return fields


def parse_audit_record(line):
    match = AUDIT_PREAMBLE.match(line)

    if match is None:
        return None

    fraction = match.group("fraction")
    microseconds = int((fraction + "000000")[:6])
    timestamp = datetime.fromtimestamp(
        int(match.group("seconds")),
        tz=timezone.utc,
    ).replace(microsecond=microseconds)
    serial = int(match.group("serial"))
    event_id = (
        f"{match.group('seconds')}.{fraction}:"
        f"{match.group('serial')}"
    )

    fields = _parse_key_values(match.group("payload"))

    if fields is None:
        return None

    return AuditRecord(
        record_type=match.group("record_type"),
        event_id=event_id,
        timestamp=timestamp,
        serial=serial,
        fields=fields,
        raw=line,
    )


def load_linux_audit_events(path, source_identity="linux_audit"):
    grouped = {}

    with Path(path).open("r", encoding="utf-8") as audit_file:
        for raw_line in audit_file:
            line = raw_line.rstrip("\r\n")

            if not line.strip():
                continue

            record = parse_audit_record(line)

            if record is None:
                continue

            key = (source_identity, record.event_id)
            grouped.setdefault(key, []).append(record)

    events = []

    for records in grouped.values():
        ordered_records = tuple(sorted(
            records,
            key=lambda record: (
                record.record_type,
                record.raw,
            ),
        ))
        first_record = ordered_records[0]
        events.append(GroupedAuditEvent(
            event_id=first_record.event_id,
            timestamp=first_record.timestamp,
            serial=first_record.serial,
            records=ordered_records,
        ))

    return sorted(
        events,
        key=lambda event: (
            event.timestamp,
            event.serial,
            event.event_id,
            source_identity,
        ),
    )
