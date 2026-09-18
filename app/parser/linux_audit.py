from ipaddress import ip_address

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
