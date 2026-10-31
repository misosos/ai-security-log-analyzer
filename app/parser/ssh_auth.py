from datetime import datetime, timezone
import ipaddress
import re
import unicodedata
from zoneinfo import ZoneInfo

from app.models.schemas import (
    AuthenticationContext,
    NormalizedEvent,
)


AUTHENTICATION_MESSAGE = re.compile(
    r"^(?P<outcome>Failed|Accepted) "
    r"(?P<method>password|publickey) for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<user>\S+) from (?P<src_ip>\S+)"
    r"(?:"
    r" port (?P<source_port>\d+) ssh2"
    r"(?:\s*:\s*.*)?"
    r"|$"
    r")"
)
SSH_PROCESS_MESSAGE = re.compile(
    r"(?:"
    r"sshd:?\s+(?P<plain_message>.+)"
    r"|(?:\S+\s+)?sshd\[(?P<pid>\d+)\]:\s+(?P<pid_message>.+)"
    r")$"
)
_RFC5424_PREFIX = re.compile(r"^<(?P<pri>[0-9]{1,3})>(?P<version>[0-9]+) ")
_RFC5424_PRI_VALUE = re.compile(r"^(?:0|[1-9][0-9]{0,2})$")
_RFC5424_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_RFC5424_HEADER = re.compile(
    r"^(?P<timestamp>[^ ]+) (?P<hostname>[^ ]{1,255}) "
    r"(?P<app>[^ ]{1,48}) (?P<procid>[^ ]{1,128}) "
    r"(?P<msgid>[^ ]{1,32}) - (?P<message>.+)$"
)
_AUTHENTICATION_PREFIX = re.compile(r"^(?:Failed|Accepted)\b")


def _parse_rfc5424_timestamp(value):
    if (
        _RFC5424_TIMESTAMP.fullmatch(value) is None
        or value.endswith("-00:00")
    ):
        raise ValueError("Unsupported RFC 5424 timestamp.") from None
    offset = re.search(r"([+-])([0-9]{2}):([0-9]{2})$", value)
    if offset is not None and (
        int(offset.group(2)) > 23 or int(offset.group(3)) > 59
    ):
        raise ValueError("Unsupported RFC 5424 timestamp.") from None
    iso_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        raise ValueError("Unsupported RFC 5424 timestamp.") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Unsupported RFC 5424 timestamp.") from None
    return parsed.astimezone(timezone.utc)


def _validate_rfc5424_text(value):
    # RFC 5424 HEADER fields are ASCII. MSG may be UTF-8, but control and
    # formatting controls can make authentication text visually deceptive.
    for char in value:
        category = unicodedata.category(char)
        if category in {"Cc", "Cf", "Cs"}:
            raise ValueError("Unsupported RFC 5424 text.") from None


def _parse_rfc5424_ssh(log):
    if len(log) > 8192 or "\r" in log or "\n" in log:
        raise ValueError("Unsupported RFC 5424 record.") from None
    prefix = _RFC5424_PREFIX.match(log)
    if prefix is None:
        raise ValueError("Unsupported RFC 5424 header.") from None
    if _RFC5424_PRI_VALUE.fullmatch(prefix.group("pri")) is None:
        raise ValueError("Unsupported RFC 5424 header.") from None
    pri = int(prefix.group("pri"))
    if pri > 191 or prefix.group("version") != "1":
        raise ValueError("Unsupported RFC 5424 header.") from None

    remainder = log[prefix.end():]
    header = _RFC5424_HEADER.fullmatch(remainder)
    if header is None:
        raise ValueError("Unsupported RFC 5424 header.") from None
    fields = header.groupdict()
    # Header fields are constrained to printable ASCII and have no inferred
    # server identity semantics. Only APP-NAME selects this parser profile.
    for name in ("hostname", "app", "procid", "msgid"):
        if not fields[name].isascii() or any(
            ord(char) < 33 or ord(char) > 126 for char in fields[name]
        ):
            raise ValueError("Unsupported RFC 5424 header.") from None
    if fields["app"] != "sshd":
        raise ValueError("Unsupported RFC 5424 application.") from None
    if fields["procid"] != "-" and (
        not fields["procid"].isascii() or not fields["procid"].isdigit()
    ):
        raise ValueError("Unsupported RFC 5424 process identifier.") from None
    if not fields["message"]:
        raise ValueError("Incomplete RFC 5424 message.") from None
    _validate_rfc5424_text(fields["message"])
    timestamp = _parse_rfc5424_timestamp(fields["timestamp"])
    return _event_from_message(
        timestamp, fields["message"], log, strict=True
    )


def _event_from_message(timestamp, message_text, log, *, strict=False):
    event_type = None
    user = None
    src_ip = None
    authentication = None
    message = AUTHENTICATION_MESSAGE.fullmatch(message_text)

    if message is None and strict and _AUTHENTICATION_PREFIX.match(message_text):
        raise ValueError("Malformed SSH authentication message.") from None

    if message is not None:
        outcome = (
            "success"
            if message.group("outcome") == "Accepted"
            else "failure"
        )
        event_type = (
            "user_login"
            if outcome == "success"
            else "login_failed"
        )
        user = message.group("user")
        src_ip = message.group("src_ip")

        source_port_text = message.group("source_port")
        source_port = (
            int(source_port_text)
            if source_port_text is not None
            else None
        )
        invalid_user = None
        if source_port is not None:
            invalid_user = message.group("invalid_user") is not None

        if strict:
            if "%" in src_ip:
                raise ValueError("Unsupported SSH source address.") from None
            try:
                ipaddress.ip_address(src_ip)
            except ValueError:
                raise ValueError("Unsupported SSH source address.") from None
            if source_port is not None and not 1 <= source_port <= 65535:
                raise ValueError("Unsupported SSH source port.") from None

        authentication = AuthenticationContext(
            outcome=outcome,
            method=message.group("method"),
            service="sshd",
            source_port=source_port,
            invalid_user=invalid_user,
        )

    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event_type,
        source="ssh",
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        application="sshd",
        protocol="ssh",
        user_agent=None,
        raw=log,
        authentication=authentication,
    )


def parse_ssh_auth_log(log, timezone=None):
    if type(log) is not str:
        raise ValueError("Unsupported SSH log record.") from None
    if log.startswith("<"):
        return _parse_rfc5424_ssh(log)
    parts = log.split()
    if len(parts) < 3:
        raise ValueError("Unsupported SSH log record.") from None

    timestamp = datetime.strptime(
        parts[0] + " " + parts[1],
        "%Y-%m-%d %H:%M:%S",
    )

    remainder = log.split(None, 2)[2].rstrip("\r\n")
    process_message = SSH_PROCESS_MESSAGE.fullmatch(remainder)
    if process_message is None:
        raise ValueError("Unsupported SSH process marker.") from None
    message_text = (
        process_message.group("plain_message")
        or process_message.group("pid_message")
    )

    if timestamp.tzinfo is None and timezone:
        timestamp = timestamp.replace(
            tzinfo=ZoneInfo(timezone)
        )

    return _event_from_message(timestamp, message_text, log)
