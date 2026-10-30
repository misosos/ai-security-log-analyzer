from datetime import datetime
import re
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


def parse_ssh_auth_log(log, timezone=None):
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

    event_type = None
    user = None
    src_ip = None
    authentication = None

    message = AUTHENTICATION_MESSAGE.match(message_text)

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
            invalid_user = (
                message.group("invalid_user") is not None
            )

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
