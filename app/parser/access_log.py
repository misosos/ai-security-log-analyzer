import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

from app.models.schemas import HttpContext, NormalizedEvent


_PREFIX = re.compile(
    r"^(?P<address>\S+) +(?P<ident>\S+) +(?P<remote_user>\S+) "
    r"\[(?P<timestamp>[^\]\r\n]+)\] +"
)
_TIMESTAMP = re.compile(
    r"[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\Z"
)
_STATUS_SIZE = re.compile(r"(?P<status>[0-9]{3}) +(?P<size>[0-9]+|-)")
_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_PROTOCOL = re.compile(r"HTTP/[0-9](?:\.[0-9])?\Z")
_HEX = frozenset("0123456789abcdefABCDEF")


def _read_quoted(line: str, start: int) -> tuple[str, int] | None:
    if start >= len(line) or line[start] != '"':
        return None
    index = start + 1
    value_start = index
    while index < len(line):
        character = line[index]
        if character == '"':
            return line[value_start:index], index + 1
        if character == "\\":
            if index + 1 >= len(line):
                return None
            if line[index + 1] in {'"', "\\"}:
                index += 2
                continue
            if (line[index + 1] == "x" and index + 3 < len(line)
                    and line[index + 2] in _HEX and line[index + 3] in _HEX):
                index += 4
                continue
            # Keep scanning so the field decoder can reject the unsupported escape.
            index += 2
            continue
        if ord(character) < 32 or ord(character) == 127:
            return None
        index += 1
    return None


def _decode_log_field(value: str) -> str | None:
    """Decode Apache quoted escapes and Nginx default byte escapes, without lossy recovery."""
    decoded = bytearray()
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            try:
                decoded.extend(character.encode("utf-8", "strict"))
            except UnicodeEncodeError:
                return None
            index += 1
            continue

        if index + 1 >= len(value):
            return None
        escaped = value[index + 1]
        if escaped in {'"', "\\"}:
            decoded.append(ord(escaped))
            index += 2
        elif (escaped == "x" and index + 3 < len(value)
              and value[index + 2] in _HEX and value[index + 3] in _HEX):
            decoded.append(int(value[index + 2:index + 4], 16))
            index += 4
        else:
            return None

    if any(byte < 32 or byte == 127 for byte in decoded):
        return None
    try:
        return decoded.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _decode_token(value: str) -> bool:
    # %l and %u are validated as fields, but intentionally are not promoted to a user.
    return _decode_log_field(value) is not None


def parse_access_log(line, timezone=None):
    """Parse the bounded Apache CLF/Combined and Nginx default combined profiles.

    ``timezone`` is intentionally unused: the access timestamp must carry its own
    numeric UTC offset. Referer is syntax-checked and discarded; User-Agent is
    retained only in the existing internal NormalizedEvent field.
    """
    if type(line) is not str:
        return None
    if line.endswith("\r\n"):
        line = line[:-2]
    elif line.endswith("\n"):
        line = line[:-1]
    if not line or any(
        ord(character) < 32 or ord(character) == 127 for character in line
    ):
        return None
    if line.startswith("{"):
        # Keep the existing JSON-custom profile disposition as a non-event.
        return None

    prefix = _PREFIX.match(line)
    if prefix is None:
        # Unrelated short text has historically been an ignored non-event. Keep
        # that disposition while rejecting records that look access-shaped.
        if "[" not in line and '"' not in line and len(line.split()) < 3:
            return None
        raise ValueError("Unsupported access log record.") from None
    if not _decode_token(prefix.group("ident")) or not _decode_token(prefix.group("remote_user")):
        raise ValueError("Invalid access identity field.") from None

    timestamp_text = prefix.group("timestamp")
    if not _TIMESTAMP.fullmatch(timestamp_text):
        raise ValueError("Invalid access timestamp format.") from None
    try:
        timestamp = datetime.strptime(timestamp_text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        raise ValueError("Invalid access timestamp.") from None

    request_field = _read_quoted(line, prefix.end())
    if request_field is None:
        raise ValueError("Invalid access request field.") from None
    encoded_request, request_end = request_field
    request = _decode_log_field(encoded_request)
    if request is None:
        raise ValueError("Unsupported access request escaping.") from None
    request_parts = request.split()
    if len(request_parts) == 1:
        # Preserve the pre-existing one-token malformed-request disposition.
        return None
    if (len(request_parts) != 3 or not _METHOD.fullmatch(request_parts[0])
            or not request_parts[1] or not _PROTOCOL.fullmatch(request_parts[2])):
        raise ValueError("Unsupported access request syntax.") from None
    method, request_target, protocol = request_parts
    try:
        url = urlsplit(request_target)
    except ValueError:
        raise ValueError("Invalid access request target.") from None

    remainder = line[request_end:]
    status_size_match = re.match(r" +" + _STATUS_SIZE.pattern, remainder)
    if status_size_match is None:
        raise ValueError("Invalid access status or response size.") from None
    status = int(status_size_match.group("status"))
    if not 100 <= status <= 599:
        raise ValueError("HTTP status is outside the supported numeric range.") from None
    size_text = status_size_match.group("size")
    response_size = int(size_text) if size_text != "-" else None

    suffix = remainder[status_size_match.end():]
    user_agent = None
    if suffix:
        if not suffix.startswith(" "):
            raise ValueError("Unsupported access trailing fields.") from None
        referer_field = _read_quoted(suffix, 1)
        if referer_field is None:
            raise ValueError("Invalid access referer field.") from None
        encoded_referer, referer_end = referer_field
        if _decode_log_field(encoded_referer) is None:
            raise ValueError("Unsupported access referer escaping.") from None
        if referer_end >= len(suffix) or suffix[referer_end] != " ":
            raise ValueError("Incomplete access combined fields.") from None
        agent_field = _read_quoted(suffix, referer_end + 1)
        if agent_field is None:
            raise ValueError("Invalid access user-agent field.") from None
        encoded_agent, agent_end = agent_field
        if agent_end != len(suffix):
            raise ValueError("Unsupported access trailing fields.") from None
        decoded_agent = _decode_log_field(encoded_agent)
        if decoded_agent is None:
            raise ValueError("Unsupported access user-agent escaping.") from None
        user_agent = None if decoded_agent == "-" else decoded_agent

    address_text = prefix.group("address")
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        raise ValueError("Invalid access source address.") from None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("Scoped IPv6 access source addresses are unsupported.") from None

    return NormalizedEvent(
        timestamp=timestamp,
        event_type="http_request",
        source="access_log",
        user=None,
        src_ip=address_text,
        dst_ip=None,
        application=None,
        protocol=protocol,
        user_agent=user_agent,
        raw=line,
        http=HttpContext(
            method=method,
            path=url.path,
            status_code=status,
            response_size=response_size,
            query=url.query or None,
        ),
    )
