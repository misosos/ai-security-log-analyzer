import re
from datetime import datetime
import ipaddress
from urllib.parse import urlsplit

from app.models.schemas import HttpContext, NormalizedEvent


def parse_access_log(line, timezone=None):
    # 1. IP
    ip_match = re.match(r'^(\S+)', line)

    if not ip_match:
        return None

    ip = ip_match.group(1)
    if ip.startswith("{"):
        # JSON/custom access profiles are unsupported; keep them non-events.
        return None

    # 2. timestamp
    timestamp_match = re.search(
        r'\[([^\]]+)\]',
        line
    )

    if not timestamp_match:
        return None

    timestamp = datetime.strptime(
        timestamp_match.group(1),
        "%d/%b/%Y:%H:%M:%S %z",
    )

    # 3. request
    request_match = re.search(
        r'"([^"]+)"',
        line
    )

    if not request_match:
        return None

    request = request_match.group(1)

    # 4. request 내부 필드 검증
    request_parts = request.split()

    if len(request_parts) != 3:
        return None

    method = request_parts[0]
    request_target = request_parts[1]
    protocol = request_parts[2]

    # 5. URL path / query 분리
    url = urlsplit(request_target)

    path = url.path
    query = url.query or None

    # 6. status / response size
    status_match = re.match(
        r"\s+([0-9]{3})\s+([0-9]+|-)(?:\s|$)",
        line[request_match.end():],
    )

    if not status_match:
        raise ValueError("Invalid access status or response size.") from None

    status = int(status_match.group(1))
    if not 100 <= status <= 599:
        raise ValueError("HTTP status is outside the supported numeric range.") from None

    response_size = (
        int(status_match.group(2))
        if status_match.group(2) != "-"
        else None
    )

    # Only validate the address after the rest of an access record is
    # structurally recognized. Unrelated input remains an ignored record.
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid access source address.") from None
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("Scoped IPv6 access source addresses are unsupported.") from None

    # 7. NormalizedEvent 생성
    return NormalizedEvent(
        timestamp=timestamp,
        event_type="http_request",
        source="access_log",
        user=None,
        src_ip=ip,
        dst_ip=None,
        application=None,
        protocol=protocol,
        user_agent=None,
        raw=line,
        http=HttpContext(
            method=method,
            path=path,
            status_code=status,
            response_size=response_size,
            query=query,
        ),
    )
