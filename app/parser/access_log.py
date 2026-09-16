import re
from urllib.parse import urlsplit

from app.models.schemas import HttpContext, NormalizedEvent


def parse_access_log(line):
    # 1. IP
    ip_match = re.match(r'^(\S+)', line)

    if not ip_match:
        return None

    ip = ip_match.group(1)

    # 2. timestamp
    timestamp_match = re.search(
        r'\[([^\]]+)\]',
        line
    )

    if not timestamp_match:
        return None

    timestamp = timestamp_match.group(1)

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
    status_match = re.search(
        r'"[^"]*"\s+(\d+)\s+(\d+|-)',
        line
    )

    if not status_match:
        return None

    status = int(status_match.group(1))

    response_size = (
        int(status_match.group(2))
        if status_match.group(2) != "-"
        else None
    )

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