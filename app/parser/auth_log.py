from datetime import datetime
from zoneinfo import ZoneInfo

from app.models.schemas import NormalizedEvent


def parse_auth_log(log, timezone=None):
    parts = log.split()

    timestamp = datetime.strptime(
        parts[0] + " " + parts[1],
        "%Y-%m-%d %H:%M:%S",
    )

    if timestamp.tzinfo is None and timezone:
        timestamp = timestamp.replace(
            tzinfo=ZoneInfo(timezone)
        )

    level = parts[2]
    event = parts[3]

    data = {}

    for part in parts[4:]:
        if "=" in part:
            key, value = part.split("=", 1)
            data[key] = value

    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event,
        source="application",
        user=data.get("user"),
        src_ip=data.get("ip"),
        dst_ip=None,
        application=data.get("application"),
        protocol=data.get("protocol"),
        user_agent=data.get("user_agent"),
        raw=log,
    )