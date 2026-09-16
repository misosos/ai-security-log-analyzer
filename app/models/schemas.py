from dataclasses import dataclass


@dataclass
class Evidence:

    type: str

    value: str | int | float | bool

    source: str

    timestamp: str | None = None

    time_range: tuple[str, str] | None = None


@dataclass
class NormalizedEvent:

    timestamp: str

    event_type: str

    source: str

    user: str | None

    src_ip: str | None

    dst_ip: str | None

    application: str | None

    protocol: str | None

    user_agent: str | None

    raw: str