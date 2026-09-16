from dataclasses import dataclass
from datetime import datetime


@dataclass
class Evidence:
    type: str
    value: str | int | float | bool
    source: str
    timestamp: str | None = None
    time_range: tuple[str, str] | None = None


@dataclass
class HttpContext:
    method: str
    path: str
    status_code: int | None
    response_size: int | None
    query: str | None = None


@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_type: str
    source: str
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    application: str | None
    protocol: str | None
    user_agent: str | None
    raw: str
    http: HttpContext | None = None


@dataclass
class DetectionResult:
    is_detected: bool
    detection_type: str | None
    evidence: list[Evidence]