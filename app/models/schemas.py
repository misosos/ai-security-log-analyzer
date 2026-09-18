from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


# =========================
# Internal Analysis Models
# =========================

@dataclass
class Evidence:
    type: str
    value: str | int | float | bool
    source: str
    timestamp: datetime | None = None
    time_range: tuple[datetime, datetime] | None = None


@dataclass
class HttpContext:
    method: str
    path: str
    status_code: int | None
    response_size: int | None
    query: str | None = None


@dataclass
class AuthenticationContext:
    outcome: Literal["success", "failure", "unknown"]
    method: str | None = None
    service: str | None = None
    source_port: int | None = None
    invalid_user: bool | None = None


@dataclass
class LinuxAuditContext:
    event_id: str
    record_types: tuple[str, ...]
    operation: str | None = None
    executable: str | None = None
    process_user_id: int | None = None
    audit_user_id: int | None = None
    audit_session_id: int | None = None
    terminal: str | None = None
    hostname: str | None = None


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
    authentication: AuthenticationContext | None = None
    linux_audit: LinuxAuditContext | None = None


@dataclass
class DetectionResult:
    is_detected: bool
    detection_type: str | None
    evidence: list[Evidence]


# =========================
# API Response Models
# =========================

class EvidenceResponse(BaseModel):
    type: str
    value: str | int | float | bool
    source: str
    timestamp: datetime | None = None
    time_range: tuple[datetime, datetime] | None = None


class DetectionResponse(BaseModel):
    is_detected: bool
    detection_type: str | None
    evidence: list[EvidenceResponse]


class AnalysisResultResponse(BaseModel):
    ip: str
    risk_level: str
    detections: dict[str, DetectionResponse]
    correlation: dict
    risk_factors: dict


class AnalysisSummary(BaseModel):
    total_sources: int
    total_ips: int
    detected_ips: int
    high_risk_ips: int


class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    summary: AnalysisSummary
    results: list[AnalysisResultResponse]
    global_correlation: dict
    ai_summary: str | None = None
