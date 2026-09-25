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
    source_instance: str | None = None
    node: str | None = None


@dataclass(frozen=True)
class LinuxAuditPathContext:
    item: int | None
    name: str | None
    nametype: str | None
    inode: int | None
    device: str | None
    mode: str | None
    owner_user_id: int | None
    owner_group_id: int | None


@dataclass(frozen=True)
class ProcessExecutionContext:
    outcome: Literal["success", "failure", "unknown"]

    architecture_raw: str
    syscall_raw: str
    architecture_name: str | None
    syscall_name: str | None
    exit_code: int | None

    process_id: int
    parent_process_id: int

    real_user_id: int | None
    effective_user_id: int | None
    saved_user_id: int | None
    filesystem_user_id: int | None

    real_group_id: int | None
    effective_group_id: int | None
    saved_group_id: int | None
    filesystem_group_id: int | None

    command_name: str | None
    executable: str | None
    terminal: str | None
    audit_rule_key: str | None

    argument_count: int
    argv: tuple[str | None, ...]
    argv_complete: bool
    incomplete_argument_indexes: tuple[int, ...]

    working_directory: str | None
    paths: tuple[LinuxAuditPathContext, ...]
    paths_complete: bool

    proctitle_raw: str | None
    proctitle_arguments: tuple[str, ...] | None

    raw_records: tuple[str, ...]


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
    process_execution: ProcessExecutionContext | None = None


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
