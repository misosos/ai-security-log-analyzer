"""Closed, privacy-safe HTTP contract for the optional local live service."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictInt


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LiveStatusResponse(_ClosedModel):
    schema_version: Literal["2"]
    service_state: Literal["READY", "RUNNING", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]
    session_id: str
    source_role: Literal["application", "ssh", "access"]
    worker_state: Literal["READY", "RUNNING_STEP", "DEGRADED", "STOPPING", "STOPPED", "FAILED"]
    publication_state: Literal["OPEN", "CLOSED"]
    latest_detection_revision: StrictInt
    available_event_count: StrictInt
    earliest_event_id: str | None
    latest_event_id: str | None
    active_observation_count: StrictInt
    published_total: StrictInt
    evicted_total: StrictInt
    replay_gap_total: StrictInt
    max_event_items: StrictInt
    max_event_bytes: StrictInt
    max_connections: StrictInt
    active_connections: StrictInt
    fixed_error_code: Literal[
        "LIVE_RUNNER_DEGRADED", "LIVE_RUNNER_FAILED", "LIVE_SHUTDOWN_TIMEOUT",
    ] | None = None
    recovery_action: str | None = None
    interpretation_notices: tuple[str, ...]
    capabilities: tuple[str, ...]
    analysis_available: bool
    analysis_revision: StrictInt | None
    active_relation_count: StrictInt
    active_risk_count: StrictInt
    active_case_count: StrictInt
    analysis_state: Literal["AVAILABLE", "UNAVAILABLE", "FAILED"]


class LiveErrorResponse(_ClosedModel):
    error_code: Literal[
        "LIVE_MONITORING_NOT_ENABLED", "LIVE_LOOPBACK_REQUIRED",
        "LIVE_INVALID_HOST", "LIVE_FORWARDED_REQUEST_REJECTED",
        "LIVE_ORIGIN_REJECTED", "LIVE_STREAM_LIMIT_REACHED",
        "LIVE_INVALID_LAST_EVENT_ID", "LIVE_SERVICE_UNAVAILABLE",
        "LIVE_STREAM_FAILED",
    ]
    user_message: str
    recovery_action: str
    retryable: bool
