"""Closed public v3 status DTO; private source and checkpoint objects stay internal."""

from typing import Literal
import re

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, model_validator


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_SESSION = re.compile(r"LIVE-SESSION-([0-9]{6,19})\Z")
_EVENT = re.compile(r"LIVE-EVENT-([0-9]{6,19})-([0-9]{6,19})\Z")


def _public_number(value: str) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number < 1 or number > 1_000_000_000_000_000_000 or value != f"{number:06d}":
        return None
    return number


class PairRoleStatus(_ClosedModel):
    role: Literal["application", "ssh"]
    service_state: Literal["READY", "RUNNING", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]
    detection_revision: StrictInt
    analysis_revision: StrictInt
    active_observation_count: StrictInt
    active_relation_count: StrictInt
    active_risk_count: StrictInt
    active_case_count: StrictInt
    checkpoint_available: StrictBool
    last_step_code: Literal["NO_DATA", "PROCESSED", "DEGRADED", "FAILED"] | None

    @model_validator(mode="after")
    def check_counts(self):
        if any(value < 0 for value in (
            self.detection_revision, self.analysis_revision, self.active_observation_count,
            self.active_relation_count, self.active_risk_count, self.active_case_count,
        )) or self.analysis_revision > self.detection_revision:
            raise ValueError("PAIR_ROLE_INVALID")
        return self


class PairStatusResponse(_ClosedModel):
    schema_version: Literal["3"]
    service_state: Literal["READY", "RUNNING", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]
    session_id: str
    roles: tuple[PairRoleStatus, PairRoleStatus]
    available_event_count: StrictInt
    event_byte_count: StrictInt
    earliest_event_id: str | None
    latest_event_id: str | None
    published_total: StrictInt
    evicted_total: StrictInt
    replay_gap_total: StrictInt
    max_event_items: StrictInt
    max_event_bytes: StrictInt
    max_connections: StrictInt
    active_connections: StrictInt
    fixed_error_code: Literal["PAIR_RUNNER_DEGRADED", "PAIR_RUNNER_FAILED"] | None
    interpretation_notices: tuple[str, str]
    capabilities: tuple[str, str, str, str]

    @model_validator(mode="after")
    def check_contract(self):
        session_match = _SESSION.fullmatch(self.session_id)
        session_number = _public_number(session_match[1]) if session_match else None
        first = _EVENT.fullmatch(self.earliest_event_id or "")
        last = _EVENT.fullmatch(self.latest_event_id or "")
        first_number = _public_number(first[2]) if first else None
        last_number = _public_number(last[2]) if last else None
        if (tuple(role.role for role in self.roles) != ("application", "ssh")
            or session_number is None
            or (self.available_event_count > 0 and (
                first is None or last is None or first_number is None or last_number is None
                or _public_number(first[1]) != session_number
                or _public_number(last[1]) != session_number
                or first_number > last_number
                or last_number - first_number + 1 != self.available_event_count))
            or any(value < 0 for value in (
                self.available_event_count, self.event_byte_count, self.published_total,
                self.evicted_total, self.replay_gap_total, self.active_connections,
            ))
            or not 0 < self.max_event_items <= 32 or not 0 < self.max_event_bytes <= 16_384
            or not 0 < self.max_connections <= 2
            or self.available_event_count > self.max_event_items
            or self.event_byte_count > self.max_event_bytes
            or self.active_connections > self.max_connections
            or self.published_total < self.evicted_total + self.available_event_count
            or (self.available_event_count == 0) != (self.earliest_event_id is None)
            or (self.available_event_count == 0) != (self.latest_event_id is None)
            or (any(role.service_state in ("DEGRADED", "FAILED") for role in self.roles)
                and self.service_state in ("READY", "RUNNING"))):
            raise ValueError("PAIR_STATUS_INVALID")
        return self
