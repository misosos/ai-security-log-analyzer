from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from app.models.schemas import (
    AuthenticationContext,
    LinuxAuditContext,
    NormalizedEvent,
    ProcessExecutionContext,
)


@dataclass(frozen=True)
class SessionProcessCoObservation:
    source_instance: str
    node: str
    audit_session_id: int
    audit_user_id: int
    session_start_timestamp: datetime
    session_start_event_id: str
    session_end_timestamp: datetime
    session_end_event_id: str
    process_observation_count: int
    process_outcome_success_count: int
    process_outcome_failure_count: int
    process_outcome_unknown_count: int
    process_event_ids: tuple[str, ...]


@dataclass(frozen=True)
class _LifecycleObservation:
    timestamp: datetime
    event_id: str


@dataclass(frozen=True)
class _ProcessObservation:
    timestamp: datetime
    event_id: str
    outcome: str
    input_index: int


@dataclass
class _ScopeObservations:
    starts: list[_LifecycleObservation] = field(default_factory=list)
    ends: list[_LifecycleObservation] = field(default_factory=list)
    processes: list[_ProcessObservation] = field(default_factory=list)


def _non_empty_string(value):
    return type(value) is str and bool(value.strip())


def _non_negative_integer(value):
    return type(value) is int and value >= 0


def _aware_datetime(value):
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _strict_join_key(context):
    if type(context) is not LinuxAuditContext:
        return None

    values = (
        context.source_instance,
        context.node,
        context.audit_session_id,
        context.audit_user_id,
    )
    if not (
        _non_empty_string(values[0])
        and _non_empty_string(values[1])
        and _non_negative_integer(values[2])
        and _non_negative_integer(values[3])
    ):
        return None

    return values


def _event_scope(event):
    if type(event) is not NormalizedEvent:
        return None
    if type(event.source) is not str or event.source != "linux_audit":
        return None
    if not _aware_datetime(event.timestamp):
        return None

    context = event.linux_audit
    join_key = _strict_join_key(context)
    if join_key is None or not _non_empty_string(context.event_id):
        return None

    return join_key, context.event_id


def _lifecycle_observation(event, event_type):
    scope = _event_scope(event)
    if (
        scope is None
        or type(event.event_type) is not str
        or event.event_type != event_type
    ):
        return None
    if type(event.authentication) is not AuthenticationContext:
        return None
    if event.authentication.outcome != "success":
        return None

    join_key, event_id = scope
    return join_key, _LifecycleObservation(event.timestamp, event_id)


def _process_observation(event, input_index):
    scope = _event_scope(event)
    if (
        scope is None
        or type(event.event_type) is not str
        or event.event_type != "process_execution_attempt"
    ):
        return None
    if type(event.process_execution) is not ProcessExecutionContext:
        return None

    outcome = event.process_execution.outcome
    if outcome not in {"success", "failure", "unknown"}:
        outcome = "unknown"

    join_key, event_id = scope
    return join_key, _ProcessObservation(
        timestamp=event.timestamp,
        event_id=event_id,
        outcome=outcome,
        input_index=input_index,
    )


def collect_session_process_co_observations(
    events: Iterable[NormalizedEvent],
) -> tuple[SessionProcessCoObservation, ...]:
    grouped = {}

    for input_index, event in enumerate(events):
        start = _lifecycle_observation(event, "session_start")
        if start is not None:
            join_key, observation = start
            grouped.setdefault(join_key, _ScopeObservations()).starts.append(
                observation
            )
            continue

        end = _lifecycle_observation(event, "session_end")
        if end is not None:
            join_key, observation = end
            grouped.setdefault(join_key, _ScopeObservations()).ends.append(
                observation
            )
            continue

        process = _process_observation(event, input_index)
        if process is not None:
            join_key, observation = process
            grouped.setdefault(
                join_key,
                _ScopeObservations(),
            ).processes.append(observation)

    relations = []

    for join_key, observations in grouped.items():
        if len(observations.starts) != 1 or len(observations.ends) != 1:
            continue

        start = observations.starts[0]
        end = observations.ends[0]
        if start.timestamp >= end.timestamp:
            continue

        processes = sorted(
            (
                process
                for process in observations.processes
                if start.timestamp <= process.timestamp <= end.timestamp
            ),
            key=lambda process: (
                process.timestamp,
                process.event_id,
                process.input_index,
            ),
        )
        if not processes:
            continue

        success_count = sum(
            process.outcome == "success" for process in processes
        )
        failure_count = sum(
            process.outcome == "failure" for process in processes
        )
        unknown_count = len(processes) - success_count - failure_count
        source_instance, node, audit_session_id, audit_user_id = join_key

        relations.append(SessionProcessCoObservation(
            source_instance=source_instance,
            node=node,
            audit_session_id=audit_session_id,
            audit_user_id=audit_user_id,
            session_start_timestamp=start.timestamp,
            session_start_event_id=start.event_id,
            session_end_timestamp=end.timestamp,
            session_end_event_id=end.event_id,
            process_observation_count=len(processes),
            process_outcome_success_count=success_count,
            process_outcome_failure_count=failure_count,
            process_outcome_unknown_count=unknown_count,
            process_event_ids=tuple(
                process.event_id for process in processes
            ),
        ))

    relations.sort(key=lambda relation: (
        relation.session_start_timestamp,
        relation.source_instance,
        relation.node,
        relation.audit_session_id,
        relation.audit_user_id,
        relation.session_start_event_id,
        relation.session_end_event_id,
    ))

    return tuple(relations)
