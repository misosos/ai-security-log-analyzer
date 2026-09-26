from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from app.detector.shared_memory_execution import (
    DETECTION_TYPE,
    SHARED_MEMORY_PREFIXES,
    SharedMemoryExecutionObservation,
)
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
class SessionProcessReviewSummary:
    session_co_observation_count: int
    process_observation_count: int
    process_outcome_success_count: int
    process_outcome_failure_count: int
    process_outcome_unknown_count: int
    shared_memory_privileged_execution_observation_count: int
    sessions_with_shared_memory_privileged_execution_count: int


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


def _validate_relation(relation):
    if type(relation) is not SessionProcessCoObservation:
        raise ValueError("relations contain an invalid item")

    if not (
        _non_empty_string(relation.source_instance)
        and _non_empty_string(relation.node)
        and _non_negative_integer(relation.audit_session_id)
        and _non_negative_integer(relation.audit_user_id)
        and _aware_datetime(relation.session_start_timestamp)
        and _aware_datetime(relation.session_end_timestamp)
        and relation.session_start_timestamp
        < relation.session_end_timestamp
        and _non_empty_string(relation.session_start_event_id)
        and _non_empty_string(relation.session_end_event_id)
    ):
        raise ValueError("relation has an invalid scope or lifecycle")

    counts = (
        relation.process_observation_count,
        relation.process_outcome_success_count,
        relation.process_outcome_failure_count,
        relation.process_outcome_unknown_count,
    )
    if not all(_non_negative_integer(count) for count in counts):
        raise ValueError("relation has an invalid count")
    if relation.process_observation_count == 0:
        raise ValueError("relation must contain a process observation")
    if (
        relation.process_observation_count
        != relation.process_outcome_success_count
        + relation.process_outcome_failure_count
        + relation.process_outcome_unknown_count
    ):
        raise ValueError("relation outcome counts are inconsistent")

    if type(relation.process_event_ids) is not tuple:
        raise ValueError("relation process_event_ids must be a tuple")
    if len(relation.process_event_ids) != relation.process_observation_count:
        raise ValueError("relation process event cardinality is inconsistent")
    if not all(
        _non_empty_string(event_id)
        for event_id in relation.process_event_ids
    ):
        raise ValueError("relation contains an invalid process event_id")


def _validate_shared_memory_observation(observation):
    if type(observation) is not SharedMemoryExecutionObservation:
        raise ValueError(
            "shared_memory_observations contain an invalid item"
        )

    if not (
        _aware_datetime(observation.timestamp)
        and type(observation.source) is str
        and observation.source == "linux_audit"
        and type(observation.event_type) is str
        and observation.event_type == "process_execution_attempt"
        and _non_empty_string(observation.source_instance)
        and _non_empty_string(observation.node)
        and _non_empty_string(observation.event_id)
        and type(observation.detection_type) is str
        and observation.detection_type == DETECTION_TYPE
        and type(observation.shared_memory_executable_path) is str
        and any(
            observation.shared_memory_executable_path.startswith(prefix)
            and len(observation.shared_memory_executable_path) > len(prefix)
            for prefix in SHARED_MEMORY_PREFIXES
        )
        and type(observation.effective_user_id) is int
        and observation.effective_user_id == 0
        and type(observation.syscall_outcome) is str
        and observation.syscall_outcome == "success"
    ):
        raise ValueError("shared-memory observation contract is invalid")


def summarize_session_process_co_observations(
    relations: tuple[SessionProcessCoObservation, ...],
    shared_memory_observations: tuple[
        SharedMemoryExecutionObservation,
        ...,
    ],
) -> SessionProcessReviewSummary:
    if type(relations) is not tuple:
        raise TypeError("relations must be a tuple")
    if type(shared_memory_observations) is not tuple:
        raise TypeError("shared_memory_observations must be a tuple")

    process_count = 0
    success_count = 0
    failure_count = 0
    unknown_count = 0
    relation_process_counts = []
    relation_owners = {}

    for relation_index, relation in enumerate(relations):
        _validate_relation(relation)
        process_count += relation.process_observation_count
        success_count += relation.process_outcome_success_count
        failure_count += relation.process_outcome_failure_count
        unknown_count += relation.process_outcome_unknown_count

        scope = (relation.source_instance, relation.node)
        process_keys = Counter(
            (*scope, event_id) for event_id in relation.process_event_ids
        )
        relation_process_counts.append(process_keys)

        for process_key in process_keys:
            previous_owner = relation_owners.setdefault(
                process_key,
                relation_index,
            )
            if previous_owner != relation_index:
                raise ValueError(
                    "process event attribution is ambiguous across relations"
                )

    shared_memory_counts = Counter()
    for observation in shared_memory_observations:
        _validate_shared_memory_observation(observation)
        shared_memory_counts[(
            observation.source_instance,
            observation.node,
            observation.event_id,
        )] += 1

    matched_observation_count = 0
    matched_relation_indexes = set()
    for process_key, observation_count in shared_memory_counts.items():
        relation_index = relation_owners.get(process_key)
        if relation_index is None:
            continue

        matched_count = min(
            observation_count,
            relation_process_counts[relation_index][process_key],
        )
        if matched_count:
            matched_observation_count += matched_count
            matched_relation_indexes.add(relation_index)

    return SessionProcessReviewSummary(
        session_co_observation_count=len(relations),
        process_observation_count=process_count,
        process_outcome_success_count=success_count,
        process_outcome_failure_count=failure_count,
        process_outcome_unknown_count=unknown_count,
        shared_memory_privileged_execution_observation_count=(
            matched_observation_count
        ),
        sessions_with_shared_memory_privileged_execution_count=(
            len(matched_relation_indexes)
        ),
    )
