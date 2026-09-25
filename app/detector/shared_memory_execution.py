from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from app.models.schemas import (
    DetectionResult,
    Evidence,
    LinuxAuditContext,
    NormalizedEvent,
    ProcessExecutionContext,
)


DETECTION_TYPE = "Privileged Shared-Memory Execution Observation"
SHARED_MEMORY_PREFIXES = (
    "/dev/shm/",
    "/run/shm/",
)
EXPECTED_EVIDENCE_TYPES = frozenset((
    "shared_memory_executable_path",
    "effective_user_id",
    "syscall_outcome",
))


@dataclass(frozen=True)
class SharedMemoryExecutionObservation:
    timestamp: datetime
    source: str
    event_type: str
    source_instance: str | None
    node: str | None
    event_id: str
    detection_type: str
    shared_memory_executable_path: str
    effective_user_id: int
    syscall_outcome: str


def _not_detected():
    return DetectionResult(
        is_detected=False,
        detection_type=None,
        evidence=[],
    )


def _is_shared_memory_child_path(value):
    if type(value) is not str or not value.strip():
        return False

    return any(
        value.startswith(prefix) and len(value) > len(prefix)
        for prefix in SHARED_MEMORY_PREFIXES
    )


def detect_shared_memory_privileged_execution(
    event: NormalizedEvent,
) -> DetectionResult:
    if not isinstance(event, NormalizedEvent):
        return _not_detected()

    if (
        event.event_type != "process_execution_attempt"
        or event.source != "linux_audit"
    ):
        return _not_detected()

    context = event.process_execution
    if not isinstance(context, ProcessExecutionContext):
        return _not_detected()

    if context.outcome != "success":
        return _not_detected()

    if (
        type(context.effective_user_id) is not int
        or context.effective_user_id != 0
    ):
        return _not_detected()

    if not _is_shared_memory_child_path(context.executable):
        return _not_detected()

    return DetectionResult(
        is_detected=True,
        detection_type=DETECTION_TYPE,
        evidence=[
            Evidence(
                type="shared_memory_executable_path",
                value=context.executable,
                source=event.source,
                timestamp=event.timestamp,
            ),
            Evidence(
                type="effective_user_id",
                value=context.effective_user_id,
                source=event.source,
                timestamp=event.timestamp,
            ),
            Evidence(
                type="syscall_outcome",
                value=context.outcome,
                source=event.source,
                timestamp=event.timestamp,
            ),
        ],
    )


def _validated_event_scope(event):
    if not isinstance(event, NormalizedEvent):
        raise ValueError("positive detection requires a NormalizedEvent")

    if type(event.timestamp) is not datetime:
        raise ValueError("positive detection requires a datetime timestamp")

    if (
        event.source != "linux_audit"
        or event.event_type != "process_execution_attempt"
    ):
        raise ValueError("positive detection has invalid event scope")

    context = event.linux_audit
    if not isinstance(context, LinuxAuditContext):
        raise ValueError("positive detection requires LinuxAuditContext")

    if type(context.event_id) is not str or not context.event_id.strip():
        raise ValueError("positive detection requires a valid event_id")

    if (
        context.source_instance is not None
        and type(context.source_instance) is not str
    ):
        raise ValueError("source_instance must be str or None")

    if context.node is not None and type(context.node) is not str:
        raise ValueError("node must be str or None")

    return context


def _validated_positive_evidence(event, result):
    if not isinstance(result, DetectionResult):
        raise ValueError("detector returned an invalid positive result")

    if result.is_detected is not True:
        raise ValueError("positive result must set is_detected to True")

    if result.detection_type != DETECTION_TYPE:
        raise ValueError("positive result has an invalid detection_type")

    if type(result.evidence) is not list or len(result.evidence) != 3:
        raise ValueError("positive result must contain three evidence items")

    evidence_by_type = {}
    for evidence in result.evidence:
        if not isinstance(evidence, Evidence):
            raise ValueError("positive result contains invalid evidence")

        if type(evidence.type) is not str:
            raise ValueError("positive result has an invalid evidence type")

        if evidence.type in evidence_by_type:
            raise ValueError("positive result contains duplicate evidence")

        evidence_by_type[evidence.type] = evidence

    if set(evidence_by_type) != EXPECTED_EVIDENCE_TYPES:
        raise ValueError("positive result has an invalid evidence contract")

    context = event.process_execution
    if not isinstance(context, ProcessExecutionContext):
        raise ValueError("positive result requires ProcessExecutionContext")

    executable = evidence_by_type["shared_memory_executable_path"]
    effective_user_id = evidence_by_type["effective_user_id"]
    outcome = evidence_by_type["syscall_outcome"]

    if (
        type(executable.value) is not str
        or executable.value != context.executable
        or not _is_shared_memory_child_path(executable.value)
    ):
        raise ValueError("positive result has invalid executable evidence")

    if (
        type(effective_user_id.value) is not int
        or effective_user_id.value != 0
        or effective_user_id.value != context.effective_user_id
    ):
        raise ValueError("positive result has invalid effective UID evidence")

    if (
        type(outcome.value) is not str
        or outcome.value != "success"
        or outcome.value != context.outcome
    ):
        raise ValueError("positive result has invalid outcome evidence")

    for evidence in result.evidence:
        if (
            evidence.source != event.source
            or evidence.timestamp != event.timestamp
            or evidence.time_range is not None
        ):
            raise ValueError("positive result has invalid evidence metadata")

    return executable.value, effective_user_id.value, outcome.value


def collect_shared_memory_execution_observations(
    events: Iterable[NormalizedEvent],
) -> tuple[SharedMemoryExecutionObservation, ...]:
    observations = []

    for event in events:
        result = detect_shared_memory_privileged_execution(event)

        if not isinstance(result, DetectionResult):
            raise ValueError("detector returned an invalid result")

        if result.is_detected is not True:
            continue

        scope = _validated_event_scope(event)
        executable, effective_user_id, outcome = (
            _validated_positive_evidence(event, result)
        )
        observations.append(SharedMemoryExecutionObservation(
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            source_instance=scope.source_instance,
            node=scope.node,
            event_id=scope.event_id,
            detection_type=result.detection_type,
            shared_memory_executable_path=executable,
            effective_user_id=effective_user_id,
            syscall_outcome=outcome,
        ))

    return tuple(observations)
