from app.models.schemas import (
    DetectionResult,
    Evidence,
    NormalizedEvent,
    ProcessExecutionContext,
)


DETECTION_TYPE = "Privileged Shared-Memory Execution Observation"
SHARED_MEMORY_PREFIXES = (
    "/dev/shm/",
    "/run/shm/",
)


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
