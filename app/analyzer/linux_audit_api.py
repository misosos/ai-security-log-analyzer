from dataclasses import dataclass
from pathlib import Path

from app.analyzer.pipeline import load_normalized_logs
from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.api_uploads import StagedLinuxAuditInput
from app.correlation.session_process import (
    SessionProcessCoObservation,
    SessionProcessReviewSummary,
    collect_session_process_co_observations,
    summarize_session_process_co_observations,
)
from app.detector.shared_memory_execution import (
    SharedMemoryExecutionObservation,
    SharedMemoryExecutionReviewSummary,
    collect_shared_memory_execution_observations,
    summarize_shared_memory_execution_observations,
)
from app.models.schemas import NormalizedEvent


_ANALYSIS_ERRORS = {
    "NO_ELIGIBLE_LINUX_AUDIT_EVENTS": (
        422,
        "No eligible Linux Audit events were found.",
    ),
    "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR": (
        500,
        "Linux Audit analysis could not be completed.",
    ),
}


@dataclass(frozen=True)
class LinuxAuditApiAnalysis:
    process_observation_count: int
    process_outcome_success_count: int
    process_outcome_failure_count: int
    process_outcome_unknown_count: int
    argv_complete_count: int
    argv_incomplete_count: int
    path_complete_count: int
    path_incomplete_count: int
    shared_memory_privileged_execution_observation_count: int
    session_co_observation_count: int
    session_process_observation_count: int
    session_process_outcome_success_count: int
    session_process_outcome_failure_count: int
    session_process_outcome_unknown_count: int
    session_linked_shared_memory_observation_count: int
    sessions_with_shared_memory_observation_count: int


class LinuxAuditAnalysisValidationError(ValueError):

    def __init__(self, code: str):
        status_code, message = _ANALYSIS_ERRORS[code]
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def _analysis_error(code: str) -> LinuxAuditAnalysisValidationError:
    return LinuxAuditAnalysisValidationError(code)


def _contract_error() -> LinuxAuditAnalysisValidationError:
    return _analysis_error("LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR")


def _validate_staged_inputs(
    staged_inputs: tuple[StagedLinuxAuditInput, ...],
) -> None:
    if type(staged_inputs) is not tuple or not staged_inputs:
        raise _contract_error()

    source_instances = set()
    paths = set()
    for staged_input in staged_inputs:
        if type(staged_input) is not StagedLinuxAuditInput:
            raise _contract_error()
        if not isinstance(staged_input.path, Path):
            raise _contract_error()
        if (
            type(staged_input.source_instance) is not str
            or not staged_input.source_instance.strip()
            or staged_input.source_instance in source_instances
        ):
            raise _contract_error()
        if (
            type(staged_input.size_bytes) is not int
            or staged_input.size_bytes <= 0
        ):
            raise _contract_error()
        if staged_input.path in paths:
            raise _contract_error()

        source_instances.add(staged_input.source_instance)
        paths.add(staged_input.path)


def _non_negative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_count_mapping(
    value: object,
    expected_keys: frozenset[str],
) -> dict[str, int]:
    if type(value) is not dict or set(value) != expected_keys:
        raise _contract_error()
    if not all(_non_negative_integer(count) for count in value.values()):
        raise _contract_error()
    return value


def _validate_process_aggregate(value: object) -> dict:
    if type(value) is not dict or set(value) != {
        "observation_count",
        "outcome_counts",
        "argv_completeness_counts",
        "path_completeness_counts",
    }:
        raise _contract_error()

    observation_count = value["observation_count"]
    if not _non_negative_integer(observation_count):
        raise _contract_error()

    outcome_counts = _validate_count_mapping(
        value["outcome_counts"],
        frozenset(("success", "failure", "unknown")),
    )
    argv_counts = _validate_count_mapping(
        value["argv_completeness_counts"],
        frozenset(("complete", "incomplete")),
    )
    path_counts = _validate_count_mapping(
        value["path_completeness_counts"],
        frozenset(("complete", "incomplete")),
    )

    if not (
        observation_count == sum(outcome_counts.values())
        and observation_count == sum(argv_counts.values())
        and observation_count == sum(path_counts.values())
    ):
        raise _contract_error()

    return value


def _validate_shared_memory_summary(
    summary: object,
    *,
    process_count: int,
    observation_count: int,
) -> None:
    if type(summary) is not SharedMemoryExecutionReviewSummary:
        raise _contract_error()

    count = summary.shared_memory_privileged_execution_observation_count
    if (
        not _non_negative_integer(count)
        or count != observation_count
        or count > process_count
    ):
        raise _contract_error()


def _validate_session_summary(
    summary: object,
    *,
    process_count: int,
    shared_memory_count: int,
    relation_count: int,
) -> None:
    if type(summary) is not SessionProcessReviewSummary:
        raise _contract_error()

    counts = (
        summary.session_co_observation_count,
        summary.process_observation_count,
        summary.process_outcome_success_count,
        summary.process_outcome_failure_count,
        summary.process_outcome_unknown_count,
        summary.shared_memory_privileged_execution_observation_count,
        summary.sessions_with_shared_memory_privileged_execution_count,
    )
    if not all(_non_negative_integer(count) for count in counts):
        raise _contract_error()

    session_count = summary.session_co_observation_count
    session_process_count = summary.process_observation_count
    linked_count = (
        summary.shared_memory_privileged_execution_observation_count
    )
    containing_session_count = (
        summary.sessions_with_shared_memory_privileged_execution_count
    )
    if not (
        session_process_count
        == summary.process_outcome_success_count
        + summary.process_outcome_failure_count
        + summary.process_outcome_unknown_count
        and session_count == relation_count
        and session_process_count <= process_count
        and linked_count <= session_process_count
        and linked_count <= shared_memory_count
        and containing_session_count <= session_count
        and (containing_session_count == 0 or linked_count > 0)
        and (linked_count == 0 or containing_session_count > 0)
        and (session_count > 0 or session_process_count == linked_count == 0)
        and (session_count == 0 or session_process_count >= session_count)
    ):
        raise _contract_error()


def analyze_staged_linux_audit_inputs(
    staged_inputs: tuple[StagedLinuxAuditInput, ...],
) -> LinuxAuditApiAnalysis:
    _validate_staged_inputs(staged_inputs)
    source_configs = [
        {
            "source": "linux_audit",
            "path": staged_input.path,
            "source_instance": staged_input.source_instance,
        }
        for staged_input in staged_inputs
    ]

    logs = load_normalized_logs(source_configs)
    if type(logs) is not list or any(
        type(event) is not NormalizedEvent or event.source != "linux_audit"
        for event in logs
    ):
        raise _contract_error()
    if not logs:
        raise _analysis_error("NO_ELIGIBLE_LINUX_AUDIT_EVENTS")

    try:
        process_aggregate = _validate_process_aggregate(
            aggregate_process_execution_observations(logs)
        )
        shared_memory_observations = (
            collect_shared_memory_execution_observations(logs)
        )
        if type(shared_memory_observations) is not tuple or any(
            type(observation) is not SharedMemoryExecutionObservation
            for observation in shared_memory_observations
        ):
            raise _contract_error()
        shared_memory_summary = (
            summarize_shared_memory_execution_observations(
                shared_memory_observations
            )
        )
        session_relations = collect_session_process_co_observations(logs)
        if type(session_relations) is not tuple or any(
            type(relation) is not SessionProcessCoObservation
            for relation in session_relations
        ):
            raise _contract_error()
        session_summary = summarize_session_process_co_observations(
            session_relations,
            shared_memory_observations,
        )
        _validate_shared_memory_summary(
            shared_memory_summary,
            process_count=process_aggregate["observation_count"],
            observation_count=len(shared_memory_observations),
        )
        _validate_session_summary(
            session_summary,
            process_count=process_aggregate["observation_count"],
            shared_memory_count=(
                shared_memory_summary
                .shared_memory_privileged_execution_observation_count
            ),
            relation_count=len(session_relations),
        )
    except (TypeError, ValueError):
        raise _contract_error() from None

    return LinuxAuditApiAnalysis(
        process_observation_count=process_aggregate["observation_count"],
        process_outcome_success_count=(
            process_aggregate["outcome_counts"]["success"]
        ),
        process_outcome_failure_count=(
            process_aggregate["outcome_counts"]["failure"]
        ),
        process_outcome_unknown_count=(
            process_aggregate["outcome_counts"]["unknown"]
        ),
        argv_complete_count=(
            process_aggregate["argv_completeness_counts"]["complete"]
        ),
        argv_incomplete_count=(
            process_aggregate["argv_completeness_counts"]["incomplete"]
        ),
        path_complete_count=(
            process_aggregate["path_completeness_counts"]["complete"]
        ),
        path_incomplete_count=(
            process_aggregate["path_completeness_counts"]["incomplete"]
        ),
        shared_memory_privileged_execution_observation_count=(
            shared_memory_summary
            .shared_memory_privileged_execution_observation_count
        ),
        session_co_observation_count=(
            session_summary.session_co_observation_count
        ),
        session_process_observation_count=(
            session_summary.process_observation_count
        ),
        session_process_outcome_success_count=(
            session_summary.process_outcome_success_count
        ),
        session_process_outcome_failure_count=(
            session_summary.process_outcome_failure_count
        ),
        session_process_outcome_unknown_count=(
            session_summary.process_outcome_unknown_count
        ),
        session_linked_shared_memory_observation_count=(
            session_summary
            .shared_memory_privileged_execution_observation_count
        ),
        sessions_with_shared_memory_observation_count=(
            session_summary
            .sessions_with_shared_memory_privileged_execution_count
        ),
    )
