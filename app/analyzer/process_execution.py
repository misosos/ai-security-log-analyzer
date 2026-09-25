from collections.abc import Iterable

from app.models.schemas import NormalizedEvent


def aggregate_process_execution_observations(
    events: Iterable[NormalizedEvent],
) -> dict:
    observation_count = 0
    outcome_counts = {
        "success": 0,
        "failure": 0,
        "unknown": 0,
    }
    argv_completeness_counts = {
        "complete": 0,
        "incomplete": 0,
    }
    path_completeness_counts = {
        "complete": 0,
        "incomplete": 0,
    }

    for event in events:
        context = event.process_execution

        if (
            event.event_type != "process_execution_attempt"
            or event.source != "linux_audit"
            or context is None
        ):
            continue

        observation_count += 1

        outcome = context.outcome
        if outcome not in ("success", "failure", "unknown"):
            outcome = "unknown"
        outcome_counts[outcome] += 1

        argv_key = (
            "complete"
            if context.argv_complete is True
            else "incomplete"
        )
        argv_completeness_counts[argv_key] += 1

        path_key = (
            "complete"
            if context.paths_complete is True
            else "incomplete"
        )
        path_completeness_counts[path_key] += 1

    return {
        "observation_count": observation_count,
        "outcome_counts": outcome_counts,
        "argv_completeness_counts": argv_completeness_counts,
        "path_completeness_counts": path_completeness_counts,
    }
