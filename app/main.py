from app.analyzer.pipeline import (
    load_normalized_logs,
    detect_attacks,
    correlate_attacks,
    assess_risk,
)

from app.analyzer.process_execution import (
    aggregate_process_execution_observations,
)
from app.analyzer.report import print_analysis_result


LOG_SOURCES = [
    {
        "source": "application",
        "path": "sample_logs/brute_force.log",
    },
    {
        "source": "ssh",
        "path": "sample_logs/ssh_auth.log",
    },
    {
        "source": "access",
        "path": "sample_logs/web_shell.log",
    },
]


def _analyze_normalized_logs(logs):

    result = detect_attacks(logs)

    result = correlate_attacks(
        logs,
        result,
    )

    result = assess_risk(result)

    return result


def analyze(log_sources=None):

    if log_sources is None:
        log_sources = LOG_SOURCES

    logs = load_normalized_logs(log_sources)

    return _analyze_normalized_logs(logs)


def main():

    logs = load_normalized_logs(LOG_SOURCES)

    result = _analyze_normalized_logs(logs)

    process_execution_aggregate = (
        aggregate_process_execution_observations(logs)
    )

    print_analysis_result(
        result,
        process_execution_aggregate=(
            process_execution_aggregate
        ),
    )


if __name__ == "__main__":
    main()