from app.analyzer.pipeline import (
    load_normalized_logs,
    detect_attacks,
    correlate_attacks,
    assess_risk,
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


def analyze(log_sources=None):

    if log_sources is None:
        log_sources = LOG_SOURCES

    logs = load_normalized_logs(log_sources)

    result = detect_attacks(logs)

    result = correlate_attacks(
        logs,
        result,
    )

    result = assess_risk(result)

    return result


if __name__ == "__main__":

    result = analyze()

    print_analysis_result(result)