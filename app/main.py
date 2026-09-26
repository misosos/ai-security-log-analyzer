import argparse
from collections.abc import Sequence
import os
from pathlib import Path
import stat
import sys

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
from app.correlation.session_process import (
    collect_session_process_co_observations,
    summarize_session_process_co_observations,
)
from app.detector.shared_memory_execution import (
    collect_shared_memory_execution_observations,
    summarize_shared_memory_execution_observations,
)


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


class _LinuxAuditInputError(ValueError):

    def __init__(self, index, reason, duplicate_of=None):
        super().__init__(reason)
        self.index = index
        self.reason = reason
        self.duplicate_of = duplicate_of


def _build_argument_parser():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--linux-audit",
        metavar="PATH",
        action="append",
        default=[],
        help=(
            "Linux Audit log file; repeat this option to add "
            "multiple files"
        ),
    )
    return parser


def _linux_audit_source_configs(paths):

    configs = []
    file_identities = {}

    for index, supplied_path in enumerate(paths, start=1):
        if (
            not isinstance(supplied_path, str)
            or not supplied_path.strip()
        ):
            raise _LinuxAuditInputError(
                index,
                "path is empty",
            )

        path = Path(supplied_path)

        try:
            path_stat = path.stat()
        except FileNotFoundError:
            raise _LinuxAuditInputError(
                index,
                "file does not exist",
            ) from None
        except OSError:
            raise _LinuxAuditInputError(
                index,
                "file metadata is unavailable",
            ) from None

        if not stat.S_ISREG(path_stat.st_mode):
            raise _LinuxAuditInputError(
                index,
                "path is not a regular file",
            )

        if path_stat.st_size == 0:
            raise _LinuxAuditInputError(
                index,
                "file is empty",
            )

        file_identity = (
            path_stat.st_dev,
            path_stat.st_ino,
        )
        duplicate_of = file_identities.get(file_identity)

        if duplicate_of is not None:
            raise _LinuxAuditInputError(
                index,
                "file duplicates an earlier input",
                duplicate_of=duplicate_of,
            )

        file_identities[file_identity] = index
        configs.append({
            "source": "linux_audit",
            "path": supplied_path,
            "source_instance": f"cli-linux-audit-{index}",
        })

    return configs


def _format_linux_audit_input_error(error):

    if error.duplicate_of is not None:
        return (
            "Linux Audit input is invalid: "
            f"input #{error.index} refers to the same file as "
            f"input #{error.duplicate_of}"
        )

    return (
        "Linux Audit input is invalid: "
        f"input #{error.index} {error.reason}"
    )


def _linux_audit_read_error_index(error, paths):

    filename = getattr(error, "filename", None)

    if filename is not None:
        filename = os.fspath(filename)

        for index, supplied_path in enumerate(paths, start=1):
            if filename == os.fspath(supplied_path):
                return index

    if filename is None and len(paths) == 1:
        return 1

    return None


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


def main(argv: Sequence[str] | None = None) -> None:

    parser = _build_argument_parser()
    args = parser.parse_args(
        [] if argv is None else list(argv)
    )

    try:
        linux_audit_configs = _linux_audit_source_configs(
            args.linux_audit
        )
    except _LinuxAuditInputError as error:
        parser.error(_format_linux_audit_input_error(error))

    sources = [config.copy() for config in LOG_SOURCES]
    sources.extend(linux_audit_configs)

    try:
        logs = load_normalized_logs(sources)
    except (OSError, UnicodeError) as error:
        if not args.linux_audit:
            raise

        input_index = _linux_audit_read_error_index(
            error,
            args.linux_audit,
        )

        if (
            getattr(error, "filename", None) is not None
            and input_index is None
        ):
            raise

        input_label = (
            f"input #{input_index}"
            if input_index is not None
            else "an input file"
        )
        parser.error(
            "Linux Audit input cannot be read: "
            f"{input_label}"
        )

    result = _analyze_normalized_logs(logs)

    process_execution_aggregate = (
        aggregate_process_execution_observations(logs)
    )

    try:
        process_observations = (
            collect_shared_memory_execution_observations(logs)
        )
        process_detection_summary = (
            summarize_shared_memory_execution_observations(
                process_observations
            )
        )
    except (TypeError, ValueError):
        print(
            "Process detection observation summary could not be "
            "created: internal contract validation failed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    try:
        session_process_relations = (
            collect_session_process_co_observations(logs)
        )
        session_process_review_summary = (
            summarize_session_process_co_observations(
                session_process_relations,
                process_observations,
            )
        )
    except (TypeError, ValueError):
        print(
            "Session-process review summary could not be created: "
            "internal contract validation failed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    print_arguments = {
        "process_execution_aggregate": (
            process_execution_aggregate
        ),
    }

    if (
        process_detection_summary
        .shared_memory_privileged_execution_observation_count
        > 0
    ):
        print_arguments["process_detection_summary"] = (
            process_detection_summary
        )

    if session_process_review_summary.session_co_observation_count > 0:
        print_arguments["session_process_review_summary"] = (
            session_process_review_summary
        )

    try:
        print_analysis_result(
            result,
            **print_arguments,
        )
    except (TypeError, ValueError):
        print(
            "Session-process review summary could not be created: "
            "internal contract validation failed.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main(sys.argv[1:])
