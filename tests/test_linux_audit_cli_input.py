import errno
from copy import deepcopy
import os
from pathlib import Path
import sys

import pytest

import app.main as main_module


FIXTURE = Path(
    "sample_logs/"
    "linux_audit_shared_memory_execution_contract_synthetic.log"
)
CANARY = "SYNTHETIC_PROCESS_SECRET_DO_NOT_EXPOSE"


def _install_main_spies(monkeypatch):
    logs = []
    analysis = {
        "results": {},
        "global_correlation": {},
    }
    aggregate = {"observation_count": 0}
    calls = []

    def fake_load(sources):
        calls.append(("load", sources))
        return logs

    def fake_analyze(received_logs):
        calls.append(("analyze", received_logs))
        return analysis

    def fake_aggregate(received_logs):
        calls.append(("aggregate", received_logs))
        return aggregate

    def fake_print(received_analysis, *, process_execution_aggregate=None):
        calls.append((
            "print",
            received_analysis,
            process_execution_aggregate,
        ))

    monkeypatch.setattr(main_module, "load_normalized_logs", fake_load)
    monkeypatch.setattr(main_module, "_analyze_normalized_logs", fake_analyze)
    monkeypatch.setattr(
        main_module,
        "aggregate_process_execution_observations",
        fake_aggregate,
    )
    monkeypatch.setattr(main_module, "print_analysis_result", fake_print)
    return calls, logs, analysis, aggregate


def _write_nonempty(path):
    path.write_text("synthetic audit input\n", encoding="utf-8")
    return path


def test_main_accepts_repeated_linux_audit_inputs_without_mutating_state(
    monkeypatch,
    tmp_path,
):
    first = _write_nonempty(tmp_path / "first-audit.log")
    second = _write_nonempty(tmp_path / "second-audit.log")
    argv = [
        "--linux-audit",
        str(first),
        "--linux-audit",
        str(second),
    ]
    original_argv = list(argv)
    original_sources = deepcopy(main_module.LOG_SOURCES)
    calls, logs, analysis, aggregate = _install_main_spies(monkeypatch)

    main_module.main(argv)

    loaded_sources = calls[0][1]
    assert loaded_sources[:3] == original_sources
    assert loaded_sources[3:] == [
        {
            "source": "linux_audit",
            "path": str(first),
            "source_instance": "cli-linux-audit-1",
        },
        {
            "source": "linux_audit",
            "path": str(second),
            "source_instance": "cli-linux-audit-2",
        },
    ]
    assert calls[1:] == [
        ("analyze", logs),
        ("aggregate", logs),
        ("print", analysis, aggregate),
    ]
    assert main_module.LOG_SOURCES == original_sources
    assert argv == original_argv

    calls.clear()
    main_module.main([])
    assert calls[0][1] == original_sources
    assert len(calls[0][1]) == 3
    assert main_module.LOG_SOURCES == original_sources


def test_main_and_main_empty_argv_ignore_global_sys_argv(
    monkeypatch,
):
    calls, _, _, _ = _install_main_spies(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["pytest", "--unknown-global-option"],
    )

    main_module.main()
    main_module.main([])

    assert [call[0] for call in calls] == [
        "load",
        "analyze",
        "aggregate",
        "print",
        "load",
        "analyze",
        "aggregate",
        "print",
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["--unknown-option"],
        ["--linux-audit"],
    ],
)
def test_argparse_rejects_unknown_or_missing_options(argv, capsys):
    with pytest.raises(SystemExit) as raised:
        main_module.main(argv)

    assert raised.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_help_is_available_without_running_analysis(capsys):
    with pytest.raises(SystemExit) as raised:
        main_module.main(["--help"])

    output = capsys.readouterr().out
    assert raised.value.code == 0
    assert "--linux-audit PATH" in output
    assert "repeat this option" in output
    assert "argv" not in output
    assert "raw" not in output


@pytest.mark.parametrize(
    ("kind", "expected_reason"),
    [
        ("missing", "file does not exist"),
        ("directory", "path is not a regular file"),
        ("empty", "file is empty"),
        ("fifo", "path is not a regular file"),
        ("whitespace", "path is empty"),
    ],
)
def test_invalid_file_boundaries_are_path_private(
    kind,
    expected_reason,
    tmp_path,
    capsys,
):
    sensitive_name = f"private-{kind}-audit.log"
    path = tmp_path / sensitive_name

    if kind == "directory":
        path.mkdir()
    elif kind == "empty":
        path.touch()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "whitespace":
        path_argument = "   "
    else:
        path_argument = str(path)

    if kind not in {"missing", "whitespace"}:
        path_argument = str(path)

    with pytest.raises(SystemExit) as raised:
        main_module.main(["--linux-audit", path_argument])

    error = capsys.readouterr().err
    assert raised.value.code == 2
    assert "input #1" in error
    assert expected_reason in error
    assert str(path) not in error
    assert sensitive_name not in error
    assert "Traceback" not in error


def test_regular_file_symlink_is_accepted_and_original_path_is_preserved(
    monkeypatch,
    tmp_path,
):
    target = _write_nonempty(tmp_path / "target-audit.log")
    link = tmp_path / "audit-link.log"
    link.symlink_to(target)
    calls, _, _, _ = _install_main_spies(monkeypatch)

    main_module.main(["--linux-audit", str(link)])

    assert calls[0][1][-1] == {
        "source": "linux_audit",
        "path": str(link),
        "source_instance": "cli-linux-audit-1",
    }


def test_broken_symlink_is_rejected_without_path_disclosure(
    tmp_path,
    capsys,
):
    link = tmp_path / "private-broken-link.log"
    link.symlink_to(tmp_path / "missing-target.log")

    with pytest.raises(SystemExit) as raised:
        main_module.main(["--linux-audit", str(link)])

    error = capsys.readouterr().err
    assert raised.value.code == 2
    assert "input #1" in error
    assert "file does not exist" in error
    assert str(link) not in error
    assert link.name not in error


@pytest.mark.parametrize("alias_kind", ["exact", "symlink", "hardlink"])
def test_duplicate_underlying_file_is_rejected(
    alias_kind,
    tmp_path,
    capsys,
):
    original = _write_nonempty(tmp_path / "private-original.log")

    if alias_kind == "exact":
        alias = original
    elif alias_kind == "symlink":
        alias = tmp_path / "private-alias.log"
        alias.symlink_to(original)
    else:
        alias = tmp_path / "private-hardlink.log"
        os.link(original, alias)

    with pytest.raises(SystemExit) as raised:
        main_module.main([
            "--linux-audit",
            str(original),
            "--linux-audit",
            str(alias),
        ])

    error = capsys.readouterr().err
    assert raised.value.code == 2
    assert "input #2 refers to the same file as input #1" in error
    assert str(original) not in error
    assert original.name not in error
    assert str(alias) not in error
    assert alias.name not in error


def test_relative_and_absolute_aliases_are_rejected(
    monkeypatch,
    tmp_path,
    capsys,
):
    original = _write_nonempty(tmp_path / "private-relative.log")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as raised:
        main_module.main([
            "--linux-audit",
            original.name,
            "--linux-audit",
            str(original),
        ])

    error = capsys.readouterr().err
    assert raised.value.code == 2
    assert "input #2 refers to the same file as input #1" in error
    assert original.name not in error
    assert str(original) not in error


def test_default_loader_failure_keeps_existing_exception_boundary(
    monkeypatch,
):
    failure = OSError(
        errno.EACCES,
        "default source failure",
        "sample_logs/private-default.log",
    )

    def fail_load(sources):
        raise failure

    monkeypatch.setattr(main_module, "load_normalized_logs", fail_load)

    with pytest.raises(OSError) as raised:
        main_module.main()

    assert raised.value is failure


@pytest.mark.parametrize("failure_kind", ["open", "decode"])
def test_loader_failures_are_bounded_and_path_private(
    failure_kind,
    monkeypatch,
    tmp_path,
    capsys,
):
    path = _write_nonempty(tmp_path / "private-readable-name.log")

    def fail_load(sources):
        if failure_kind == "open":
            raise OSError(
                errno.EACCES,
                "sensitive underlying exception",
                str(path),
            )
        raise UnicodeDecodeError(
            "utf-8",
            b"private raw bytes",
            0,
            1,
            "sensitive decode detail",
        )

    monkeypatch.setattr(main_module, "load_normalized_logs", fail_load)

    with pytest.raises(SystemExit) as raised:
        main_module.main(["--linux-audit", str(path)])

    error = capsys.readouterr().err
    assert raised.value.code == 2
    assert "Linux Audit input cannot be read: input #1" in error
    assert str(path) not in error
    assert path.name not in error
    assert "sensitive" not in error
    assert "private raw bytes" not in error
    assert "Traceback" not in error


def test_fixture_reaches_process_telemetry_without_detection_details(capsys):
    main_module.main(["--linux-audit", str(FIXTURE)])

    output = capsys.readouterr().out
    assert "===== Process Execution Telemetry =====" in output
    assert "success: 12" in output
    assert "failure: 1" in output
    assert "unknown: 1" in output
    assert "argv evidence completeness:" in output
    assert "PATH evidence completeness:" in output
    assert "syscall" in output
    assert "completeness" in output
    assert "Shared-memory privileged execution" not in output
    assert "review observation" not in output
    assert CANARY not in output

    for private_detail in (
        "/dev/shm/",
        "/run/shm/",
        "effective_user_id",
        "source_instance",
        "event_id",
        "PROCTITLE",
        "raw_records",
    ):
        assert private_detail not in output


def test_analyze_public_contract_remains_unchanged():
    result = main_module.analyze([])

    assert set(result) == {"results", "global_correlation"}
    assert "process_execution_aggregate" not in result
    assert "process_detection_summary" not in result
