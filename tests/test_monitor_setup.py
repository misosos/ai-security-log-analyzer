"""Phase 20 trusted setup wizard contracts."""

from pathlib import Path
import json
import os
import shlex
import socket
import sys
import tempfile

import pytest

from app import monitor_setup
from app.monitor_setup import MonitorSetupError, create_monitor_config, dry_run_application, main, run_setup
from app.live_monitoring import load_live_monitor_config, open_live_tail_session
from app.live_monitoring.config import LiveMonitorConfigV2, LiveMonitorError, load_live_monitor_setup_config


APP_LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1\n"


def test_wizard_creates_private_v2_config_without_running_monitor(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("y", "application", str(source), "y"))
    lines: list[str] = []
    result = run_setup(output=output, ask=lambda _: next(answers), emit=lines.append)
    assert result.status == "CREATED"
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "2"
    assert load_live_monitor_config(output).role == "application"
    assert str(source) not in "\n".join(lines)
    assert str(output) not in "\n".join(lines[:-1])  # explicitly scoped interactive command only
    assert output.read_bytes().endswith(b"\n")
    assert len(output.read_bytes()) < 4096
    assert output.read_bytes() == (json.dumps(json.loads(output.read_bytes()), ensure_ascii=False,
                                            sort_keys=True, separators=(",", ":")) + "\n").encode()
    trusted = load_live_monitor_setup_config(output)
    assert trusted.source_path == source
    assert str(source) not in repr(trusted)
    session = open_live_tail_session(load_live_monitor_config(output))
    try:
        assert session.poll_once() == 0  # FROM_END: the sampled line was not analyzed.
    finally:
        session.close()


def test_dry_run_is_bounded_and_read_only(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    before = source.read_bytes()
    summary = dry_run_application(source)
    assert summary.parsed_count == 1
    assert summary.inspected_bytes <= 4096
    assert source.read_bytes() == before


def test_cancel_leaves_no_artifact(tmp_path: Path) -> None:
    output = tmp_path / "private" / "monitor.json"
    result = run_setup(output=output, ask=lambda _: "", emit=lambda _: None)
    assert result.status == "CANCELLED"
    assert not output.parent.exists()


def test_cancel_at_final_approval_leaves_no_artifact(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("YES", "application", str(source), "no"))
    result = run_setup(output=output, ask=lambda _: next(answers), emit=lambda _: None)
    assert result.status == "CANCELLED" and not output.parent.exists()


@pytest.mark.parametrize("answer", ("y", "Y", " yes ", "YES"))
def test_only_explicit_yes_is_approval(answer: str, tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("yes", "application", str(source), answer))
    assert run_setup(output=output, ask=lambda _: next(answers), emit=lambda _: None).status == "CREATED"


@pytest.mark.parametrize("answer", ("", "n", "true", "1", "yes please"))
def test_other_approval_values_cancel(answer: str, tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("yes", "application", str(source), answer))
    assert run_setup(output=output, ask=lambda _: next(answers), emit=lambda _: None).status == "CANCELLED"
    assert not output.parent.exists()


def test_atomic_writer_never_replaces_existing_file(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    output.parent.mkdir(mode=0o700)
    output.write_text("keep", encoding="utf-8")
    try:
        create_monitor_config(source, output)
    except Exception:
        pass
    assert output.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("value", ("relative.log", "~/secret.log", "$HOME/secret.log", "https://example/x",
                                   "/tmp/*.log", "", "/tmp/../x", "/tmp//x", "/tmp/a\x00b"))
def test_source_path_rejections_are_fixed_and_private(value: str) -> None:
    with pytest.raises(MonitorSetupError) as caught:
        dry_run_application(value)
    assert caught.value.code == "SETUP_INVALID_INPUT"
    if value:
        assert value not in str(caught.value) and value not in repr(caught.value)


def test_missing_symlink_directory_fifo_and_socket_are_rejected(tmp_path: Path) -> None:
    regular = tmp_path / "regular.log"
    regular.write_text(APP_LINE, encoding="utf-8")
    alias = tmp_path / "alias.log"
    alias.symlink_to(regular)
    parent = tmp_path / "alias-dir"
    parent.symlink_to(tmp_path, target_is_directory=True)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    for path, code in ((tmp_path / "missing", "SETUP_PATH_MISSING"),
                       (alias, "SETUP_SYMLINK_REJECTED"),
                       (parent / "regular.log", "SETUP_SYMLINK_REJECTED"),
                       (tmp_path, "SETUP_NOT_REGULAR_FILE"),
                       (fifo, "SETUP_NOT_REGULAR_FILE")):
        with pytest.raises(MonitorSetupError) as caught:
            dry_run_application(path)
        assert caught.value.code == code
    with tempfile.TemporaryDirectory(prefix="setup-sock-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp") as directory:
        sock_path = Path(directory) / "s"
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(sock_path))
            with pytest.raises(MonitorSetupError) as caught:
                dry_run_application(sock_path)
            assert caught.value.code == "SETUP_NOT_REGULAR_FILE"
        finally:
            sock.close()


@pytest.mark.parametrize(("payload", "code"), (
    (b"abc\x00def\n", "SETUP_BINARY_INPUT"),
    (b"\xff\n", "SETUP_INVALID_UTF8"),
    (b"x" * 2049 + b"\n", "SETUP_LINE_TOO_LONG"),
    (b"not an application line\n", "SETUP_UNSUPPORTED_FORMAT"),
    (b"PK\x03\x04binary archive", "SETUP_BINARY_INPUT"),
))
def test_invalid_dry_run_never_prints_payload(tmp_path: Path, payload: bytes, code: str) -> None:
    source = tmp_path / "source.log"
    source.write_bytes(payload)
    with pytest.raises(MonitorSetupError) as caught:
        dry_run_application(source)
    assert caught.value.code == code
    assert str(source) not in str(caught.value)


def test_ignored_rejected_partial_and_empty_policy(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_bytes(APP_LINE.encode() + b"\n" + b"not valid\n" + b"pending")
    summary = dry_run_application(source)
    assert (summary.parsed_count, summary.ignored_count, summary.rejected_count) == (1, 1, 1)
    assert summary.partial_line
    source.write_bytes(b"")
    empty = dry_run_application(source)
    assert empty.empty_source and empty.inspected_lines == 0 and empty.parsed_count == 0


def test_sample_byte_and_line_caps(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE * 100, encoding="utf-8")
    summary = dry_run_application(source)
    assert summary.inspected_bytes == 4096
    assert summary.inspected_lines == 16
    assert summary.parsed_count == 16
    assert summary.sample_limited

    source.write_text(APP_LINE * 17, encoding="utf-8")
    summary = dry_run_application(source)
    assert summary.inspected_lines == 16
    assert summary.sample_limited  # line cap, even though the byte cap was not reached


def test_v2_exact_schema_and_v1_compatibility(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    path = tmp_path / "monitor.json"
    path.write_text(json.dumps(LiveMonitorConfigV2(source).as_document()), encoding="utf-8")
    path.chmod(0o600)
    assert load_live_monitor_config(path).role == "application"
    assert load_live_monitor_setup_config(path).source_path == source
    for edit in (
        lambda doc: doc.update({"secret": "unsafe"}),
        lambda doc: doc["sources"].append(doc["sources"][0]),
        lambda doc: doc["sources"][0].update({"enabled": 1}),
        lambda doc: doc["sources"][0].update({"source_role": "ssh"}),
        lambda doc: doc["sources"][0].update({"source_path": "relative.log"}),
        lambda doc: doc["sources"][0].update({"checkpoint_policy": "ENABLED"}),
        lambda doc: doc["sources"][0].update({"source_id": "SOURCE-000002"}),
        lambda doc: doc["sources"][0].update({"rotation_policy": "FOLLOW"}),
        lambda doc: doc.update({"schema_version": "3"}),
    ):
        document = LiveMonitorConfigV2(source).as_document()
        edit(document)
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(LiveMonitorError):
            load_live_monitor_config(path)
    disabled = LiveMonitorConfigV2(source, enabled=False).as_document()
    path.write_text(json.dumps(disabled), encoding="utf-8")
    assert not load_live_monitor_setup_config(path).enabled
    with pytest.raises(LiveMonitorError) as caught:
        load_live_monitor_config(path)
    assert caught.value.code == "SOURCE_DISABLED"
    duplicate = json.dumps(LiveMonitorConfigV2(source).as_document()).replace(
        '"schema_version": "2"', '"schema_version": "2", "schema_version": "2"')
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(LiveMonitorError) as caught:
        load_live_monitor_config(path)
    assert caught.value.code == "DUPLICATE_JSON_KEY"


def test_output_symlink_parent_symlink_and_no_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    output = private / "monitor.json"
    alias = private / "alias.json"
    alias.symlink_to(source)
    for destination, code in ((alias, "SETUP_OUTPUT_SYMLINK"),
                              (tmp_path / "parent-alias" / "monitor.json", "SETUP_UNSAFE_PARENT")):
        if destination.parent.name == "parent-alias":
            destination.parent.symlink_to(private, target_is_directory=True)
        with pytest.raises(MonitorSetupError) as caught:
            create_monitor_config(source, destination)
        assert caught.value.code == code
    assert not output.exists() and alias.is_symlink()


def test_replacement_after_preview_is_rejected_before_config_creation(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("yes", "application", str(source)))

    def answer(_prompt: str) -> str:
        try:
            return next(answers)
        except StopIteration:
            replacement = tmp_path / "replacement.log"
            replacement.write_text(APP_LINE, encoding="utf-8")
            replacement.replace(source)
            return "yes"

    with pytest.raises(MonitorSetupError) as caught:
        run_setup(output=output, ask=answer, emit=lambda _: None)
    assert caught.value.code == "SETUP_SOURCE_CHANGED"
    assert not output.exists()


@pytest.mark.parametrize("stage", ("write", "file_fsync", "parent_fsync", "link", "chmod", "validate"))
def test_save_fault_does_not_leave_final_or_temporary_file(tmp_path: Path, monkeypatch, stage: str) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    real_write = monitor_setup.os.write
    real_fsync = monitor_setup.os.fsync
    real_link = monitor_setup.os.link
    real_chmod = monitor_setup.os.fchmod
    real_validate = monitor_setup.load_live_monitor_setup_config

    if stage == "write":
        monkeypatch.setattr(monitor_setup.os, "write", lambda *_: (_ for _ in ()).throw(OSError("secret")))
    elif stage in ("file_fsync", "parent_fsync"):
        calls = 0

        def fsync(fd):
            nonlocal calls
            calls += 1
            if calls == (1 if stage == "file_fsync" else 2):
                raise OSError("secret")
            return real_fsync(fd)

        monkeypatch.setattr(monitor_setup.os, "fsync", fsync)
    elif stage == "link":
        monkeypatch.setattr(monitor_setup.os, "link", lambda *_, **__: (_ for _ in ()).throw(OSError("secret")))
    elif stage == "chmod":
        monkeypatch.setattr(monitor_setup.os, "fchmod", lambda *_: (_ for _ in ()).throw(OSError("secret")))
    else:
        monkeypatch.setattr(monitor_setup, "load_live_monitor_setup_config",
                            lambda *_: (_ for _ in ()).throw(LiveMonitorError("INVALID_CONFIG")))
    try:
        with pytest.raises(MonitorSetupError) as caught:
            create_monitor_config(source, output)
        assert "secret" not in str(caught.value) and "secret" not in repr(caught.value)
        assert not output.exists()
        assert not output.parent.exists() or not list(output.parent.iterdir())
    finally:
        monkeypatch.setattr(monitor_setup.os, "write", real_write)
        monkeypatch.setattr(monitor_setup.os, "fsync", real_fsync)
        monkeypatch.setattr(monitor_setup.os, "link", real_link)
        monkeypatch.setattr(monitor_setup.os, "fchmod", real_chmod)
        monkeypatch.setattr(monitor_setup, "load_live_monitor_setup_config", real_validate)


def test_cli_cancellation_and_fixed_error_exit(capsys, tmp_path: Path) -> None:
    assert main([], ask=lambda _: "", emit=lambda _: None) == 0
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    answers = iter(("y", "application", str(source)))
    assert main(["--output", "relative.json"], ask=lambda _: next(answers), emit=lambda _: None) == 2
    captured = capsys.readouterr()
    assert "SETUP_INVALID_INPUT" in captured.err


@pytest.mark.parametrize("role", ("ssh", "access", "linux-audit", "anything", ""))
def test_wizard_rejects_other_roles_without_fallback(role: str, tmp_path: Path) -> None:
    answers = iter(("yes", role))
    with pytest.raises(MonitorSetupError) as caught:
        run_setup(output=tmp_path / "monitor.json", ask=lambda _: next(answers), emit=lambda _: None)
    assert caught.value.code == "SETUP_UNSUPPORTED_ROLE"
    assert not (tmp_path / "monitor.json").exists()


def test_privacy_canaries_never_enter_safe_result_error_or_failure_output(tmp_path: Path, capsys) -> None:
    account = "account_private_marker"
    address = "198.51.100.77"
    query = "/private_marker?q=private_marker"
    source = tmp_path / "source_private_marker.log"
    source.write_text(f"2026-01-02 03:04:05 INFO login_failed user={account} ip={address} path={query}\n", encoding="utf-8")
    output = tmp_path / "private" / "config_private_marker.json"
    safe = create_monitor_config(source, output)
    error = MonitorSetupError("SETUP_SAVE_FAILED")
    surface = repr(safe) + repr(error) + str(error) + repr(load_live_monitor_setup_config(output))
    for private in (account, address, query, str(source), str(output)):
        assert private not in surface
    bad = tmp_path / "bad_private_marker.log"
    bad.write_bytes(b"secret_raw_marker\x00\n")
    answers = iter(("yes", "application", str(bad)))
    assert main(["--output", str(tmp_path / "other_private_marker.json")],
                ask=lambda _: next(answers), emit=lambda _: None) == 3
    failure = capsys.readouterr()
    for private in ("secret_raw_marker", str(bad), str(output), "private_marker"):
        assert private not in failure.out + failure.err


def test_dry_run_read_failure_is_fixed_and_closes_descriptor(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    original = monitor_setup.os.read
    descriptors: list[int] = []

    def broken(fd: int, _size: int) -> bytes:
        descriptors.append(fd)
        raise OSError("private read failure")

    monkeypatch.setattr(monitor_setup.os, "read", broken)
    try:
        with pytest.raises(MonitorSetupError) as caught:
            dry_run_application(source)
    finally:
        monkeypatch.setattr(monitor_setup.os, "read", original)
    assert caught.value.code == "SETUP_SOURCE_CHANGED"
    assert "private read failure" not in str(caught.value)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_setup_isolated_from_analysis_server_browser_and_network(tmp_path: Path, monkeypatch) -> None:
    from app.analyzer import pipeline
    from app.analyzer import html_report
    from app.live_monitoring import runner
    import subprocess
    import webbrowser

    def forbidden(*_args, **_kwargs):
        raise AssertionError("setup crossed an analysis or execution boundary")

    for name in ("detect_attacks", "correlate_attacks", "assess_risk"):
        monkeypatch.setattr(pipeline, name, forbidden)
    monkeypatch.setattr(html_report, "render_investigation_report_html", forbidden)
    monkeypatch.setattr(runner.LiveMonitoringRunner, "run", forbidden)
    monkeypatch.setattr(webbrowser, "open", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)

    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    answers = iter(("yes", "application", str(source), "yes"))
    assert run_setup(output=output, ask=lambda _: next(answers), emit=lambda _: None).status == "CREATED"
    assert output.exists()


def test_unsupported_safe_open_is_fixed_failure(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    monkeypatch.delattr(monitor_setup.os, "O_NOFOLLOW")
    with pytest.raises(MonitorSetupError) as caught:
        dry_run_application(source)
    assert caught.value.code == "SETUP_UNSUPPORTED_OS"


def test_quoted_unicode_source_and_shell_quoted_command(tmp_path: Path) -> None:
    source = tmp_path / "공백 ' 로그.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "공백 ' 설정.json"
    answers = iter(("yes", "application", f'"{source}"', "yes"))
    lines: list[str] = []
    run_setup(output=output, ask=lambda _: next(answers), emit=lines.append)
    assert load_live_monitor_config(output).path == source
    assert shlex.split(lines[-1])[-1] == str(output)
