"""Fault-injection coverage at the restricted report file-operation boundary."""

import errno
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from contextlib import contextmanager

import pytest

from app import restricted_report as report


APPROVAL = report.APPROVAL
LINE = b"2026-09-11 10:00:01 INFO login_failed user=fault-account-5c ip=192.0.2.56\n"


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _input(path: Path) -> Path:
    source = path / "synthetic-input.log"
    source.write_bytes(LINE)
    source.chmod(0o600)
    return source


def _dirfd(path: Path) -> int:
    return os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))


def _bind_test_socket(server: socket.socket, endpoint: Path) -> None:
    try:
        server.bind(str(endpoint))
    except (OSError, ValueError):
        pytest.fail("Could not bind the private test Unix socket.", pytrace=False)


@contextmanager
def _short_private_socket_dir():
    """Create a private temp directory whose Unix socket path fits portably."""
    # 100 bytes, including the terminating NUL, stays below the common
    # sockaddr_un.sun_path capacities without relying on a platform-specific
    # temporary pathname. The default temp directory is tried first; its
    # existing parent is an explicitly checked shorter system-temp candidate.
    max_sun_path_bytes = 100
    default = Path(tempfile.gettempdir()).resolve(strict=True)
    candidates = (default, default.parent)
    seen = set()
    for candidate in candidates:
        temporary = None
        try:
            base = candidate.resolve(strict=True)
            if base in seen:
                continue
            seen.add(base)
            info = base.stat()
            if not stat.S_ISDIR(info.st_mode):
                continue
            if info.st_uid != os.geteuid() and not (
                info.st_mode & stat.S_ISVTX and info.st_mode & stat.S_IWOTH
            ):
                continue
            temporary = tempfile.TemporaryDirectory(prefix="r5c-", dir=base)
            private = Path(temporary.name)
            private.chmod(0o700)
            endpoint = private / "s"
            if len(os.fsencode(endpoint)) + 1 > max_sun_path_bytes:
                temporary.cleanup()
                continue
        except (OSError, ValueError):
            if temporary is not None:
                try:
                    temporary.cleanup()
                except OSError:
                    pytest.fail("Could not clean the private test directory.", pytrace=False)
            continue
        try:
            yield private, endpoint
        finally:
            try:
                temporary.cleanup()
            except OSError:
                pytest.fail("Could not clean the private test directory.", pytrace=False)
        return
    pytest.fail("No verified temporary directory has a portable Unix socket path.", pytrace=False)


def _record(status="success", role="application", report_id="a" * 32):
    return {
        "status": status,
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "schema_version": report.SCHEMA_VERSION,
        "source_role": role,
        "report_id": report_id,
        "identifier_counts": {"account": 1, "ipv4": 1, "ipv6": 0, "hostname": 0},
        "case_count": 0,
        "relation_count": 0,
        "observation_count": 1,
    }


@pytest.mark.parametrize("fault", ["open", "write_enospc", "file_fsync", "publish", "directory_fsync"])
def test_atomic_publish_faults_never_claim_success_or_leave_temp(tmp_path, monkeypatch, fault):
    private = _private(tmp_path / "private")
    fd = _dirfd(private)
    try:
        if fault == "open":
            real_open = report.os.open

            def fail_temp_open(path, flags, *args, **kwargs):
                if isinstance(path, str) and path.startswith(".restricted-"):
                    raise OSError(errno.EACCES, "private-open-canary")
                return real_open(path, flags, *args, **kwargs)

            monkeypatch.setattr(report.os, "open", fail_temp_open)
        elif fault == "write_enospc":
            monkeypatch.setattr(report.os, "write", lambda *_args: (_ for _ in ()).throw(OSError(errno.ENOSPC, "private-write-canary")))
        elif fault == "file_fsync":
            real_fsync = report.os.fsync

            def fail_file_fsync(target_fd):
                if stat.S_ISREG(os.fstat(target_fd).st_mode):
                    raise OSError(errno.EIO, "private-fsync-canary")
                return real_fsync(target_fd)

            monkeypatch.setattr(report.os, "fsync", fail_file_fsync)
        elif fault == "publish":
            monkeypatch.setattr(report.os, "link", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(errno.EIO, "private-link-canary")))
        elif fault == "directory_fsync":
            real_fsync = report.os.fsync
            calls = 0

            def fail_dir_fsync(target_fd):
                nonlocal calls
                if stat.S_ISDIR(os.fstat(target_fd).st_mode):
                    calls += 1
                    raise OSError(errno.EIO, "private-dir-sync-canary")
                return real_fsync(target_fd)

            monkeypatch.setattr(report.os, "fsync", fail_dir_fsync)

        with pytest.raises(report.RestrictedReportError) as failure:
            report._atomic_publish(fd, "result.json", b'{"safe":true}\n')
        assert "private-" not in str(failure.value)
        assert not (private / "result.json").exists()
        assert not list(private.glob(".restricted-*.tmp"))
    finally:
        os.close(fd)


def test_audit_enospc_and_fsync_failure_roll_back_partial_row(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    fd = _dirfd(private)
    try:
        real_write = report.os.write
        writes = 0

        def fail_audit_write(target_fd, data):
            nonlocal writes
            writes += 1
            if writes == 1:
                return real_write(target_fd, data[: max(1, len(data) // 2)])
            if writes == 2:
                raise OSError(errno.ENOSPC, "audit-write-canary")
            return real_write(target_fd, data)

        monkeypatch.setattr(report.os, "write", fail_audit_write)
        with pytest.raises(report.RestrictedReportError):
            report._audit_append(fd, _record())
        assert not (private / report.AUDIT_NAME).exists()
    finally:
        os.close(fd)

    private2 = _private(tmp_path / "private-fsync")
    fd2 = _dirfd(private2)
    try:
        real_fsync = report.os.fsync
        calls = 0

        def fail_first_audit_fsync(target_fd):
            nonlocal calls
            if stat.S_ISREG(os.fstat(target_fd).st_mode):
                calls += 1
                if calls == 1:
                    raise OSError(errno.EIO, "audit-fsync-canary")
            return real_fsync(target_fd)

        monkeypatch.setattr(report.os, "fsync", fail_first_audit_fsync)
        with pytest.raises(report.RestrictedReportError):
            report._audit_append(fd2, _record())
        assert not (private2 / report.AUDIT_NAME).exists()
    finally:
        os.close(fd2)


def test_audit_close_fault_rolls_back_row_and_retries_close(tmp_path, monkeypatch):
    private = _private(tmp_path / "private-close")
    fd = _dirfd(private)
    real_close = report.os.close
    failed = False

    def fail_first_close(target_fd):
        nonlocal failed
        if not failed:
            failed = True
            raise OSError(errno.EIO, "audit-close-canary")
        return real_close(target_fd)

    monkeypatch.setattr(report.os, "close", fail_first_close)
    try:
        with pytest.raises(report.RestrictedReportError):
            report._audit_append(fd, _record())
    finally:
        monkeypatch.setattr(report.os, "close", real_close)
        os.close(fd)
    assert failed
    assert not (private / report.AUDIT_NAME).exists()


def test_export_audit_failure_rolls_back_report_and_leaves_fixed_failure_record(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    source = _input(private)
    output = private / "report.json"
    real_append = report._audit_append

    def fail_success_then_write_failure(dir_fd, record):
        if record["status"] == "success":
            raise report.RestrictedReportError()
        return real_append(dir_fd, record)

    monkeypatch.setattr(report, "_audit_append", fail_success_then_write_failure)
    with pytest.raises(report.RestrictedReportError) as failure:
        report.export_report("application", str(source), str(output), approval_reader=lambda: APPROVAL)
    assert not failure.value.recovery_needed
    assert not output.exists()
    audit = [json.loads(row) for row in (private / report.AUDIT_NAME).read_bytes().splitlines()]
    assert [row["status"] for row in audit] == ["failure"]
    assert audit[0]["report_id"]
    assert "fault-account-5c" not in json.dumps(audit)


def test_audit_open_and_report_serialization_faults_never_publish(tmp_path, monkeypatch):
    private = _private(tmp_path / "private-open-audit")
    source = _input(private)
    output = private / "report.json"
    real_open = report.os.open

    def fail_audit_open(name, flags, *args, **kwargs):
        if name == report.AUDIT_NAME:
            raise OSError(errno.EACCES, "audit-open-canary")
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(report.os, "open", fail_audit_open)
    with pytest.raises(report.RestrictedReportError):
        report.export_report("application", str(source), str(output), approval_reader=lambda: APPROVAL)
    assert not output.exists()
    assert not (private / report.AUDIT_NAME).exists()

    monkeypatch.undo()
    private2 = _private(tmp_path / "private-serialize")
    source2 = _input(private2)
    output2 = private2 / "report.json"
    monkeypatch.setattr(report, "_canonical_json", lambda _value: (_ for _ in ()).throw(TypeError("serialize-canary")))
    with pytest.raises(report.RestrictedReportError) as failure:
        report.export_report("application", str(source2), str(output2), approval_reader=lambda: APPROVAL)
    assert not output2.exists()
    assert "serialize-canary" not in str(failure.value)


def test_failed_report_rollback_is_marked_for_safe_manual_recovery(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    source = _input(private)
    output = private / "report.json"
    real_unlink = report.os.unlink

    def fail_audit(_dir_fd, _record):
        raise report.RestrictedReportError()

    def keep_published_report(name, *args, **kwargs):
        if name == output.name:
            raise OSError(errno.EIO, "rollback-canary-path")
        return real_unlink(name, *args, **kwargs)

    monkeypatch.setattr(report, "_audit_append", fail_audit)
    monkeypatch.setattr(report.os, "unlink", keep_published_report)
    with pytest.raises(report.RestrictedReportError) as failure:
        report.export_report("application", str(source), str(output), approval_reader=lambda: APPROVAL)
    assert failure.value.recovery_needed
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == report.SCHEMA_VERSION
    assert not list(private.glob(".restricted-*.tmp"))
    assert "rollback-canary-path" not in repr(failure.value)


def test_cli_reports_fixed_recovery_guidance_without_paths_or_exception(monkeypatch, capsys, tmp_path):
    output = tmp_path / "secret-output-path.json"

    def fail_with_residual(*_args, **_kwargs):
        raise report.RestrictedReportError(recovery_needed=True)

    monkeypatch.setattr(report, "export_report", fail_with_residual)
    result = report.main(["--source-role", "application", "--input", "/private/input-canary",
                          "--output", str(output)])
    captured = capsys.readouterr()
    assert result == 1
    assert "남아 있을 수 있습니다" in captured.err
    assert str(output) not in captured.err and "/private/input-canary" not in captured.err
    assert "secret-output-path" not in captured.err


def test_known_target_symlink_dangling_target_and_private_parent_symlink_reject_before_audit(tmp_path):
    private = _private(tmp_path / "private")
    source = _input(private)
    target = private / "target.json"
    target.symlink_to(private / "missing-target")
    with pytest.raises(report.RestrictedReportError):
        report.export_report("application", str(source), str(target), approval_reader=lambda: APPROVAL)
    assert target.is_symlink() and not (private / report.AUDIT_NAME).exists()

    alias = tmp_path / "parent-alias"
    alias.symlink_to(private, target_is_directory=True)
    with pytest.raises(report.RestrictedReportError):
        report.export_report("application", str(source), str(alias / "new.json"), approval_reader=lambda: APPROVAL)
    assert not (private / report.AUDIT_NAME).exists()


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o777])
def test_unsafe_parent_modes_are_rejected(tmp_path, mode):
    parent = _private(tmp_path / "parent")
    parent.chmod(mode)
    with pytest.raises(report.RestrictedReportError):
        report._open_private_directory(parent)


def test_input_fifo_socket_device_and_symlink_are_rejected(tmp_path):
    private = _private(tmp_path / "private")
    fifo = private / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(report.RestrictedReportError):
        report._read_private_input(str(fifo))

    alias = private / "alias"
    alias.symlink_to(fifo)
    with pytest.raises(report.RestrictedReportError):
        report._read_private_input(str(alias))

    with _short_private_socket_dir() as (_socket_dir, sock_path):
        server = socket.socket(socket.AF_UNIX)
        try:
            _bind_test_socket(server, sock_path)
            with pytest.raises(report.RestrictedReportError):
                report._read_private_input(str(sock_path))
        finally:
            server.close()
            sock_path.unlink(missing_ok=True)

    with pytest.raises(report.RestrictedReportError):
        report._read_private_input("/dev/null")


def test_output_fifo_and_input_path_component_symlink_reject_without_audit(tmp_path):
    private = _private(tmp_path / "private")
    source = _input(private)
    alias_dir = tmp_path / "alias-dir"
    alias_dir.symlink_to(private, target_is_directory=True)
    with pytest.raises(report.RestrictedReportError):
        report._read_private_input(str(alias_dir / source.name))

    fifo_target = private / "fifo.json"
    os.mkfifo(fifo_target, 0o600)
    with pytest.raises(report.RestrictedReportError):
        report.export_report("application", str(source), str(fifo_target), approval_reader=lambda: APPROVAL)
    assert stat.S_ISFIFO(fifo_target.stat().st_mode)
    assert not (private / report.AUDIT_NAME).exists()


def test_output_socket_is_rejected_without_blocking_or_creating_audit(tmp_path):
    private = _private(tmp_path / "private-socket")
    source = _input(private)
    with _short_private_socket_dir() as (short_root, target):
        server = socket.socket(socket.AF_UNIX)
        try:
            _bind_test_socket(server, target)
            with pytest.raises(report.RestrictedReportError):
                report.export_report("application", str(source), str(target), approval_reader=lambda: APPROVAL)
            assert stat.S_ISSOCK(target.lstat().st_mode)
            assert not (short_root / report.AUDIT_NAME).exists()
        finally:
            server.close()
            target.unlink(missing_ok=True)


def test_owner_mismatch_and_invalid_identifier_projection_fail_closed(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    real_euid = os.geteuid
    monkeypatch.setattr(report.os, "geteuid", lambda: real_euid() + 1000)
    with pytest.raises(report.RestrictedReportError):
        report._open_private_directory(private)
    monkeypatch.undo()

    parsed = report._parse_lines(LINE, "application")
    value = report._build_report("application", parsed)
    value["subjects"][0]["identifiers"][0] = {"kind": "ipv4", "value": "not-an-ip"}
    with pytest.raises(report.RestrictedReportError):
        report._validate_report(value)


def test_input_identity_and_length_change_during_read_fail_closed(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    source = _input(private)
    real_read = report.os.read
    changed = False

    def mutate_after_first_read(fd, count):
        nonlocal changed
        result = real_read(fd, count)
        if result and not changed:
            changed = True
            source.write_bytes(LINE + b"2026-09-11 10:00:02 INFO login_failed user=second ip=192.0.2.58\n")
            source.chmod(0o600)
        return result

    monkeypatch.setattr(report.os, "read", mutate_after_first_read)
    with pytest.raises(report.RestrictedReportError):
        report._read_private_input(str(source))
    assert changed


def test_input_byte_and_line_count_limits_reject_without_truncation(tmp_path):
    private = _private(tmp_path / "private")
    source = private / "input.log"
    source.write_bytes(b"x" * report.MAX_INPUT_BYTES)
    source.chmod(0o600)
    data, _ = report._read_private_input(str(source))
    assert len(data) == report.MAX_INPUT_BYTES
    source.write_bytes(b"x" * (report.MAX_INPUT_BYTES + 1))
    source.chmod(0o600)
    with pytest.raises(report.RestrictedReportError):
        report._read_private_input(str(source))

    exact = (LINE * report.MAX_LINES)
    events = report._parse_lines(exact, "application")
    assert len(events) == report.MAX_LINES
    with pytest.raises(report.RestrictedReportError):
        report._parse_lines(exact + LINE, "application")


def test_temp_close_and_cleanup_unlink_faults_never_report_success(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    fd = _dirfd(private)
    try:
        real_close = report.os.close
        failed = False

        def fail_temp_close(target_fd):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError(errno.EIO, "close-canary")
            return real_close(target_fd)

        monkeypatch.setattr(report.os, "close", fail_temp_close)
        with pytest.raises(report.RestrictedReportError):
            report._atomic_publish(fd, "close.json", b"{}\n")
        assert failed and not (private / "close.json").exists()
        assert not list(private.glob(".restricted-*.tmp"))
    finally:
        os.close(fd)

    private2 = _private(tmp_path / "private-unlink")
    fd2 = _dirfd(private2)
    try:
        real_unlink = report.os.unlink

        def fail_first_temp_unlink(name, *args, **kwargs):
            if isinstance(name, str) and name.startswith(".restricted-"):
                monkeypatch.setattr(report.os, "unlink", real_unlink)
                raise OSError(errno.EIO, "unlink-canary")
            return real_unlink(name, *args, **kwargs)

        monkeypatch.setattr(report.os, "unlink", fail_first_temp_unlink)
        with pytest.raises(report.RestrictedReportError):
            report._atomic_publish(fd2, "unlink.json", b"{}\n")
        assert not (private2 / "unlink.json").exists()
        assert not list(private2.glob(".restricted-*.tmp"))
    finally:
        os.close(fd2)


def test_lenient_umask_still_produces_private_report_and_audit(tmp_path):
    private = _private(tmp_path / "private")
    source = _input(private)
    output = private / "report.json"
    process = __import__("subprocess").run(
        [os.sys.executable, "-m", "app.restricted_report", "--source-role", "application",
         "--input", str(source), "--output", str(output)],
        input=APPROVAL + "\n", text=True, capture_output=True, check=False,
        env={"HOME": str(_private(tmp_path / "home")), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
             "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        preexec_fn=lambda: os.umask(0),
    )
    assert process.returncode == 0
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE((private / report.AUDIT_NAME).stat().st_mode) == 0o600


def test_audit_row_limit_rejects_next_event_without_mutating_existing_rows(tmp_path):
    private = _private(tmp_path / "private")
    fd = _dirfd(private)
    try:
        for index in range(report.MAX_AUDIT_EVENTS):
            report._audit_append(fd, _record(report_id=f"{index:032x}"))
        path = private / report.AUDIT_NAME
        before = path.read_bytes()
        assert len(before) <= report.MAX_AUDIT_BYTES
        with pytest.raises(report.RestrictedReportError):
            report._audit_append(fd, _record(report_id="f" * 32))
        assert path.read_bytes() == before
    finally:
        os.close(fd)


def test_oversized_audit_file_is_rejected_without_reading_or_mutating(tmp_path):
    private = _private(tmp_path / "private-oversized-audit")
    path = private / report.AUDIT_NAME
    path.write_bytes(b"x" * (report.MAX_AUDIT_BYTES + 1))
    path.chmod(0o600)
    before = path.read_bytes()
    fd = _dirfd(private)
    try:
        with pytest.raises(report.RestrictedReportError):
            report._audit_append(fd, _record())
        assert path.read_bytes() == before
    finally:
        os.close(fd)


def test_output_bound_rejects_oversize_closed_projection(monkeypatch):
    sample = "2026-09-11 10:00:01 INFO login_failed user=bounded ip=192.0.2.57\n"
    value = report._build_report("application", report._parse_lines(sample.encode(), "application"))
    value["observations"] = [{"type": "x" * (report.MAX_OUTPUT_BYTES + 1), "count": 1}]
    with pytest.raises(report.RestrictedReportError):
        report._validate_report(value)

    value = report._build_report("application", report._parse_lines(sample.encode(), "application"))
    exact_size = len(report._canonical_json(value))
    monkeypatch.setattr(report, "MAX_OUTPUT_BYTES", exact_size)
    report._validate_report(value)
    monkeypatch.setattr(report, "MAX_OUTPUT_BYTES", exact_size - 1)
    with pytest.raises(report.RestrictedReportError):
        report._validate_report(value)


def test_canonical_json_rejects_nonfinite_and_invalid_unicode():
    for value in ({"value": float("nan")}, {"value": float("inf")}, {"value": "\ud800"}):
        with pytest.raises(report.RestrictedReportError):
            report._canonical_json(value)


def test_unknown_filesystem_is_rejected_without_disclosing_mount_path(tmp_path, monkeypatch):
    private = _private(tmp_path / "private")
    target = str(private.resolve())
    mount_line = f"1 0 0:1 / {target} rw - nfs4 server:/export rw"
    real_read_text = Path.read_text

    def fake_read_text(path, *args, **kwargs):
        if str(path) == "/proc/self/mountinfo":
            return mount_line
        return real_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    monkeypatch.setattr(report.sys, "platform", "linux")
    with pytest.raises(report.RestrictedReportError) as failure:
        report._check_local_filesystem(private)
    assert str(private) not in str(failure.value)
