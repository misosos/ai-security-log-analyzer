"""Separate-process synthetic loopback smoke; never reads user logs or settings."""

from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


def _line(role: str, second: int, failed: bool = True) -> bytes:
    if role == "application":
        action = "login_failed" if failed else "user_login"
        value = f"2026-01-02 03:04:{second:02d} INFO {action} user=synthetic_user ip=192.0.2.19 service=ssh"
    else:
        action = "Failed" if failed else "Accepted"
        value = (f"2026-01-02 03:04:{second:02d} sshd: {action} password for synthetic_user "
                 "from 198.51.100.29 port 45001 ssh2")
    payload = value.encode("utf-8")
    return str(len(payload)).encode("ascii") + b" " + payload


_FAILURE_STAGES = {
    "CHILD_START", "LISTENER_READY", "FRAME_SENT", "ANALYSIS_CONFIRMED",
    "SIGNAL_SENT", "PROCESS_EXIT", "LISTENER_RELEASED", "PORT_REUSED",
    "TEMP_CLEANUP",
}
_FAILURE_CATEGORIES = {
    "CHILD_START_FAILED", "READINESS_TIMEOUT", "CHILD_EXITED_EARLY",
    "READINESS_MARKER_INVALID",
    "CONNECT_REFUSED", "CONNECT_TIMEOUT", "CONNECT_LOCAL_RESOURCE",
    "CONNECTION_FAILED", "FRAME_SEND_FAILED", "ANALYSIS_TIMEOUT",
    "SIGNAL_FAILED", "PROCESS_TIMEOUT", "EXIT_NONZERO",
    "OUTPUT_CONTRACT_MISMATCH", "LISTENER_STILL_BOUND", "TEMP_CLEANUP_FAILED",
    "INTERNAL_FAILURE",
}
_child_stage = "CHILD_START"


def _write_private_marker(path: Path, value: str) -> None:
    """Publish a complete 0600 marker atomically inside the private smoke directory."""
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        encoded = value.encode("ascii")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_ready_port(path: Path) -> int:
    try:
        value = path.read_text(encoding="ascii")
        if not value or not value.isascii() or not value.isdecimal():
            raise ValueError
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except Exception:
        raise SmokeFailure("LISTENER_READY", "READINESS_MARKER_INVALID") from None


class SmokeFailure(Exception):
    """Failure with only a fixed stage/category; never retains subprocess output."""

    def __init__(self, stage: str, category: str, child_stage: str | None = None,
                 child_category: str | None = None):
        self.stage = stage if stage in _FAILURE_STAGES else "CHILD_START"
        self.category = category if category in _FAILURE_CATEGORIES else "INTERNAL_FAILURE"
        self.child_stage = child_stage if child_stage in _FAILURE_STAGES else None
        self.child_category = child_category if child_category == "CHILD_RUNTIME_FAILURE" else None
        super().__init__(self.category)

    def __repr__(self) -> str:
        return (f"SmokeFailure(stage={self.stage!r}, category={self.category!r}, "
                f"child_stage={self.child_stage!r}, child_category={self.child_category!r})")


def _child_diagnostic(process: subprocess.Popen[str]) -> tuple[str | None, str | None]:
    """Extract only an allowlisted marker; discard all other child output."""
    if process.poll() is None:
        return None, None
    try:
        _stdout, stderr = process.communicate(timeout=1)
    except Exception:
        return None, None
    pattern = re.compile(
        r"^TCP_SYSLOG_CHILD_FAILURE role=(?:application|ssh) "
        r"stage=([A-Z_]+) category=(CHILD_RUNTIME_FAILURE)$"
    )
    for line in stderr.splitlines():
        match = pattern.fullmatch(line)
        if match and match.group(1) in _FAILURE_STAGES:
            return match.group(1), match.group(2)
    return None, None


def _connect_failure_category(exc: Exception) -> str:
    """Map socket failures to fixed categories without exposing exception text."""
    if isinstance(exc, TimeoutError):
        return "CONNECT_TIMEOUT"
    if isinstance(exc, OSError):
        if exc.errno == errno.ECONNREFUSED:
            return "CONNECT_REFUSED"
        if exc.errno in {errno.EADDRNOTAVAIL, errno.EMFILE, errno.ENFILE, errno.ENOBUFS,
                         errno.ENOMEM, errno.EACCES, errno.EPERM}:
            return "CONNECT_LOCAL_RESOURCE"
    return "CONNECTION_FAILED"


async def _child(role: str, ready_path: Path, settled_path: Path) -> int:
    global _child_stage
    _child_stage = "CHILD_START"
    from app.log_collection.runtime import TcpRuntimeConfig, TcpSyslogRuntime

    runtime = TcpSyslogRuntime(TcpRuntimeConfig(
        schema_version="tcp-syslog-runtime/v1", source_role=role, bind_family="ipv4",
        port=0, connection_limit=2, idle_timeout_seconds=10.0,
        read_timeout_seconds=2.0, parser_timezone="Asia/Seoul",
        startup_mode="synthetic_pilot", test_only_ephemeral_port=True,
    ))
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopping.set)
    await runtime.start()
    _child_stage = "LISTENER_READY"
    port = runtime._server.sockets[0].getsockname()[1]
    _write_private_marker(ready_path, str(port))
    _child_stage = "FRAME_SENT"
    await runtime.wait_until_processed(7, timeout=15.0)
    _child_stage = "ANALYSIS_CONFIRMED"
    summary = runtime.internal_analysis_summary()
    if summary.revision != 7 or summary.case_count < 1:
        await runtime.stop()
        raise RuntimeError
    _write_private_marker(settled_path, "settled")
    await stopping.wait()
    _child_stage = "SIGNAL_SENT"
    snapshot = runtime.snapshot()
    await runtime.stop()
    _child_stage = "PROCESS_EXIT"
    if snapshot.accepted_frames != 7 or snapshot.parsed_events != 6 or snapshot.parser_rejected_events != 1:
        raise RuntimeError
    print(f"TCP_SYSLOG_PROCESS_COMPLETE role={role} accepted=7 parsed=6 analyzed=7 rejected=0")
    return 0


def _parent_run(role: str, signum: int) -> None:
    if role not in {"application", "ssh"} or signum not in {signal.SIGINT, signal.SIGTERM}:
        raise SmokeFailure("CHILD_START", "INTERNAL_FAILURE")
    signame = "SIGINT" if signum == signal.SIGINT else "SIGTERM"
    stage = "CHILD_START"
    failure: SmokeFailure | None = None
    process: subprocess.Popen[str] | None = None
    try:
        temporary = tempfile.TemporaryDirectory(prefix="tcp-syslog-34-2-")
    except Exception:
        failure = SmokeFailure("CHILD_START", "CHILD_START_FAILED")
        print(
            f"TCP_SYSLOG_SMOKE_FAILURE role={role} signal={signame} "
            f"stage={failure.stage} category={failure.category}",
            file=sys.stderr,
        )
        raise failure from None
    try:
        root = Path(temporary.name)
        os.chmod(root, 0o700)
        home = root / "home"
        home.mkdir(mode=0o700)
        ready, settled = root / "ready", root / "settled"
        env = {
            "HOME": str(home),
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.getcwd(),
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        }
        command = [sys.executable, __file__, "--child", role, str(ready), str(settled)]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env)
        except Exception:
            raise SmokeFailure("CHILD_START", "CHILD_START_FAILED") from None

        deadline = time.monotonic() + 15
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not ready.exists():
            category = "CHILD_EXITED_EARLY" if process.poll() is not None else "READINESS_TIMEOUT"
            raise SmokeFailure("LISTENER_READY", category)
        stage = "LISTENER_READY"
        if process.poll() is not None:
            child_stage, child_category = _child_diagnostic(process)
            raise SmokeFailure("LISTENER_READY", "CHILD_EXITED_EARLY", child_stage, child_category)
        port = _read_ready_port(ready)
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        except Exception as exc:
            child_stage, child_category = _child_diagnostic(process)
            category = ("CHILD_EXITED_EARLY" if process.poll() is not None
                        else _connect_failure_category(exc))
            raise SmokeFailure("LISTENER_READY", category, child_stage, child_category) from None
        try:
            stage = "FRAME_SENT"
            frames = [_line(role, second) for second in range(1, 6)] + [_line(role, 6, False)]
            connection.sendall(frames[0][:5])
            connection.sendall(frames[0][5:] + b"".join(frames[1:]))
            invalid = b"not a valid role record"
            connection.sendall(str(len(invalid)).encode() + b" " + invalid)
        except Exception:
            raise SmokeFailure("FRAME_SENT", "FRAME_SEND_FAILED") from None
        finally:
            connection.close()
        deadline = time.monotonic() + 15
        while not settled.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not settled.exists():
            category = "CHILD_EXITED_EARLY" if process.poll() is not None else "ANALYSIS_TIMEOUT"
            raise SmokeFailure("ANALYSIS_CONFIRMED", category)
        stage = "ANALYSIS_CONFIRMED"
        try:
            process.send_signal(signum)
        except Exception:
            raise SmokeFailure("SIGNAL_SENT", "SIGNAL_FAILED") from None
        stage = "SIGNAL_SENT"
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            raise SmokeFailure("PROCESS_EXIT", "PROCESS_TIMEOUT") from None
        stage = "PROCESS_EXIT"
        expected = f"TCP_SYSLOG_PROCESS_COMPLETE role={role} accepted=7 parsed=6 analyzed=7 rejected=0\n"
        if process.returncode != 0:
            raise SmokeFailure("PROCESS_EXIT", "EXIT_NONZERO")
        if stdout != expected or stderr:
            raise SmokeFailure("PROCESS_EXIT", "OUTPUT_CONTRACT_MISMATCH")
        stage = "LISTENER_RELEASED"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))
        except Exception:
            raise SmokeFailure("PORT_REUSED", "LISTENER_STILL_BOUND") from None
        stage = "PORT_REUSED"
    except SmokeFailure as exc:
        failure = exc
    except Exception:
        failure = SmokeFailure(stage, "INTERNAL_FAILURE")
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    failure = failure or SmokeFailure("PROCESS_EXIT", "PROCESS_TIMEOUT")
            try:
                # Drain and close both pipes even when the child exited before readiness.
                process.communicate(timeout=5)
            except Exception:
                failure = failure or SmokeFailure("PROCESS_EXIT", "PROCESS_TIMEOUT")
        try:
            temporary.cleanup()
        except Exception:
            failure = failure or SmokeFailure("TEMP_CLEANUP", "TEMP_CLEANUP_FAILED")
        if Path(temporary.name).exists():
            failure = failure or SmokeFailure("TEMP_CLEANUP", "TEMP_CLEANUP_FAILED")
    if failure is not None:
        diagnostic = (
            f"TCP_SYSLOG_SMOKE_FAILURE role={role} signal={signame} "
            f"stage={failure.stage} category={failure.category}"
        )
        if failure.child_stage is not None:
            diagnostic += (f" child_stage={failure.child_stage} "
                           f"child_category={failure.child_category}")
        print(diagnostic, file=sys.stderr)
        raise failure from None


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        role = sys.argv[2]
        try:
            return asyncio.run(_child(role, Path(sys.argv[3]), Path(sys.argv[4])))
        except Exception:
            stage = _child_stage if _child_stage in _FAILURE_STAGES else "CHILD_START"
            print(
                f"TCP_SYSLOG_CHILD_FAILURE role={role if role in {'application', 'ssh'} else 'unknown'} "
                f"stage={stage} category=CHILD_RUNTIME_FAILURE",
                file=sys.stderr,
            )
            return 70
    try:
        _parent_run("application", signal.SIGINT)
        _parent_run("application", signal.SIGTERM)
        _parent_run("ssh", signal.SIGINT)
        _parent_run("ssh", signal.SIGTERM)
    except SmokeFailure:
        return 1
    print("TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
