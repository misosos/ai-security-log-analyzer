"""Separate-process synthetic loopback smoke; never reads user logs or settings."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
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


async def _child(role: str, ready_path: Path, settled_path: Path) -> int:
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
    port = runtime._server.sockets[0].getsockname()[1]
    ready_path.write_text(str(port), encoding="ascii")
    os.chmod(ready_path, 0o600)
    await runtime.wait_until_processed(7, timeout=15.0)
    summary = runtime.internal_analysis_summary()
    if summary.revision != 7 or summary.case_count < 1:
        await runtime.stop()
        return 3
    settled_path.write_text("settled", encoding="ascii")
    os.chmod(settled_path, 0o600)
    await stopping.wait()
    snapshot = runtime.snapshot()
    await runtime.stop()
    if snapshot.accepted_frames != 7 or snapshot.parsed_events != 6 or snapshot.parser_rejected_events != 1:
        return 4
    print(f"TCP_SYSLOG_PROCESS_COMPLETE role={role} accepted=7 parsed=6 analyzed=7 rejected=0")
    return 0


def _parent_run(role: str, signum: int) -> None:
    with tempfile.TemporaryDirectory(prefix="tcp-syslog-34-2-") as parent:
        root = Path(parent)
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
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
        try:
            deadline = time.monotonic() + 15
            while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not ready.exists():
                raise RuntimeError("synthetic runtime readiness failed")
            port = int(ready.read_text(encoding="ascii"))
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                # Partial frame followed by a batch of wire-ordered frames.
                frames = [_line(role, second) for second in range(1, 6)] + [_line(role, 6, False)]
                connection.sendall(frames[0][:5])
                connection.sendall(frames[0][5:] + b"".join(frames[1:]))
                invalid = b"not a valid role record"
                connection.sendall(str(len(invalid)).encode() + b" " + invalid)
            while not settled.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if not settled.exists():
                raise RuntimeError("synthetic processing did not settle")
            process.send_signal(signum)
            stdout, stderr = process.communicate(timeout=10)
            expected = f"TCP_SYSLOG_PROCESS_COMPLETE role={role} accepted=7 parsed=6 analyzed=7 rejected=0\n"
            if process.returncode != 0 or stdout != expected or stderr:
                raise RuntimeError("synthetic subprocess contract failed")
            # Verify that the listener has released the selected loopback port.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))
        except Exception:
            if process.poll() is None:
                process.kill()
                process.communicate()
            raise RuntimeError("synthetic subprocess smoke failed") from None


def main() -> int:
    if len(sys.argv) == 5 and sys.argv[1] == "--child":
        return asyncio.run(_child(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])))
    _parent_run("application", signal.SIGINT)
    _parent_run("application", signal.SIGTERM)
    _parent_run("ssh", signal.SIGINT)
    _parent_run("ssh", signal.SIGTERM)
    print("TCP_SYSLOG_SMOKE_COMPLETE roles=2 subprocesses=4 synthetic=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
