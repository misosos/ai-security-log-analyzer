"""Process-level synthetic smoke for the TCP Syslog management CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.getcwd())
from app import tcp_syslog_management as management  # noqa: E402


PYTHON = sys.executable
SAVE_APPROVAL = "TCP Syslog 설정 저장을 승인합니다"
REVEAL_APPROVAL = "로컬 TCP 연결 정보를 표시합니다"
DELETE_APPROVAL = "TCP Syslog 설정 삭제를 승인합니다"


def _free_high_port() -> int:
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port >= 49152:
            return port
    raise RuntimeError("port")


def _command(flag: str) -> list[str]:
    return [PYTHON, "-u", "-m", "app.monitor_setup", flag]


def _run(role: str, signum: int) -> None:
    stage = "sandbox"
    with tempfile.TemporaryDirectory(prefix="tcp-management-34-4-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        home = root / "home"
        home.mkdir(mode=0o700)
        env = {
            "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
            "PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.getcwd(),
            "PYTHONNOUSERSITE": "1", "TZ": "UTC",
        }
        port = _free_high_port()
        stage = "setup"
        setup = subprocess.run(_command("--setup-tcp-syslog"), input=f"{1 if role == 'application' else 2}\n1\n{port}\n{SAVE_APPROVAL}\n",
                               text=True, capture_output=True, env=env, timeout=15)
        if setup.returncode != 0 or setup.stderr or str(port) in setup.stdout:
            raise RuntimeError("setup")
        if sys.platform == "darwin":
            config_parent = home / "Library" / "Application Support" / "ai-security-log-analyzer"
        else:
            config_parent = home / ".config" / "ai-security-log-analyzer"
        config_path = config_parent / "tcp-syslog.json"
        data = json.loads(config_path.read_text(encoding="utf-8"))
        if data["source_role"] != role or config_path.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError("config")
        if config_path.parent.stat().st_mode & 0o777 != 0o700:
            raise RuntimeError("parent")
        stage = "show"
        shown = subprocess.run(_command("--show-tcp-syslog"), text=True, capture_output=True,
                               env=env, timeout=5)
        if (shown.returncode != 0 or str(port) in shown.stdout or str(config_path) in shown.stdout
                or shown.stderr):
            raise RuntimeError("show")

        stage = "runtime"
        child = subprocess.Popen(_command("--run-tcp-syslog"), text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 10
            lines: list[str] = []
            ready = False
            while time.monotonic() < deadline and child.poll() is None:
                readable, _, _ = select.select([child.stdout], [], [], 0.2)
                if readable:
                    line = child.stdout.readline()
                    lines.append(line)
                    if "현재 상태: 수집 중" in line:
                        ready = True
                        break
            if not ready:
                raise RuntimeError("readiness")
            stage = "second-run"
            second = subprocess.run(_command("--run-tcp-syslog"), text=True, capture_output=True,
                                    env=env, timeout=5)
            if second.returncode != 4 or str(port) in second.stdout or second.stderr:
                raise RuntimeError("single-run-lock")
            stage = "setup-while-running"
            blocked_setup = subprocess.run(_command("--setup-tcp-syslog"), input="1\n1\n55001\n",
                                           text=True, capture_output=True, env=env, timeout=5)
            if blocked_setup.returncode != 4 or str(port) in blocked_setup.stdout or blocked_setup.stderr:
                raise RuntimeError(stage)
            stage = "delete-while-running"
            blocked_delete = subprocess.run(_command("--delete-tcp-syslog"),
                                            input=f"{DELETE_APPROVAL}\n", text=True,
                                            capture_output=True, env=env, timeout=5)
            if blocked_delete.returncode != 4 or not config_path.exists() or blocked_delete.stderr:
                raise RuntimeError(stage)
            stage = "reveal-cancel"
            declined = subprocess.run(_command("--reveal-tcp-syslog-endpoint"), input="취소\n",
                                     text=True, capture_output=True, env=env, timeout=5)
            if declined.returncode != 0 or str(port) in declined.stdout:
                raise RuntimeError(stage)
            stage = "reveal"
            reveal = subprocess.run(_command("--reveal-tcp-syslog-endpoint"),
                                    input=f"{REVEAL_APPROVAL}\n", text=True,
                                    capture_output=True, env=env, timeout=5)
            if reveal.returncode != 0 or f"127.0.0.1:{port}" not in reveal.stdout:
                active_lock = management._tcp_lock_is_held(config_path)
                stage = (f"reveal-{reveal.returncode}-{int('로컬 연결 주소:' in reveal.stdout)}-"
                         f"{int('표시를 취소했습니다' in reveal.stdout)}-{int('[::1]' in reveal.stdout)}-"
                         f"{int(active_lock)}-{int(REVEAL_APPROVAL in reveal.stdout)}")
                raise RuntimeError(stage)
            stage = "frame"
            if role == "application":
                message = b"2026-01-02 03:04:05 INFO login_failed user=synthetic_account ip=192.0.2.88 service=ssh"
            else:
                message = b"2026-01-02 03:04:05 sshd: Failed password for synthetic_account from 198.51.100.88 port 45001 ssh2"
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                connection.sendall(str(len(message)).encode("ascii") + b" " + message)
            # The CLI emits bounded summaries at a fixed cadence; wait without logging payload data.
            deadline = time.monotonic() + 7
            while time.monotonic() < deadline:
                readable, _, _ = select.select([child.stdout], [], [], 0.2)
                if readable:
                    line = child.stdout.readline()
                    lines.append(line)
                    if "분석 완료 1" in line:
                        break
            stage = "shutdown"
            child.send_signal(signum)
            stdout_tail, stderr = child.communicate(timeout=10)
            stdout = "".join(lines) + stdout_tail
            canaries = ("synthetic_account", "192.0.2.88", "198.51.100.88", str(config_path), str(port))
            if (child.returncode != 0 or stderr or any(value in stdout for value in canaries)
                    or "분석 완료 1" not in stdout or "수집을 종료했습니다" not in stdout):
                raise RuntimeError("runtime-output")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", port))

        except Exception:
            if child.poll() is None:
                child.kill()
                child.communicate()
            raise RuntimeError(stage) from None

        stage = "restart"
        restarted = subprocess.Popen(_command("--run-tcp-syslog"), text=True, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env)
        try:
            deadline = time.monotonic() + 10
            restart_lines: list[str] = []
            ready = False
            while time.monotonic() < deadline and restarted.poll() is None:
                readable, _, _ = select.select([restarted.stdout], [], [], 0.2)
                if readable:
                    line = restarted.stdout.readline()
                    restart_lines.append(line)
                    if "현재 상태: 수집 중" in line:
                        ready = True
                        break
            if not ready:
                raise RuntimeError("restart-readiness")
            restarted.send_signal(signal.SIGTERM)
            tail, error = restarted.communicate(timeout=10)
            restart_output = "".join(restart_lines) + tail
            if (restarted.returncode != 0 or error or "분석 완료 0" not in restart_output
                    or str(port) in restart_output or str(config_path) in restart_output):
                raise RuntimeError("restart-state")
        except Exception:
            if restarted.poll() is None:
                restarted.kill()
                restarted.communicate()
            raise RuntimeError("restart") from None

        stage = "delete"
        preserved = config_path.parent / "monitoring.json"
        checkpoint = config_path.parent / "checkpoint-source-000001.json"
        preserved.write_text("synthetic-file-config", encoding="utf-8")
        checkpoint.write_text("synthetic-checkpoint", encoding="utf-8")
        cancelled = subprocess.run(_command("--delete-tcp-syslog"), input="취소\n", text=True,
                                   capture_output=True, env=env, timeout=5)
        if cancelled.returncode != 0 or not config_path.exists():
            raise RuntimeError("delete-cancel")
        deleted = subprocess.run(_command("--delete-tcp-syslog"), input=f"{DELETE_APPROVAL}\n",
                                 text=True, capture_output=True, env=env, timeout=5)
        if (deleted.returncode != 0 or config_path.exists() or not preserved.exists()
                or not checkpoint.exists()):
            raise RuntimeError("delete")


def main() -> int:
    for role, signum in (("application", signal.SIGINT), ("ssh", signal.SIGTERM)):
        try:
            _run(role, signum)
        except Exception as error:
            stage = str(error) if (str(error) in {"sandbox", "setup", "show", "runtime", "second-run",
                                                  "reveal", "frame", "shutdown", "delete", "config", "parent",
                                                  "setup-while-running", "delete-while-running", "reveal-cancel",
                                                  "restart", "restart-readiness", "restart-state"}
                                   or str(error).startswith("reveal-")) else "harness"
            print(f"TCP_SYSLOG_MANAGEMENT_SMOKE_FAILED role={role} stage={stage}", file=sys.stderr)
            return 1
    print("TCP_SYSLOG_MANAGEMENT_SMOKE_PASS roles=2 synthetic=1 leaks=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
