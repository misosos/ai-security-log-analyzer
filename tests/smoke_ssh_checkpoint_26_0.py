"""Foreground CLI smoke with only synthetic SSH and a temporary user home."""

import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]


def _line(second: int, outcome: str = "Failed") -> str:
    return (f"2026-01-02 03:04:{second:02d} sshd: {outcome} password "
            "for SYNTHETIC_ACCOUNT from 192.0.2.33 port 5001 ssh2\n")


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def _status(port: int) -> dict:
    with urlopen(f"http://127.0.0.1:{port}/api/v1/live/status", timeout=1) as response:
        assert response.status == 200
        return json.loads(response.read(8192))


def _wait(port: int, predicate, seconds: float = 12.0) -> dict:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            status = _status(port)
            if predicate(status):
                return status
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("SMOKE_STATUS_TIMEOUT")


def _start(port: int, env: dict, stdout: Path, stderr: Path) -> subprocess.Popen:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(
            [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
             "--port", str(port)], cwd=ROOT, env=env, stdout=out, stderr=err,
            start_new_session=True,
        )
    try:
        _wait(port, lambda status: status["source_role"] == "ssh")
    except Exception:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
        codes = re.findall(r"\b(?:CHECKPOINT|LIVE_RUNTIME|DEFAULT_CONFIG|LOCAL_WEB)_[A-Z_]+\b",
                           stderr.read_text(encoding="utf-8", errors="replace"))
        raise RuntimeError("SMOKE_SERVER_START_FAILED:" + (codes[-1] if codes else "NO_FIXED_CODE")) from None
    return process


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    process.wait(timeout=12)
    assert process.returncode == 0


def _no_listener(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0


def main() -> None:
    process = None
    scratch = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    with TemporaryDirectory(prefix="ssh-checkpoint-cli-", dir=scratch) as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)
        source = root / "synthetic-ssh.log"
        source.write_text(_line(0), encoding="utf-8")
        config = home / "Library/Application Support/ai-security-log-analyzer/monitoring.json"
        config.parent.mkdir(parents=True, mode=0o700)
        config.parent.chmod(0o700)
        document = {"schema_version": "2", "sources": [{
            "source_id": "SOURCE-000001", "source_role": "ssh", "source_path": str(source),
            "display_alias": "SSH 로그 1", "enabled": True, "start_position": "FROM_END",
            "parser_timezone": "Asia/Seoul", "checkpoint_policy": "BOUNDED_REPLAY_V1",
            "rotation_policy": "FAIL_CLOSED",
        }]}
        config.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        config.chmod(0o600)
        env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(root)}
        port = _port()
        try:
            process = _start(port, env, root / "stdout.log", root / "stderr.log")
            first = _status(port)
            assert first["latest_detection_revision"] == 0
            with source.open("a", encoding="utf-8") as stream:
                stream.writelines(_line(index) for index in range(1, 6))
            _wait(port, lambda status: status["latest_detection_revision"] >= 1)
            _stop(process)
            process = None
            _no_listener(port)
            with source.open("a", encoding="utf-8") as stream:
                stream.write(_line(6, "Accepted"))
            port = _port()
            process = _start(port, env, root / "stdout2.log", root / "stderr2.log")
            recovered = _wait(port, lambda status: status["active_case_count"] >= 1)
            assert recovered["active_relation_count"] == 2
            _stop(process)
            process = None
            _no_listener(port)
            show = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--show"],
                                  cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
            assert show.returncode == 0 and "ssh" in show.stdout
            reset = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
                                   cwd=ROOT, env=env, input="yes\n", capture_output=True,
                                   text=True, timeout=10)
            assert reset.returncode == 0
            assert not (config.parent / "checkpoint-source-000001.json").exists()
            port = _port()
            process = _start(port, env, root / "stdout3.log", root / "stderr3.log")
            fresh = _status(port)
            assert fresh["latest_detection_revision"] == 0
            assert fresh["active_relation_count"] == fresh["active_case_count"] == 0
            _stop(process)
            process = None
            _no_listener(port)
            assert source.exists() and config.exists()
            assert not any(canary in show.stdout + show.stderr + reset.stdout + reset.stderr
                           for canary in (str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33"))
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
    print("SSH_CHECKPOINT_CLI_SMOKE_PASS restart_reset_fresh_epoch_cleanup")


if __name__ == "__main__":
    main()
