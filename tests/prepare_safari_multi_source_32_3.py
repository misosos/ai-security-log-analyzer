"""Start/stop a disposable synthetic server for manual Safari acceptance."""

import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

from app.monitor_setup import create_monitor_pair_config

ROOT = Path(__file__).resolve().parents[1]
STATE = Path(tempfile.gettempdir()).resolve() / "multi-source-safari-32-3-state.json"


def start() -> None:
    if STATE.exists() or STATE.is_symlink():
        raise SystemExit("SAFARI_TEST_ALREADY_PREPARED")
    directory = Path(tempfile.mkdtemp(prefix="multi-source-safari-32-3-",
                                     dir=Path(tempfile.gettempdir()).resolve()))
    os.chmod(directory, 0o700)
    app, ssh = directory / "application.log", directory / "ssh.log"
    app.write_text("2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n", encoding="utf-8")
    ssh.write_text("2026-01-02 03:04:05 sshd: Failed password for synthetic from 198.51.100.23 port 5001 ssh2\n",
                   encoding="utf-8")
    config = directory / "private" / "monitoring.json"
    create_monitor_pair_config(app, ssh, config)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, "-m", "app.local_web", "--monitor-config", str(config),
         "--no-browser", "--port", str(port)],
        cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    origin = f"http://127.0.0.1:{port}"
    for _ in range(200):
        if process.poll() is not None:
            shutil.rmtree(directory)
            raise SystemExit("SAFARI_TEST_START_FAILED")
        try:
            with urlopen(origin + "/api/health", timeout=0.2) as response:
                if response.status == 200:
                    break
        except Exception:
            time.sleep(0.05)
    else:
        process.send_signal(signal.SIGINT)
        shutil.rmtree(directory)
        raise SystemExit("SAFARI_TEST_START_TIMEOUT")
    payload = json.dumps({"pid": process.pid, "port": port, "directory": str(directory)}).encode()
    descriptor = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    print(f"Synthetic Safari acceptance server ready: {origin}/")
    print("Stop with: PYTHONPATH=. uv run python tests/prepare_safari_multi_source_32_3.py --stop")


def stop() -> None:
    if STATE.is_symlink() or not STATE.is_file():
        raise SystemExit("SAFARI_TEST_NOT_PREPARED")
    value = json.loads(STATE.read_text(encoding="utf-8"))
    pid, port = value.get("pid"), value.get("port")
    directory = Path(value.get("directory", ""))
    expected_parent = Path(tempfile.gettempdir()).resolve()
    if (type(pid) is not int or type(port) is not int or not directory.is_absolute()
        or directory.parent != expected_parent or not directory.name.startswith("multi-source-safari-32-3-")):
        raise SystemExit("SAFARI_TEST_STATE_INVALID")
    try:
        os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}/api/health", timeout=0.2):
                time.sleep(0.05)
        except Exception:
            break
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        os.kill(pid, signal.SIGTERM)
    shutil.rmtree(directory)
    STATE.unlink()
    print("Synthetic Safari acceptance server stopped and temporary files removed.")


if __name__ == "__main__":
    if sys.argv[1:] == ["--stop"]:
        stop()
    elif not sys.argv[1:]:
        start()
    else:
        raise SystemExit("SAFARI_TEST_INVALID_ARGUMENT")
