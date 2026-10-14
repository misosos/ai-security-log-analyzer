"""OS-temporary CLI → v2 loader → actual loopback runtime smoke."""

from http.client import HTTPConnection
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

from app.live_monitoring.config import resolve_default_monitor_config_path


APP_LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1\n"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _get_json(port: int, path: str) -> tuple[int, dict]:
    connection = HTTPConnection("127.0.0.1", port, timeout=0.5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_cli_created_v2_config_runs_in_existing_local_web(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    output = tmp_path / "private" / "monitor.json"
    setup = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup", "--output", str(output), "--no-color"],
        input=f"yes\napplication\n{source}\nyes\n", text=True, capture_output=True,
        timeout=8, check=False,
    )
    assert setup.returncode == 0, "setup subprocess failed"
    assert output.exists() and output.stat().st_mode & 0o777 == 0o600
    assert source.stat().st_size == len(APP_LINE.encode())

    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "app.local_web", "--monitor-config", str(output),
         "--no-browser", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                health, _ = _get_json(port, "/api/health")
                status, body = _get_json(port, "/api/v1/live/status")
                if health == 200 and status == 200:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        else:
            assert False, "loopback readiness timeout"
        assert process.poll() is None, "local runtime exited before readiness"
        assert body["source_role"] == "application"
        assert body["latest_detection_revision"] == 0  # FROM_END excluded existing line.
        with source.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            status, body = _get_json(port, "/api/v1/live/status")
            if status == 200 and body["latest_detection_revision"] >= 1:
                break
            time.sleep(0.05)
        assert body["analysis_revision"] == body["latest_detection_revision"]
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)
            assert False, "local runtime failed to stop within deadline"
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    assert list(tmp_path.rglob(".monitor-*")) == []


def test_dry_run_json_is_repeated_and_timezone_independent(tmp_path: Path) -> None:
    source = tmp_path / "source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    program = (
        "import json,sys; from dataclasses import asdict; "
        "from app.monitor_setup import dry_run_application; "
        "print(json.dumps(asdict(dry_run_application(sys.argv[1])),sort_keys=True))"
    )
    outputs = []
    for zone in ("UTC", "Asia/Seoul", "UTC"):
        env = os.environ.copy()
        env["TZ"] = zone
        result = subprocess.run([sys.executable, "-c", program, str(source)], env=env,
                                capture_output=True, text=True, timeout=5, check=True)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1] == outputs[2]


def test_default_setup_show_monitor_delete_lifecycle(tmp_path: Path) -> None:
    home = tmp_path / "test-home"
    home.mkdir(mode=0o700)
    env = os.environ.copy()
    env["HOME"] = str(home)  # subprocess-only; never modifies the caller's HOME.
    env["XDG_CONFIG_HOME"] = ""
    source = tmp_path / "synthetic.log"
    source.write_text(APP_LINE, encoding="utf-8")
    default = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                  xdg_config_home="")
    setup = subprocess.run([sys.executable, "-m", "app.monitor_setup"],
                           input=f"yes\napplication\n{source}\nyes\n", env=env,
                           capture_output=True, text=True, timeout=8)
    assert setup.returncode == 0 and default.exists()
    assert default.stat().st_mode & 0o777 == 0o600
    shown = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--show"],
                           env=env, capture_output=True, text=True, timeout=8)
    assert shown.returncode == 0 and "application" in shown.stdout
    assert str(source) not in shown.stdout + shown.stderr
    assert str(default) not in shown.stdout + shown.stderr

    port = _free_port()
    process = subprocess.Popen([sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                                "--port", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env)
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                health, _ = _get_json(port, "/api/health")
                status, body = _get_json(port, "/api/v1/live/status")
                if health == status == 200:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        else:
            assert False, "default live readiness timeout"
        assert process.poll() is None and body["latest_detection_revision"] == 0
        assert str(source) not in json.dumps(body) and str(default) not in json.dumps(body)
        with urlopen(f"http://127.0.0.1:{port}/api/v1/live/events", timeout=5) as stream:
            snapshot = b""
            for _ in range(8):
                line = stream.readline()
                snapshot += line
                if line == b"\n":
                    break
            assert b"event: snapshot" in snapshot
            for secret in (str(source).encode(), str(default).encode(), b"synthetic", b"192.0.2.1"):
                assert secret not in snapshot
        with urlopen(f"http://127.0.0.1:{port}/openapi.json", timeout=5) as response:
            openapi = response.read()
        assert str(source).encode() not in openapi and str(default).encode() not in openapi
        with source.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            _, body = _get_json(port, "/api/v1/live/status")
            if body["latest_detection_revision"] >= 1:
                break
            time.sleep(0.05)
        assert body["analysis_revision"] == body["latest_detection_revision"]
        cancelled = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--delete"],
                                   input="no\n", env=env, capture_output=True, text=True, timeout=8)
        assert cancelled.returncode == 0 and default.exists()
        deleted = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--delete"],
                                 input="yes\n", env=env, capture_output=True, text=True, timeout=8)
        assert deleted.returncode == 0 and not default.exists() and source.exists()
        # An already-open live source is not stopped merely by removing its config pathname.
        assert _get_json(port, "/api/v1/live/status")[0] == 200
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)
            assert False, "default runtime failed to stop"
    assert str(source) not in stdout + stderr and str(default) not in stdout + stderr
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    missing = subprocess.run([sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                              "--port", str(port)], env=env, capture_output=True, text=True, timeout=8)
    assert missing.returncode == 4 and "DEFAULT_CONFIG_MISSING" in missing.stderr
    assert list(tmp_path.rglob(".monitor-*")) == []
