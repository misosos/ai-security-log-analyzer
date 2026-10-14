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
