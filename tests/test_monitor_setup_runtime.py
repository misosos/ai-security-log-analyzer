"""OS-temporary CLI → v2 loader → actual loopback runtime smoke."""

from http.client import HTTPConnection
import asyncio
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import time
from urllib.request import Request, urlopen

from app.live_monitoring.config import resolve_default_monitor_config_path
from app.local_web import _live_runtime
from app.monitor_setup import create_monitor_config


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


def _sse_frames(port: int, count: int, *, cursor: str | None = None) -> list[tuple[str, dict]]:
    frames = []
    request = Request(f"http://127.0.0.1:{port}/api/v1/live/events",
                      headers={"Last-Event-ID": cursor} if cursor is not None else {})
    with urlopen(request, timeout=5) as stream:
        for _ in range(count):
            lines = []
            for _ in range(30):
                line = stream.readline()
                if line == b"\n":
                    break
                assert line, "SSE stream closed before requested frame"
                lines.append(line)
            else:
                assert False, "SSE frame exceeded bounded line count"
            event = next(line[7:].decode("ascii").strip() for line in lines
                         if line.startswith(b"event: "))
            payload = json.loads(next(line[6:] for line in lines if line.startswith(b"data: ")))
            frames.append((event, payload))
    return frames


def _wait_live_status(port: int, predicate, *, seconds: float = 8) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            status, body = _get_json(port, "/api/v1/live/status")
            if status == 200 and predicate(body):
                return body
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise AssertionError("bounded live status condition not reached")


def _stop_runtime(process: subprocess.Popen, port: int) -> tuple[str, str]:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        output = process.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=3)
        raise AssertionError("local runtime failed to stop within deadline") from None
    assert process.returncode == 0
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0
    return output


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
        assert process.poll() is None and body["latest_detection_revision"] == 0, (
            process.stderr.read() if process.poll() is not None else "unexpected revision"
        )
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
        assert deleted.returncode == 4 and "CHECKPOINT_DELETE_FAILED" in deleted.stderr
        assert default.exists() and source.exists()
        # A checkpoint-enabled active process owns its recovery file; deletion fails closed.
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
    # Same-file restart replays committed analysis privately, then processes
    # only the complete line appended while the server was stopped.
    with source.open("a", encoding="utf-8") as stream:
        stream.write(APP_LINE)
    restart_port = _free_port()
    restarted = subprocess.Popen([sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                                  "--port", str(restart_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=env)
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if restarted.poll() is not None:
                break
            try:
                _, resumed = _get_json(restart_port, "/api/v1/live/status")
                if resumed["latest_detection_revision"] >= 2:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        assert restarted.poll() is None and resumed["latest_detection_revision"] >= 2
        assert resumed["analysis_revision"] == resumed["latest_detection_revision"]
    finally:
        if restarted.poll() is None:
            restarted.send_signal(signal.SIGINT)
        restarted.communicate(timeout=8)
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", restart_port)) != 0
    deleted = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--delete"],
                             input="yes\n", env=env, capture_output=True, text=True, timeout=8)
    assert deleted.returncode == 0 and not default.exists() and source.exists()
    assert not (default.parent / "checkpoint-source-000001.json").exists()
    missing = subprocess.run([sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                              "--port", str(port)], env=env, capture_output=True, text=True, timeout=8)
    assert missing.returncode == 4 and "DEFAULT_CONFIG_MISSING" in missing.stderr
    assert list(tmp_path.rglob(".monitor-*")) == []
    assert list(tmp_path.rglob(".checkpoint-*")) == []


def test_cli_explicit_checkpoint_reset_starts_a_new_epoch(tmp_path: Path) -> None:
    home = tmp_path / "reset-home"
    home.mkdir(mode=0o700)
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = ""
    source = tmp_path / "synthetic-reset.log"
    source.write_text(APP_LINE, encoding="utf-8")
    config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                 xdg_config_home="")
    setup = subprocess.run([sys.executable, "-m", "app.monitor_setup"],
                           input=f"yes\napplication\n{source}\nyes\n", env=env,
                           capture_output=True, text=True, timeout=8)
    assert setup.returncode == 0 and config.exists()
    port = _free_port()
    process = subprocess.Popen([sys.executable, "-m", "app.local_web", "--monitor",
                                "--no-browser", "--port", str(port)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        _wait_live_status(port, lambda body: body["latest_detection_revision"] == 0)
        with source.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        _wait_live_status(port, lambda body: body["latest_detection_revision"] >= 1)
        active_reset = subprocess.run(
            [sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
            input="yes\n", env=env, capture_output=True, text=True, timeout=8,
        )
        assert active_reset.returncode == 3 and "CHECKPOINT_RESET_ACTIVE" in active_reset.stderr
    finally:
        stdout, stderr = _stop_runtime(process, port)
    checkpoint = config.parent / "checkpoint-source-000001.json"
    assert checkpoint.exists()
    rotated = tmp_path / "retained-old.log"
    source.replace(rotated)
    source.write_text(APP_LINE * 3, encoding="utf-8")
    failed = subprocess.run([sys.executable, "-m", "app.local_web", "--monitor",
                             "--no-browser", "--port", str(port)], env=env,
                            capture_output=True, text=True, timeout=8)
    assert failed.returncode == 4 and checkpoint.exists()
    cancelled = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
                               input="no\n", env=env, capture_output=True, text=True, timeout=8)
    assert cancelled.returncode == 0 and checkpoint.exists()
    reset = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
                           input="yes\n", env=env, capture_output=True, text=True, timeout=8)
    assert reset.returncode == 0 and not checkpoint.exists()
    assert config.exists() and source.exists() and rotated.exists()
    for output in (stdout + stderr, active_reset.stdout + active_reset.stderr,
                   failed.stdout + failed.stderr,
                   cancelled.stdout + cancelled.stderr, reset.stdout + reset.stderr):
        for private in (str(source), str(config), "synthetic", "192.0.2.1"):
            assert private not in output
    restarted_port = _free_port()
    restarted = subprocess.Popen([sys.executable, "-m", "app.local_web", "--monitor",
                                  "--no-browser", "--port", str(restarted_port)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        initial = _wait_live_status(restarted_port,
                                    lambda body: body["latest_detection_revision"] == 0)
        assert initial["analysis_revision"] == 0
        assert _get_json(restarted_port, "/api/v1/live/status")[1]["latest_detection_revision"] == 0
        with source.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        resumed = _wait_live_status(restarted_port,
                                    lambda body: body["latest_detection_revision"] >= 1)
        assert resumed["analysis_revision"] == resumed["latest_detection_revision"]
    finally:
        restart_stdout, restart_stderr = _stop_runtime(restarted, restarted_port)
    assert str(source) not in restart_stdout + restart_stderr
    assert config.exists() and source.exists() and rotated.exists()
    assert list(tmp_path.rglob(".checkpoint-*")) == []


def test_two_reset_processes_do_not_share_approval_lock(tmp_path: Path) -> None:
    """An approval prompt holds the advisory lock across separate OS processes."""
    home = tmp_path / "isolated-home"
    home.mkdir(mode=0o700)
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = ""
    source = tmp_path / "private-source.log"
    source.write_text(APP_LINE, encoding="utf-8")
    config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                 xdg_config_home="")
    create_monitor_config(source, config)
    service, _ = _live_runtime(config, checkpoint_default=True)
    asyncio.run(service.close())
    checkpoint = config.parent / "checkpoint-source-000001.json"
    lock = config.parent / "checkpoint-source-000001.lock"
    assert checkpoint.is_file() and checkpoint.stat().st_mode & 0o777 == 0o600
    assert lock.is_file() and lock.stat().st_mode & 0o777 == 0o600
    assert config.parent.stat().st_mode & 0o777 == 0o700
    original = checkpoint.read_bytes()
    sibling = config.parent / "leave-alone.txt"
    sibling.write_text("sentinel", encoding="utf-8")

    first = subprocess.Popen(
        [sys.executable, "-u", "-m", "app.monitor_setup", "--reset-checkpoint"],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        assert first.stdout is not None and first.stdin is not None
        prompt = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(first.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 8
            while b"[y/N]" not in prompt and time.monotonic() < deadline:
                if selector.select(timeout=0.1):
                    chunk = os.read(first.stdout.fileno(), 4096)
                    assert chunk, "first reset exited before approval prompt"
                    prompt.extend(chunk)
        assert b"[y/N]" in prompt and first.poll() is None
        second = subprocess.run(
            [sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
            input="yes\n", env=env, capture_output=True, text=True, timeout=8,
        )
        assert second.returncode == 3
        assert "CHECKPOINT_RESET_ACTIVE" in second.stderr
        assert checkpoint.read_bytes() == original
        first.stdin.write(b"no\n")
        first.stdin.flush()
        first_output, first_error = first.communicate(timeout=8)
        assert first.returncode == 0 and checkpoint.read_bytes() == original
        assert b"CHECKPOINT_RESET_ACTIVE" not in first_error
        approved = subprocess.run(
            [sys.executable, "-m", "app.monitor_setup", "--reset-checkpoint"],
            input="yes\n", env=env, capture_output=True, text=True, timeout=8,
        )
        assert approved.returncode == 0 and not checkpoint.exists()
        assert config.exists() and source.exists() and sibling.read_text(encoding="utf-8") == "sentinel"
        for output in (bytes(prompt), first_output, first_error,
                       second.stdout.encode(), second.stderr.encode(),
                       approved.stdout.encode(), approved.stderr.encode()):
            for canary in (str(source).encode(), str(config).encode(),
                           b"synthetic", b"192.0.2.1"):
                assert canary not in output
    finally:
        if first.poll() is None:
            first.kill()
            first.communicate(timeout=3)


def test_checkpoint_restart_rebuilds_safe_analysis_without_republishing_old_events(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-private-canary.log"
    source.write_text(APP_LINE, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_config(source, config)
    program = (
        "import sys; from pathlib import Path; from app.local_web import run_local_web; "
        "raise SystemExit(run_local_web(int(sys.argv[2]), open_browser=False, "
        "monitor_default=True, default_config_resolver=lambda: Path(sys.argv[1])))"
    )
    secrets = (str(source).encode(), str(config).encode(), b"ACCOUNT_PRIVATE_CANARY",
               b"192.0.2.123", b"192.0.2.1", b"private-query-canary",
               b"private-raw-line-canary")

    def start(port: int) -> subprocess.Popen:
        return subprocess.Popen([sys.executable, "-c", program, str(config), str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    first_port = _free_port()
    first = start(first_port)
    try:
        initial = _wait_live_status(first_port, lambda body: body["service_state"] == "RUNNING")
        assert initial["latest_detection_revision"] == 0  # Existing line is FROM_END.
        failures = "".join(
            f"2026-01-02 03:04:{second:02d} INFO login_failed "
            "user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123 "
            "query=private-query-canary note=private-raw-line-canary\n"
            for second in range(5)
        )
        with source.open("a", encoding="utf-8") as stream:
            stream.write(failures)
        committed = _wait_live_status(
            first_port, lambda body: body["latest_detection_revision"] >= 1
            and body["published_total"] >= 2,
        )
        assert committed["analysis_revision"] == committed["latest_detection_revision"] == 1
        assert committed["active_risk_count"] >= 1
        first_session = committed["session_id"]
        first_frames = _sse_frames(first_port, 1 + committed["published_total"])
        assert [name for name, _ in first_frames] == [
            "snapshot", "observation_changes", "analysis_changes",
        ]
        previous_cursor = first_frames[-1][1]["event_id"]
        for _, payload in first_frames:
            wire = json.dumps(payload, ensure_ascii=False).encode()
            assert all(secret not in wire for secret in secrets)
    finally:
        first_output = _stop_runtime(first, first_port)

    checkpoint = config.parent / "checkpoint-source-000001.json"
    assert checkpoint.exists() and checkpoint.stat().st_mode & 0o777 == 0o600
    assert list(config.parent.glob(".checkpoint-*")) == []
    second_port = _free_port()
    second = start(second_port)
    try:
        restored = _wait_live_status(second_port, lambda body: body["service_state"] == "RUNNING")
        assert restored["session_id"] != first_session
        assert restored["latest_detection_revision"] == restored["analysis_revision"] == 1
        assert restored["published_total"] == restored["available_event_count"] == 0
        assert restored["active_risk_count"] >= 1
        restored_snapshot = _sse_frames(second_port, 1)
        assert restored_snapshot[0][0] == "snapshot"
        assert restored_snapshot[0][1]["analysis"]["revision"] == 1
        assert restored_snapshot[0][1]["analysis"]["risk_count"] >= 1
        assert restored_snapshot[0][1]["published_total"] == 0
        stale_cursor = _sse_frames(second_port, 2, cursor=previous_cursor)
        assert [name for name, _ in stale_cursor] == ["replay_gap", "snapshot"]
        assert stale_cursor[0][1]["code"] == "FOREIGN_SESSION"

        with source.open("a", encoding="utf-8") as stream:
            stream.write("2026-01-02 03:04:06 INFO user_login "
                         "user=ACCOUNT_PRIVATE_CANARY ip=192.0.2.123 "
                         "query=private-query-canary note=private-raw-line-canary\n")
        updated = _wait_live_status(
            second_port, lambda body: body["analysis_revision"] >= 2
            and body["active_relation_count"] >= 2 and body["active_case_count"] >= 1,
        )
        assert updated["latest_detection_revision"] == updated["analysis_revision"] == 2
        assert updated["published_total"] == 1  # New analysis only; old events were not replayed.
        frames = _sse_frames(second_port, 1 + updated["published_total"])
        assert [name for name, _ in frames] == ["snapshot", "analysis_changes"]
        snapshot = frames[0][1]["analysis"]
        assert {item["relation_type"] for item in snapshot["relations"]} == {
            "failed_to_successful_login", "brute_force_to_successful_login",
        }
        assert any(item["rule_id"] == "CASE-BRUTE-SUCCESS-01" for item in snapshot["cases"])
        assert snapshot["risk_count"] >= 1
        assert frames[1][1]["revision"] == 2
        assert any(item["rule_id"] == "CASE-BRUTE-SUCCESS-01"
                   for item in frames[1][1]["case_changes"])
        _, status_body = _get_json(second_port, "/api/v1/live/status")
        with urlopen(f"http://127.0.0.1:{second_port}/openapi.json", timeout=5) as response:
            openapi = response.read()
        for public in (json.dumps(status_body).encode(), openapi,
                       *(json.dumps(payload, ensure_ascii=False).encode() for _, payload in frames)):
            assert all(secret not in public for secret in secrets)
    finally:
        second_output = _stop_runtime(second, second_port)
    for output in (*first_output, *second_output):
        assert all(secret.decode() not in output for secret in secrets)
    assert list(config.parent.glob(".checkpoint-*")) == []
