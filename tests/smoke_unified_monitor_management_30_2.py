"""Temporary-home CLI/process lifecycle for both private v2 monitor roles."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import selectors
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import time
from urllib.request import Request, urlopen

from smoke_ssh_checkpoint_26_0 import (
    ROOT, _assert_private_output, _default_config_for, _line as ssh_line,
    _management, _mode, _no_listener, _port, _status, _stop, _wait,
)


def _app_line(second: int, outcome: str = "login_failed") -> str:
    return (f"2026-01-02 03:04:{second:02d} INFO {outcome} "
            "user=SYNTHETIC_ACCOUNT ip=192.0.2.33\n")


def _frames(port: int, count: int, *, cursor: str | None = None) -> list[tuple[str, dict]]:
    request = Request(f"http://127.0.0.1:{port}/api/v1/live/events",
                      headers={"Last-Event-ID": cursor} if cursor is not None else {})
    frames = []
    with urlopen(request, timeout=5) as stream:
        for _ in range(count):
            lines = []
            for _ in range(30):
                line = stream.readline()
                if line == b"\n":
                    break
                assert line, "SSE_CLOSED"
                lines.append(line)
            else:
                raise AssertionError("SSE_FRAME_LIMIT")
            kind = next(line[7:].decode("ascii").strip() for line in lines
                        if line.startswith(b"event: "))
            payload = json.loads(next(line[6:] for line in lines if line.startswith(b"data: ")))
            frames.append((kind, payload))
    return frames


def _start(role: str, port: int, env: dict, stdout: Path, stderr: Path) -> subprocess.Popen:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(
            [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
             "--port", str(port)], cwd=ROOT, env=env, stdout=out, stderr=err,
            start_new_session=True,
        )
    try:
        _wait(port, lambda body: body["source_role"] == role)
    except Exception:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)
        raise AssertionError("UNIFIED_SERVER_START_FAILED") from None
    return process


def _competing_reset(env: dict, checkpoint: Path) -> None:
    original = checkpoint.read_bytes()
    first = subprocess.Popen(
        [sys.executable, "-u", "-m", "app.monitor_setup", "--reset-checkpoint"],
        cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert first.stdout is not None and first.stdin is not None
        prompt = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(first.stdout, selectors.EVENT_READ)
            until = time.monotonic() + 10
            while b"[y/N]" not in prompt and time.monotonic() < until:
                if selector.select(timeout=0.1):
                    chunk = os.read(first.stdout.fileno(), 4096)
                    assert chunk, "RESET_PROMPT_CLOSED"
                    prompt.extend(chunk)
        assert b"[y/N]" in prompt and first.poll() is None
        second = _management(env, "--reset-checkpoint", answer="yes\n")
        assert second.returncode == 3 and "CHECKPOINT_RESET_ACTIVE" in second.stderr
        assert checkpoint.read_bytes() == original
        first.stdin.write(b"no\n")
        first.stdin.flush()
        output, error = first.communicate(timeout=10)
        assert first.returncode == 0 and checkpoint.read_bytes() == original
        assert not error
        for surface in (bytes(prompt), output, error,
                        second.stdout.encode(), second.stderr.encode()):
            assert all(canary not in surface for canary in (
                str(checkpoint).encode(), b"SYNTHETIC_ACCOUNT", b"192.0.2.33"))
    finally:
        if first.poll() is None:
            first.kill()
            first.communicate(timeout=3)


def _role_flow(role: str, choice: str) -> None:
    process = None
    scratch = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    with TemporaryDirectory(prefix="unified-monitor-smoke-", dir=scratch) as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)
        source = root / "synthetic.log"
        line = ssh_line if role == "ssh" else _app_line
        source.write_text(line(0), encoding="utf-8")
        env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(root),
               "XDG_CONFIG_HOME": ""}
        config = _default_config_for(home, sys.platform)
        setup = subprocess.run(
            [sys.executable, "-m", "app.monitor_setup"], cwd=ROOT, env=env,
            input=f"yes\n{choice}\n{source}\nyes\n", capture_output=True, text=True,
            timeout=10,
        )
        assert setup.returncode == 0, "UNIFIED_SETUP_FAILED"
        assert "uv run python -m app.local_web --monitor" in setup.stdout
        assert (_mode(config.parent), _mode(config)) == (0o700, 0o600)
        checkpoint = config.parent / "checkpoint-source-000001.json"
        lock = config.parent / "checkpoint-source-000001.lock"
        sibling = config.parent / "sibling.txt"
        sibling.write_text("synthetic sibling", encoding="utf-8")
        initial_source = source.read_bytes()
        show = _management(env, "--show")
        assert show.returncode == 0 and "복구 자료: 없음" in show.stdout
        assert ("SSH 인증 로그" if role == "ssh" else "애플리케이션 로그인 로그") in show.stdout
        for result in (setup, show):
            _assert_private_output(result, str(source), str(config), str(checkpoint),
                                   "SYNTHETIC_ACCOUNT", "192.0.2.33")
        port = _port()
        try:
            process = _start(role, port, env, root / "stdout.log", root / "stderr.log")
            first = _status(port)
            assert first["latest_detection_revision"] == first["analysis_revision"] == 0
            assert source.read_bytes() == initial_source
            assert (_mode(checkpoint), _mode(lock)) == (0o600, 0o600)
            competing_port = _port()
            competing = subprocess.run(
                [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                 "--port", str(competing_port)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
            assert competing.returncode != 0 and "CHECKPOINT_ALREADY_OWNED" in competing.stderr
            _no_listener(competing_port)
            for operation, code in (("--reset-checkpoint", "CHECKPOINT_RESET_ACTIVE"),
                                    ("--delete", "CHECKPOINT")):
                denied = _management(env, operation, answer="yes\n")
                assert denied.returncode != 0 and code in denied.stderr
                _assert_private_output(denied, str(source), str(config), str(checkpoint),
                                       "SYNTHETIC_ACCOUNT", "192.0.2.33")
            with source.open("a", encoding="utf-8") as stream:
                stream.writelines(line(index) for index in range(1, 6))
            _wait(port, lambda body: body["analysis_revision"] >= 1
                  and body["active_risk_count"] >= 1)
            with source.open("a", encoding="utf-8") as stream:
                stream.write(line(6, "Accepted" if role == "ssh" else "user_login"))
            analyzed = _wait(port, lambda body: body["analysis_revision"] >= 2
                             and body["active_relation_count"] >= 2
                             and body["active_case_count"] >= 1)
            old_frames = _frames(port, 1 + analyzed["published_total"])
            old_cursor = old_frames[-1][1]["event_id"]
            _stop(process)
            process = None
            _no_listener(port)
            assert checkpoint.exists() and config.exists()
            recovered_show = _management(env, "--show")
            assert recovered_show.returncode == 0
            assert "복구 자료: 정상" in recovered_show.stdout
            _assert_private_output(recovered_show, str(source), str(config), str(checkpoint),
                                   "SYNTHETIC_ACCOUNT", "192.0.2.33")
            port = _port()
            process = _start(role, port, env, root / "stdout2.log", root / "stderr2.log")
            restored = _status(port)
            assert restored["analysis_revision"] == analyzed["analysis_revision"]
            assert restored["latest_detection_revision"] == analyzed["latest_detection_revision"]
            assert restored["published_total"] == restored["available_event_count"] == 0
            assert restored["active_relation_count"] >= 2
            assert restored["active_risk_count"] >= 1 and restored["active_case_count"] >= 1
            fresh_frames = _frames(port, 1)
            assert [kind for kind, _ in fresh_frames] == ["snapshot"]
            gap_frames = _frames(port, 2, cursor=old_cursor)
            assert [kind for kind, _ in gap_frames] == ["replay_gap", "snapshot"]
            assert gap_frames[0][1]["code"] == "FOREIGN_SESSION"
            for public in (first, analyzed, restored,
                           *(payload for _, payload in old_frames + fresh_frames + gap_frames)):
                encoded = json.dumps(public, ensure_ascii=False)
                assert not any(canary in encoded for canary in (
                    str(source), str(config), str(checkpoint), "SYNTHETIC_ACCOUNT", "192.0.2.33"))
            _stop(process)
            process = None
            _no_listener(port)
            before = checkpoint.read_bytes()
            _competing_reset(env, checkpoint)
            cancelled_reset = _management(env, "--reset-checkpoint", answer="no\n")
            assert cancelled_reset.returncode == 0 and checkpoint.read_bytes() == before
            reset = _management(env, "--reset-checkpoint", answer="yes\n")
            assert reset.returncode == 0 and not checkpoint.exists()
            assert config.exists() and source.exists() and lock.exists() and sibling.exists()
            assert "원본 로그" in reset.stdout and "연속성" in reset.stdout
            port = _port()
            process = _start(role, port, env, root / "stdout3.log", root / "stderr3.log")
            fresh = _status(port)
            assert fresh["analysis_revision"] == fresh["latest_detection_revision"] == 0
            assert fresh["active_relation_count"] == fresh["active_case_count"] == 0
            _stop(process)
            process = None
            _no_listener(port)
            cancelled_delete = _management(env, "--delete", answer="no\n")
            assert cancelled_delete.returncode == 0 and config.exists() and checkpoint.exists()
            deleted = _management(env, "--delete", answer="yes\n")
            assert deleted.returncode == 0 and not config.exists() and not checkpoint.exists()
            assert source.exists() and lock.exists() and sibling.exists() and config.parent.exists()
            missing_port = _port()
            missing = subprocess.run(
                [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser",
                 "--port", str(missing_port)], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=10,
            )
            assert missing.returncode != 0 and "DEFAULT_CONFIG_MISSING" in missing.stderr
            _no_listener(missing_port)
            for result in (cancelled_reset, reset, cancelled_delete, deleted, missing):
                _assert_private_output(result, str(source), str(config), str(checkpoint),
                                       "SYNTHETIC_ACCOUNT", "192.0.2.33")
            for capture in root.glob("std*.log"):
                content = capture.read_text(encoding="utf-8", errors="replace")
                assert not any(canary in content for canary in (
                    str(source), str(config), str(checkpoint), "SYNTHETIC_ACCOUNT",
                    "192.0.2.33"))
            assert not list(config.parent.glob(".monitor-*"))
            assert not list(config.parent.glob(".checkpoint-*"))
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
    assert not root.exists()


def _two_setups_no_clobber(role: str, choice: str) -> None:
    scratch = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    with TemporaryDirectory(prefix="unified-setup-race-", dir=scratch) as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)
        source = root / "synthetic.log"
        source.write_text((ssh_line if role == "ssh" else _app_line)(0), encoding="utf-8")
        env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(root),
               "XDG_CONFIG_HOME": ""}
        barrier = Barrier(2)

        def run_setup() -> subprocess.CompletedProcess:
            barrier.wait(timeout=5)
            return subprocess.run(
                [sys.executable, "-m", "app.monitor_setup"], cwd=ROOT, env=env,
                input=f"yes\n{choice}\n{source}\nyes\n", text=True,
                capture_output=True, timeout=10,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run_setup)
            second = pool.submit(run_setup)
            results = (first.result(timeout=15), second.result(timeout=15))
        assert sorted(result.returncode for result in results) == [0, 4]
        config = _default_config_for(home, sys.platform)
        assert (_mode(config.parent), _mode(config)) == (0o700, 0o600)
        assert not list(config.parent.glob(".monitor-*"))
        for result in results:
            _assert_private_output(result, str(source), str(config),
                                   "SYNTHETIC_ACCOUNT", "192.0.2.33")
    assert not root.exists()


def main() -> None:
    _role_flow("application", "1")
    _role_flow("ssh", "2")
    _two_setups_no_clobber("application", "1")
    _two_setups_no_clobber("ssh", "2")
    print("UNIFIED_MONITOR_MANAGEMENT_SMOKE_PASS application_ssh_cleanup")


if __name__ == "__main__":
    main()
