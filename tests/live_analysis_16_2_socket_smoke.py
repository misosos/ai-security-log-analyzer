"""Opt-in real loopback lifecycle check using only synthetic temporary data."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen


def _status(port):
    with urlopen(f"http://127.0.0.1:{port}/api/v1/live/status", timeout=2) as response:
        assert response.status == 200
        return json.loads(response.read())


def main():
    with tempfile.TemporaryDirectory(prefix="live-socket-smoke-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"initial line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-m", "app.local_web", "--monitor-config",
             str(config.resolve()), "--no-browser", "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("server exited before readiness")
                try:
                    state = _status(port)
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("server readiness timeout")
            assert state["latest_detection_revision"] == 0
            with urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2) as response:
                assert response.status == 200
            with source.open("ab") as stream:
                for second in range(5):
                    stream.write((f"2026-01-02 03:04:{second:02d} INFO login_failed "
                                  "user=synthetic ip=192.0.2.11\n").encode())
                stream.write(b"2026-01-02 03:04:06 INFO user_login "
                             b"user=synthetic ip=192.0.2.11\n")
            for _ in range(100):
                state = _status(port)
                if state["published_total"]:
                    break
                time.sleep(0.05)
            assert state["published_total"] >= 1
            assert "analysis" not in state and "cases" not in state
            with urlopen(f"http://127.0.0.1:{port}/api/v1/live/events", timeout=3) as response:
                assert response.status == 200
                frames = b""
                for _ in range(100):
                    frames += response.readline()
                    if b"event: observation_changes" in frames:
                        break
                assert b"event: snapshot" in frames
                assert b"event: observation_changes" in frames
                assert b"CASE-BRUTE-SUCCESS-01" not in frames
                assert b"synthetic.log" not in frames
        finally:
            if process.poll() is None:
                os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=6)
            assert process.returncode == 0
            assert str(config) not in stdout + stderr
            assert str(source) not in stdout + stderr
            with socket.socket() as probe:
                assert probe.connect_ex(("127.0.0.1", port)) != 0
    print("real loopback smoke passed; process, listener and temporary directory closed")


if __name__ == "__main__":
    main()
