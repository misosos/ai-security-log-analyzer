"""Opt-in loopback HTTP/SSE smoke; synthetic data and temporary files only."""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _get(url: str) -> bytes:
    with urlopen(url, timeout=3) as response:
        assert response.status == 200
        return response.read()


def _frame(stream) -> bytes:
    lines = []
    while True:
        line = stream.readline()
        if not line:
            raise AssertionError("stream closed before expected event")
        lines.append(line)
        if line == b"\n":
            return b"".join(lines)


def _webdriver(method: str, path: str, payload: dict | None = None):
    request = Request(
        "http://127.0.0.1:4444" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"}, method=method,
    )
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())["value"]


def _safari_script(session_id: str, script: str):
    return _webdriver("POST", f"/session/{session_id}/execute/sync",
                      {"script": script, "args": []})


def main() -> None:
    port = _free_port()
    with tempfile.TemporaryDirectory(prefix="live-analysis-smoke-") as root:
        source = Path(root) / "source.log"
        source.write_bytes(b"existing line\n")
        config = Path(root) / "monitor.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        process = subprocess.Popen(
            [sys.executable, "-m", "app.local_web", "--monitor-config", str(config.resolve()),
             "--no-browser", "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        base = f"http://127.0.0.1:{port}"
        safari_session = None
        try:
            for _ in range(100):
                try:
                    assert json.loads(_get(base + "/api/health"))["status"] == "ok"
                    break
                except Exception:
                    if process.poll() is not None:
                        _, diagnostic = process.communicate(timeout=1)
                        cleaned = diagnostic.decode(errors="replace")
                        for secret in (str(config), str(source), root):
                            cleaned = cleaned.replace(secret, "[temporary path]")
                        raise AssertionError(f"server exited before health: {cleaned[:200]}") from None
                    time.sleep(0.05)
            else:
                raise AssertionError("server did not become ready")
            assert b"live-monitoring.js" in _get(base + "/")
            initial = json.loads(_get(base + "/api/v1/live/status"))
            assert initial["schema_version"] == "2"
            assert initial["analysis_available"] is True
            assert initial["latest_detection_revision"] == 0
            if os.environ.get("LIVE_SAFARI_WEBDRIVER") == "1":
                safari_session = _webdriver("POST", "/session", {
                    "capabilities": {"alwaysMatch": {"browserName": "safari"}}})["sessionId"]
                _webdriver("POST", f"/session/{safari_session}/url", {"url": base + "/"})
                for _ in range(100):
                    if _safari_script(safari_session,
                                      "return !document.getElementById('live-monitoring').hidden && "
                                      "document.getElementById('live-service-state').textContent.includes('모니터링 중');"):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("Safari live region did not become visible")
            with urlopen(Request(base + "/api/v1/live/events"), timeout=5) as stream:
                first = _frame(stream)
                assert b"event: snapshot" in first
                assert b'"analysis_available":true' in first
                append_started = time.perf_counter()
                with source.open("ab") as output:
                    for second in range(5):
                        output.write((f"2026-01-02 03:04:{second:02d} INFO login_failed "
                                      "user=PRIVATE_ACCOUNT_CANARY ip=192.0.2.123\n").encode())
                    output.write(b"2026-01-02 03:04:06 INFO user_login "
                                 b"user=PRIVATE_ACCOUNT_CANARY ip=192.0.2.123\n")
                frames = []
                for _ in range(8):
                    frame = _frame(stream)
                    frames.append(frame)
                    if b"event: analysis_changes" in frame and b"CASE-BRUTE-SUCCESS-01" in frame:
                        break
                wire = b"".join(frames)
                append_to_analysis_sse_ms = (time.perf_counter() - append_started) * 1000
                assert b"event: observation_changes" in wire
                assert b"event: analysis_changes" in wire
                for secret in (b"PRIVATE_ACCOUNT_CANARY", b"192.0.2.123",
                               b"source.log", str(config).encode()):
                    assert secret not in wire + first
                event_ids = [line[4:].strip().decode() for line in wire.splitlines()
                             if line.startswith(b"id: ")]
                assert event_ids
            if safari_session is not None:
                for _ in range(100):
                    if _safari_script(safari_session,
                                      "return !document.getElementById('live-show-pending').hidden;"):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("Safari pending button did not become visible")
                for key in ("live-observations", "live-relations", "live-risks", "live-cases"):
                    assert _safari_script(safari_session,
                                          f"return document.getElementById('{key}').children.length;") == 0
                _safari_script(safari_session,
                               "document.getElementById('live-show-pending').click();")
                for key in ("live-observations", "live-relations", "live-risks", "live-cases"):
                    assert _safari_script(safari_session,
                                          f"return document.getElementById('{key}').children.length;") >= 1
                assert not _safari_script(safari_session,
                                          "return document.body.textContent.includes('PRIVATE_ACCOUNT_CANARY');")
                _safari_script(safari_session,
                               "document.getElementById('live-pause').click();")
                assert _safari_script(safari_session,
                                      "return document.getElementById('live-pause').textContent;") == "화면 업데이트 다시 시작"
                _safari_script(safari_session,
                               "document.getElementById('live-pause').click();")
            with urlopen(Request(base + "/api/v1/live/events",
                                 headers={"Last-Event-ID": event_ids[0]}), timeout=5) as replay:
                assert b"event: snapshot" in _frame(replay)
                assert b"event: analysis_changes" in _frame(replay)
            with urlopen(Request(base + "/api/v1/live/events",
                                 headers={"Last-Event-ID": "invalid"}), timeout=5) as gap:
                assert b"event: replay_gap" in _frame(gap)
                assert b"event: snapshot" in _frame(gap)
            status = _get(base + "/api/v1/live/status")
            assert b'"active_case_count":1' in status
            assert b"PRIVATE_ACCOUNT_CANARY" not in status
            assert b"LiveAnalysisSnapshot" not in _get(base + "/openapi.json")
        finally:
            if safari_session is not None:
                _webdriver("DELETE", f"/session/{safari_session}")
            process.send_signal(signal.SIGINT)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                raise AssertionError("server did not shut down") from None
            for secret in (str(config).encode(), str(source).encode(), b"PRIVATE_ACCOUNT_CANARY"):
                assert secret not in stdout + stderr
        assert process.returncode == 0
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0
    print("loopback HTTP/SSE smoke PASS; Safari WebDriver tested=" +
          str(os.environ.get("LIVE_SAFARI_WEBDRIVER") == "1") +
          "; append-to-analysis-SSE one sample ms=" +
          str(round(append_to_analysis_sse_ms, 3)) +
          "; temporary source and listener closed")


if __name__ == "__main__":
    main()
