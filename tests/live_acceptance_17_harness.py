"""Opt-in local Safari acceptance fixture; synthetic data, no private paths printed."""

import json
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen


PORT = 8000
BASE = f"http://127.0.0.1:{PORT}"
ACCOUNT = "SYNTHETIC_ACCOUNT_CANARY_P17"
IP = "192.0.2.123"
SOURCE_NAME = "SYNTHETIC_SOURCE_FILENAME_CANARY_P17.log"
CONFIG_NAME = "SYNTHETIC_CONFIG_FILENAME_CANARY_P17.json"


def _append(source: Path, seconds: tuple[int, ...], *, success: bool = False) -> None:
    with source.open("ab") as output:
        for second in seconds:
            kind = "user_login" if success else "login_failed"
            output.write((f"2026-01-02 03:04:{second:02d} INFO {kind} "
                          f"user={ACCOUNT} ip={IP} note=RAW_LINE_CANARY_P17\n").encode())


def _port_open() -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.5)
        return probe.connect_ex(("127.0.0.1", PORT)) == 0


def _status() -> dict:
    with urlopen(BASE + "/api/v1/live/status", timeout=3) as response:
        assert response.status == 200
        body = json.loads(response.read())
    assert body["schema_version"] == "2"
    return body


def main() -> None:
    if _port_open():
        raise SystemExit("검수 포트를 사용할 수 없습니다. 기존 서버를 종료한 뒤 다시 실행하세요.")
    with tempfile.TemporaryDirectory(prefix="live-acceptance-17-") as temporary:
        source = Path(temporary) / SOURCE_NAME
        source.write_bytes(b"2026-01-02 03:03:00 INFO login_failed user=OLD_LINE_CANARY_P17 ip=192.0.2.4\n")
        config = Path(temporary) / CONFIG_NAME
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        process = subprocess.Popen(
            [sys.executable, "-m", "app.local_web", "--monitor-config",
             str(config.resolve()), "--no-browser", "--port", str(PORT)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(100):
                try:
                    first = _status()
                    break
                except Exception:
                    if process.poll() is not None:
                        raise RuntimeError("검수용 서버가 시작되지 않았습니다.") from None
                    time.sleep(0.05)
            else:
                raise RuntimeError("검수용 서버 준비 시간이 초과됐습니다.")
            assert first["latest_detection_revision"] == 0
            print("READY: Safari에서 http://127.0.0.1:8000/ 을 여세요.", flush=True)
            print("명령: first, threshold, success, more, truncate, status, stop", flush=True)
            for command in sys.stdin:
                command = command.strip()
                if command == "first":
                    _append(source, (0,))
                    print("APPENDED: 합성 실패 인증 1줄", flush=True)
                elif command == "threshold":
                    _append(source, (1, 2, 3, 4))
                    print("APPENDED: 합성 실패 인증 4줄", flush=True)
                elif command == "success":
                    _append(source, (6,), success=True)
                    print("APPENDED: 합성 성공 인증 1줄", flush=True)
                elif command == "more":
                    _append(source, (7,))
                    print("APPENDED: 합성 실패 인증 1줄", flush=True)
                elif command == "truncate":
                    source.write_bytes(b"")
                    print("TRUNCATED: 합성 source를 비워 terminal 경계를 요청했습니다.", flush=True)
                elif command == "status":
                    current = _status()
                    print("STATUS: service=" + current["service_state"] +
                          " detection_revision=" + str(current["latest_detection_revision"]) +
                          " analysis_revision=" + str(current["analysis_revision"]) +
                          " events=" + str(current["available_event_count"]), flush=True)
                elif command == "stop":
                    break
                else:
                    print("UNKNOWN_COMMAND", flush=True)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                stdout, stderr = process.communicate(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=7)
                raise RuntimeError("검수용 서버 종료 시간이 초과됐습니다.") from None
            for secret in (str(config).encode(), str(source).encode(), ACCOUNT.encode(), IP.encode()):
                assert secret not in stdout + stderr
            assert process.returncode == 0
            assert not _port_open()
            print("CLOSED: 프로세스 종료, listener 해제, 임시 자료 정리 예정", flush=True)
    print("CLEAN: 임시 자료 정리 완료", flush=True)


if __name__ == "__main__":
    main()
