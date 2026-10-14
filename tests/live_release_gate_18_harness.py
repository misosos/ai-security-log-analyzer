"""Opt-in Safari replay-gap fixture; no production behavior or private paths changed."""

import asyncio
import json
import socket
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
from urllib.request import urlopen

from app.api import create_app
from app.local_web import _live_runtime, _server
from app.live_monitoring.service import LiveMonitoringService
from tests.live_acceptance_17_harness import _append


PORT = 8000
BASE = f"http://127.0.0.1:{PORT}"
_ORIGINAL_WAIT = LiveMonitoringService._wait_for_update
_RELEASE_SSE = Event()


async def _gated_wait(self: LiveMonitoringService, generation: int) -> bool:
    # A test-only slow-consumer boundary: the existing bounded replay buffer remains
    # the source of truth and the production stream still calls replay_after().
    await asyncio.to_thread(_RELEASE_SSE.wait)
    return await _ORIGINAL_WAIT(self, generation)


def _status() -> dict:
    with urlopen(BASE + "/api/v1/live/status", timeout=3) as response:
        assert response.status == 200
        return json.loads(response.read())


def _wait_for(predicate) -> dict:
    for _ in range(100):
        try:
            status = _status()
        except Exception:
            time.sleep(0.05)
            continue
        if predicate(status):
            return status
        time.sleep(0.05)
    raise RuntimeError("검수용 서버 상태를 확인하지 못했습니다.") from None


def main() -> None:
    with socket.socket() as probe:
        probe.settimeout(0.25)
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            raise SystemExit("검수 포트가 사용 중입니다. 기존 서버를 종료해 주세요.")
    with TemporaryDirectory(prefix="live-release-gate-18-") as temporary:
        source = Path(temporary) / "SYNTHETIC_GATE18_SOURCE_CANARY.log"
        source.write_bytes(b"2026-01-02 03:03:00 INFO login_failed user=OLD_SYNTHETIC_LINE ip=192.0.2.4\n")
        config = Path(temporary) / "SYNTHETIC_GATE18_CONFIG_CANARY.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, runner = _live_runtime(config.resolve())
        # Test-only lower retention makes a genuine old-cursor gap with a few lines.
        service.publication_buffer._max_items = 2
        LiveMonitoringService._wait_for_update = _gated_wait
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", PORT))
        listener.listen(128)
        server = _server(create_app(live_monitoring_service=service,
                                    live_monitoring_runner=runner), PORT)
        thread = Thread(target=server.run, kwargs={"sockets": [listener]},
                        name="live-release-gate-server")
        thread.start()
        try:
            initial = _wait_for(lambda value: value["service_state"] == "RUNNING")
            assert initial["latest_detection_revision"] == 0
            print("READY: http://127.0.0.1:8000/", flush=True)
            print("명령: seed, gap, status, stop", flush=True)
            for command in sys.stdin:
                command = command.strip()
                if command == "seed":
                    _append(source, (0,))
                    current = _wait_for(lambda value: value["available_event_count"] >= 1)
                    assert current["latest_detection_revision"] == 1
                    print("SEEDED: 첫 안전 event 준비", flush=True)
                elif command == "gap":
                    current = _status()
                    assert current["active_connections"] >= 1
                    assert current["available_event_count"] >= 1
                    _append(source, (1, 2, 3, 4))
                    current = _wait_for(lambda value: value["evicted_total"] >= 1)
                    assert current["latest_detection_revision"] >= 2
                    _RELEASE_SSE.set()
                    print("GAP_READY: 이전 event eviction 및 SSE 알림 해제", flush=True)
                elif command == "status":
                    current = _status()
                    print("STATUS: service=" + current["service_state"] +
                          " revision=" + str(current["latest_detection_revision"]) +
                          " retained=" + str(current["available_event_count"]) +
                          " evicted=" + str(current["evicted_total"]) +
                          " gaps=" + str(current["replay_gap_total"]) +
                          " connections=" + str(current["active_connections"]), flush=True)
                elif command == "stop":
                    break
                else:
                    print("UNKNOWN_COMMAND", flush=True)
        finally:
            _RELEASE_SSE.set()
            server.should_exit = True
            thread.join(timeout=7)
            if thread.is_alive():
                server.force_exit = True
                thread.join(timeout=1)
                raise RuntimeError("검수용 서버 종료 시간이 초과됐습니다.") from None
            listener.close()
            asyncio.run(service.close())
            LiveMonitoringService._wait_for_update = _ORIGINAL_WAIT
            with socket.socket() as probe:
                probe.settimeout(0.25)
                assert probe.connect_ex(("127.0.0.1", PORT)) != 0
            print("CLOSED: listener, service, 임시 자료 정리 예정", flush=True)
    print("CLEAN: 임시 자료 정리 완료", flush=True)


if __name__ == "__main__":
    main()
