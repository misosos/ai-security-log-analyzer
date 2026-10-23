"""Explicit real-loopback v3 HTTP/SSE smoke with synthetic files only."""

import asyncio
import json
from pathlib import Path
import socket
import tempfile

import httpx
import uvicorn

from app.live_monitoring import pair_service
from app.api import create_app
from app.local_web import _pair_runtime
from app.monitor_setup import create_monitor_pair_config


APPLICATION = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")


async def _next_event(lines, kind: str):
    async def read():
        event_id = None
        async for line in lines:
            if line.startswith("id: "):
                event_id = line[4:]
            if line == f"event: {kind}":
                return event_id
        raise AssertionError("SMOKE_STREAM_ENDED")
    return await asyncio.wait_for(read(), timeout=8)


async def smoke():
    with tempfile.TemporaryDirectory(prefix="pair-public-smoke-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as name:
        root = Path(name)
        application, ssh = root / "application.log", root / "ssh.log"
        application.write_text("", encoding="utf-8")
        ssh.write_text("", encoding="utf-8")
        config = root / "private" / "monitoring.json"
        create_monitor_pair_config(application, ssh, config)
        pair_service.POLL_INTERVAL_SECONDS = 0.01  # Test-only cadence, not a product latency promise.
        service, runner = _pair_runtime(config)
        app = create_app(live_monitoring_service=service, live_monitoring_runner=runner)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        address = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0,
                                                log_level="error", access_log=False))
        task = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            async with httpx.AsyncClient(base_url=address, timeout=10) as client:
                for _ in range(100):
                    try:
                        health = await client.get("/api/health")
                        if health.status_code == 200:
                            break
                    except httpx.ConnectError:
                        pass
                    await asyncio.sleep(0.05)
                else:
                    raise AssertionError("SMOKE_START_FAILED")
                assert health.json() == {"status": "ok"}
                asset = await client.get("/assets/multi-source-live.js")
                assert asset.status_code == 200 and b"MultiSourceLive" in asset.content
                status = (await client.get("/api/v1/live/status")).json()
                assert status["schema_version"] == "3"
                assert [item["role"] for item in status["roles"]] == ["application", "ssh"]
                async with client.stream("GET", "/api/v1/live/events") as response:
                    assert response.status_code == 200
                    lines = response.aiter_lines()
                    await _next_event(lines, "snapshot")
                    with application.open("a", encoding="utf-8") as file:
                        file.write(APPLICATION * 5)
                    first_id = await _next_event(lines, "observation_changes")
                    assert first_id is not None
                    await _next_event(lines, "analysis_changes")
                    with ssh.open("a", encoding="utf-8") as file:
                        file.write(SSH * 5)
                    await _next_event(lines, "observation_changes")
                    await _next_event(lines, "analysis_changes")
                async with client.stream("GET", "/api/v1/live/events",
                                         headers={"Last-Event-ID": first_id}) as response:
                    assert response.status_code == 200
                    lines = response.aiter_lines()
                    await _next_event(lines, "snapshot")
                    await _next_event(lines, "analysis_changes")
                with application.open("a", encoding="utf-8") as file:
                    file.write(APPLICATION * 240)
                for _ in range(300):
                    status = (await client.get("/api/v1/live/status")).json()
                    if status["evicted_total"] > 0:
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("SMOKE_EVICTION_MISSING")
                async with client.stream("GET", "/api/v1/live/events",
                                         headers={"Last-Event-ID": first_id}) as response:
                    assert response.status_code == 200
                    lines = response.aiter_lines()
                    await _next_event(lines, "replay_gap")
                    await _next_event(lines, "snapshot")
                replacement = root / "replacement.log"
                replacement.write_text(APPLICATION, encoding="utf-8")
                application.rename(root / "old_application.log")
                replacement.rename(application)
                for _ in range(300):
                    status = (await client.get("/api/v1/live/status")).json()
                    if status["service_state"] in ("DEGRADED", "FAILED"):
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("SMOKE_TERMINAL_FAILURE_MISSING")
                assert status["roles"][0]["service_state"] in ("DEGRADED", "FAILED")
                status = (await client.get("/api/v1/live/status")).json()
                assert all(item["detection_revision"] >= 1 for item in status["roles"])
                public = json.dumps(status) + (await client.get("/openapi.json")).text
                for canary in (str(application), str(ssh), "192.0.2.9", "198.51.100.23"):
                    assert canary not in public
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=10)
            assert service.active_connections == 0
            for worker in service.runtime.workers.values():
                assert worker._session._fd == -1
                assert worker._checkpoint._lock_fd == -1


if __name__ == "__main__":
    asyncio.run(smoke())
    print("internal pair loopback HTTP/SSE smoke: PASS")
