"""Development-only synthetic v3 publication timings; no SLA gate."""

import argparse
import asyncio
import math
from pathlib import Path
import statistics
import tempfile
from time import perf_counter

from fastapi.testclient import TestClient

from app.live_monitoring.pair_http import create_internal_pair_app
from app.live_monitoring.pair_publication import attach_pair_publication
from app.live_monitoring.pair_service import PairMonitoringService
from app.live_monitoring.multi_source import open_internal_pair_runtime
from app.monitor_setup import create_monitor_pair_config


APPLICATION = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")
CASES = ("two_role_status", "initial_sse_snapshot", "application_publication",
         "ssh_publication", "successive_pair_publication", "mixed_replay",
         "replay_gap", "status_http")


def _fixture(root: Path):
    application, ssh = root / "application.log", root / "ssh.log"
    application.write_text("", encoding="utf-8")
    ssh.write_text("", encoding="utf-8")
    config = root / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    return application, ssh, config


def _append(path: Path, line: str, count: int = 5):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(line * count)


def _settled(runtime, service):
    assert service.active_connections == 0
    for worker in runtime.workers.values():
        assert worker._session._fd == -1
        assert worker._checkpoint._lock_fd == -1
        assert worker._checkpoint._parent_fd == -1
        assert worker._session._active_lease is None
        assert worker._session._queue.item_count == 0
        assert worker._accumulator._active is None
        assert worker._analysis._active is None
        assert worker._publication._active is None


def _once(case: str) -> tuple[float, int]:
    with tempfile.TemporaryDirectory(prefix="pair-public-bench-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as name:
        application, ssh, config = _fixture(Path(name))
        if case == "status_http":
            app = create_internal_pair_app(config)
            with TestClient(app, base_url="http://127.0.0.1",
                            client=("127.0.0.1", 50000)) as client:
                started = perf_counter()
                response = client.get("/api/v1/live/status")
                elapsed = perf_counter() - started
                assert response.status_code == 200
                payload = len(response.content)
            _settled(app.state.pair_service.runtime, app.state.pair_service)
            return elapsed * 1000, payload
        runtime = open_internal_pair_runtime(config)
        publication = attach_pair_publication(runtime)
        service = PairMonitoringService(runtime, publication)
        try:
            if case == "two_role_status":
                started = perf_counter()
                payload = len(service.status().model_dump_json().encode("utf-8"))
            elif case == "initial_sse_snapshot":
                async def snapshot():
                    connection = service.open_connection(None)
                    stream = connection.stream()
                    try:
                        return len(await anext(stream))
                    finally:
                        await stream.aclose()
                started = perf_counter()
                payload = asyncio.run(snapshot())
            elif case in ("application_publication", "ssh_publication", "successive_pair_publication"):
                if case != "ssh_publication":
                    _append(application, APPLICATION)
                if case != "application_publication":
                    _append(ssh, SSH)
                started = perf_counter()
                if case == "successive_pair_publication":
                    runtime.cycle()
                    runtime.cycle()
                else:
                    runtime.cycle()
                payload = sum(len(event.encoded) for event in publication.replay_after(None).events)
            elif case in ("mixed_replay", "replay_gap"):
                _append(application, APPLICATION)
                _append(ssh, SSH)
                runtime.cycle()
                cursor = publication.replay_after(None).events[0].event_id
                started = perf_counter()
                if case == "replay_gap":
                    for _ in range(40):
                        _append(application, APPLICATION, 1)
                        runtime.cycle()
                replay = publication.replay_after(cursor)
                assert replay.status == ("GAP" if case == "replay_gap" else "REPLAY")
                payload = sum(len(event.encoded) for event in replay.events)
                if replay.status == "GAP":
                    payload = len((replay.gap_code or "").encode()) + sum(
                        len(role.encode()) for role in replay.affected_roles)
            else:
                raise RuntimeError("BENCHMARK_INVALID_CASE")
            elapsed = perf_counter() - started
            return elapsed * 1000, payload
        finally:
            asyncio.run(service.close())
            _settled(runtime, service)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--samples", type=int, default=10)
    args = parser.parse_args()
    if not 0 <= args.warmup <= 20 or not 3 <= args.samples <= 100:
        raise SystemExit("BENCHMARK_INVALID_LIMIT")
    print("case n median_ms p95_ms max_ms payload_bytes")
    for case in CASES:
        for _ in range(args.warmup):
            _once(case)
        values = sorted(_once(case) for _ in range(args.samples))
        times = [item[0] for item in values]
        sizes = [item[1] for item in values]
        print(f"{case} {len(times)} {statistics.median(times):.3f} "
              f"{times[math.ceil(.95 * len(times)) - 1]:.3f} {times[-1]:.3f} "
              f"{statistics.median(sizes):.0f}")


if __name__ == "__main__":
    main()
