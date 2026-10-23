"""Development-only multi-source UI/API latency sample. No SLA claim."""

import argparse
import asyncio
import json
import statistics
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import create_app
from app.local_web import _pair_runtime
from app.monitor_setup import create_monitor_pair_config

APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = "2026-01-02 03:04:05 sshd: Failed password for synthetic from 198.51.100.23 port 5001 ssh2\n"


def timed(samples, fn):
    for _ in range(3):
        fn()
    values = []
    payload = 0
    for _ in range(samples):
        before = time.perf_counter_ns()
        payload = int(fn() or 0)
        values.append((time.perf_counter_ns() - before) / 1_000_000)
    ordered = sorted(values)
    return {"samples": samples, "median_ms": round(statistics.median(values), 3),
            "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * .95))], 3),
            "max_ms": round(max(values), 3), "payload_bytes": payload}


def _distribution(values, payload_bytes=0):
    ordered = sorted(values)
    return {"samples": len(values), "median_ms": round(statistics.median(values), 3),
            "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * .95))], 3),
            "max_ms": round(max(values), 3), "payload_bytes": payload_bytes}


def _lifecycle_samples(root: Path, samples: int, *, checkpointed: bool):
    starts, closes = [], []
    payload = 0
    for index in range(samples + 3):
        case = root / f"lifecycle-{int(checkpointed)}-{index}"
        case.mkdir(mode=0o700)
        app, ssh, config = case / "application.log", case / "ssh.log", case / "private" / "monitoring.json"
        app.write_text("", encoding="utf-8"); ssh.write_text("", encoding="utf-8")
        create_monitor_pair_config(app, ssh, config)
        if checkpointed:
            seeded, _ = _pair_runtime(config)
            asyncio.run(seeded.close())
        before = time.perf_counter_ns()
        service, _ = _pair_runtime(config)
        start_ms = (time.perf_counter_ns() - before) / 1_000_000
        payload = len(service.status().model_dump_json())
        before = time.perf_counter_ns()
        asyncio.run(service.close())
        close_ms = (time.perf_counter_ns() - before) / 1_000_000
        if index >= 3:
            starts.append(start_ms); closes.append(close_ms)
    return _distribution(starts, payload), _distribution(closes)


def benchmark(samples=20):
    with tempfile.TemporaryDirectory(prefix="multi-source-32-3-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as directory:
        root = Path(directory)
        app, ssh, config = root / "application.log", root / "ssh.log", root / "private" / "monitoring.json"
        app.write_text("", encoding="utf-8"); ssh.write_text("", encoding="utf-8")
        create_monitor_pair_config(app, ssh, config)
        service, runner = _pair_runtime(config)
        runtime = service.runtime
        results = {}
        results["two_role_status"] = timed(samples, lambda: len(service.status().model_dump_json()))

        async def initial_sse():
            connection = service.open_connection(None)
            try:
                return len(await anext(connection.stream()))
            finally:
                connection.release()
        results["initial_sse_snapshot"] = timed(samples, lambda: asyncio.run(initial_sse()))

        def append_role(path, line, role):
            before = runtime.workers[role].snapshot().accumulator.revision
            with path.open("a", encoding="utf-8") as output: output.write(line)
            for _ in range(6):
                runtime.cycle()
                after = runtime.workers[role].snapshot().accumulator.revision
                if after > before: break
            return service.publication.byte_count

        results["application_append_to_publication"] = timed(samples, lambda: append_role(app, APP, "application"))
        results["ssh_append_to_publication"] = timed(samples, lambda: append_role(ssh, SSH, "ssh"))

        def both():
            before = {role: runtime.workers[role].snapshot().accumulator.revision for role in ("application", "ssh")}
            with app.open("a", encoding="utf-8") as out: out.write(APP)
            with ssh.open("a", encoding="utf-8") as out: out.write(SSH)
            for _ in range(6):
                runtime.cycle()
                if all(runtime.workers[role].snapshot().accumulator.revision > before[role]
                       for role in before): break
            return service.publication.byte_count
        results["both_role_publication"] = timed(samples, both)
        results["mixed_replay"] = timed(samples, lambda: len(service.publication.replay_after(None).events))
        with TestClient(create_app(live_monitoring_service=service), base_url="http://127.0.0.1",
                        client=("127.0.0.1", 12345)) as client:
            results["status_http"] = timed(samples, lambda: len(client.get("/api/v1/live/status").content))

        asyncio.run(service.close())
        results["v3_server_start"], fresh_close = _lifecycle_samples(root, samples, checkpointed=False)
        results["checkpoint_restart"], results["normal_close"] = _lifecycle_samples(
            root, samples, checkpointed=True)
        results["normal_close"]["payload_bytes"] = fresh_close["payload_bytes"]
        print(json.dumps({"environment": "local developer machine; synthetic files", "warmup": 3,
                          "sample_count": samples, "operations": results,
                          "interpretation": "Development measurements only; not an operating SLA or worst-case bound."},
                         sort_keys=True, indent=2))
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=20)
    benchmark(max(5, parser.parse_args().samples))
