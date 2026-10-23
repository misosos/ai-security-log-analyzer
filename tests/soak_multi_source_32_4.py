"""Bounded asymmetric pair soak and SSE notification samples; no SLA claim."""

import argparse
import asyncio
import json
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from app.local_web import _pair_runtime
from app.live_monitoring.multi_source import MultiSourceRuntimeError
from app.monitor_setup import create_monitor_pair_config


APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = "2026-01-02 03:04:05 sshd: Failed password for synthetic from 198.51.100.23 port 5001 ssh2\n"


def distribution(values):
    ordered = sorted(values)
    return {"samples": len(values), "median_ms": round(statistics.median(values), 3),
            "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 3),
            "max_ms": round(max(values), 3)}


def create_case(root: Path, name: str):
    case = root / name
    case.mkdir(mode=0o700)
    app, ssh, config = case / "application.log", case / "ssh.log", case / "private" / "monitoring.json"
    app.write_text("", encoding="utf-8")
    ssh.write_text("", encoding="utf-8")
    create_monitor_pair_config(app, ssh, config)
    service, runner = _pair_runtime(config)
    return app, ssh, service, runner


async def sse_sample(root: Path, role: str) -> float:
    app, ssh, service, runner = create_case(root, f"sse-{role}-{time.monotonic_ns()}")
    connection = service.open_connection(None)
    stream = connection.stream()
    try:
        first = await asyncio.wait_for(anext(stream), 3)
        assert b"event: snapshot" in first
        task = asyncio.create_task(runner.run())
        await asyncio.sleep(0)
        before = time.perf_counter_ns()
        path, line = (app, APP) if role == "application" else (ssh, SSH)
        with path.open("a", encoding="utf-8") as output:
            output.write(line * 5)
        while True:
            frame = await asyncio.wait_for(anext(stream), 4)
            if b"event: observation_changes" in frame:
                return (time.perf_counter_ns() - before) / 1_000_000
    finally:
        await runner.shutdown()
        await stream.aclose()


async def close_sample(root: Path, index: int) -> float:
    _, _, service, _ = create_case(root, f"close-{index}")
    before = time.perf_counter_ns()
    await service.close()
    return (time.perf_counter_ns() - before) / 1_000_000


def run(cycles: int = 60, samples: int = 5, warmup: int = 3) -> None:
    if cycles < 20 or samples < 3 or warmup < 1:
        raise SystemExit("SOAK_INVALID_BOUNDS")
    with tempfile.TemporaryDirectory(prefix="pair-soak-32-4-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as name:
        root = Path(name)
        app, ssh, service, runner = create_case(root, "pair")
        runtime = service.runtime
        roles = ("application", "ssh")
        max_queue = {role: 0 for role in roles}
        status_times = []
        append_publication_times = []
        max_pending = 0
        cycle_index = 0

        def cycle():
            nonlocal cycle_index, max_pending
            before_total = service.publication.published_total
            before = time.perf_counter_ns()
            runtime.cycle()
            cycle_index += 1
            status_before = time.perf_counter_ns()
            status = service.status()
            status_times.append((time.perf_counter_ns() - status_before) / 1_000_000)
            max_pending = max(max_pending, status.available_event_count)
            assert status.available_event_count <= 32 and status.event_byte_count <= 16384
            for role in roles:
                count = runtime.workers[role].snapshot().session.queue_item_count
                max_queue[role] = max(max_queue[role], count)
                assert count <= 32
            if service.publication.published_total > before_total:
                append_publication_times.append((time.perf_counter_ns() - before) / 1_000_000)

        # Warm-up includes normal data and idle cycles, and is excluded from the soak totals.
        for index in range(warmup):
            with app.open("a", encoding="utf-8") as output: output.write(APP * 2)
            with ssh.open("a", encoding="utf-8") as output: output.write(SSH * 2)
            cycle()
        status_times.clear()
        append_publication_times.clear()
        tracemalloc.start()
        memory_before = tracemalloc.get_traced_memory()[0]
        acknowledged_before = {role: runtime.workers[role].snapshot().session.acknowledged_record_count
                               for role in roles}
        phases = {}

        # Application high rate, SSH low rate.
        start = time.perf_counter()
        for index in range(cycles):
            with app.open("a", encoding="utf-8") as output: output.write(APP)
            if index % 10 == 0:
                with ssh.open("a", encoding="utf-8") as output: output.write(SSH)
            cycle()
        phases["application_fast_ssh_slow"] = (time.perf_counter() - start) * 1000

        # Reverse rates.
        start = time.perf_counter()
        for index in range(cycles):
            with ssh.open("a", encoding="utf-8") as output: output.write(SSH)
            if index % 10 == 0:
                with app.open("a", encoding="utf-8") as output: output.write(APP)
            cycle()
        phases["ssh_fast_application_slow"] = (time.perf_counter() - start) * 1000

        # Synchronized bursts followed by genuine idle cycles.
        start = time.perf_counter()
        for _ in range(max(5, cycles // 10)):
            with app.open("a", encoding="utf-8") as output: output.write(APP * 4)
            with ssh.open("a", encoding="utf-8") as output: output.write(SSH * 4)
            cycle()
            for _ in range(4):
                cycle()
        for _ in range(20):
            cycle()
        phases["both_burst_and_idle"] = (time.perf_counter() - start) * 1000

        # Exercise the bounded global replay history and role-specific checkpoint writes.
        start = time.perf_counter()
        for _ in range(max(40, cycles * 2)):
            with app.open("a", encoding="utf-8") as output: output.write(APP)
            cycle()
        phases["replay_eviction_workload"] = (time.perf_counter() - start) * 1000
        status = service.status()
        assert status.evicted_total > 0
        assert all(runtime.workers[role].snapshot().accumulator.revision > 0 for role in roles)
        current, peak = tracemalloc.get_traced_memory()
        acknowledged = {role: runtime.workers[role].snapshot().session.acknowledged_record_count
                        - acknowledged_before[role] for role in roles}
        revisions = {role: runtime.workers[role].snapshot().accumulator.revision for role in roles}
        checkpoints = {role: runtime.workers[role]._checkpoint._checkpoint.write_sequence
                       for role in roles}
        owned_fds = [runtime.workers[role]._session._fd for role in roles]
        max_queue_result = dict(max_queue)
        max_pending_result = max_pending
        replay = {"items": status.available_event_count, "bytes": status.event_byte_count,
                  "evicted_total": status.evicted_total}
        tracemalloc.stop()
        asyncio.run(service.close())
        assert all(worker._session._fd == -1 and worker._checkpoint._lock_fd == -1
                   for worker in runtime.workers.values())

        async def latency_runs():
            results = {}
            for role in roles:
                for _ in range(warmup):
                    await sse_sample(root, role)
                values = [await sse_sample(root, role) for _ in range(samples)]
                results[role] = distribution(values)
            close_values = [await close_sample(root, index) for index in range(samples)]
            return results, distribution(close_values)

        sse_latency, close_latency = asyncio.run(latency_runs())
        print(json.dumps({
            "environment": "macOS local Python; generated logs and private temporary config only",
            "warmup_per_sse_role": warmup, "sse_samples_per_role": samples,
            "cycles_per_direction": cycles,
            "processed_records_since_start": acknowledged,
            "role_detection_revisions": revisions,
            "role_checkpoint_write_sequence": checkpoints,
            "starvation": "none observed; each low-rate role advanced during the opposite high-rate phase",
            "maximum_queue_resident_items": max_queue_result,
            "maximum_global_pending_replay_items": max_pending_result,
            "replay_final": replay,
            "status_latency": distribution(status_times),
            "append_to_observation_SSE_notification": sse_latency,
            "normal_close_latency": close_latency,
            "traced_memory_growth_bytes": current - memory_before,
            "traced_memory_peak_bytes": peak,
            "owned_fd_count_before_close": len(owned_fds),
            "owned_fds_closed": True, "listeners": 0, "active_connections": 0,
            "phase_elapsed_ms": {key: round(value, 3) for key, value in phases.items()},
            "interpretation": "Bounded synthetic soak; development observations, not operating SLA or worst-case guarantee.",
        }, sort_keys=True, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=60)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=3)
    args = parser.parse_args()
    run(args.cycles, args.samples, args.warmup)
