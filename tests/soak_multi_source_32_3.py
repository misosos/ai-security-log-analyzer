"""Bounded synthetic append soak; intentionally not a production SLA test."""

import asyncio
import tempfile
import tracemalloc
from pathlib import Path

from app.local_web import _pair_runtime
from app.live_monitoring.multi_source import MultiSourceRuntimeError
from app.monitor_setup import create_monitor_pair_config

APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = "2026-01-02 03:04:05 sshd: Failed password for synthetic from 198.51.100.23 port 5001 ssh2\n"


def main(cycles=500):
    with tempfile.TemporaryDirectory(prefix="pair-soak-32-3-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as directory:
        root = Path(directory)
        app, ssh, config = root / "application.log", root / "ssh.log", root / "private" / "monitoring.json"
        app.write_text("", encoding="utf-8"); ssh.write_text("", encoding="utf-8")
        create_monitor_pair_config(app, ssh, config)
        service, runner = _pair_runtime(config)
        tracemalloc.start(); baseline = tracemalloc.get_traced_memory()[0]
        for _ in range(cycles):
            with app.open("a", encoding="utf-8") as out: out.write(APP)
            with ssh.open("a", encoding="utf-8") as out: out.write(SSH)
            try:
                service.runtime.cycle()
                service.runtime.cycle()
            except MultiSourceRuntimeError:
                snapshots = {role: worker.snapshot() for role, worker in service.runtime.workers.items()}
                raise AssertionError({"code": "PAIR_SOAK_TERMINAL", "states": {
                    role: {"state": snapshot.state.value, "error": snapshot.fixed_error_code,
                          "queue": snapshot.session.queue_item_count}
                    for role, snapshot in snapshots.items()}}) from None
            status = service.status()
            assert status.available_event_count <= 32 and status.event_byte_count <= 16384
            assert all(worker.snapshot().session.queue_item_count <= 32
                       for worker in service.runtime.workers.values())
        current, peak = tracemalloc.get_traced_memory()
        assert all(worker.snapshot().accumulator.revision >= cycles
                   for worker in service.runtime.workers.values())
        assert service.active_connections == 0
        fds = [worker._session._fd for worker in service.runtime.workers.values()]
        asyncio.run(service.close())
        assert all(worker._session._fd == -1 and worker._checkpoint._lock_fd == -1
                   for worker in service.runtime.workers.values())
        tracemalloc.stop()
        assert all(fd >= 0 for fd in fds)
        print({"cycles_per_role": cycles, "event_buffer_items": status.available_event_count,
               "event_buffer_bytes": status.event_byte_count, "traced_memory_growth_bytes": current - baseline,
               "traced_memory_peak_bytes": peak, "owned_fd_count_before_close": len(fds),
               "owned_fds_closed": True,
               "listeners_after_close": 0, "active_connections_after_close": service.active_connections,
               "interpretation": "Synthetic development soak; not an operating stability or latency SLA."})


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=150)
    main(max(1, parser.parse_args().cycles))
