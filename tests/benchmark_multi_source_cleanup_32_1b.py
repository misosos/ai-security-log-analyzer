"""Reproducible development timings for the private pair runtime; no SLA gate."""

import argparse
import math
from pathlib import Path
import statistics
import tempfile
from time import perf_counter

from app.live_monitoring.checkpoint import LiveCheckpointManager
from app.live_monitoring.multi_source import MultiSourceRuntimeError, open_internal_pair_runtime
from app.live_monitoring.worker import LiveProcessingWorker
from app.monitor_setup import create_monitor_pair_config


APPLICATION_LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH_LINE = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
            "from 198.51.100.23 port 5001 ssh2\n")
CASES = ("idle_cycle", "application_256_prefix", "ssh_256_prefix", "both_backlog_cycle",
         "application_checkpoint", "ssh_checkpoint", "normal_close", "fault_close")


def _fixture(root: Path):
    application = root / "application.log"
    ssh = root / "ssh.log"
    application.write_text(APPLICATION_LINE, encoding="utf-8")
    ssh.write_text(SSH_LINE, encoding="utf-8")
    config = root / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    return application, ssh, config


def _append(path: Path, line: str, count: int) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(line * count)


def _settled(runtime) -> None:
    for worker in runtime.workers.values():
        if (worker._session._fd != -1 or worker._checkpoint._lock_fd != -1
            or worker._checkpoint._parent_fd != -1 or worker._session._queue.item_count
            or worker._session._active_lease is not None
            or worker._accumulator._active is not None
            or worker._analysis._active is not None
            or worker._publication._active is not None):
            raise RuntimeError("BENCHMARK_RESOURCE_FAILURE")


def _once(case: str) -> float:
    with tempfile.TemporaryDirectory(prefix="pair-benchmark-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as directory:
        application, ssh, config = _fixture(Path(directory))
        runtime = open_internal_pair_runtime(config)
        original_commit = LiveCheckpointManager.commit_step
        original_close = LiveProcessingWorker.close
        measured = []
        try:
            if case == "idle_cycle":
                started = perf_counter()
                runtime.cycle()
                measured.append(perf_counter() - started)
            elif case in ("application_256_prefix", "ssh_256_prefix"):
                role = case.split("_256_")[0]
                _append(application if role == "application" else ssh,
                        APPLICATION_LINE if role == "application" else SSH_LINE, 256)
                started = perf_counter()
                while runtime.workers[role]._accumulator.snapshot().history_record_count < 256:
                    runtime.cycle()
                measured.append(perf_counter() - started)
            elif case == "both_backlog_cycle":
                _append(application, APPLICATION_LINE, 16)
                _append(ssh, SSH_LINE, 16)
                started = perf_counter()
                runtime.cycle()
                measured.append(perf_counter() - started)
            elif case in ("application_checkpoint", "ssh_checkpoint"):
                role = case.removesuffix("_checkpoint")

                def timed_commit(self, *args, **kwargs):
                    started = perf_counter()
                    try:
                        return original_commit(self, *args, **kwargs)
                    finally:
                        if self._config.source_role == role:
                            measured.append(perf_counter() - started)

                LiveCheckpointManager.commit_step = timed_commit
                _append(application if role == "application" else ssh,
                        APPLICATION_LINE if role == "application" else SSH_LINE, 1)
                runtime.cycle()
            elif case == "normal_close":
                started = perf_counter()
                runtime.close()
                measured.append(perf_counter() - started)
            elif case == "fault_close":
                def fault_ssh(self):
                    if self._session.source_role == "ssh":
                        original_close(self)
                        raise RuntimeError("PRIVATE_BENCHMARK_CANARY")
                    return original_close(self)

                LiveProcessingWorker.close = fault_ssh
                started = perf_counter()
                try:
                    runtime.close()
                except MultiSourceRuntimeError as error:
                    if error.code != "PAIR_CLOSE_FAILED" or "PRIVATE" in str(error):
                        raise RuntimeError("BENCHMARK_FAULT_CONTRACT") from None
                else:
                    raise RuntimeError("BENCHMARK_FAULT_NOT_OBSERVED")
                measured.append(perf_counter() - started)
            else:
                raise RuntimeError("BENCHMARK_INVALID_CASE")
        finally:
            LiveCheckpointManager.commit_step = original_commit
            LiveProcessingWorker.close = original_close
            if runtime.state != "STOPPED":
                try:
                    runtime.close()
                except MultiSourceRuntimeError:
                    pass
            _settled(runtime)
        if len(measured) != 1:
            raise RuntimeError("BENCHMARK_MEASUREMENT_FAILURE")
        return measured[0] * 1000


def main() -> None:
    parser = argparse.ArgumentParser(description="Private synthetic pair runtime benchmark")
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--samples", type=int, default=20)
    args = parser.parse_args()
    if not 0 <= args.warmup <= 20 or not 3 <= args.samples <= 100:
        raise SystemExit("BENCHMARK_INVALID_LIMIT")
    print("case n median_ms p95_ms max_ms")
    for case in CASES:
        for _ in range(args.warmup):
            _once(case)
        values = sorted(_once(case) for _ in range(args.samples))
        p95 = values[math.ceil(0.95 * len(values)) - 1]
        print(f"{case} {len(values)} {statistics.median(values):.3f} "
              f"{p95:.3f} {values[-1]:.3f}")


if __name__ == "__main__":
    main()
