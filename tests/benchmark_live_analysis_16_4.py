"""Opt-in synthetic Phase 16.4 measurements; not an operational SLA."""

import json
import statistics
import tempfile
import time
from pathlib import Path

from app import local_web
from tests.benchmark_live_analysis_16_2 import _run_one, _stats, _status_while_runner_runs


WARMUPS = 2
SAMPLES = 12


def _empty_step():
    with tempfile.TemporaryDirectory(prefix="live-audit-benchmark-") as root:
        source = Path(root) / "synthetic.log"
        source.write_bytes(b"old line\n")
        config = Path(root) / "live.json"
        config.write_text(json.dumps({
            "schema_version": "1", "start_policy": "FROM_END",
            "source": {"role": "application", "path": str(source.resolve())},
        }), encoding="utf-8")
        config.chmod(0o600)
        service, _ = local_web._live_runtime(config.resolve())
        try:
            start = time.perf_counter_ns()
            assert service._worker.step().status == "NO_DATA"
            step_ms = (time.perf_counter_ns() - start) / 1e6
        finally:
            start = time.perf_counter_ns()
            service._worker.close()
            shutdown_ms = (time.perf_counter_ns() - start) / 1e6
        assert service._worker._session._fd == -1
        return step_ms, shutdown_ms


def main():
    prefixes = {}
    for prefix in (16, 64, 128, 256):
        for _ in range(WARMUPS):
            _run_one(prefix=prefix)
        samples = [_run_one(prefix=prefix) for _ in range(SAMPLES)]
        prefixes[str(prefix)] = {
            "events": prefix,
            "raw_bytes": samples[0]["raw_bytes"],
            "detections": samples[0]["detections"],
            "relations": samples[0]["relations"],
            "risks": samples[0]["risks"],
            "cases": samples[0]["cases"],
            **{key: _stats([sample[key] for sample in samples]) for key in (
                "worker_ms", "detection_ms", "analysis_ms", "publication_prepare_ms",
                "publication_commit_ms", "commit_ms", "serialization_ms",
                "snapshot_serialization_ms",
            )},
        }
    for _ in range(WARMUPS):
        _empty_step()
    empty = [_empty_step() for _ in range(SAMPLES)]
    print(json.dumps({
        "warmups": WARMUPS,
        "samples": SAMPLES,
        "tracemalloc": False,
        "empty_worker_ms": _stats([sample[0] for sample in empty]),
        "shutdown_ms": _stats([sample[1] for sample in empty]),
        "prefixes": prefixes,
        "runner_status": _status_while_runner_runs(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
