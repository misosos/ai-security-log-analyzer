"""Development-only synthetic SSH checkpoint timings; never an operational SLA."""

import json
import math
from pathlib import Path
import statistics
import sys
from tempfile import TemporaryDirectory
from time import perf_counter_ns

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.local_web import _live_runtime
from app.live_monitoring import checkpoint as checkpoint_module
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from test_ssh_checkpoint_26_0 import _append, _close, _fixture, _line


COUNTS = (1, 16, 64, 128, 256)


def _summary(samples: list[float]) -> dict[str, float | int]:
    values = sorted(samples)
    return {"n": len(values), "median_ms": round(statistics.median(values), 3),
            "p95_ms": round(values[math.ceil(len(values) * 0.95) - 1], 3),
            "max_ms": round(values[-1], 3)}


def _measure_one(root: Path, count: int) -> dict[str, float]:
    source, config = _fixture(root)
    start = perf_counter_ns()
    initial, _ = _live_runtime(config, checkpoint_default=True)
    initial_ms = (perf_counter_ns() - start) / 1_000_000
    try:
        lines = tuple(_line(index % 60) for index in range(1, count + 1))
        for index in range(0, count, 16):
            _append(source, *lines[index:index + 16])
            initial._worker.step()
    finally:
        _close(initial)

    timings: dict[str, float] = {"initial": initial_ms}
    original_parse = checkpoint_module.parse_live_records
    original_digest = checkpoint_module._semantic_digest
    original_pread = checkpoint_module.os.pread
    original_read = checkpoint_module.LiveCheckpointManager._read_optional
    original_detection = LiveDetectionAccumulator.prepare
    original_analysis = LiveAnalysisAccumulator.prepare

    def timed(label, original):
        def measure(*args, **kwargs):
            started = perf_counter_ns()
            try:
                return original(*args, **kwargs)
            finally:
                timings[label] = timings.get(label, 0.0) + (perf_counter_ns() - started) / 1_000_000
        return measure

    checkpoint_module.parse_live_records = timed("parser", original_parse)
    checkpoint_module._semantic_digest = timed("semantic_digest", original_digest)
    checkpoint_module.os.pread = timed("file_replay_read", original_pread)
    checkpoint_module.LiveCheckpointManager._read_optional = timed("checkpoint_load", original_read)
    LiveDetectionAccumulator.prepare = timed("detection_prepare", original_detection)
    LiveAnalysisAccumulator.prepare = timed("analysis_prepare", original_analysis)
    try:
        started = perf_counter_ns()
        restored, _ = _live_runtime(config, checkpoint_default=True)
        timings["total_recovery"] = (perf_counter_ns() - started) / 1_000_000
    finally:
        checkpoint_module.parse_live_records = original_parse
        checkpoint_module._semantic_digest = original_digest
        checkpoint_module.os.pread = original_pread
        checkpoint_module.LiveCheckpointManager._read_optional = original_read
        LiveDetectionAccumulator.prepare = original_detection
        LiveAnalysisAccumulator.prepare = original_analysis
    try:
        started = perf_counter_ns()
        restored.status()
        timings["status"] = (perf_counter_ns() - started) / 1_000_000
        if count < 256:
            _append(source, _line(1, "Accepted"))
            started = perf_counter_ns()
            restored._worker.step()
            timings["first_append_step"] = (perf_counter_ns() - started) / 1_000_000
    finally:
        _close(restored)
    return timings


def main() -> None:
    result = {}
    scratch = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    with TemporaryDirectory(prefix="ssh-checkpoint-benchmark-", dir=scratch) as directory:
        root = Path(directory)
        for count in COUNTS:
            samples = [_measure_one(root / f"{count}-{attempt}", count)
                       for attempt in range(4)]
            # First iteration warms imports and filesystem caches; keep it out of stats.
            result[str(count)] = {key: _summary([item[key] for item in samples[1:]])
                                  for key in samples[0]}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
