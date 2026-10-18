"""Synthetic, test-only Vector 0.59.0 Unix-socket feasibility harness.

This module is never imported by production. Isolated execution receives only
the pinned binary, this script, and a private scratch directory. It emits safe
counts/digests, never captured SSH payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time


MAX_FRAME = 4096
PROJECT_MAX_LINE = 2048
MAX_RECORDS = 256
MAX_HISTORY_BYTES = 256 * 1024
MARKER = re.compile(rb"PILOT_SEQ=(\d{1,4})$")
SAFE_ERROR = "PILOT_FAILED"
PRIVACY_CANARIES = (b"ACCOUNT_CANARY", b"IP_CANARY", b"FILENAME_CANARY",
                    b"QUERY_CANARY", b"RAW_LINE_CANARY", b"EXCEPTION_CANARY")


def synthetic_line(number: int, *, accepted: bool = False, suffix: bytes = b"") -> bytes:
    """The marker is fixture-only; real SSH logs have no delivery sequence."""
    second = number % 60
    action = b"Accepted" if accepted else b"Failed"
    line = (b"2026-01-02 03:04:" + f"{second:02d}".encode() + b" sshd: " + action
            + b" password for pilot from 192.0.2.10 port 5001 ssh2: "
            + suffix + b" PILOT_SEQ=" + str(number).encode())
    return line + b"\n"


def safe_digest(records: tuple[bytes, ...] | list[bytes]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(record)
    return digest.hexdigest()


class BoundedReceiver:
    """One active Unix stream, strict LF frames, bounded trusted history."""

    def __init__(self, path: Path):
        self.path = path
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.settimeout(0.2)
        self.listener.bind(str(path))
        os.chmod(path, 0o600)
        self.listener.listen(1)
        self.records: list[bytes] = []
        self.total_bytes = 0
        self.error: str | None = None
        self.connections = 0
        self.peer_uid_verified = False
        self._active: socket.socket | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._read_enabled = threading.Event()
        self._read_enabled.set()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                with self._lock:
                    self._active = connection
                    self.connections += 1
                if hasattr(socket, "SO_PEERCRED"):
                    try:
                        import struct
                        credential = connection.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                        _pid, uid, _gid = struct.unpack("3i", credential)
                        self.peer_uid_verified = uid == os.getuid()
                    except OSError:
                        self.error = "PEER_CHECK_FAILED"
                    if not self.peer_uid_verified:
                        self.error = "PEER_CHECK_FAILED"
                connection.settimeout(0.2)
                pending = bytearray()
                while not self._stop.is_set() and self.error is None:
                    if not self._read_enabled.wait(0.2):
                        continue
                    try:
                        chunk = connection.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    pending.extend(chunk)
                    while b"\n" in pending:
                        end = pending.index(b"\n") + 1
                        frame = bytes(pending[:end])
                        del pending[:end]
                        if len(frame) > MAX_FRAME:
                            self.error = "FRAME_TOO_LARGE"
                            break
                        try:
                            frame.decode("utf-8", errors="strict")
                        except UnicodeDecodeError:
                            self.error = "FRAME_NOT_UTF8"
                            break
                        with self._lock:
                            if (len(self.records) >= MAX_RECORDS or
                                    self.total_bytes + len(frame) > MAX_HISTORY_BYTES):
                                self.error = "HISTORY_FULL"
                                break
                            self.records.append(frame)
                            self.total_bytes += len(frame)
                    if len(pending) > MAX_FRAME:
                        self.error = "FRAME_TOO_LARGE"
                with self._lock:
                    self._active = None

    def snapshot(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self.records)

    def wait_count(self, count: int, seconds: float = 8.0) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.error is not None:
                return False
            if len(self.snapshot()) >= count:
                return True
            time.sleep(0.05)
        return False

    def pause(self) -> None:
        self._read_enabled.clear()

    def resume(self) -> None:
        self._read_enabled.set()

    def disconnect(self) -> None:
        with self._lock:
            active = self._active
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self._read_enabled.set()
        self.disconnect()
        self.listener.close()
        self._thread.join(timeout=2)
        if self.path.exists():
            self.path.unlink()

    def safe_summary(self) -> dict[str, object]:
        records = self.snapshot()
        sequence = []
        for record in records:
            match = MARKER.search(record.rstrip(b"\n"))
            sequence.append(int(match.group(1)) if match else None)
        return {
            "count": len(records), "bytes": sum(map(len, records)),
            "sequence": sequence, "sha256": safe_digest(records),
            "connections": self.connections,
            "peer_uid_verified": self.peer_uid_verified,
            "error": self.error,
        }


def private_file(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def append(path: Path, *lines: bytes) -> None:
    with path.open("ab", buffering=0) as stream:
        for line in lines:
            stream.write(line)
        os.fsync(stream.fileno())


def make_config(directory: Path, *, read_from: str = "end") -> Path:
    config = {
        "data_dir": str(directory / "state"),
        "api": {"enabled": False},
        "sources": {"ssh_file": {
            "type": "file", "include": [str(directory / "ssh.log")],
            "read_from": read_from, "glob_minimum_cooldown_ms": 100,
            "fingerprint": {"strategy": "device_and_inode"},
            "file_key": "", "host_key": "", "max_line_bytes": PROJECT_MAX_LINE,
        }},
        "sinks": {"private_socket": {
            "type": "socket", "inputs": ["ssh_file"],
            "mode": "unix_stream", "path": str(directory / "receiver.sock"),
            "encoding": {"codec": "raw_message"},
            "framing": {"method": "newline_delimited"},
            "buffer": {"type": "memory", "max_events": 32, "when_full": "block"},
        }},
    }
    (directory / "state").mkdir(mode=0o700)
    path = directory / "vector.json"
    private_file(path, (json.dumps(config, sort_keys=True) + "\n").encode())
    return path


def child_limits() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))


def start_vector(binary: Path, config: Path) -> tuple[subprocess.Popen[bytes], float]:
    started = time.monotonic()
    out_fd = os.open(config.parent / "vector.stdout", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    err_fd = os.open(config.parent / "vector.stderr", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        process = subprocess.Popen(
            [str(binary), "--config-json", str(config)],
            stdin=subprocess.DEVNULL, stdout=out_fd, stderr=err_fd,
            env={"HOME": "/tmp", "XDG_CONFIG_HOME": "/tmp", "XDG_CACHE_HOME": "/tmp",
                 "VECTOR_LOG": "error", "PATH": "/usr/local/bin:/usr/bin:/bin"},
            start_new_session=True, preexec_fn=child_limits,
        )
    finally:
        os.close(out_fd)
        os.close(err_fd)
    return process, started


def stop_vector(process: subprocess.Popen[bytes], directory: Path) -> dict[str, object]:
    started = time.monotonic()
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
        timed_out = True
    else:
        timed_out = False
    stdout = (directory / "vector.stdout").read_bytes()[:1024 * 1024 + 1]
    stderr = (directory / "vector.stderr").read_bytes()[:1024 * 1024 + 1]
    combined = stdout + stderr
    return {"exit": process.returncode,
            "shutdown_ms": round((time.monotonic()-started)*1000),
            "timeout": timed_out, "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "output_over_limit": len(stdout) > 1024 * 1024 or len(stderr) > 1024 * 1024,
            "source_path_visible": b"/tmp/pilot/" in combined,
            "raw_payload_visible": b"PILOT_SEQ=" in combined,
            "ip_visible": b"192.0.2.10" in combined,
            "account_visible": b"pilot from" in combined,
            "privacy_canary_visible": any(canary in combined for canary in PRIVACY_CANARIES)}


def inspect_private_state(directory: Path) -> dict[str, object]:
    state = directory / "state"
    members = sorted(state.rglob("*"))[:129] if state.exists() else []
    regular = [item for item in members if item.is_file() and not item.is_symlink()]
    contents = b"".join(item.read_bytes()[:1024 * 1024] for item in regular)
    return {"file_count": len(regular), "directory_count": sum(item.is_dir() for item in members),
            "scan_limit_exceeded": len(members) > 128,
            "unexpected_type": any(item.is_symlink() or not (item.is_file() or item.is_dir())
                                   for item in members),
            "file_modes": [oct(item.stat().st_mode & 0o777) for item in regular],
            "directory_mode": oct(state.stat().st_mode & 0o777) if state.exists() else None,
            "total_bytes": sum(item.stat().st_size for item in regular),
            "source_path_literal": b"/tmp/pilot/" in contents,
            "file_name_literal": b"ssh.log" in contents,
            "raw_marker_literal": b"PILOT_SEQ=" in contents,
            "ip_literal": b"192.0.2.10" in contents,
            "privacy_canary_literal": any(canary in contents for canary in PRIVACY_CANARIES),
            "offset_field_name": b"offset" in contents.lower(),
            "fingerprint_field_name": b"fingerprint" in contents.lower(),
            "inode_field_name": b"inode" in contents.lower()}


def classify(expected: list[bytes], actual: tuple[bytes, ...]) -> dict[str, object]:
    expected_sequence = [int(MARKER.search(line.rstrip(b"\n")).group(1)) for line in expected]
    received_sequence = [int(match.group(1)) if (match := MARKER.search(line.rstrip(b"\n")))
                         else None for line in actual]
    return {
        "expected_sequence": expected_sequence,
        "received_sequence": received_sequence,
        "byte_equal": list(actual) == expected,
        "duplicate": len(received_sequence) - len(set(received_sequence)),
        "gap": [item for item in expected_sequence if item not in received_sequence],
        "order_equal": received_sequence == expected_sequence,
        "expected_sha256": safe_digest(expected),
        "received_sha256": safe_digest(actual),
    }


def run_scenario(binary: Path, root: Path, name: str) -> dict[str, object]:
    directory = root / name
    directory.mkdir(mode=0o700)
    source = directory / "ssh.log"
    private_file(source, synthetic_line(0))
    receiver = BoundedReceiver(directory / "receiver.sock")
    config = make_config(directory)
    validation_started = time.monotonic()
    validate_out = directory / "validate.stdout"
    validate_err = directory / "validate.stderr"
    out_fd = os.open(validate_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    err_fd = os.open(validate_err, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        validation = subprocess.run(
            [str(binary), "validate", "--skip-healthchecks", "--config-json", str(config)],
            stdout=out_fd, stderr=err_fd, timeout=12, check=False, preexec_fn=child_limits,
            env={"HOME": "/tmp", "XDG_CONFIG_HOME": "/tmp", "XDG_CACHE_HOME": "/tmp",
                 "PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
    finally:
        os.close(out_fd)
        os.close(err_fd)
    validation_ms = round((time.monotonic() - validation_started) * 1000)
    validation_stdout = validate_out.read_bytes()
    validation_stderr = validate_err.read_bytes()
    validation_output = validation_stdout + validation_stderr
    if validation.returncode:
        receiver.close()
        return {"scenario": name, "status": "CONFIG_INVALID", "validation_exit": validation.returncode,
                "validation_stdout_bytes": len(validation_stdout),
                "validation_stderr_bytes": len(validation_stderr)}
    process, started = start_vector(binary, config)
    expected: list[bytes] = []
    process_summaries: list[dict[str, object]] = []
    try:
        # File discovery and socket connection; no pre-existing line may appear.
        time.sleep(0.8)
        if name in {"startup", "normal", "analysis", "bulk64", "partial", "long", "invalid_utf8", "privacy", "restart", "fresh", "rename", "copytruncate", "disconnect", "backpressure"}:
            first = synthetic_line(1)
            if name == "partial":
                midpoint = first.index(b"PILOT_SEQ")
                append(source, first[:midpoint] + "한".encode()[:1])
                time.sleep(0.5)
                before_lf = receiver.safe_summary()["count"]
                error_before_lf = receiver.error
                append(source, "한".encode()[1:] + first[midpoint:])
                expected.append(first[:midpoint] + "한".encode() + first[midpoint:])
            elif name == "normal":
                expected = [synthetic_line(index) for index in range(1, 17)]
                expected.extend([synthetic_line(17), synthetic_line(17)])
                append(source, *expected)
            elif name == "analysis":
                expected = [synthetic_line(index) for index in range(1, 6)]
                expected.append(synthetic_line(6, accepted=True))
                append(source, *expected)
            elif name == "bulk64":
                expected = [synthetic_line(index) for index in range(1, 65)]
                append(source, *expected)
            elif name == "long":
                expected = [synthetic_line(1, suffix=b"X" * (PROJECT_MAX_LINE - 1 - len(first))),
                            synthetic_line(2, suffix=b"Y" * (PROJECT_MAX_LINE + 2 - len(first)))]
                append(source, *expected)
            elif name == "invalid_utf8":
                expected = [synthetic_line(1, suffix=b"\xff")]
                append(source, *expected)
            elif name == "privacy":
                expected = [synthetic_line(1, suffix=b" ".join(PRIVACY_CANARIES))]
                append(source, *expected)
            elif name == "backpressure":
                receiver.pause()
                expected = [synthetic_line(index) for index in range(1, 257)]
                append(source, *expected)
                time.sleep(0.7)
                receiver.resume()
            else:
                expected.append(first)
                append(source, first)
        receiver.wait_count(min(len(expected), MAX_RECORDS), 6)
        first_delivery_ms = round((time.monotonic() - started) * 1000)
        if name == "restart":
            process_summaries.append(stop_vector(process, config.parent))
            second = synthetic_line(2, accepted=True)
            append(source, second)
            expected.append(second)
            process, _ = start_vector(binary, config)
            receiver.wait_count(2, 7)
        elif name == "fresh":
            process_summaries.append(stop_vector(process, config.parent))
            # A fresh *different* state directory preserves FROM_END, not continuity.
            new_directory = root / "fresh_second"
            new_directory.mkdir(mode=0o700)
            new_source = new_directory / "ssh.log"
            private_file(new_source, b"".join(expected))
            receiver.close()
            receiver = BoundedReceiver(new_directory / "receiver.sock")
            config = make_config(new_directory)
            process, _ = start_vector(binary, config)
            time.sleep(0.8)
            second = synthetic_line(2)
            append(new_source, second)
            expected = [second]
            receiver.wait_count(1, 7)
        elif name == "rename":
            with source.open("ab", buffering=0) as old_writer:
                source.rename(directory / "ssh.log.1")
                private_file(source, b"")
                second = synthetic_line(2)
                late = synthetic_line(3)
                append(source, second)
                old_writer.write(late)
                old_writer.flush()
                expected.extend([second, late])
            receiver.wait_count(3, 7)
        elif name == "copytruncate":
            (directory / "ssh.log.1").write_bytes(source.read_bytes())
            with source.open("wb") as stream:
                stream.truncate(0)
            second = synthetic_line(2)
            append(source, second)
            expected.append(second)
            receiver.wait_count(2, 7)
        elif name == "disconnect":
            receiver.disconnect()
            time.sleep(0.3)
            second = synthetic_line(2)
            append(source, second)
            expected.append(second)
            receiver.wait_count(2, 7)
        observed = receiver.snapshot()
        summary = {"scenario": name, "status": "OBSERVED", **classify(expected, observed),
                   "receiver": receiver.safe_summary(),
                   "validation_ms": validation_ms,
                   "validation_source_path_visible": b"/tmp/pilot/" in validation_output,
                   "validation_raw_payload_visible": b"PILOT_SEQ=" in validation_output,
                   "delivery_ms": first_delivery_ms,
                   "before_lf": before_lf if name == "partial" else None,
                   "error_before_lf": error_before_lf if name == "partial" else None}
        return summary
    finally:
        process_summaries.append(stop_vector(process, config.parent))
        receiver.close()
        if "summary" in locals():
            summary["processes"] = process_summaries
            summary["state"] = inspect_private_state(directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--summary-output", type=Path)
    parser.add_argument("--verify-summary", type=Path)
    parser.add_argument("--summarize-runs", type=Path, nargs="+")
    parser.add_argument("--scenario", choices=(
        "startup", "normal", "analysis", "bulk64", "partial", "long", "invalid_utf8", "privacy", "restart",
        "fresh", "rename", "copytruncate", "disconnect", "backpressure"))
    args = parser.parse_args(argv)
    if args.verify_summary is not None:
        return verify_analysis_summary(args.verify_summary)
    if args.summarize_runs is not None:
        return summarize_runs(args.summarize_runs)
    if args.binary is None or args.work is None or args.summary_output is None:
        print(SAFE_ERROR)
        return 2
    try:
        if not args.binary.is_file() or args.work.exists() or args.summary_output.exists():
            print(SAFE_ERROR)
            return 2
        args.work.mkdir(mode=0o700)
    except OSError:
        print(SAFE_ERROR)
        return 2
    scenarios = ("startup", "normal", "analysis", "bulk64", "partial", "long", "invalid_utf8", "privacy", "restart", "fresh",
                 "rename", "copytruncate", "disconnect", "backpressure")
    if args.scenario is not None:
        scenarios = (args.scenario,)
    results = []
    for name in scenarios:
        try:
            results.append(run_scenario(args.binary, args.work, name))
        except Exception as error:
            results.append({"scenario": name, "status": "HARNESS_ERROR",
                            "error_type": type(error).__name__,
                            "error_errno": getattr(error, "errno", None)})
    output = args.summary_output
    private_file(output, (json.dumps(results, sort_keys=True, separators=(",", ":")) + "\n").encode())
    print("VECTOR_PILOT_SCENARIOS", len(results))
    return 0 if all(item["status"] == "OBSERVED" for item in results) else 1


def verify_analysis_summary(summary_path: Path) -> int:
    """Host-only: match Vector's synthetic digest, then run batch/live oracles."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        summaries = json.loads(summary_path.read_text(encoding="utf-8"))
        observed = next(item for item in summaries if item["scenario"] == "analysis")
        expected_lines = [synthetic_line(index) for index in range(1, 6)]
        expected_lines.append(synthetic_line(6, accepted=True))
        if (not observed["byte_equal"] or observed["received_sha256"] != safe_digest(expected_lines)
                or observed["received_sequence"] != list(range(1, 7))):
            print("VECTOR_ANALYSIS_BYTES_NOT_EQUAL")
            return 1

        from tempfile import TemporaryDirectory
        from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
        from app.analyzer.pipeline import assess_risk_with_metadata, correlate_attacks, detect_attacks
        from app.live_monitoring import (LiveDetectionAccumulator, LiveMonitorConfig,
                                         LiveProcessingWorker, open_live_tail_session)
        from app.loader.file_loader import load_log_lines
        from app.parser.registry import get_parser, get_timezone
        from app.parser.time_utils import normalize_to_utc

        with TemporaryDirectory(prefix="v251-parity-", dir="/tmp") as directory:
            source = Path(directory) / "synthetic.log"
            private_file(source, synthetic_line(0))
            session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
            detector = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
            worker = LiveProcessingWorker(session, detector, 16, 4096)
            try:
                append(source, *expected_lines)
                worker.step()
                live_events = tuple(detector._history)
                batch_source = Path(directory) / "batch.log"
                private_file(batch_source, b"".join(expected_lines))
                parser_func = get_parser("ssh")
                timezone_name = get_timezone("ssh")
                batch_items = []
                for line in load_log_lines(batch_source):
                    event = parser_func(line, timezone_name)
                    event.timestamp = normalize_to_utc(event.timestamp)
                    batch_items.append(event)
                batch_events = tuple(batch_items)
                if live_events != batch_events:
                    print("VECTOR_NORMALIZED_PARITY_FAILED")
                    return 1
                detection = detect_attacks(batch_events)
                analysis = assess_risk_with_metadata(correlate_attacks(batch_events, detection), {})
                cases = project_investigation_cases_from_analysis(analysis)
                if (worker._analysis._state._results != analysis["results"]
                        or worker._analysis._state._projection != cases
                        or not analysis["results"]["192.0.2.10"]["detections"]["brute_force"].is_detected
                        or not analysis["results"]["192.0.2.10"]["correlation"][
                            "brute_force_to_success"]["is_correlated"]
                        or not cases.cases):
                    print("VECTOR_ANALYSIS_PARITY_FAILED")
                    return 1
            finally:
                worker.close()
        print("VECTOR_BATCH_TAIL_PARITY_PASS normalized_detection_relation_risk_case")
        return 0
    except Exception as error:
        print("VECTOR_PARITY_HARNESS_ERROR", type(error).__name__)
        return 1


def summarize_runs(paths: list[Path]) -> int:
    """Report only bounded development timings, never raw captures or paths."""
    try:
        runs = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        names = ("startup", "normal", "analysis", "bulk64", "partial", "restart",
                 "rename", "copytruncate", "disconnect", "backpressure")
        summary = {}
        for name in names:
            values = [item for run in runs for item in run if item["scenario"] == name]
            if not values:
                continue
            fields = {}
            for field in ("validation_ms", "delivery_ms"):
                samples = sorted(item[field] for item in values if type(item.get(field)) is int)
                if samples:
                    fields[field] = {"n": len(samples), "median": statistics.median(samples),
                                     "p95": samples[math.ceil(0.95 * len(samples)) - 1],
                                     "max": samples[-1]}
            summary[name] = fields
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print("VECTOR_BENCHMARK_SUMMARY_FAILED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
