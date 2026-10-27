"""Bounded synthetic-only subprocess smoke; child output stays captured."""

import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.log_collection.jsonl_runtime import JsonlCollectorRuntime, JsonlRuntimeConfig


def _line(role: str) -> str:
    if role == "application":
        return "2026-01-02 03:04:05 INFO user_login user=synthetic_user ip=192.0.2.41 service=ssh"
    return "2026-01-02 03:04:05 sshd: Accepted password for synthetic_user from 192.0.2.41 port 45001 ssh2"


def _envelope(role: str) -> bytes:
    data = {"schema_version": 1, "source_role": role, "payload": _line(role),
            "collector_instance_alias": "synthetic-collector", "sequence_hint": None,
            "retry_hint": False}
    return json.dumps(data, separators=(",", ":")).encode() + b"\n"


async def _child(role: str) -> None:
    runtime = JsonlCollectorRuntime(JsonlRuntimeConfig(
        source_role=role, host="127.0.0.1", port=0, test_only_ephemeral_port=True,
    ))
    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopping.set)
    await runtime.start()
    port = runtime._server.sockets[0].getsockname()[1]
    print(f"READY {port}", flush=True)
    await runtime.wait_until_processed(1, timeout=3)
    print("PROCESSED 1", flush=True)
    await stopping.wait()
    await runtime.stop()
    if (runtime._server is not None or runtime._connections
            or runtime._worker is not None or runtime.snapshot().active_connections != 0):
        raise RuntimeError("synthetic cleanup invariant failed")
    print("STOPPED 1", flush=True)


def _child_run(role: str, sig: int) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="jsonl-runtime-") as private_home:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": private_home,
               "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
               "PYTHONNOUSERSITE": "1"}
        try:
            proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", role],
                                    cwd=Path(__file__).resolve().parents[1], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception:
            return False, "CHILD_START"
        stage = "CHILD_START"
        try:
            ready = proc.stdout.readline().strip()
            if not ready.startswith("READY "):
                return False, "LISTENER_READY"
            port = int(ready.split()[1])
            stage = "FRAME_SENT"
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(_envelope(role))
            processed = proc.stdout.readline().strip()
            if processed != "PROCESSED 1":
                return False, "ANALYSIS_CONFIRMED"
            stage = "SIGNAL_SENT"
            proc.send_signal(sig)
            stdout, _stderr = proc.communicate(timeout=5)
            if proc.returncode != 0 or "STOPPED 1" not in stdout:
                return False, "PROCESS_EXIT"
            stage = "PORT_REUSED"
            with socket.socket() as reuse:
                reuse.bind(("127.0.0.1", port))
            return True, "COMPLETE"
        except Exception:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
            return False, stage
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        asyncio.run(_child(sys.argv[2]))
        return 0
    runs = 0
    for role in ("application", "ssh"):
        for sig in (signal.SIGINT, signal.SIGTERM):
            ok, stage = _child_run(role, sig)
            runs += 1
            if not ok:
                print(f"COLLECTOR_JSONL_RUNTIME_SMOKE_FAIL role={role} stage={stage} runs={runs}")
                return 1
    print("COLLECTOR_JSONL_RUNTIME_SMOKE_PASS roles=2 subprocesses=4 synthetic=1 leaks=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
