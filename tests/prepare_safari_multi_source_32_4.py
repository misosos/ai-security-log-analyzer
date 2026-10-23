"""Prepare and control a synthetic-only v3 server for manual Safari 18.6 checks."""

import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

from app.live_monitoring.config import resolve_default_monitor_config_path


ROOT = Path(__file__).resolve().parents[1]
STATE = Path(tempfile.gettempdir()).resolve() / "multi-source-safari-32-4-state.json"
APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")


def _env(home: Path) -> dict[str, str]:
    result = os.environ.copy()
    result["HOME"] = str(home)
    result.pop("XDG_CONFIG_HOME", None)
    return result


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _read_status(port: int) -> dict:
    with urlopen(f"http://127.0.0.1:{port}/api/v1/live/status", timeout=1) as response:
        return json.load(response)


def _start(home: Path, port: int) -> int:
    process = subprocess.Popen(
        [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser", "--port", str(port)],
        cwd=ROOT, env=_env(home), stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    for _ in range(200):
        if process.poll() is not None:
            raise SystemExit("SAFARI_PAIR_START_FAILED")
        try:
            if _read_status(port).get("schema_version") == "3":
                return process.pid
        except Exception:
            time.sleep(0.05)
    process.send_signal(signal.SIGINT)
    process.wait(timeout=5)
    raise SystemExit("SAFARI_PAIR_START_TIMEOUT")


def _load() -> dict:
    if STATE.is_symlink() or not STATE.is_file():
        raise SystemExit("SAFARI_PAIR_NOT_PREPARED")
    value = json.loads(STATE.read_text(encoding="utf-8"))
    root = Path(value.get("root", ""))
    if (not root.is_absolute() or root.parent != Path(tempfile.gettempdir()).resolve()
        or not root.name.startswith("multi-source-safari-32-4-")
        or Path(value.get("home", "")).parent != root):
        raise SystemExit("SAFARI_PAIR_STATE_INVALID")
    return value


def _save(value: dict) -> None:
    temporary = STATE.with_name(STATE.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, STATE)


def _process_is_ours(pid: int) -> bool:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "args="],
                            text=True, capture_output=True, check=False)
    return result.returncode == 0 and "app.local_web" in result.stdout and "--monitor" in result.stdout


def _stop_server(value: dict) -> None:
    pid = value.get("pid")
    if type(pid) is not int or not _process_is_ours(pid):
        raise SystemExit("SAFARI_PAIR_PROCESS_CHANGED")
    try:
        os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{value['port']}/api/health", timeout=0.2):
                time.sleep(0.05)
        except Exception:
            if not _process_is_ours(pid):
                return
            break
    if _process_is_ours(pid):
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _process_is_ours(pid):
            time.sleep(0.05)
    if _process_is_ours(pid):
        raise SystemExit("SAFARI_PAIR_STOP_FAILED")


def _cli(value: dict, args: list[str], answer: str = "") -> subprocess.CompletedProcess:
    result = subprocess.run([sys.executable, "-m", "app.monitor_setup", *args],
                            cwd=ROOT, env=_env(Path(value["home"])), input=answer,
                            text=True, capture_output=True, timeout=15, check=False)
    combined = result.stdout + result.stderr
    for secret in ("192.0.2.9", "198.51.100.23", "synthetic", "application.log", "ssh.log"):
        if secret in combined:
            raise SystemExit("SAFARI_PAIR_PRIVATE_OUTPUT")
    return result


def _prepare() -> None:
    if STATE.exists() or STATE.is_symlink():
        raise SystemExit("SAFARI_PAIR_ALREADY_PREPARED")
    root = Path(tempfile.mkdtemp(prefix="multi-source-safari-32-4-",
                                 dir=Path(tempfile.gettempdir()).resolve()))
    os.chmod(root, 0o700)
    home = root / "home"
    home.mkdir(mode=0o700)
    application, ssh = root / "application.log", root / "ssh.log"
    application.write_text(APP, encoding="utf-8")
    ssh.write_text(SSH, encoding="utf-8")
    value = {"root": str(root), "home": str(home), "application": str(application),
             "ssh": str(ssh), "port": _free_port(), "pid": None}
    config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                  xdg_config_home=None)
    wizard = subprocess.run([sys.executable, "-m", "app.monitor_setup", "--multi-source", "--no-color"],
                            cwd=ROOT, env=_env(home),
                            input=f"yes\n{application}\n{ssh}\nyes\n", text=True,
                            capture_output=True, timeout=15, check=False)
    for secret in (str(application), str(ssh), "192.0.2.9", "198.51.100.23", "synthetic"):
        if secret in wizard.stdout + wizard.stderr:
            shutil.rmtree(root)
            raise SystemExit("SAFARI_PAIR_SETUP_PRIVACY_FAILED")
    if wizard.returncode != 0 or not config.is_file():
        shutil.rmtree(root)
        raise SystemExit("SAFARI_PAIR_SETUP_FAILED")
    value["pid"] = _start(home, value["port"])
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    print(f"Safari 18.6 synthetic pair ready: http://127.0.0.1:{value['port']}/")
    print("Control: --status | --append application|ssh|both [count] | --gap | --truncate application|ssh")
    print("Recovery: --restart | --reset application|ssh|all | --stop")


def _append(value: dict, role: str, count: int) -> None:
    if not 1 <= count <= 512:
        raise SystemExit("SAFARI_PAIR_INVALID_COUNT")
    targets = ("application", "ssh") if role == "both" else (role,)
    for name in targets:
        line, path = (APP, Path(value["application"])) if name == "application" else (SSH, Path(value["ssh"]))
        with path.open("a", encoding="utf-8") as output:
            output.write(line * count)
    print(f"Synthetic append completed for {','.join(targets)} ({count} each).")


def _control(args: list[str]) -> None:
    value = _load()
    if args == ["--status"]:
        status = _read_status(value["port"])
        print(json.dumps({"service_state": status["service_state"],
                          "roles": [{"role": row["role"], "service_state": row["service_state"],
                                     "detection_revision": row["detection_revision"]}
                                    for row in status["roles"]],
                          "replay_items": status["available_event_count"],
                          "replay_bytes": status["event_byte_count"]}))
        return
    if args and args[0] == "--append" and len(args) in (2, 3):
        role = args[1]
        if role not in ("application", "ssh", "both"):
            raise SystemExit("SAFARI_PAIR_INVALID_ROLE")
        _append(value, role, int(args[2]) if len(args) == 3 else 5)
        return
    if args == ["--gap"]:
        _append(value, "application", 240)
        print("Appended synthetic records to exercise bounded replay eviction; refresh status with --status.")
        return
    if args and args[0] in ("--truncate", "--replace") and len(args) == 2:
        role = args[1]
        if role not in ("application", "ssh"):
            raise SystemExit("SAFARI_PAIR_INVALID_ROLE")
        source = Path(value[role])
        if args[0] == "--truncate":
            source.write_text("", encoding="utf-8")
        else:
            replacement = source.with_name(source.name + ".replacement")
            replacement.write_text(APP if role == "application" else SSH, encoding="utf-8")
            os.replace(replacement, source)
        print(f"Synthetic {role} {args[0][2:]} injected; use --status to inspect safe state.")
        return
    if args == ["--restart"]:
        _stop_server(value)
        value["port"] = _free_port()
        value["pid"] = _start(Path(value["home"]), value["port"])
        _save(value)
        print("Pair restarted from role checkpoints. Reload Safari manually; the page does not auto-resume.")
        print(f"Loopback URL: http://127.0.0.1:{value['port']}/")
        return
    if args and args[0] == "--reset" and len(args) == 2:
        role = args[1]
        if role not in ("application", "ssh", "all"):
            raise SystemExit("SAFARI_PAIR_INVALID_ROLE")
        _stop_server(value)
        result = _cli(value, ["--reset-checkpoint", "--role", role], "yes\n")
        if result.returncode != 0:
            raise SystemExit("SAFARI_PAIR_RESET_FAILED")
        value["port"] = _free_port()
        value["pid"] = _start(Path(value["home"]), value["port"])
        _save(value)
        print(f"{role} checkpoint reset and pair restarted. Reload Safari manually.")
        print(f"Loopback URL: http://127.0.0.1:{value['port']}/")
        return
    if args == ["--delete"]:
        _stop_server(value)
        result = _cli(value, ["--delete"], "yes\n")
        if result.returncode != 0 or Path(value["application"]).exists() is False or Path(value["ssh"]).exists() is False:
            raise SystemExit("SAFARI_PAIR_DELETE_FAILED")
        root = Path(value["root"])
        if root.parent != Path(tempfile.gettempdir()).resolve() or not root.name.startswith("multi-source-safari-32-4-"):
            raise SystemExit("SAFARI_PAIR_STATE_INVALID")
        shutil.rmtree(root)
        STATE.unlink()
        print("Private setup and its role checkpoints deleted; both synthetic source logs preserved; server stopped.")
        return
    if args == ["--stop"]:
        _stop_server(value)
        root = Path(value["root"])
        if root.parent != Path(tempfile.gettempdir()).resolve() or not root.name.startswith("multi-source-safari-32-4-"):
            raise SystemExit("SAFARI_PAIR_STATE_INVALID")
        shutil.rmtree(root)
        STATE.unlink()
        print("Synthetic Safari server stopped; generated files removed.")
        return
    raise SystemExit("SAFARI_PAIR_INVALID_ARGUMENT")


if __name__ == "__main__":
    if not sys.argv[1:]:
        _prepare()
    else:
        _control(sys.argv[1:])
