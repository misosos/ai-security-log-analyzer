"""Exercise the real v3 CLI lifecycle with an isolated HOME and synthetic logs."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

from app.live_monitoring.config import resolve_default_monitor_config_path


APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")
ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], env: dict[str, str], *, input_text: str = "",
         expected: int = 0) -> str:
    result = subprocess.run([sys.executable, *args], cwd=ROOT, env=env,
                            input=input_text, text=True, capture_output=True,
                            timeout=15, check=False)
    if result.returncode != expected:
        raise AssertionError(f"CLI_EXIT_{Path(args[1]).stem.upper()}_{result.returncode}")
    text = result.stdout + result.stderr
    for secret in ("192.0.2.9", "198.51.100.23", "synthetic", "application.log", "ssh.log"):
        if secret in text:
            raise AssertionError("CLI_PRIVATE_OUTPUT")
    return text


def _port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _status(port: int) -> dict:
    with urlopen(f"http://127.0.0.1:{port}/api/v1/live/status", timeout=1) as response:
        return json.load(response)


def _start(port: int, env: dict[str, str]) -> subprocess.Popen:
    process = subprocess.Popen(
        [sys.executable, "-m", "app.local_web", "--monitor", "--no-browser", "--port", str(port)],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    for _ in range(200):
        if process.poll() is not None:
            raise AssertionError("V3_MONITOR_EXITED")
        try:
            value = _status(port)
            if value.get("schema_version") == "3":
                return process
        except Exception:
            time.sleep(0.05)
    process.send_signal(signal.SIGINT)
    process.wait(timeout=5)
    raise AssertionError("V3_MONITOR_TIMEOUT")


def _stop(process: subprocess.Popen) -> None:
    process.send_signal(signal.SIGINT)
    try:
        code = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
        raise AssertionError("V3_SIGINT_TIMEOUT") from None
    if code != 0:
        raise AssertionError("V3_SIGINT_FAILED")


def smoke() -> None:
    with tempfile.TemporaryDirectory(prefix="pair-cli-32-4-",
                                     dir=Path(tempfile.gettempdir()).resolve()) as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir(mode=0o700)
        app, ssh = root / "synthetic-app.log", root / "synthetic-ssh.log"
        app.write_text(APP, encoding="utf-8")
        ssh.write_text(SSH, encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(home)
        env.pop("XDG_CONFIG_HOME", None)
        config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                     xdg_config_home=None)

        wizard = _run(["-m", "app.monitor_setup", "--multi-source", "--no-color"], env,
                      input_text=f"yes\n{app}\n{ssh}\nyes\n")
        assert "두 로그는 이 컴퓨터에서만 처리됩니다." in wizard
        assert "기존 줄은 처리하지 않고 저장 뒤 새 줄부터 시작합니다." in wizard
        assert "제한된 형식 확인만 수행합니다." in wizard
        assert config.is_file()
        config_value = json.loads(config.read_text(encoding="utf-8"))
        roles = {item["source_role"]: item for item in config_value["sources"]}
        assert set(roles) == {"application", "ssh"}

        shown = _run(["-m", "app.monitor_setup", "--show"], env)
        assert "애플리케이션 로그인 로그" in shown and "SSH 인증 로그" in shown
        assert "전체 실행 가능 여부: 가능" in shown

        port = _port()
        process = _start(port, env)
        try:
            initial = _status(port)
            assert [item["detection_revision"] for item in initial["roles"]] == [0, 0]
            busy_reset = _run(["-m", "app.monitor_setup", "--reset-checkpoint",
                               "--role", "application"], env, input_text="yes\n", expected=3)
            busy_delete = _run(["-m", "app.monitor_setup", "--delete"], env,
                               input_text="yes\n", expected=3)
            assert "사용 중입니다" in busy_reset and "사용 중입니다" in busy_delete
            with app.open("a", encoding="utf-8") as output:
                output.write(APP * 5)
            with ssh.open("a", encoding="utf-8") as output:
                output.write(SSH * 5)
            for _ in range(100):
                changed = _status(port)
                if all(item["detection_revision"] > 0 for item in changed["roles"]):
                    break
                time.sleep(0.05)
            assert all(item["detection_revision"] > 0 for item in changed["roles"])
        finally:
            _stop(process)

        app_checkpoint = config.parent / roles["application"]["checkpoint_name"]
        ssh_checkpoint = config.parent / roles["ssh"]["checkpoint_name"]
        assert app_checkpoint.exists() and ssh_checkpoint.exists()
        single_reset = _run(["-m", "app.monitor_setup", "--reset-checkpoint",
                             "--role", "ssh"], env, input_text="yes\n")
        assert "해당 역할의 과거 분석 연속성이 끊깁니다" in single_reset
        assert "선택하지 않은 역할의 복구 자료는 보존됩니다" in single_reset
        assert app_checkpoint.exists() and not ssh_checkpoint.exists()

        process = _start(_port(), env)
        _stop(process)
        all_reset = _run(["-m", "app.monitor_setup", "--reset-checkpoint",
                          "--role", "all"], env, input_text="yes\n")
        assert "과거 분석 연속성이 끊깁니다" in all_reset
        assert app.exists() and ssh.exists() and config.exists()

        process = _start(_port(), env)
        _stop(process)
        deleted = _run(["-m", "app.monitor_setup", "--delete"], env, input_text="yes\n")
        assert "원본 로그와 다른 파일은 삭제하지 않습니다" in deleted
        assert "설정과 연결된 복구 자료를 삭제했습니다" in deleted
        assert not config.exists() and app.exists() and ssh.exists()
        print("synthetic actual CLI: wizard/show/monitor/role reset/all reset/delete PASS")
        print("monitor startup skipped existing lines; both roles processed appended lines")
        print("running reset/delete rejected; source logs preserved after delete")


if __name__ == "__main__":
    smoke()
