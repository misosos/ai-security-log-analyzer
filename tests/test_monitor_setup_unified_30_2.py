"""Shared application/SSH management contracts at the real CLI boundary."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.live_monitoring.config import resolve_default_monitor_config_path


@pytest.mark.parametrize("choice,role,label", (
    ("1", "application", "애플리케이션 로그인 로그"),
    ("2", "ssh", "SSH 인증 로그"),
))
def test_cli_setup_and_show_use_safe_log_kind(
    tmp_path: Path, choice: str, role: str, label: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    source = tmp_path / "synthetic.log"
    line = (
        "2026-01-02 03:04:05 INFO login_failed user=SYNTHETIC_ACCOUNT ip=192.0.2.33\n"
        if role == "application" else
        "2026-01-02 03:04:05 sshd: Failed password for SYNTHETIC_ACCOUNT from 192.0.2.33\n"
    )
    source.write_text(line, encoding="utf-8")
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = ""
    config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                 xdg_config_home="")
    setup = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup"],
        input=f"yes\n{choice}\n{source}\nyes\n", text=True, capture_output=True,
        env=env, timeout=10,
    )
    if setup.returncode != 0:
        pytest.fail("UNIFIED_SETUP_FAILED", pytrace=False)
    show = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup", "--show"],
        text=True, capture_output=True, env=env, timeout=10,
    )
    if show.returncode != 0 or label not in show.stdout or role not in show.stdout:
        pytest.fail("UNIFIED_SHOW_ROLE_LABEL_FAILED", pytrace=False)
    for required in ("schema 2", "BOUNDED_REPLAY_V1", "FAIL_CLOSED", "config 권한 적합 True",
                     "현재 source 사용 가능 True", "FIRST_START"):
        assert required in show.stdout
    public = setup.stdout + setup.stderr + show.stdout + show.stderr
    if any(private in public for private in (
        str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33", line.strip(),
    )):
        pytest.fail("UNIFIED_MANAGEMENT_PRIVATE_VALUE_EXPOSED", pytrace=False)
