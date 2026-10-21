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
    if show.returncode != 0 or label not in show.stdout:
        pytest.fail("UNIFIED_SHOW_ROLE_LABEL_FAILED", pytrace=False)
    for required in ("설정 버전: 2", "같은 파일의 제한된 이력 복구",
                     "파일 교체·길이 축소 시 자동 이어받지 않습니다", "설정 권한: 적합",
                     "원본 로그: 사용 가능", "복구 자료: 없음"):
        if required not in show.stdout:
            pytest.fail("UNIFIED_SHOW_SAFE_SUMMARY_MISSING", pytrace=False)
    if any(internal in show.stdout for internal in (
        "(application)", "(ssh)", "BOUNDED_REPLAY_V1", "FAIL_CLOSED", "FIRST_START",
    )):
        pytest.fail("UNIFIED_SHOW_INTERNAL_CODE_VISIBLE", pytrace=False)
    public = setup.stdout + setup.stderr + show.stdout + show.stderr
    if any(private in public for private in (
        str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33", line.strip(),
    )):
        pytest.fail("UNIFIED_MANAGEMENT_PRIVATE_VALUE_EXPOSED", pytrace=False)
