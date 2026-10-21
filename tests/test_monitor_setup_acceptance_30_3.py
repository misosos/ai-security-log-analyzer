"""User recovery guidance must identify a checkpoint problem without private data."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.live_monitoring.config import resolve_default_monitor_config_path


def test_show_checkpoint_review_guides_manual_checkpoint_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    source = tmp_path / "synthetic.log"
    source.write_text(
        "2026-01-02 03:04:05 INFO login_failed user=SYNTHETIC_ACCOUNT ip=192.0.2.33\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(HOME=str(home), XDG_CONFIG_HOME="", PYTHONDONTWRITEBYTECODE="1")
    created = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup"],
        input=f"yes\n1\n{source}\nyes\n", text=True, capture_output=True,
        env=env, timeout=10,
    )
    if created.returncode != 0:
        pytest.fail("CHECKPOINT_REVIEW_FIXTURE_FAILED", pytrace=False)
    config = resolve_default_monitor_config_path(platform=sys.platform, home=home,
                                                 xdg_config_home="")
    checkpoint = config.parent / "checkpoint-source-000001.json"
    checkpoint.write_bytes(b"{")
    checkpoint.chmod(0o600)
    show = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup", "--show"],
        text=True, capture_output=True, env=env, timeout=10,
    )
    if show.returncode != 0 or "현재 source 사용 가능 True" not in show.stdout:
        pytest.fail("CHECKPOINT_REVIEW_SHOW_FAILED", pytrace=False)
    if ("복구 자료 검토 필요" not in show.stdout
            or "다음 행동: 복구 자료를 수동으로 확인" not in show.stdout
            or "원본 로그의 접근 가능 여부" in show.stdout):
        pytest.fail("CHECKPOINT_REVIEW_GUIDANCE_FAILED", pytrace=False)
    if "존재 False" in show.stdout:
        pytest.fail("CHECKPOINT_REVIEW_FALSE_ABSENCE", pytrace=False)
    public = created.stdout + created.stderr + show.stdout + show.stderr
    if any(value in public for value in (
        str(source), str(config), str(checkpoint), "SYNTHETIC_ACCOUNT", "192.0.2.33",
    )):
        pytest.fail("CHECKPOINT_REVIEW_PRIVATE_VALUE_EXPOSED", pytrace=False)
