"""User recovery guidance must identify a checkpoint problem without private data."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from app.live_monitoring.config import resolve_default_monitor_config_path


@pytest.mark.parametrize("choice,label", (
    ("1", "애플리케이션 로그인 로그"),
    ("2", "SSH 인증 로그"),
))
def test_show_uses_user_language_without_internal_codes(
    tmp_path: Path, choice: str, label: str,
) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    source = tmp_path / "synthetic.log"
    line = (
        "2026-01-02 03:04:05 INFO login_failed user=SYNTHETIC_ACCOUNT ip=192.0.2.33\n"
        if choice == "1" else
        "2026-01-02 03:04:05 sshd: Failed password for SYNTHETIC_ACCOUNT from 192.0.2.33\n"
    )
    source.write_text(line, encoding="utf-8")
    env = os.environ.copy()
    env.update(HOME=str(home), XDG_CONFIG_HOME="", PYTHONDONTWRITEBYTECODE="1")
    created = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup"],
        input=f"yes\n{choice}\n{source}\nyes\n", text=True, capture_output=True,
        env=env, timeout=10,
    )
    shown = subprocess.run(
        [sys.executable, "-m", "app.monitor_setup", "--show"],
        text=True, capture_output=True, env=env, timeout=10,
    )
    if created.returncode != 0 or shown.returncode != 0:
        pytest.fail("USER_SHOW_FIXTURE_FAILED", pytrace=False)
    if any(required not in shown.stdout for required in (
        "설정 버전: 2", f"로그 종류: {label}", "새 줄부터", "복구 자료: 없음",
        "설정 권한: 적합", "원본 로그: 사용 가능", "다음 행동:",
    )):
        pytest.fail("USER_SHOW_MEANING_MISSING", pytrace=False)
    if any(internal in shown.stdout for internal in (
        "(application)", "(ssh)", "schema", "FROM_END", "BOUNDED_REPLAY_V1",
        "FAIL_CLOSED", "FIRST_START", "True", "False", "parser timezone",
    )):
        pytest.fail("USER_SHOW_INTERNAL_CODE_VISIBLE", pytrace=False)
    public = created.stdout + created.stderr + shown.stdout + shown.stderr
    if any(private in public for private in (
        str(source), "SYNTHETIC_ACCOUNT", "192.0.2.33", line.strip(),
    )):
        pytest.fail("USER_SHOW_PRIVATE_VALUE_EXPOSED", pytrace=False)


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
    if show.returncode != 0 or "원본 로그: 사용 가능" not in show.stdout:
        pytest.fail("CHECKPOINT_REVIEW_SHOW_FAILED", pytrace=False)
    if ("복구 자료: 검토 필요" not in show.stdout
            or "다음 행동: 복구 자료를 수동으로 확인" not in show.stdout
            or "원본 로그의 접근 가능 여부" in show.stdout):
        pytest.fail("CHECKPOINT_REVIEW_GUIDANCE_FAILED", pytrace=False)
    if "존재·이력 확인 불가" not in show.stdout or "존재 False" in show.stdout:
        pytest.fail("CHECKPOINT_REVIEW_FALSE_ABSENCE", pytrace=False)
    public = created.stdout + created.stderr + show.stdout + show.stderr
    if any(value in public for value in (
        str(source), str(config), str(checkpoint), "SYNTHETIC_ACCOUNT", "192.0.2.33",
    )):
        pytest.fail("CHECKPOINT_REVIEW_PRIVATE_VALUE_EXPOSED", pytrace=False)
