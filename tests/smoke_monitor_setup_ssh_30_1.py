"""Separate-process SSH wizard to default live checkpoint smoke, synthetic only."""

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from smoke_ssh_checkpoint_26_0 import (
    ROOT, _assert_private_output, _default_config_for, _line, _management,
    _mode, _no_listener, _port, _start, _status, _stop, _wait,
)


def main() -> None:
    scratch = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    process = None
    with TemporaryDirectory(prefix="ssh-wizard-smoke-", dir=scratch) as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)
        source = root / "synthetic-ssh.log"
        source.write_text(_line(0), encoding="utf-8")
        env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(root)}
        config = _default_config_for(home, sys.platform)
        setup = subprocess.run(
            [sys.executable, "-m", "app.monitor_setup"], cwd=ROOT, env=env,
            input=f"yes\n2\n{source}\nyes\n", capture_output=True, text=True, timeout=10,
        )
        assert setup.returncode == 0, "SSH wizard setup failed"
        assert "인증 실패 1건" in setup.stdout and "성공 기록 0건" in setup.stdout
        assert "uv run python -m app.local_web --monitor" in setup.stdout
        assert config.exists() and (_mode(config.parent), _mode(config)) == (0o700, 0o600)
        _assert_private_output(setup, str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33")
        show = _management(env, "--show")
        assert show.returncode == 0 and "ssh" in show.stdout
        _assert_private_output(show, str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33")
        port = _port()
        try:
            process = _start(port, env, root / "stdout.log", root / "stderr.log")
            first = _status(port)
            assert first["latest_detection_revision"] == 0
            assert first["analysis_revision"] == 0
            with source.open("a", encoding="utf-8") as stream:
                stream.writelines(_line(index) for index in range(1, 6))
                stream.write(_line(6, "Accepted"))
            analyzed = _wait(port, lambda body: body["latest_detection_revision"] >= 1
                             and body["analysis_revision"] >= 1)
            assert analyzed["source_role"] == "ssh"
            _stop(process)
            process = None
            _no_listener(port)
            with source.open("a", encoding="utf-8") as stream:
                stream.write(_line(7, "Failed"))
            port = _port()
            process = _start(port, env, root / "stdout2.log", root / "stderr2.log")
            recovered = _wait(port, lambda body: body["analysis_revision"] >= 1)
            assert recovered["source_role"] == "ssh"
            _stop(process)
            process = None
            _no_listener(port)
            for capture in root.glob("std*.log"):
                content = capture.read_text(encoding="utf-8", errors="replace")
                assert not any(canary in content for canary in (
                    str(source), str(config), "SYNTHETIC_ACCOUNT", "192.0.2.33"))
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
    assert not root.exists()
    print("SSH_WIZARD_SMOKE_PASS restart_checkpoint_listener_cleanup")


if __name__ == "__main__":
    main()
