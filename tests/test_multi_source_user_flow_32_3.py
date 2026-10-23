"""Phase 32.3 user flows must retain safe v1/v2 behavior and accept closed v3."""

from pathlib import Path
import json

import pytest

from app import local_web
from app.monitor_setup import main as setup_main
from app.monitor_setup import create_monitor_pair_config


APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")


def _files(root: Path):
    app, ssh = root / "application.log", root / "ssh.log"
    app.write_text(APP, encoding="utf-8")
    ssh.write_text(SSH, encoding="utf-8")
    return app, ssh, root / "private" / "monitoring.json"


def test_multi_source_wizard_creates_closed_private_pair(tmp_path: Path, capsys):
    app, ssh, config = _files(tmp_path)
    answers = iter(("y", str(app), str(ssh), "y", "y"))
    result = setup_main(["--multi-source", "--output", str(config)],
                        ask=lambda _prompt: next(answers))
    assert result == 0
    text = capsys.readouterr().out
    payload = json.loads(config.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "3"
    assert [item["source_role"] for item in payload["sources"]] == ["application", "ssh"]
    assert str(app) not in text and str(ssh) not in text and str(config) not in text
    assert config.stat().st_mode & 0o777 == 0o600


def test_multi_source_wizard_cancel_and_no_clobber(tmp_path: Path, capsys):
    app, ssh, config = _files(tmp_path)
    result = setup_main(["--multi-source", "--output", str(config)],
                        ask=lambda _prompt: "n")
    assert result == 0 and not config.exists()
    create_monitor_pair_config(app, ssh, config)
    original = config.read_bytes()
    answers = iter(("y", str(app), str(ssh), "y", "y"))
    result = setup_main(["--multi-source", "--output", str(config)],
                        ask=lambda _prompt: next(answers))
    assert result != 0
    assert config.read_bytes() == original
    assert "이미 있습니다" in capsys.readouterr().err


def test_multi_source_wizard_rejects_same_identity_symlink_and_replacement(tmp_path: Path, capsys):
    app, ssh, config = _files(tmp_path)
    answers = iter(("y", str(app), str(app), "y"))
    assert setup_main(["--multi-source", "--output", str(config)],
                      ask=lambda _prompt: next(answers)) == 2
    assert not config.exists()
    link = tmp_path / "ssh-link.log"
    link.symlink_to(ssh)
    answers = iter(("y", str(app), str(link)))
    assert setup_main(["--multi-source", "--output", str(config)],
                      ask=lambda _prompt: next(answers)) == 3
    assert not config.exists()
    steps = iter(("y", str(app), str(ssh), "y", "y"))
    # Source replacement between bounded preview and no-clobber save is rejected.
    def replace_at_final_prompt(prompt):
        answer = next(steps)
        if prompt.startswith("이 두 로그 설정"):
            app.write_text(APP + APP, encoding="utf-8")
        return answer
    assert setup_main(["--multi-source", "--output", str(config)],
                      ask=replace_at_final_prompt) == 3
    assert not config.exists()
    captured = capsys.readouterr()
    assert str(app) not in captured.err + captured.out and str(ssh) not in captured.err + captured.out


def test_v3_show_reset_delete_and_selective_preservation(tmp_path: Path, capsys, monkeypatch):
    app, ssh, config = _files(tmp_path)
    create_monitor_pair_config(app, ssh, config)
    pair = json.loads(config.read_text(encoding="utf-8"))
    from app.live_monitoring.multi_source import open_internal_pair_runtime
    runtime = open_internal_pair_runtime(config)
    runtime.close()
    monkeypatch.setattr("app.monitor_setup.resolve_default_monitor_config_path", lambda: config)
    assert setup_main(["--show"]) == 0
    shown = capsys.readouterr().out
    assert "애플리케이션 로그인 로그" in shown and "SSH 인증 로그" in shown
    assert str(app) not in shown and str(ssh) not in shown
    assert setup_main(["--reset-checkpoint", "--role", "application"],
                      ask=lambda _prompt: "n") == 0
    assert (config.parent / pair["sources"][0]["checkpoint_name"]).exists()
    assert setup_main(["--reset-checkpoint", "--role", "application"],
                      ask=lambda _prompt: "y") == 0
    assert (config.parent / pair["sources"][0]["checkpoint_name"]).exists() is False
    assert (config.parent / pair["sources"][1]["checkpoint_name"]).exists()
    assert app.exists() and ssh.exists() and config.exists()
    capsys.readouterr()
    assert setup_main(["--delete"], ask=lambda _prompt: "n") == 0
    assert config.exists() and app.exists() and ssh.exists()
    assert setup_main(["--delete"], ask=lambda _prompt: "y") == 0
    assert not config.exists() and app.exists() and ssh.exists()
    assert not (config.parent / pair["sources"][1]["checkpoint_name"]).exists()


def test_local_web_v3_monitor_selects_pair_service_before_listener(tmp_path: Path, monkeypatch):
    app_file, ssh_file, config = _files(tmp_path)
    create_monitor_pair_config(app_file, ssh_file, config)
    listeners = []
    services = []
    original_pair_runtime = local_web._pair_runtime
    def capture_runtime(path):
        result = original_pair_runtime(path)
        services.append(result[0])
        return result
    monkeypatch.setattr(local_web, "_pair_runtime", capture_runtime)
    class Listener:
        def close(self):
            self.closed = True
    class Server:
        should_exit = False
        force_exit = False
        def run(self, sockets):
            import time
            while not self.should_exit:
                time.sleep(0.005)
    def listener(port):
        listeners.append(port)
        return Listener()
    # The explicit v3 path must be accepted by the production runtime factory.
    result = local_web.run_local_web(
        open_browser=False, monitor_default=True,
        default_config_resolver=lambda: config,
        listener_factory=listener,
        server_factory=lambda _app, _port: Server(),
        readiness=lambda _port: True,
        sleep=lambda _duration: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    assert result == 0
    assert listeners
    assert services
    assert all(worker._session._fd == -1 and worker._checkpoint._lock_fd == -1
               for worker in services[0].runtime.workers.values())


def test_schema3_production_app_lifespan_accepts_pair_runner_state(tmp_path: Path):
    from fastapi.testclient import TestClient
    from app.api import create_app
    app_file, ssh_file, config = _files(tmp_path)
    create_monitor_pair_config(app_file, ssh_file, config)
    service, runner = local_web._pair_runtime(config)
    with TestClient(create_app(live_monitoring_service=service,
                               live_monitoring_runner=runner), base_url="http://127.0.0.1",
                      client=("127.0.0.1", 12345)) as client:
        assert client.get("/api/health").json() == {"status": "ok"}
        status = client.get("/api/v1/live/status")
        assert status.status_code == 200, status.text
        assert status.json()["schema_version"] == "3"


def test_v3_reset_delete_refuse_live_role_lock(tmp_path: Path, monkeypatch):
    app_file, ssh_file, config = _files(tmp_path)
    create_monitor_pair_config(app_file, ssh_file, config)
    from app.live_monitoring.config import load_live_monitor_pair_config
    from app.live_monitoring.checkpoint import LiveCheckpointManager
    from app.live_monitoring.multi_source import open_internal_pair_runtime
    runtime = open_internal_pair_runtime(config)
    runtime.close()
    monkeypatch.setattr("app.monitor_setup.resolve_default_monitor_config_path", lambda: config)
    pair = load_live_monitor_pair_config(config)
    held = LiveCheckpointManager(config, pair.sources[0])
    try:
        assert setup_main(["--reset-checkpoint", "--role", "application"],
                          ask=lambda _prompt: "y") == 3
        assert setup_main(["--delete"], ask=lambda _prompt: "y") == 3
        assert config.exists() and app_file.exists() and ssh_file.exists()
    finally:
        held.close()


def test_v1_v2_cli_compatibility_remains_available():
    assert local_web._arguments(["--monitor"]).monitor is True
    assert local_web._arguments(["--monitor-config", "/tmp/single-v2.json"]).monitor_config == "/tmp/single-v2.json"
