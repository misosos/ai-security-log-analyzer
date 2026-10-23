"""Private v3 pair configuration stays closed and cannot start old runtime."""

import json
from pathlib import Path

import pytest

from app.live_monitoring.config import (
    LiveMonitorError, load_live_monitor_config, load_live_monitor_pair_config,
)
from app.monitor_setup import MonitorSetupError, create_monitor_pair_config
from app import local_web


def _sources(tmp_path: Path) -> tuple[Path, Path, Path]:
    application = tmp_path / "application.log"
    ssh = tmp_path / "ssh.log"
    application.write_text("synthetic\n", encoding="utf-8")
    ssh.write_text("synthetic\n", encoding="utf-8")
    return application, ssh, tmp_path / "private" / "monitoring.json"


def test_pair_creation_is_private_closed_and_not_a_runtime(tmp_path: Path) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)
    assert output.parent.stat().st_mode & 0o777 == 0o700
    assert output.stat().st_mode & 0o777 == 0o600
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == "3"
    assert len(document["sources"]) == 2
    assert [entry["source_role"] for entry in document["sources"]] == ["application", "ssh"]
    assert [entry["source_path"] for entry in document["sources"]] == [str(application), str(ssh)]
    names = [(entry["checkpoint_name"], entry["checkpoint_lock_name"])
             for entry in document["sources"]]
    assert len({name for pair in names for name in pair}) == 4
    assert all("/" not in name and "." not in name[:-5] for pair in names for name in pair)
    assert all(str(path) not in json.dumps(names) for path in (application, ssh))
    loaded = load_live_monitor_pair_config(output)
    assert loaded.as_document() == document
    assert str(application) not in repr(loaded) and str(ssh) not in repr(loaded)
    with pytest.raises(LiveMonitorError, match="UNSUPPORTED_SCHEMA"):
        load_live_monitor_config(output)


@pytest.mark.parametrize("edit", [
    lambda doc: doc["sources"].reverse(),
    lambda doc: doc["sources"].append(doc["sources"][0]),
    lambda doc: doc["sources"][1].update(source_role="application"),
    lambda doc: doc["sources"][0].update(source_path="relative.log"),
    lambda doc: doc["sources"][0].update(checkpoint_name="private-derived.json"),
    lambda doc: doc["sources"][1].update(checkpoint_lock_name="../unsafe.lock"),
    lambda doc: doc["sources"][0].update(enabled=False),
    lambda doc: doc["sources"][1].update(source_role="access"),
    lambda doc: doc.update(extra="private"),
])
def test_pair_loader_rejects_mutated_contract(tmp_path: Path, edit) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)
    document = json.loads(output.read_text(encoding="utf-8"))
    edit(document)
    output.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LiveMonitorError):
        load_live_monitor_pair_config(output)


def test_pair_no_clobber_and_source_symlink(tmp_path: Path) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)
    before = output.read_bytes()
    with pytest.raises(MonitorSetupError):
        create_monitor_pair_config(application, ssh, output)
    assert output.read_bytes() == before
    output.unlink()
    alias = tmp_path / "alias.log"
    alias.symlink_to(ssh)
    with pytest.raises(MonitorSetupError):
        create_monitor_pair_config(application, alias, output)
    assert not output.exists()


def test_pair_rejects_non_private_parent_and_does_not_expose_paths(tmp_path: Path) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)
    output.parent.chmod(0o755)
    try:
        with pytest.raises(LiveMonitorError) as caught:
            load_live_monitor_pair_config(output)
        assert str(application) not in str(caught.value) + repr(caught.value)
        assert str(ssh) not in str(caught.value) + repr(caught.value)
    finally:
        output.parent.chmod(0o700)


def test_pair_rejects_same_file_hardlink_and_orphan_checkpoint(tmp_path: Path) -> None:
    application, ssh, output = _sources(tmp_path)
    ssh.unlink()
    ssh.hardlink_to(application)
    with pytest.raises(MonitorSetupError, match="SETUP_INVALID_INPUT"):
        create_monitor_pair_config(application, ssh, output)
    assert not output.exists()
    ssh.unlink()
    ssh.write_text("synthetic\n", encoding="utf-8")
    output.parent.mkdir(mode=0o700)
    (output.parent / "checkpoint-ssh-v3.json").write_text("orphan", encoding="utf-8")
    with pytest.raises(MonitorSetupError, match="CHECKPOINT_ORPHAN"):
        create_monitor_pair_config(application, ssh, output)
    assert not output.exists()


def test_pair_rejects_symlinked_config_without_path_leak(tmp_path: Path) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)
    alias = output.parent / "alias.json"
    alias.symlink_to(output)
    with pytest.raises(LiveMonitorError) as caught:
        load_live_monitor_pair_config(alias)
    assert str(output) not in str(caught.value) + repr(caught.value)


def test_pair_starts_through_production_paths_without_sample_fallback(tmp_path: Path, capsys) -> None:
    application, ssh, output = _sources(tmp_path)
    create_monitor_pair_config(application, ssh, output)

    class Listener:
        closed = False
        def close(self):
            self.closed = True

    class Server:
        should_exit = False
        force_exit = False
        def run(self, sockets):
            import time
            while not self.should_exit:
                time.sleep(0.005)

    listeners = []
    def listener(_port: int):
        sock = Listener()
        listeners.append(sock)
        return sock

    for options in ({"monitor_config": output},
                    {"monitor_default": True, "default_config_resolver": lambda: output}):
        result = local_web.run_local_web(open_browser=False, listener_factory=listener,
                                         server_factory=lambda _app, _port: Server(),
                                         readiness=lambda _port: True,
                                         sleep=lambda _duration: (_ for _ in ()).throw(KeyboardInterrupt()),
                                         **options)
        assert result == 0
        captured = capsys.readouterr()
        assert not captured.err
        assert str(output) not in captured.out and str(application) not in captured.out
        assert str(ssh) not in captured.out
    assert len(listeners) == 2
