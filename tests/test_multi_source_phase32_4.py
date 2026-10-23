"""Independent role failure checks for Phase 32.4; synthetic files only."""

from pathlib import Path

import pytest

from app.live_monitoring.checkpoint import LiveCheckpointError, LiveCheckpointManager
from app.live_monitoring.config import load_live_monitor_pair_config
from app.live_monitoring.multi_source import MultiSourceRuntimeError, open_internal_pair_runtime
from app.live_monitoring.worker import LiveProcessingWorker
from app.monitor_setup import create_monitor_pair_config


APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")


def pair_files(root: Path):
    app, ssh = root / "application.log", root / "ssh.log"
    app.write_text(APP, encoding="utf-8")
    ssh.write_text(SSH, encoding="utf-8")
    config = root / "private" / "monitoring.json"
    create_monitor_pair_config(app, ssh, config)
    return app, ssh, config


@pytest.mark.parametrize("role", ["application", "ssh"])
@pytest.mark.parametrize("fault", ["truncate", "replace"])
def test_each_role_file_identity_fault_stops_pair_without_quiet_success(
    tmp_path: Path, role: str, fault: str,
):
    app, ssh, config = pair_files(tmp_path)
    runtime = open_internal_pair_runtime(config)
    sources = {"application": app, "ssh": ssh}
    other = "ssh" if role == "application" else "application"
    try:
        runtime.cycle()
        source = sources[role]
        if fault == "truncate":
            source.write_text("", encoding="utf-8")
        else:
            replacement = tmp_path / f"replacement-{role}.log"
            replacement.write_text(APP if role == "application" else SSH, encoding="utf-8")
            replacement.replace(source)
        with sources[other].open("a", encoding="utf-8") as stream:
            stream.write(APP if other == "application" else SSH)
        with pytest.raises(MultiSourceRuntimeError) as failed:
            runtime.cycle()
        assert "PAIR_" in str(failed.value)
        assert str(tmp_path) not in str(failed.value) + repr(failed.value)
        before = runtime.workers[other]._session.snapshot()
        with sources[other].open("a", encoding="utf-8") as stream:
            stream.write(APP if other == "application" else SSH)
        with pytest.raises(MultiSourceRuntimeError):
            runtime.cycle()
        assert runtime.workers[other]._session.snapshot() == before
    finally:
        runtime.close()
    assert all(worker._session._fd == -1 and worker._checkpoint._lock_fd == -1
               for worker in runtime.workers.values())


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_each_role_damaged_checkpoint_fails_pair_start_closed(tmp_path: Path, role: str):
    _, _, config = pair_files(tmp_path)
    sources = {item.source_role: item for item in load_live_monitor_pair_config(config).sources}
    runtime = open_internal_pair_runtime(config)
    runtime.close()
    checkpoint = config.parent / sources[role].checkpoint_name
    checkpoint.write_text("not a checkpoint", encoding="utf-8")
    checkpoint.chmod(0o600)
    with pytest.raises(MultiSourceRuntimeError) as failed:
        open_internal_pair_runtime(config)
    assert failed.value.code == "PAIR_START_FAILED"
    assert str(tmp_path) not in str(failed.value) + repr(failed.value)
    for source in sources.values():
        if source.source_role == role:
            for _ in range(2):
                with pytest.raises(LiveCheckpointError) as damaged:
                    LiveCheckpointManager(config, source)
                assert damaged.value.code == "CHECKPOINT_CORRUPT"
        else:
            manager = LiveCheckpointManager(config, source)
            manager.close()


@pytest.mark.parametrize("role", ["application", "ssh"])
def test_worker_fault_stops_pair_before_other_role_can_collect(
    tmp_path: Path, role: str, monkeypatch: pytest.MonkeyPatch,
):
    app, ssh, config = pair_files(tmp_path)
    runtime = open_internal_pair_runtime(config)
    other = "ssh" if role == "application" else "application"
    worker = runtime.workers[role]
    other_worker = runtime.workers[other]
    with (app if other == "application" else ssh).open("a", encoding="utf-8") as output:
        output.write(APP if other == "application" else SSH)
    original_step = LiveProcessingWorker.step

    def fail_selected(instance):
        if instance is worker:
            raise RuntimeError("/private/path account 192.0.2.9 host raw-line")
        return original_step(instance)

    monkeypatch.setattr(LiveProcessingWorker, "step", fail_selected)
    try:
        with pytest.raises(MultiSourceRuntimeError) as failed:
            runtime.cycle()
        assert failed.value.code in {"PAIR_FAILED", "PAIR_DEGRADED"}
        after = other_worker._session.snapshot()
        assert all(canary not in str(failed.value) + repr(failed.value)
                   for canary in (str(tmp_path), "account", "192.0.2.9", "raw-line"))
        with (app if other == "application" else ssh).open("a", encoding="utf-8") as output:
            output.write(APP if other == "application" else SSH)
        with pytest.raises(MultiSourceRuntimeError):
            runtime.cycle()
        assert other_worker._session.snapshot() == after
    finally:
        runtime.close()
