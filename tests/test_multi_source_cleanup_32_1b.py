"""Faults during internal pair startup must settle every owned resource."""

from pathlib import Path
import json
import os

import pytest

from app.live_monitoring import multi_source
from app.live_monitoring.checkpoint import LiveCheckpointManager
from app.live_monitoring.multi_source import MultiSourceRuntimeError
from app.live_monitoring.core import LiveTailSession
from app.live_monitoring.worker import LiveProcessingWorker
from app.monitor_setup import create_monitor_pair_config


PRIVATE_MESSAGE = (
    "PRIVATE_RUNTIME_CANARY /private/synthetic/application-canary.log "
    "/private/synthetic/ssh-canary.log account-canary 192.0.2.47 "
    "hostname-canary raw-line-canary"
)


def _config(tmp_path: Path) -> Path:
    application = tmp_path / "application-canary.log"
    ssh = tmp_path / "ssh-canary.log"
    application.write_text("synthetic application line\n", encoding="utf-8")
    ssh.write_text("synthetic SSH line\n", encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    return config


def _inject_tail_and_ssh_close_failure(monkeypatch) -> list[str]:
    attempts = []
    original_close = LiveCheckpointManager.close

    def fail_tail(*args, **kwargs):
        raise RuntimeError(PRIVATE_MESSAGE)

    def close_manager(self):
        attempts.append(self._config.source_role)
        if self._config.source_role == "ssh":
            raise RuntimeError(PRIVATE_MESSAGE)
        return original_close(self)

    monkeypatch.setattr(multi_source, "open_live_tail_session", fail_tail)
    monkeypatch.setattr(LiveCheckpointManager, "close", close_manager)
    return attempts


def test_startup_cleanup_attempts_application_after_ssh_close_fault(tmp_path: Path,
                                                                    monkeypatch):
    config = _config(tmp_path)
    attempts = _inject_tail_and_ssh_close_failure(monkeypatch)
    with pytest.raises(Exception):
        multi_source.open_internal_pair_runtime(config)
    assert attempts == ["ssh", "application"]


def test_startup_cleanup_hides_internal_fault_text(tmp_path: Path, monkeypatch, caplog):
    config = _config(tmp_path)
    _inject_tail_and_ssh_close_failure(monkeypatch)
    with pytest.raises(Exception) as caught:
        multi_source.open_internal_pair_runtime(config)
    assert isinstance(caught.value, MultiSourceRuntimeError)
    assert caught.value.code == "PAIR_START_FAILED"
    safe_text = str(caught.value) + repr(caught.value) + caplog.text
    for canary in (PRIVATE_MESSAGE, str(config), "application-canary.log", "ssh-canary.log",
                   "account-canary", "192.0.2.47", "hostname-canary", "raw-line-canary"):
        assert canary not in safe_text


@pytest.mark.parametrize(
    "stage,failed_managers,failed_tail,failed_lock",
    [
        ("tail", ("ssh",), False, False),
        ("tail", ("application",), False, False),
        ("tail", ("ssh", "application"), False, False),
        ("tail", ("ssh",), True, False),
        ("tail", (), False, True),
        ("worker", ("ssh",), False, False),
    ],
)
def test_startup_cleanup_fault_matrix(tmp_path: Path, monkeypatch, caplog, stage,
                                      failed_managers, failed_tail, failed_lock):
    config = _config(tmp_path)
    managers = []
    sessions = []
    workers = []
    owned_descriptors = []
    manager_attempts = []
    tail_attempts = []
    original_manager_init = LiveCheckpointManager.__init__
    original_manager_close = LiveCheckpointManager.close
    original_tail_open = multi_source.open_live_tail_session
    original_tail_close = LiveTailSession.close
    original_worker_init = LiveProcessingWorker.__init__
    original_restore = LiveCheckpointManager.initialize_or_restore
    original_os_close = os.close
    lock_faulted = False

    def init_manager(self, *args, **kwargs):
        original_manager_init(self, *args, **kwargs)
        managers.append(self)
        owned_descriptors.extend((self._lock_fd, self._parent_fd))

    def close_manager(self):
        manager_attempts.append(self._config.source_role)
        if self._config.source_role in failed_managers:
            raise RuntimeError(PRIVATE_MESSAGE)
        return original_manager_close(self)

    def open_tail(*args, **kwargs):
        if stage == "tail" and sessions:
            raise RuntimeError(PRIVATE_MESSAGE)
        session = original_tail_open(*args, **kwargs)
        sessions.append(session)
        owned_descriptors.append(session._fd)
        return session

    def close_tail(self):
        tail_attempts.append(self.source_role)
        if failed_tail:
            raise RuntimeError(PRIVATE_MESSAGE)
        return original_tail_close(self)

    def init_worker(self, *args, **kwargs):
        original_worker_init(self, *args, **kwargs)
        workers.append(self)

    def fail_restore(self, worker):
        if stage == "worker" and self._config.source_role == "ssh":
            raise RuntimeError(PRIVATE_MESSAGE)
        return original_restore(self, worker)

    def close_descriptor(descriptor):
        nonlocal lock_faulted
        if (failed_lock and not lock_faulted and len(managers) == 2
            and descriptor == managers[1]._lock_fd):
            lock_faulted = True
            raise OSError(PRIVATE_MESSAGE)
        return original_os_close(descriptor)

    with monkeypatch.context() as faults:
        faults.setattr(LiveCheckpointManager, "__init__", init_manager)
        faults.setattr(LiveCheckpointManager, "close", close_manager)
        faults.setattr(multi_source, "open_live_tail_session", open_tail)
        faults.setattr(LiveTailSession, "close", close_tail)
        faults.setattr(LiveProcessingWorker, "__init__", init_worker)
        faults.setattr(LiveCheckpointManager, "initialize_or_restore", fail_restore)
        faults.setattr(os, "close", close_descriptor)
        with pytest.raises(MultiSourceRuntimeError) as caught:
            multi_source.open_internal_pair_runtime(config)

    assert caught.value.code == "PAIR_START_FAILED"
    assert len(managers) == 2
    assert set(manager_attempts) == {"application", "ssh"}
    assert len(sessions) == (1 if stage == "tail" else 2)
    assert len(workers) == (0 if stage == "tail" else 2)
    assert set(tail_attempts) == {session.source_role for session in sessions}
    assert lock_faulted is failed_lock
    for descriptor in owned_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    for manager in managers:
        assert manager._lock_fd == -1
        assert manager._parent_fd == -1
        assert manager._closed
        manager.close()  # Repeated cleanup is idempotent.
    for session in sessions:
        assert session._fd == -1
        assert session._queue.item_count == 0
        assert session._active_lease is None
        session.close()
    for worker in workers:
        assert not worker._accumulator.snapshot().active_proposal
        assert not worker._analysis.snapshot().active_proposal
        assert worker._publication._active is None
    safe = str(caught.value) + repr(caught.value) + json.dumps({
        "code": caught.value.code, "summary": str(caught.value)
    }) + caplog.text
    for canary in (PRIVATE_MESSAGE, str(config), "application-canary.log", "ssh-canary.log",
                   "account-canary", "192.0.2.47", "hostname-canary", "raw-line-canary"):
        assert canary not in safe
    sources = [manager._config for manager in managers]
    for source in sources:
        acquired = LiveCheckpointManager(config, source)
        acquired.close()


def test_repeated_pair_close_after_fault_settles_both_roles(tmp_path: Path, monkeypatch,
                                                            caplog):
    config = _config(tmp_path)
    runtime = multi_source.open_internal_pair_runtime(config)
    original_close = LiveProcessingWorker.close
    attempts = []

    def fail_ssh_once(self):
        attempts.append(self._session.source_role)
        if self._session.source_role == "ssh" and attempts.count("ssh") == 1:
            raise RuntimeError(PRIVATE_MESSAGE)
        return original_close(self)

    with monkeypatch.context() as faults:
        faults.setattr(LiveProcessingWorker, "close", fail_ssh_once)
        with pytest.raises(MultiSourceRuntimeError, match="PAIR_CLOSE_FAILED") as caught:
            runtime.close()
        runtime.close()
    safe = str(caught.value) + repr(caught.value) + repr(runtime) + json.dumps({
        "code": caught.value.code, "state": runtime.state
    }) + caplog.text
    for canary in (PRIVATE_MESSAGE, str(config), "application-canary.log", "ssh-canary.log",
                   "account-canary", "192.0.2.47", "hostname-canary", "raw-line-canary"):
        assert canary not in safe
    assert attempts[:2] == ["ssh", "application"]
    assert runtime.state == "STOPPED"
    for worker in runtime.workers.values():
        assert worker._session._fd == -1
        assert worker._checkpoint._lock_fd == -1
        assert worker._session._queue.item_count == 0
        assert worker._session._active_lease is None
        assert not worker._accumulator.snapshot().active_proposal
        assert not worker._analysis.snapshot().active_proposal
