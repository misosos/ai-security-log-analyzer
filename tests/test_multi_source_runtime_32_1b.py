"""Internal v3 pair runtime must keep two trusted single-source chains separate."""

from pathlib import Path

import pytest

from app.monitor_setup import create_monitor_config, create_monitor_pair_config
from app.live_monitoring.checkpoint import LiveCheckpointError, LiveCheckpointManager
from app.live_monitoring.config import load_live_monitor_pair_config
from app.live_monitoring.multi_source import open_internal_pair_runtime
from app.live_monitoring import multi_source
from app.live_monitoring.worker import LiveProcessingWorker
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.local_web import _live_runtime
import asyncio
from dataclasses import asdict


APP_LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic_account ip=192.0.2.9\n"
SSH_LINE = ("2026-01-02 03:04:05 sshd: Failed password for synthetic_account "
            "from 198.51.100.23 port 5001 ssh2\n")


@pytest.fixture(autouse=True)
def _deterministic_admission_clock(monkeypatch):
    # Functional cases exercise both roles independent of host scheduling;
    # the soft-budget case below replaces this with an explicit slow clock.
    monkeypatch.setattr(multi_source, "monotonic", lambda: 0.0)


def _fixture(tmp_path: Path):
    application = tmp_path / "application.log"
    ssh = tmp_path / "ssh.log"
    application.write_text(APP_LINE, encoding="utf-8")
    ssh.write_text(SSH_LINE, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    return application, ssh, config


def test_pair_cycle_alternates_and_keeps_role_state_separate(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    try:
        assert runtime.cycle() == (("application", "NO_DATA"), ("ssh", "NO_DATA"))
        application.write_text(APP_LINE * 2, encoding="utf-8")
        ssh.write_text(SSH_LINE * 2, encoding="utf-8")
        assert runtime.cycle() == (("ssh", "PROCESSED"), ("application", "PROCESSED"))
        assert runtime.workers["application"]._accumulator.snapshot().history_record_count == 1
        assert runtime.workers["ssh"]._accumulator.snapshot().history_record_count == 1
        assert runtime.workers["application"]._analysis is not runtime.workers["ssh"]._analysis
    finally:
        runtime.close()


@pytest.mark.parametrize("active_role", ["application", "ssh"])
def test_pair_one_role_input_leaves_other_revision_unchanged(tmp_path: Path,
                                                               active_role: str):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    try:
        source = application if active_role == "application" else ssh
        with source.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE if active_role == "application" else SSH_LINE)
        statuses = dict(runtime.cycle())
        other = "ssh" if active_role == "application" else "application"
        assert statuses == {active_role: "PROCESSED", other: "NO_DATA"}
        assert runtime.workers[active_role]._accumulator.snapshot().revision == 1
        assert runtime.workers[other]._accumulator.snapshot().revision == 0
        assert runtime.workers[other]._analysis.snapshot().revision == 0
    finally:
        runtime.close()


def test_pair_restart_restores_independent_prefix_without_old_publication(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        runtime.cycle()
        snapshots = {role: worker._analysis.snapshot() for role, worker in runtime.workers.items()}
    finally:
        runtime.close()
    restored = open_internal_pair_runtime(config)
    try:
        for role, worker in restored.workers.items():
            assert worker._analysis.snapshot() == snapshots[role]
            assert worker.publication_buffer.snapshot().published_total == 0
    finally:
        restored.close()


def test_pair_second_lock_failure_releases_first_lock(tmp_path: Path):
    _, _, config = _fixture(tmp_path)
    sources = load_live_monitor_pair_config(config).sources
    blocker = LiveCheckpointManager(config, sources[1])
    try:
        with pytest.raises(ValueError, match="PAIR_START_FAILED"):
            open_internal_pair_runtime(config)
        first = LiveCheckpointManager(config, sources[0])
        first.close()
        assert not (config.parent / sources[0].checkpoint_name).exists()
    finally:
        blocker.close()


def test_pair_second_initialization_failure_removes_new_first_checkpoint(tmp_path: Path,
                                                                           monkeypatch):
    _, _, config = _fixture(tmp_path)
    sources = load_live_monitor_pair_config(config).sources
    original = LiveCheckpointManager.initialize_or_restore

    def fail_second(self, worker):
        if self._config.source_role == "ssh":
            raise LiveCheckpointError("CHECKPOINT_CORRUPT")
        return original(self, worker)

    monkeypatch.setattr(LiveCheckpointManager, "initialize_or_restore", fail_second)
    with pytest.raises(ValueError, match="PAIR_START_FAILED"):
        open_internal_pair_runtime(config)
    assert not (config.parent / sources[0].checkpoint_name).exists()
    first = LiveCheckpointManager(config, sources[0])
    first.close()


def test_pair_corrupt_checkpoint_fails_without_other_role_start(tmp_path: Path):
    _, _, config = _fixture(tmp_path)
    sources = load_live_monitor_pair_config(config).sources
    broken = config.parent / sources[1].checkpoint_name
    broken.write_text("invalid", encoding="utf-8")
    broken.chmod(0o600)
    with pytest.raises(ValueError, match="PAIR_START_FAILED"):
        open_internal_pair_runtime(config)
    assert not (config.parent / sources[0].checkpoint_name).exists()


def test_pair_changed_source_and_swapped_role_checkpoint_fail_closed(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    sources = load_live_monitor_pair_config(config).sources
    pair = open_internal_pair_runtime(config)
    pair.close()
    app_checkpoint = config.parent / sources[0].checkpoint_name
    ssh_checkpoint = config.parent / sources[1].checkpoint_name
    app_bytes, ssh_bytes = app_checkpoint.read_bytes(), ssh_checkpoint.read_bytes()
    app_checkpoint.write_bytes(ssh_bytes)
    ssh_checkpoint.write_bytes(app_bytes)
    with pytest.raises(ValueError, match="PAIR_START_FAILED"):
        open_internal_pair_runtime(config)
    app_checkpoint.write_bytes(app_bytes)
    ssh_checkpoint.write_bytes(ssh_bytes)
    replacement = tmp_path / "replacement.log"
    replacement.write_text(APP_LINE, encoding="utf-8")
    replacement.replace(application)
    with pytest.raises(ValueError, match="PAIR_START_FAILED"):
        open_internal_pair_runtime(config)


def test_pair_terminal_failure_stops_other_role(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    try:
        runtime.cycle()
        application.write_text("", encoding="utf-8")  # fail-closed truncation
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        with pytest.raises(ValueError, match="PAIR_FAILED"):
            runtime.cycle()  # SSH first may commit; application then fails.
        before = runtime.workers["ssh"]._accumulator.snapshot()
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        with pytest.raises(ValueError, match="PAIR_FAILED"):
            runtime.cycle()
        assert runtime.workers["ssh"]._accumulator.snapshot() == before
    finally:
        runtime.close()


def test_pair_close_attempts_both_roles_after_one_close_failure(tmp_path: Path, monkeypatch):
    _, _, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    application_fd = runtime.workers["application"]._session._fd
    ssh_fd = runtime.workers["ssh"]._session._fd
    original = LiveProcessingWorker.close

    def fail_one(self):
        if self._session.source_role == "application":
            raise RuntimeError("PRIVATE_EXCEPTION_CANARY")
        return original(self)

    monkeypatch.setattr(LiveProcessingWorker, "close", fail_one)
    with pytest.raises(ValueError, match="PAIR_CLOSE_FAILED") as caught:
        runtime.close()
    assert "PRIVATE_EXCEPTION_CANARY" not in str(caught.value) + repr(caught.value)
    for descriptor in (application_fd, ssh_fd):
        with pytest.raises(OSError):
            __import__("os").fstat(descriptor)


@pytest.mark.parametrize("burst_role", ["application", "ssh"])
def test_pair_burst_fairness_one_step_per_role_per_cycle(tmp_path: Path, burst_role: str):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    try:
        burst_file, other_file = ((application, ssh) if burst_role == "application"
                                  else (ssh, application))
        with burst_file.open("a", encoding="utf-8") as stream:
            stream.write((APP_LINE if burst_role == "application" else SSH_LINE) * 32)
        with other_file.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE if burst_role == "application" else APP_LINE)
        result = runtime.cycle()
        assert [role for role, _ in result] == ["application", "ssh"]
        assert all(status == "PROCESSED" for _, status in result)
        assert runtime.workers[burst_role]._accumulator.snapshot().history_record_count == 16
        other = "ssh" if burst_role == "application" else "application"
        assert runtime.workers[other]._accumulator.snapshot().history_record_count == 1
        assert [role for role, _ in runtime.cycle()] == ["ssh", "application"]
    finally:
        runtime.close()


def test_pair_rejects_same_file_identity_at_runtime(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    ssh.unlink()
    ssh.hardlink_to(application)
    with pytest.raises(ValueError, match="PAIR_SOURCE_DUPLICATE"):
        open_internal_pair_runtime(config)


@pytest.mark.parametrize("stage,expected", [("prepare", "DEGRADED"),
                                             ("commit", "FAILED")])
@pytest.mark.parametrize("fault_role", ["application", "ssh"])
def test_pair_role_fault_stops_other_without_cross_source_retry(tmp_path: Path, monkeypatch,
                                                                 stage: str, expected: str,
                                                                 fault_role: str):
    application, ssh, config = _fixture(tmp_path)
    runtime = open_internal_pair_runtime(config)
    if fault_role == "ssh":
        runtime.cycle()  # Make SSH the first role in the faulting cycle.
    original = getattr(LiveDetectionAccumulator, stage if stage == "prepare"
                       else "commit_prepared")

    def fail_role(self, proposal):
        if self.source_role == fault_role:
            raise RuntimeError("PRIVATE_EXCEPTION_CANARY")
        return original(self, proposal)

    monkeypatch.setattr(LiveDetectionAccumulator,
                        stage if stage == "prepare" else "commit_prepared", fail_role)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        with pytest.raises(ValueError, match=f"PAIR_{expected}") as caught:
            runtime.cycle()
        safe_text = str(caught.value) + repr(caught.value) + repr(runtime)
        for canary in ("PRIVATE_EXCEPTION_CANARY", str(application), str(ssh), str(config),
                       "synthetic_account", "192.0.2.9", "198.51.100.23"):
            assert canary not in safe_text
        assert runtime.state == expected
        other = "ssh" if fault_role == "application" else "application"
        assert runtime.workers[other]._accumulator.snapshot().history_record_count == 0
        session = runtime.workers[fault_role]._session.snapshot()
        assert not session.active_lease
        assert session.acknowledged_record_count == (0 if stage == "prepare" else 1)
        with pytest.raises(ValueError, match=f"PAIR_{expected}"):
            runtime.cycle()
    finally:
        runtime.close()


def test_pair_role_analysis_parity_with_existing_single_source_runtime(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    app_v2 = tmp_path / "app_v2" / "monitoring.json"
    ssh_v2 = tmp_path / "ssh_v2" / "monitoring.json"
    create_monitor_config(application, app_v2)
    create_monitor_config(ssh, ssh_v2, role="ssh")
    app_single, _ = _live_runtime(app_v2, checkpoint_default=True)
    ssh_single, _ = _live_runtime(ssh_v2, checkpoint_default=True)
    pair = open_internal_pair_runtime(config)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE * 5)
            stream.write("2026-01-02 03:04:06 INFO user_login user=synthetic_account ip=192.0.2.9\n")
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE * 5)
            stream.write("2026-01-02 03:04:06 sshd: Accepted password for synthetic_account "
                         "from 198.51.100.23 port 5001 ssh2\n")
        pair.cycle()
        app_single._worker.step()
        ssh_single._worker.step()
        for role, single in (("application", app_single), ("ssh", ssh_single)):
            assert pair.workers[role]._accumulator.snapshot() == single._worker._accumulator.snapshot()
            assert pair.workers[role]._analysis.snapshot() == single._worker._analysis.snapshot()
            pair_publication = asdict(pair.workers[role].publication_buffer.snapshot())
            single_publication = asdict(single._worker.publication_buffer.snapshot())
            for session_specific in ("session_id", "earliest_available_event_id",
                                     "latest_available_event_id"):
                pair_publication.pop(session_specific)
                single_publication.pop(session_specific)
            assert pair_publication == single_publication
    finally:
        pair.close()
        asyncio.run(app_single.close())
        asyncio.run(ssh_single.close())


def test_pair_each_role_bounded_256_prefix_and_no_silent_eviction(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    pair = open_internal_pair_runtime(config)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE * 256)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE * 256)
        for _ in range(64):
            pair.cycle()
            if all(worker._accumulator.snapshot().history_record_count == 256
                   for worker in pair.workers.values()):
                break
        assert all(worker._accumulator.snapshot().history_record_count == 256
                   for worker in pair.workers.values())
        for source, line in ((application, APP_LINE), (ssh, SSH_LINE)):
            with source.open("a", encoding="utf-8") as stream:
                stream.write(line)
        with pytest.raises(ValueError, match="PAIR_DEGRADED"):
            pair.cycle()
        assert all(worker._accumulator.snapshot().history_record_count == 256
                   for worker in pair.workers.values())
    finally:
        pair.close()


def test_pair_checkpoint_names_modes_and_settled_resources(tmp_path: Path):
    application, ssh, config = _fixture(tmp_path)
    sources = load_live_monitor_pair_config(config).sources
    pair = open_internal_pair_runtime(config)
    try:
        for source in sources:
            checkpoint = config.parent / source.checkpoint_name
            lock = config.parent / source.checkpoint_lock_name
            assert checkpoint.stat().st_mode & 0o777 == 0o600
            assert lock.stat().st_mode & 0o777 == 0o600
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        pair.cycle()
        for worker in pair.workers.values():
            assert not worker._session.snapshot().active_lease
            assert not worker._accumulator.snapshot().active_proposal
            assert not worker._analysis.snapshot().active_proposal
            assert worker._publication._active is None
            assert worker._session.snapshot().queue_item_count == 0
    finally:
        pair.close()


def test_pair_soft_budget_defers_second_role_and_prioritizes_it_next(tmp_path: Path,
                                                                      monkeypatch):
    application, ssh, config = _fixture(tmp_path)
    pair = open_internal_pair_runtime(config)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP_LINE)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH_LINE)
        ticks = iter((0.0, 0.2))
        monkeypatch.setattr(multi_source, "monotonic", lambda: next(ticks))
        assert pair.cycle() == (("application", "PROCESSED"),)
        assert pair.workers["ssh"]._accumulator.snapshot().history_record_count == 0
        ticks = iter((0.0, 0.0))
        assert pair.cycle() == (("ssh", "PROCESSED"), ("application", "NO_DATA"))
    finally:
        pair.close()


def test_pair_async_idle_waits_and_stops_without_busy_loop(tmp_path: Path):
    _, _, config = _fixture(tmp_path)
    pair = open_internal_pair_runtime(config)

    async def exercise():
        task = asyncio.create_task(pair.run())
        await asyncio.sleep(0.03)
        pair.request_stop()
        await task

    try:
        asyncio.run(exercise())
        assert all(worker.snapshot().step_revision == 1 for worker in pair.workers.values())
    finally:
        pair.close()


def test_pair_async_runner_rejects_second_caller(tmp_path: Path):
    _, _, config = _fixture(tmp_path)
    pair = open_internal_pair_runtime(config)

    async def exercise():
        first = asyncio.create_task(pair.run())
        await asyncio.sleep(0.01)
        with pytest.raises(ValueError, match="PAIR_BUSY"):
            await pair.run()
        with pytest.raises(ValueError, match="PAIR_BUSY"):
            pair.cycle()
        pair.request_stop()
        await first

    try:
        asyncio.run(exercise())
    finally:
        pair.close()
