"""Same-file checkpoint replay must rebuild trusted state without old publication."""

import asyncio
import json
import os
from pathlib import Path
import time

import pytest

from app.local_web import _live_runtime
from app.monitor_setup import create_monitor_config
from app.monitor_setup import show_default_config, delete_default_config, MonitorSetupError
from app.live_monitoring.checkpoint import LiveCheckpointError, LiveCheckpointManager, CHECKPOINT_NAME, LOCK_NAME
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState


FAILURE = "2026-01-02 03:04:05 INFO login_failed user=canary_account ip=192.0.2.9\n"
SUCCESS = "2026-01-02 03:04:06 INFO user_login user=canary_account ip=192.0.2.9\n"


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "canary-source.log"
    source.write_text(FAILURE, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_config(source, config)
    return source, config


def _close(service) -> None:
    asyncio.run(service.close())


def test_same_file_replay_restores_prefix_without_republishing(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        assert worker.step().status == "NO_DATA"
        assert worker._accumulator.snapshot().history_record_count == 0
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        assert worker.step().status == "PROCESSED"
        assert worker._accumulator.snapshot().history_record_count == 1
        original_detection = worker._accumulator.snapshot()
        original_analysis = worker._analysis.snapshot()
        assert worker.publication_buffer.snapshot().published_total > 0
    finally:
        _close(service)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(SUCCESS)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        assert worker._accumulator.snapshot() == original_detection
        assert worker._analysis.snapshot() == original_analysis
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.step().status == "PROCESSED"
        assert worker._accumulator.snapshot().history_record_count == 2
        assert worker._analysis.snapshot().relation_count >= 1
    finally:
        _close(service)


def test_changed_file_is_rejected_without_fallback(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    replacement = tmp_path / "replacement.log"
    replacement.write_text(FAILURE, encoding="utf-8")
    replacement.replace(source)
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_SOURCE_CHANGED"
    assert str(source) not in repr(caught.value)
    assert (config.parent / CHECKPOINT_NAME).exists()


def test_rename_with_old_writer_still_appending_does_not_handoff(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    original_checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
    try:
        with source.open("a", encoding="utf-8") as old_writer:
            replacement = tmp_path / "new-generation.log"
            replacement.write_text(SUCCESS, encoding="utf-8")
            replacement.replace(source)
            old_writer.write(FAILURE)
            old_writer.flush()
            with pytest.raises(LiveWorkerError) as caught:
                worker.step()
        assert caught.value.code == "POLL_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._session.snapshot().state == "FAILED"
        assert worker._session.snapshot().acknowledged_record_count == 0
        assert worker._session.snapshot().queue_item_count == 0
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == original_checkpoint
        assert all(canary not in str(caught.value) + repr(caught.value)
                   for canary in (str(source), str(config), "canary_account", "192.0.2.9"))
    finally:
        _close(service)


def test_concurrent_default_instance_is_rejected(tmp_path: Path) -> None:
    _, config = _fixture(tmp_path)
    first, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with pytest.raises(LiveCheckpointError) as caught:
            _live_runtime(config, checkpoint_default=True)
        assert caught.value.code == "CHECKPOINT_ALREADY_OWNED"
    finally:
        _close(first)


def test_replaced_lock_name_after_poll_stops_before_queue_ack(tmp_path: Path, monkeypatch) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
    lock = config.parent / LOCK_NAME
    original_poll = worker._session.poll_once

    def poll_then_replace_lock():
        result = original_poll()
        lock.unlink()
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        return result

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(type(worker._session), "poll_once", lambda self: poll_then_replace_lock())
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "CHECKPOINT_PREPARE_FAILED"
        for canary in (str(source), str(config), "canary_account", "192.0.2.9"):
            assert canary not in str(caught.value) + repr(caught.value)
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert worker._session.snapshot().acknowledged_record_count == 0
        assert worker._session.snapshot().available_item_count == 1
        assert worker._session.snapshot().leased_item_count == 0
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == checkpoint
    finally:
        _close(service)


@pytest.mark.parametrize("change", ("replace", "truncate"))
def test_source_change_after_poll_stops_before_ack_and_checkpoint(
    tmp_path: Path, monkeypatch, change: str,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    previous_checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
    original_poll = type(worker._session).poll_once

    def poll_then_change(session):
        result = original_poll(session)
        if change == "replace":
            replacement = tmp_path / "replacement.log"
            replacement.write_text(FAILURE, encoding="utf-8")
            replacement.replace(source)
        else:
            with source.open("r+b") as stream:
                stream.truncate(0)
        return result

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(type(worker._session), "poll_once", poll_then_change)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "SOURCE_CHANGED_BEFORE_ACK"
        assert all(value not in str(caught.value) + repr(caught.value)
                   for value in (str(source), str(config), "canary_account", "192.0.2.9"))
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        queue = worker._session.snapshot()
        assert queue.acknowledged_record_count == 0
        assert queue.available_item_count == queue.queue_item_count == 1
        assert queue.leased_item_count == 0 and not queue.active_lease
        assert queue.released_lease_count == 1
        assert worker._accumulator.snapshot().revision == 0
        assert not worker._accumulator.snapshot().active_proposal
        assert worker._analysis.snapshot().revision == 0
        assert not worker._analysis.snapshot().active_proposal
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.publication_buffer._active is None
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == previous_checkpoint
    finally:
        _close(service)


def test_source_replacement_after_publication_prepare_aborts_entire_batch(
    tmp_path: Path, monkeypatch,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    previous_checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
    original_prepare = type(worker.publication_buffer).prepare_batch

    def prepare_then_replace(buffer, *args):
        proposal = original_prepare(buffer, *args)
        replacement = tmp_path / "replacement.log"
        replacement.write_text(FAILURE, encoding="utf-8")
        replacement.replace(source)
        return proposal

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(type(worker.publication_buffer), "prepare_batch", prepare_then_replace)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "SOURCE_CHANGED_BEFORE_ACK"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        queue = worker._session.snapshot()
        assert queue.acknowledged_record_count == 0
        assert queue.available_item_count == queue.queue_item_count == 1
        assert not queue.active_lease and queue.released_lease_count == 1
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
        assert not worker._accumulator.snapshot().active_proposal
        assert not worker._analysis.snapshot().active_proposal
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.publication_buffer._active is None
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == previous_checkpoint
    finally:
        _close(service)


def test_replaced_lock_name_stops_idle_worker_before_poll(tmp_path: Path) -> None:
    _, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    lock = config.parent / LOCK_NAME
    try:
        lock.unlink()
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "POLL_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
    finally:
        _close(service)


def test_replaced_lock_name_after_ack_stops_without_checkpoint_advance(
    tmp_path: Path, monkeypatch,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    checkpoint = config.parent / CHECKPOINT_NAME
    prior = checkpoint.read_bytes()
    original = LiveCheckpointManager.commit_step

    def replace_lock_before_commit(self, *args):
        lock = config.parent / LOCK_NAME
        lock.unlink()
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        return original(self, *args)

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        with monkeypatch.context() as patch:
            patch.setattr(LiveCheckpointManager, "commit_step", replace_lock_before_commit)
            with pytest.raises(LiveWorkerError) as caught:
                worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._session.snapshot().acknowledged_record_count == 1
        assert worker._accumulator.snapshot().revision == 1
        assert worker._analysis.snapshot().revision == 1
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
        assert checkpoint.read_bytes() == prior
    finally:
        _close(service)


def test_unsupported_checkpoint_lock_platform_fails_closed(tmp_path: Path,
                                                            monkeypatch) -> None:
    from app.live_monitoring import checkpoint as checkpoint_module

    _, config = _fixture(tmp_path)
    monkeypatch.setattr(checkpoint_module, "fcntl", None)
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_UNSAFE"


def test_replay_preserves_brute_relation_risk_and_case_semantics(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        with source.open("a", encoding="utf-8") as stream:
            for second in range(5):
                stream.write(f"2026-01-02 03:04:{second:02d} INFO login_failed "
                             "user=canary_account ip=192.0.2.9\n")
        assert worker.step().status == "PROCESSED"
        prior_detection = worker._accumulator.snapshot()
        prior_analysis = worker._analysis.snapshot()
    finally:
        _close(service)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        assert worker._accumulator.snapshot() == prior_detection
        assert worker._analysis.snapshot() == prior_analysis
        assert worker.publication_buffer.snapshot().published_total == 0
        with source.open("a", encoding="utf-8") as stream:
            stream.write(SUCCESS)
        assert worker.step().status == "PROCESSED"
        relations = worker._analysis.snapshot().relations
        assert {item.relation_type for item in relations if item.state == "ACTIVE"} == {
            "failed_to_successful_login", "brute_force_to_successful_login"
        }
        assert any(item.rule_id == "CASE-BRUTE-SUCCESS-01" for item in worker._analysis.snapshot().cases)
        assert worker._analysis.snapshot().risk_count >= 1
    finally:
        _close(service)


def test_checkpoint_private_metadata_and_corruption_rejected(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        service._worker.step()
    finally:
        _close(service)
    checkpoint = config.parent / CHECKPOINT_NAME
    content = checkpoint.read_text(encoding="utf-8")
    for canary in ("canary_account", "192.0.2.9", str(source), str(config), FAILURE):
        assert canary not in content
    document = json.loads(content)
    assert document["batches"] == [1]
    assert document["committed_offset"] > document["replay_start_offset"]
    assert checkpoint.stat().st_mode & 0o777 == 0o600
    document["unknown"] = "must reject"
    checkpoint.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_CORRUPT"


def test_truncation_rejected_and_no_checkpoint_replay_on_explicit_config(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        service._worker.step()
    finally:
        _close(service)
    with source.open("r+b") as stream:
        stream.truncate(0)
    with pytest.raises((LiveCheckpointError, ValueError)):
        _live_runtime(config, checkpoint_default=True)
    # Explicit --monitor-config retains v0.2 FROM_END semantics even with v2 policy.
    explicit, _ = _live_runtime(config)
    try:
        assert explicit._worker._accumulator.snapshot().revision == 0
        assert explicit._worker.step().status == "NO_DATA"
    finally:
        _close(explicit)


def test_observed_shrink_above_cursor_does_not_ack_or_advance_checkpoint(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE * 200)
        assert worker.step().status == "PROCESSED"
        before_size = source.stat().st_size
        assert worker._session._offset + 1 < before_size
        prior_checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
        prior_ack = worker._session.snapshot().acknowledged_record_count
        prior_revision = worker._accumulator.snapshot().revision
        prior_publication = worker.publication_buffer.snapshot().latest_committed_detection_revision
        with source.open("r+b") as stream:
            stream.truncate(worker._session._offset + 1)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "POLL_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._session.snapshot().error_code == "SOURCE_TRUNCATED"
        assert worker._session.snapshot().acknowledged_record_count == prior_ack
        assert worker._accumulator.snapshot().revision == prior_revision
        assert worker._analysis.snapshot().revision == prior_revision
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == prior_publication
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == prior_checkpoint
    finally:
        _close(service)


def test_partial_ignored_and_rejected_replay_without_old_events(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write("\n")
            stream.write("not an application event\n")
            stream.write(FAILURE)
            stream.write("2026-01-02 03:04:06 INFO user_login user=canary_account ")
        assert service._worker.step().status == "PROCESSED"
        before = service._worker._accumulator.snapshot()
        assert before.total_parsed == 1
        assert service._worker._session.snapshot().partial_buffer_byte_count > 0
    finally:
        _close(service)
    with source.open("a", encoding="utf-8") as stream:
        stream.write("ip=192.0.2.9\n")
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert service._worker._accumulator.snapshot() == before
        assert service._worker.publication_buffer.snapshot().published_total == 0
        assert service._worker.step().status == "PROCESSED"
        assert service._worker._analysis.snapshot().relation_count >= 1
    finally:
        _close(service)


def test_replay_preserves_crlf_and_multibyte_byte_boundaries(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("ab") as stream:
            stream.write("무시할 줄\r\n".encode("utf-8"))
            stream.write(FAILURE.rstrip("\n").encode("utf-8") + b"\r\n")
            stream.write("미완성".encode("utf-8"))
        assert service._worker.step().status == "PROCESSED"
        before = service._worker._accumulator.snapshot()
        checkpoint = json.loads((config.parent / CHECKPOINT_NAME).read_text(encoding="utf-8"))
        assert checkpoint["committed_offset"] < source.stat().st_size
        assert checkpoint["partial_line_present"] is True
    finally:
        _close(service)
    with source.open("ab") as stream:
        stream.write(b"\n")
    restored, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot() == before
        assert restored._worker.publication_buffer.snapshot().published_total == 0
        assert restored._worker.step().status == "PROCESSED"
    finally:
        _close(restored)


def test_checkpoint_failure_after_publication_is_terminal_and_keeps_old_file(
    tmp_path: Path, monkeypatch,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    old_bytes = (config.parent / CHECKPOINT_NAME).read_bytes()
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(LiveCheckpointManager, "_write",
                            lambda *_args: (_ for _ in ()).throw(OSError("private exception")))
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._accumulator.snapshot().revision == 1
        assert worker._analysis.snapshot().revision == 1
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == old_bytes
        with pytest.raises(LiveWorkerError):
            worker.step()
    finally:
        _close(service)


def test_replay_semantic_mismatch_is_terminal_start_failure(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
            stream.write(FAILURE)
        service._worker.step()
    finally:
        _close(service)
    with source.open("r+b") as stream:
        raw = stream.read()
        stream.seek(0)
        marker = raw.rfind(b"192.0.2.9")
        assert marker >= 0
        stream.write(raw[:marker] + b"192.0.2.8" + raw[marker + len(b"192.0.2.9"):])
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_REPLAY_MISMATCH"


@pytest.mark.parametrize("mutation", ("world_readable", "symlink"))
def test_unsafe_checkpoint_is_not_ignored(tmp_path: Path, mutation: str) -> None:
    _, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    checkpoint = config.parent / CHECKPOINT_NAME
    if mutation == "world_readable":
        checkpoint.chmod(0o644)
    else:
        checkpoint.rename(config.parent / "held-checkpoint.json")
        checkpoint.symlink_to(config.parent / "held-checkpoint.json")
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_UNSAFE"


def test_show_and_delete_include_checkpoint_without_exposing_positions(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    first = show_default_config(config)
    assert first.recovery_state == "FIRST_START" and not first.checkpoint_exists
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        service._worker.step()
        shown = show_default_config(config)
        assert shown.recovery_state == "RECOVERABLE"
        assert shown.checkpoint_exists and shown.bounded_history_count == 1
        for canary in (str(source), str(config), "192.0.2.9", "canary_account"):
            assert canary not in repr(shown)
        with pytest.raises(MonitorSetupError) as caught:
            delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None)
        assert caught.value.code == "CHECKPOINT_DELETE_FAILED"
        assert config.exists()
    finally:
        _close(service)
    assert delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None).status == "DELETED"
    assert not config.exists() and not (config.parent / CHECKPOINT_NAME).exists()
    assert source.exists()


def test_checkpoint_deleted_config_cannot_be_silently_recreated(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    config.unlink()  # Simulates an interrupted two-file delete, not a supported CLI action.
    with pytest.raises(MonitorSetupError) as caught:
        create_monitor_config(source, config)
    assert caught.value.code == "CHECKPOINT_ORPHAN"
    assert not config.exists() and (config.parent / CHECKPOINT_NAME).exists()


def test_replay_record_bound_releases_fifo_before_ack(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write("\n" * 257)
        for _ in range(16):
            assert worker.step().status == "PROCESSED"
        prior_revision = worker._accumulator.snapshot().revision
        assert prior_revision == 16
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "CHECKPOINT_PREPARE_FAILED"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        queue = worker._session.snapshot()
        assert queue.available_item_count == 1 and queue.leased_item_count == 0
        assert worker._accumulator.snapshot().revision == prior_revision
        assert worker._analysis.snapshot().revision == prior_revision
    finally:
        _close(service)


def test_atomic_replace_fault_preserves_prior_checkpoint_and_cleans_temp(
    tmp_path: Path, monkeypatch,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    checkpoint = config.parent / CHECKPOINT_NAME
    prior = checkpoint.read_bytes()
    original = os.replace

    def fail_checkpoint_replace(source_name, target_name, **kwargs):
        if target_name == CHECKPOINT_NAME:
            raise OSError("private canary exception")
        return original(source_name, target_name, **kwargs)

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(os, "replace", fail_checkpoint_replace)
        with pytest.raises(LiveWorkerError) as caught:
            service._worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert checkpoint.read_bytes() == prior
        assert list(config.parent.glob(".checkpoint-*")) == []
    finally:
        _close(service)


@pytest.mark.parametrize("point", ("temp_create", "write", "fsync", "atomic_replace"))
def test_update_write_fault_keeps_prior_checkpoint_and_stops_worker(
    tmp_path: Path, monkeypatch, point: str,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    checkpoint = config.parent / CHECKPOINT_NAME
    prior = checkpoint.read_bytes()
    original_open, original_write = os.open, os.write
    original_fsync, original_replace = os.fsync, os.replace

    def fail_open(path, *args, **kwargs):
        if type(path) is str and path.startswith(".checkpoint-"):
            raise OSError("private fault")
        return original_open(path, *args, **kwargs)

    def fail_write(fd, data):
        raise OSError("private fault")

    def fail_fsync(fd):
        raise OSError("private fault")

    def fail_replace(source_name, target_name, **kwargs):
        if target_name == CHECKPOINT_NAME:
            raise OSError("private fault")
        return original_replace(source_name, target_name, **kwargs)

    with source.open("a", encoding="utf-8") as stream:
        stream.write(FAILURE)
    with monkeypatch.context() as patch:
        name, replacement = {
            "temp_create": ("open", fail_open),
            "write": ("write", fail_write),
            "fsync": ("fsync", fail_fsync),
            "atomic_replace": ("replace", fail_replace),
        }[point]
        patch.setattr(os, name, replacement)
        with pytest.raises(LiveWorkerError) as caught:
            service._worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert "private fault" not in repr(caught.value)
        assert service._worker.snapshot().state is LiveWorkerState.FAILED
        assert service._worker._accumulator.snapshot().revision == 1
        assert service._worker._analysis.snapshot().revision == 1
        assert service._worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
        assert checkpoint.read_bytes() == prior
        assert list(config.parent.glob(".checkpoint-*")) == []
    _close(service)


def test_delete_second_file_failure_is_explicit_and_orphan_blocks_new_setup(
    tmp_path: Path, monkeypatch,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original = os.unlink

    def fail_checkpoint_unlink(name, **kwargs):
        if name == CHECKPOINT_NAME:
            raise OSError("private canary exception")
        return original(name, **kwargs)

    monkeypatch.setattr(os, "unlink", fail_checkpoint_unlink)
    with pytest.raises(MonitorSetupError) as caught:
        delete_default_config(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_DELETE_FAILED"
    assert not config.exists() and (config.parent / CHECKPOINT_NAME).exists()
    with pytest.raises(MonitorSetupError) as orphan:
        create_monitor_config(source, config)
    assert orphan.value.code == "CHECKPOINT_ORPHAN"


def test_safe_verification_is_utc_kst_and_repeat_deterministic(tmp_path: Path,
                                                                monkeypatch) -> None:
    from app.live_monitoring.checkpoint import _semantic_digest

    old_zone = os.environ.get("TZ")
    values = []
    try:
        for index, zone in enumerate(("UTC", "Asia/Seoul", "UTC")):
            monkeypatch.setenv("TZ", zone)
            if hasattr(time, "tzset"):
                time.tzset()
            source, config = _fixture(tmp_path / f"run-{index}")
            service, _ = _live_runtime(config, checkpoint_default=True)
            try:
                with source.open("a", encoding="utf-8") as stream:
                    stream.write(FAILURE)
                service._worker.step()
                values.append(_semantic_digest(service._worker))
            finally:
                _close(service)
    finally:
        if old_zone is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", old_zone)
        if hasattr(time, "tzset"):
            time.tzset()
    assert values[0] == values[1] == values[2]


@pytest.mark.parametrize("point", ("temp_create", "write", "fsync", "atomic_publish"))
def test_initial_checkpoint_fault_prevents_server_start(tmp_path: Path, monkeypatch,
                                                       point: str) -> None:
    _, config = _fixture(tmp_path)
    original_open, original_write = os.open, os.write
    original_fsync, original_replace = os.fsync, os.replace

    def fail_open(path, *args, **kwargs):
        if type(path) is str and path.startswith(".checkpoint-"):
            raise OSError("internal canary")
        return original_open(path, *args, **kwargs)

    def fail_write(fd, data):
        raise OSError("internal canary")

    def fail_fsync(fd):
        raise OSError("internal canary")

    def fail_replace(source_name, target_name, **kwargs):
        if target_name == CHECKPOINT_NAME:
            raise OSError("internal canary")
        return original_replace(source_name, target_name, **kwargs)

    monkeypatch.setattr(os, {"temp_create": "open", "write": "write",
                             "fsync": "fsync", "atomic_publish": "replace"}[point],
                        {"temp_create": fail_open, "write": fail_write,
                         "fsync": fail_fsync, "atomic_publish": fail_replace}[point])
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_WRITE_FAILED"
    assert "internal canary" not in str(caught.value)
    assert list(config.parent.glob(".checkpoint-*")) == []


@pytest.mark.parametrize("point", ("range_read", "parser", "detection", "analysis"))
def test_replay_fault_fails_closed_before_publication(tmp_path: Path, monkeypatch,
                                                      point: str) -> None:
    from app.live_monitoring import checkpoint as checkpoint_module
    from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
    from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator

    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        service._worker.step()
    finally:
        _close(service)
    if point == "range_read":
        original = os.pread

        def fail_replay(fd, amount, offset):
            if offset > 0:
                raise OSError("internal canary")
            return original(fd, amount, offset)
        monkeypatch.setattr(os, "pread", fail_replay)
    elif point == "parser":
        monkeypatch.setattr(checkpoint_module, "parse_live_records",
                            lambda *_args: (_ for _ in ()).throw(RuntimeError("internal canary")))
    elif point == "detection":
        monkeypatch.setattr(LiveDetectionAccumulator, "prepare",
                            lambda *_args: (_ for _ in ()).throw(RuntimeError("internal canary")))
    else:
        monkeypatch.setattr(LiveAnalysisAccumulator, "prepare",
                            lambda *_args: (_ for _ in ()).throw(RuntimeError("internal canary")))
    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_REPLAY_MISMATCH"
    assert "internal canary" not in str(caught.value)


def test_fault_after_checkpoint_commit_does_not_reprocess_revision(tmp_path: Path,
                                                                   monkeypatch) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    original = LiveCheckpointManager.commit_step

    def raise_after_commit(self, *args):
        original(self, *args)
        raise RuntimeError("private exception")

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        monkeypatch.setattr(LiveCheckpointManager, "commit_step", raise_after_commit)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._accumulator.snapshot().revision == 1
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
    finally:
        _close(service)
        monkeypatch.setattr(LiveCheckpointManager, "commit_step", original)
    restored, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot().revision == 1
        assert restored._worker.publication_buffer.snapshot().published_total == 0
        assert restored._worker.step().status == "NO_DATA"
    finally:
        _close(restored)


@pytest.mark.parametrize("point", ("directory_fsync", "post_write_validation"))
def test_post_replace_fault_restores_complete_checkpoint_without_old_publication(
    tmp_path: Path, monkeypatch, point: str,
) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    checkpoint = config.parent / CHECKPOINT_NAME
    prior = checkpoint.read_bytes()
    manager = worker._checkpoint
    original_fsync = os.fsync
    original_read = LiveCheckpointManager._read_optional
    reads = 0

    def fail_directory_fsync(descriptor):
        if descriptor == manager._parent_fd:
            raise OSError("private post-replace canary")
        return original_fsync(descriptor)

    def fail_post_write_read(self):
        nonlocal reads
        if self is manager:
            reads += 1
            if reads == 2:
                raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")
        return original_read(self)

    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(FAILURE)
        with monkeypatch.context() as patch:
            if point == "directory_fsync":
                patch.setattr(os, "fsync", fail_directory_fsync)
            else:
                patch.setattr(LiveCheckpointManager, "_read_optional", fail_post_write_read)
            with pytest.raises(LiveWorkerError) as caught:
                worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert "private post-replace canary" not in repr(caught.value)
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._accumulator.snapshot().revision == 1
        assert worker._analysis.snapshot().revision == 1
        assert worker.publication_buffer.snapshot().latest_committed_detection_revision == 1
        assert checkpoint.read_bytes() != prior
        assert list(config.parent.glob(".checkpoint-*")) == []
    finally:
        _close(service)

    restored, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot().revision == 1
        assert restored._worker._analysis.snapshot().revision == 1
        assert restored._worker.publication_buffer.snapshot().published_total == 0
        assert restored._worker.step().status == "NO_DATA"
        with source.open("a", encoding="utf-8") as stream:
            stream.write(SUCCESS)
        assert restored._worker.step().status == "PROCESSED"
        assert restored._worker._analysis.snapshot().relation_count >= 1
    finally:
        _close(restored)


def test_checkpoint_close_fault_is_bounded_and_retry_releases_fd(tmp_path: Path,
                                                                  monkeypatch) -> None:
    _, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    with monkeypatch.context() as patch:
        patch.setattr(LiveCheckpointManager, "close",
                      lambda _self: (_ for _ in ()).throw(OSError("private close canary")))
        with pytest.raises(LiveWorkerError) as caught:
            worker.close()
        assert caught.value.code == "CLOSE_FAILURE"
        assert "private close canary" not in str(caught.value)
        assert worker.snapshot().state is LiveWorkerState.FAILED
    worker.close()
    assert worker.snapshot().state is LiveWorkerState.STOPPED
    assert worker._session._fd == -1
