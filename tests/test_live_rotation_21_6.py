"""Characterize rotation evidence without enabling automatic handoff."""

import os
from pathlib import Path

import pytest

from app.local_web import _live_runtime
from app.live_monitoring.checkpoint import CHECKPOINT_NAME, LiveCheckpointError
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState
from tests.test_live_checkpoint import FAILURE, SUCCESS, _close, _fixture


def test_old_file_eof_does_not_prove_writer_has_stopped(tmp_path: Path) -> None:
    source = tmp_path / "application.log"
    source.write_bytes(b"old\n")
    with source.open("rb", buffering=0) as reader, source.open("ab", buffering=0) as writer:
        reader.seek(0, os.SEEK_END)
        rotated = tmp_path / "rotated.log"
        source.replace(rotated)
        source.write_bytes(b"new\n")
        assert reader.read(1) == b""
        writer.write(b"late-old\n")
        writer.flush()
        assert reader.read() == b"late-old\n"
        assert source.read_bytes() == b"new\n"


def test_retained_old_generation_cannot_replay_from_new_source_path(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as writer:
            writer.write(FAILURE)
        assert service._worker.step().status == "PROCESSED"
    finally:
        _close(service)
    checkpoint = config.parent / CHECKPOINT_NAME
    original = checkpoint.read_bytes()
    rotated = tmp_path / "retained-old-generation.log"
    source.replace(rotated)
    # Keep the replacement at least as long as the committed offset so this
    # exercises the checkpoint identity gate rather than the tail offset gate.
    source.write_text(SUCCESS * 3, encoding="utf-8")

    with pytest.raises(LiveCheckpointError) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "CHECKPOINT_SOURCE_CHANGED"
    assert checkpoint.read_bytes() == original
    assert rotated.exists()
    assert source.exists()
    assert all(value not in str(caught.value) + repr(caught.value)
               for value in (str(source), str(rotated), str(config), "canary_account"))


def test_partial_old_line_is_not_joined_to_new_generation(tmp_path: Path) -> None:
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    checkpoint = config.parent / CHECKPOINT_NAME
    original = checkpoint.read_bytes()
    try:
        with source.open("ab") as writer:
            writer.write(FAILURE.encode("utf-8")[:-1])
        assert worker.step().status == "NO_DATA"
        rotated = tmp_path / "old-partial.log"
        source.replace(rotated)
        source.write_bytes(b"continuation\n")
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "POLL_FAILURE"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker._session.snapshot().acknowledged_record_count == 0
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert checkpoint.read_bytes() == original
    finally:
        _close(service)


def test_copytruncate_regrowth_can_preserve_identity_and_observed_size(tmp_path: Path) -> None:
    source = tmp_path / "application.log"
    source.write_bytes(b"old-line\n")
    with source.open("rb", buffering=0) as reader:
        before = os.fstat(reader.fileno())
        old_bytes = reader.read()
        with source.open("r+b", buffering=0) as writer:
            writer.truncate(0)
            writer.write(b"new-line\n")
        after = os.fstat(reader.fileno())
        assert (before.st_dev, before.st_ino, before.st_size) == (
            after.st_dev, after.st_ino, after.st_size)
        assert os.pread(reader.fileno(), after.st_size, 0) != old_bytes
