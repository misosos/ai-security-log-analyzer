"""Explicit new-epoch recovery never edits the source or monitoring config."""

import asyncio
import os
from pathlib import Path

import pytest

from app.local_web import _live_runtime
from app import monitor_setup
from app.monitor_setup import MonitorSetupError, create_monitor_config, reset_default_checkpoint
from app.live_monitoring.checkpoint import CHECKPOINT_NAME


LINE = "2026-01-02 03:04:05 INFO login_failed user=epoch_canary ip=192.0.2.9\n"


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "source-canary.log"
    source.write_text(LINE, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_config(source, config)
    return source, config, config.parent / CHECKPOINT_NAME


def _close(service) -> None:
    asyncio.run(service.close())


def test_reset_requires_approval_and_removes_only_checkpoint(tmp_path: Path) -> None:
    source, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original_config = config.read_bytes()
    original_source = source.read_bytes()
    sibling = config.parent / "keep.txt"
    sibling.write_text("keep", encoding="utf-8")
    original_checkpoint = checkpoint.read_bytes()

    assert reset_default_checkpoint(config, ask=lambda _: "no", emit=lambda _: None).status == "CANCELLED"
    assert checkpoint.read_bytes() == original_checkpoint
    result = reset_default_checkpoint(config, ask=lambda _: " YES ", emit=lambda _: None)
    assert result.status == "RESET"
    assert not checkpoint.exists()
    assert config.read_bytes() == original_config
    assert source.read_bytes() == original_source
    assert sibling.read_text(encoding="utf-8") == "keep"
    assert config.parent.exists()


def test_reset_eof_cancels_without_deletion(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original = checkpoint.read_bytes()
    output = []
    result = reset_default_checkpoint(
        config, ask=lambda _: (_ for _ in ()).throw(EOFError), emit=output.append,
    )
    assert result.status == "CANCELLED"
    assert checkpoint.read_bytes() == original
    assert any("취소" in line for line in output)


def test_active_monitor_blocks_reset_and_keeps_checkpoint(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    original = checkpoint.read_bytes()
    try:
        with pytest.raises(MonitorSetupError) as caught:
            reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
        assert caught.value.code == "CHECKPOINT_RESET_ACTIVE"
        assert checkpoint.read_bytes() == original
    finally:
        _close(service)


def test_same_content_checkpoint_swap_during_approval_is_rejected(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original = checkpoint.read_bytes()

    def replace(_prompt: str) -> str:
        replacement = config.parent / "replacement.tmp"
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(checkpoint)
        return "yes"

    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=replace, emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_CHANGED"
    assert checkpoint.read_bytes() == original


def test_checkpoint_missing_or_malformed_never_resets_silently(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    with pytest.raises(MonitorSetupError) as missing:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert missing.value.code == "CHECKPOINT_RESET_MISSING"
    checkpoint.write_text("{}", encoding="utf-8")
    checkpoint.chmod(0o600)
    with pytest.raises(MonitorSetupError) as malformed:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert malformed.value.code == "CHECKPOINT_RESET_UNSAFE"
    assert checkpoint.exists()


def test_reset_then_restart_starts_new_prefix_at_current_end(tmp_path: Path) -> None:
    source, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(LINE)
        assert service._worker.step().status == "PROCESSED"
        assert service._worker._accumulator.snapshot().revision == 1
    finally:
        _close(service)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(LINE)
    assert reset_default_checkpoint(config, ask=lambda _: "y", emit=lambda _: None).status == "RESET"
    assert not checkpoint.exists()
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        worker = service._worker
        assert worker._accumulator.snapshot().revision == 0
        assert worker._analysis.snapshot().revision == 0
        assert worker.publication_buffer.snapshot().published_total == 0
        assert worker.step().status == "NO_DATA"
        with source.open("a", encoding="utf-8") as stream:
            stream.write(LINE)
        assert worker.step().status == "PROCESSED"
        assert worker._accumulator.snapshot().revision == 1
    finally:
        _close(service)


def test_reset_messages_do_not_expose_private_values(tmp_path: Path) -> None:
    source, config, _ = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    output: list[str] = []
    assert reset_default_checkpoint(config, ask=lambda _: "yes", emit=output.append).status == "RESET"
    rendered = "\n".join(output)
    for canary in (str(source), str(config), "epoch_canary", "192.0.2.9", "source-canary.log"):
        assert canary not in rendered
    assert "FROM_END" in rendered
    assert "연속성" in rendered
    assert "원본 로그" in rendered


def test_reset_uses_no_recursive_deletion(tmp_path: Path, monkeypatch) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    unlinked = []
    original_unlink = os.unlink

    def observe(path, *args, **kwargs):
        unlinked.append(path)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", observe)
    assert reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None).status == "RESET"
    assert unlinked == [CHECKPOINT_NAME]
    assert not checkpoint.exists()


def test_concurrent_reset_is_denied_while_first_waits_for_approval(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original = checkpoint.read_bytes()

    def compete(_prompt: str) -> str:
        with pytest.raises(MonitorSetupError) as caught:
            reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
        assert caught.value.code == "CHECKPOINT_RESET_ACTIVE"
        return "no"

    assert reset_default_checkpoint(config, ask=compete, emit=lambda _: None).status == "CANCELLED"
    assert checkpoint.read_bytes() == original


def test_config_swap_during_approval_rejects_without_deletion(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original = checkpoint.read_bytes()

    def replace(_prompt: str) -> str:
        replacement = config.parent / "config-replacement.tmp"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(config)
        return "yes"

    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=replace, emit=lambda _: None)
    assert caught.value.code == "DEFAULT_CONFIG_CHANGED"
    assert checkpoint.read_bytes() == original


def test_checkpoint_symlink_is_not_deleted(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    target = config.parent / "other-private.json"
    target.write_bytes(checkpoint.read_bytes())
    checkpoint.unlink()
    checkpoint.symlink_to(target)
    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_UNSAFE"
    assert checkpoint.is_symlink() and target.exists()


def test_wrong_checkpoint_mode_is_not_deleted(tmp_path: Path) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    checkpoint.chmod(0o644)
    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_UNSAFE"
    assert checkpoint.exists()


def test_unlink_failure_keeps_config_and_checkpoint(tmp_path: Path, monkeypatch) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original_unlink = os.unlink

    def fail_target(path, *args, **kwargs):
        if path == CHECKPOINT_NAME:
            raise OSError("private unlink canary")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", fail_target)
    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_FAILED"
    assert "private unlink canary" not in str(caught.value) + repr(caught.value)
    assert config.exists() and checkpoint.exists()


def test_fsync_failure_after_unlink_is_not_reported_as_success(tmp_path: Path, monkeypatch) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    original_fsync = os.fsync

    def fail_parent_fsync(fd: int) -> None:
        if os.fstat(fd).st_mode & 0o170000 == 0o040000:
            raise OSError("private fault canary")
        original_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_parent_fsync)
    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_POST_DELETE_FAILED"
    assert "private fault canary" not in str(caught.value) + repr(caught.value)
    assert config.exists() and not checkpoint.exists()


def test_cli_reset_is_explicit_and_mode_conflicts_are_rejected(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    _, config, checkpoint = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    monkeypatch.setattr(monitor_setup, "resolve_default_monitor_config_path", lambda: config)
    assert monitor_setup.main(["--reset-checkpoint"], ask=lambda _: "no") == 0
    assert checkpoint.exists()
    assert monitor_setup.main(["--reset-checkpoint", "--output", str(config)]) == 2
    assert monitor_setup.main(["--reset-checkpoint", "--delete"]) == 2
    assert monitor_setup.main(["--reset-checkpoint"], ask=lambda _: "y") == 0
    assert not checkpoint.exists() and config.exists()
    output = capsys.readouterr()
    assert str(config) not in output.out + output.err
