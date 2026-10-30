"""SSH restart must rebuild the same bounded trusted prefix without old SSE."""

import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path

import pytest

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import assess_risk_with_metadata, correlate_attacks, detect_attacks
from app.analyzer.risk import load_account_metadata
from app.live_monitoring.checkpoint import CHECKPOINT_NAME, LiveCheckpointError, LiveCheckpointManager
from app.live_monitoring.config import LiveMonitorError, load_live_monitor_config, load_live_monitor_setup_config
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.parser_adapter import parse_live_records
from app.live_monitoring.service import encode_live_sse_event
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState
from app.local_web import _live_runtime
from app.monitor_setup import MonitorSetupError, reset_default_checkpoint, show_default_config


def _line(second: int, result: str = "Failed") -> str:
    return (f"2026-01-02 03:04:{second:02d} sshd: {result} password for "
            "SSH_ACCOUNT_CANARY from 198.51.100.23 port 5001 ssh2\n")


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "SSH_SOURCE_PATH_CANARY.log"
    source.write_text(_line(0), encoding="utf-8")
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    config = parent / "monitoring.json"
    document = {"schema_version": "2", "sources": [{
        "source_id": "SOURCE-000001", "source_role": "ssh", "source_path": str(source),
        "display_alias": "SSH 로그 1", "enabled": True, "start_position": "FROM_END",
        "parser_timezone": "Asia/Seoul", "checkpoint_policy": "BOUNDED_REPLAY_V1",
        "rotation_policy": "FAIL_CLOSED",
    }]}
    config.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    config.chmod(0o600)
    return source, config


def _append(source: Path, *lines: str) -> None:
    with source.open("a", encoding="utf-8") as stream:
        stream.writelines(lines)


def _batch_expected(lines: tuple[str, ...]):
    records = tuple(LiveTailRecord("ssh", index, line.rstrip("\n"),
                                   len(line.rstrip("\n").encode("utf-8")))
                    for index, line in enumerate(lines, 1))
    parsed = parse_live_records("ssh", records)
    events = tuple(outcome.event for outcome in parsed.outcomes if outcome.event is not None)
    from app.main import _analyze_normalized_logs_with_context
    from app.investigation_role_snapshot_36_4 import (
        AnalysisSourceRoleSnapshot, AnalysisWithSourceRoleSnapshot,
    )

    analysis, contexts, owner = _analyze_normalized_logs_with_context(events)
    run = AnalysisWithSourceRoleSnapshot(
        analysis, AnalysisSourceRoleSnapshot.from_events(analysis, events),
        contexts, owner,
    )
    return analysis["results"], project_investigation_cases_from_analysis(run)


def _close(service) -> None:
    asyncio.run(service.close())


def test_ssh_v2_config_uses_existing_schema_and_runtime(tmp_path: Path):
    _, config = _fixture(tmp_path)
    parsed = load_live_monitor_setup_config(config)
    assert parsed.schema_version == "2"
    assert parsed.source_role == "ssh"
    assert parsed.checkpoint_policy == "BOUNDED_REPLAY_V1"
    assert load_live_monitor_config(config).role == "ssh"


def test_ssh_restart_rebuilds_prefix_without_republishing(tmp_path: Path):
    source, config = _fixture(tmp_path)
    first, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert first._worker.step().status == "NO_DATA"
        with source.open("a", encoding="utf-8") as stream:
            stream.writelines(_line(second) for second in range(1, 6))
        assert first._worker.step().status == "PROCESSED"
        old_detection = first._worker._accumulator.snapshot()
        old_analysis = first._worker._analysis.snapshot()
    finally:
        _close(first)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(_line(6, "Accepted"))
    restored, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot() == old_detection
        assert restored._worker._analysis.snapshot() == old_analysis
        assert restored._worker.publication_buffer.snapshot().published_total == 0
        assert restored._worker.step().status == "PROCESSED"
        assert restored._worker._analysis.snapshot().relation_count == 2
        assert restored._worker._analysis.snapshot().case_count == 1
    finally:
        _close(restored)


def test_ssh_show_and_explicit_reset_preserve_source_and_config(tmp_path: Path):
    source, config = _fixture(tmp_path)
    first, _ = _live_runtime(config, checkpoint_default=True)
    _close(first)
    before_source, before_config = source.read_bytes(), config.read_bytes()
    checkpoint = config.parent / CHECKPOINT_NAME
    assert show_default_config(config).checkpoint_exists
    output = []
    assert reset_default_checkpoint(config, ask=lambda _: "no", emit=output.append).status == "CANCELLED"
    assert checkpoint.exists()
    assert reset_default_checkpoint(config, ask=lambda _: "yes", emit=output.append).status == "RESET"
    rendered = "\n".join(output) + repr(asdict(show_default_config(config)))
    for canary in (str(source), str(config), "SSH_ACCOUNT_CANARY", "198.51.100.23"):
        assert canary not in rendered
    assert not checkpoint.exists()
    assert source.read_bytes() == before_source
    assert config.read_bytes() == before_config
    second, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert second._worker._accumulator.snapshot().history_record_count == 0
    finally:
        _close(second)


@pytest.mark.parametrize(("prefix", "suffix"), (
    (tuple(_line(i) for i in range(1, 6)), (_line(6, "Accepted"),)),
    (tuple(_line(i) for i in range(1, 5)), (_line(5), _line(6, "Accepted"))),
    ((_line(1), " \n", "malformed\n", "2026-01-02 03:04:02 sshd: unrelated\n"),
     (_line(3, "Accepted"),)),
    ((_line(1), _line(1)), (_line(2, "Accepted"),)),
    ((_line(3), _line(1)), (_line(2, "Accepted"),)),
    ((_line(1).replace("SSH_ACCOUNT_CANARY", "OTHER_ACCOUNT"), _line(2)),
     (_line(3, "Accepted"),)),
))
def test_recovered_ssh_prefix_matches_uninterrupted_and_batch(
    tmp_path: Path, prefix: tuple[str, ...], suffix: tuple[str, ...],
):
    continuous_source, continuous_config = _fixture(tmp_path / "continuous")
    restart_source, restart_config = _fixture(tmp_path / "restart")
    continuous, _ = _live_runtime(continuous_config, checkpoint_default=True)
    first, _ = _live_runtime(restart_config, checkpoint_default=True)
    try:
        _append(continuous_source, *prefix)
        _append(restart_source, *prefix)
        assert continuous._worker.step().status == first._worker.step().status == "PROCESSED"
        before_detection = first._worker._accumulator.snapshot()
        before_analysis = first._worker._analysis.snapshot()
    finally:
        _close(first)
    restored, _ = _live_runtime(restart_config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot() == before_detection
        assert restored._worker._analysis.snapshot() == before_analysis
        assert restored._worker.publication_buffer.snapshot().published_total == 0
        _append(continuous_source, *suffix)
        _append(restart_source, *suffix)
        assert continuous._worker.step().status == restored._worker.step().status == "PROCESSED"
        assert restored._worker._accumulator.snapshot() == continuous._worker._accumulator.snapshot()
        assert restored._worker._analysis.snapshot() == continuous._worker._analysis.snapshot()
        expected_results, expected_cases = _batch_expected(prefix + suffix)
        assert restored._worker._analysis._state._results == expected_results
        assert restored._worker._analysis._state._projection == expected_cases
    finally:
        _close(restored)
        _close(continuous)


@pytest.mark.parametrize("damage", (
    "malformed", "schema", "role", "offset", "semantic", "mode",
    "source_replace", "source_shrink", "source_missing", "symlink",
))
def test_ssh_corruption_never_falls_back_to_from_end(tmp_path: Path, damage: str):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        _append(source, _line(1))
        service._worker.step()
    finally:
        _close(service)
    checkpoint = config.parent / CHECKPOINT_NAME
    if damage in ("malformed", "schema", "role", "offset", "semantic"):
        document = json.loads(checkpoint.read_text(encoding="utf-8"))
        if damage == "malformed":
            document["unexpected"] = "NO"
        elif damage == "schema":
            document["schema_version"] = "unknown"
        elif damage == "role":
            document["source_role"] = "application"
        elif damage == "offset":
            document["committed_offset"] = document["committed_file_size"] + 1
        else:
            document["semantic_digest"] = "0" * 64
        checkpoint.write_text(json.dumps(document), encoding="utf-8")
    elif damage == "mode":
        checkpoint.chmod(0o644)
    elif damage == "source_replace":
        replacement = tmp_path / "replacement.log"
        replacement.write_bytes(source.read_bytes())
        replacement.replace(source)
    elif damage == "source_shrink":
        with source.open("r+b") as stream:
            stream.truncate(0)
    elif damage == "source_missing":
        source.rename(tmp_path / "unavailable-synthetic.log")
    else:
        other = config.parent / "other.txt"
        other.write_text("synthetic", encoding="utf-8")
        checkpoint.unlink()
        checkpoint.symlink_to(other)
    with pytest.raises((LiveCheckpointError, LiveMonitorError)) as caught:
        _live_runtime(config, checkpoint_default=True)
    allowed = {
        "CHECKPOINT_CORRUPT", "CHECKPOINT_REPLAY_MISMATCH", "CHECKPOINT_SOURCE_CHANGED",
        "CHECKPOINT_UNSAFE",
    }
    if damage in ("source_shrink", "source_missing"):
        allowed.add("INTERNAL_FAILURE")
    if damage == "source_missing":
        allowed.add("SOURCE_UNAVAILABLE")
    assert caught.value.code in allowed
    rendered = str(caught.value) + repr(caught.value)
    for canary in ("SSH_ACCOUNT_CANARY", "198.51.100.23", str(source), str(config)):
        assert canary not in rendered


def test_ssh_invalid_partial_utf8_does_not_advance_checkpoint(tmp_path: Path):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    checkpoint = config.parent / CHECKPOINT_NAME
    before = checkpoint.read_bytes()
    try:
        with source.open("ab") as stream:
            stream.write(b"\xc3")
        assert service._worker.step().status == "NO_DATA"
        assert checkpoint.read_bytes() == before
        with source.open("ab") as stream:
            stream.write(b"\n")
        with pytest.raises(LiveWorkerError):
            service._worker.step()
        assert service._worker.snapshot().state is LiveWorkerState.FAILED
        assert checkpoint.read_bytes() == before
    finally:
        _close(service)


def test_ssh_257th_parsed_event_fails_before_ack_without_advancing_checkpoint(tmp_path: Path):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    try:
        for group in range(16):
            _append(source, *(_line((group * 16 + index) % 60) for index in range(16)))
            assert worker.step().status == "PROCESSED"
        prior_detection = worker._accumulator.snapshot()
        prior_analysis = worker._analysis.snapshot()
        checkpoint = (config.parent / CHECKPOINT_NAME).read_bytes()
        _append(source, _line(17))
        with pytest.raises(LiveWorkerError):
            worker.step()
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert worker._accumulator.snapshot() == prior_detection
        assert worker._analysis.snapshot() == prior_analysis
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == checkpoint
        assert worker._session.snapshot().available_item_count == 1
    finally:
        _close(service)


@pytest.mark.parametrize("target", ("source", "config"))
def test_ssh_private_monitor_rejects_path_symlink_before_checkpoint(tmp_path: Path, target: str):
    source, config = _fixture(tmp_path)
    path = source if target == "source" else config
    original = path.with_name("synthetic-original" + path.suffix)
    path.rename(original)
    path.symlink_to(original)
    with pytest.raises((LiveMonitorError, LiveCheckpointError)) as caught:
        _live_runtime(config, checkpoint_default=True)
    assert caught.value.code == "SYMLINK_REJECTED"
    assert not (config.parent / CHECKPOINT_NAME).exists()


def test_ssh_active_lock_blocks_second_monitor_and_reset(tmp_path: Path):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with pytest.raises(LiveCheckpointError) as second:
            _live_runtime(config, checkpoint_default=True)
        assert second.value.code == "CHECKPOINT_ALREADY_OWNED"
        with pytest.raises(MonitorSetupError) as reset:
            reset_default_checkpoint(config, ask=lambda _: "yes", emit=lambda _: None)
        assert reset.value.code == "CHECKPOINT_RESET_ACTIVE"
        assert source.exists()
    finally:
        _close(service)


def test_v1_ssh_explicit_config_keeps_from_end_without_checkpoint(tmp_path: Path):
    source = tmp_path / "old-ssh.log"
    source.write_text(_line(0), encoding="utf-8")
    config = tmp_path / "legacy.json"
    config.write_text(json.dumps({"schema_version": "1", "source": {
        "role": "ssh", "path": str(source)}, "start_policy": "FROM_END"}), encoding="utf-8")
    config.chmod(0o600)
    service, _ = _live_runtime(config)
    try:
        assert service._worker._checkpoint is None
        assert service._worker.step().status == "NO_DATA"
    finally:
        _close(service)
    assert not (config.parent / CHECKPOINT_NAME).exists()


def test_explicit_v2_ssh_config_keeps_from_end_without_private_checkpoint(tmp_path: Path):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config)
    try:
        assert service._worker._checkpoint is None
        _append(source, _line(1))
        assert service._worker.step().status == "PROCESSED"
    finally:
        _close(service)
    assert not (config.parent / CHECKPOINT_NAME).exists()
    restarted, _ = _live_runtime(config)
    try:
        assert restarted._worker.step().status == "NO_DATA"
        assert restarted._worker._accumulator.snapshot().history_record_count == 0
    finally:
        _close(restarted)


def test_ssh_partial_line_is_not_committed_and_completes_after_restart(tmp_path: Path):
    source, config = _fixture(tmp_path)
    line = _line(1)
    first, _ = _live_runtime(config, checkpoint_default=True)
    try:
        with source.open("a", encoding="utf-8") as stream:
            stream.write(line[:-1])
        assert first._worker.step().status == "NO_DATA"
        assert first._worker._accumulator.snapshot().history_record_count == 0
    finally:
        _close(first)
    restored, _ = _live_runtime(config, checkpoint_default=True)
    try:
        assert restored._worker._accumulator.snapshot().history_record_count == 0
        _append(source, "\n")
        assert restored._worker.step().status == "PROCESSED"
        assert restored._worker._accumulator.snapshot().history_record_count == 1
    finally:
        _close(restored)


def test_ssh_private_checkpoint_and_public_surfaces_exclude_canaries(tmp_path: Path):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    try:
        _append(source, _line(1))
        service._worker.step()
        checkpoint = config.parent / CHECKPOINT_NAME
        private = json.loads(checkpoint.read_text(encoding="utf-8"))
        assert private["source_role"] == "ssh"
        assert type(private["file_inode"]) is int
        assert type(private["committed_offset"]) is int
        assert os.stat(checkpoint).st_mode & 0o777 == 0o600
        assert os.stat(config.parent).st_mode & 0o777 == 0o700
        safe = (repr(service._worker) + repr(service._worker._checkpoint)
                + service.status().model_dump_json()
                + repr(asdict(service._worker.snapshot()))
                + encode_live_sse_event("snapshot", service.publication_buffer.snapshot()).decode())
        for canary in ("SSH_ACCOUNT_CANARY", "198.51.100.23", str(source), str(config)):
            assert canary not in checkpoint.read_text(encoding="utf-8") + safe
    finally:
        _close(service)


def test_ssh_checkpoint_write_failure_is_terminal_after_publication(tmp_path: Path, monkeypatch):
    source, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    worker = service._worker
    before = (config.parent / CHECKPOINT_NAME).read_bytes()
    try:
        _append(source, _line(1))

        def fail_write(_manager, _checkpoint):
            raise LiveCheckpointError("CHECKPOINT_WRITE_FAILED")

        monkeypatch.setattr(LiveCheckpointManager, "_write", fail_write)
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "CHECKPOINT_FAILED_AFTER_PUBLICATION"
        assert worker.snapshot().state is LiveWorkerState.FAILED
        assert worker.publication_buffer.snapshot().published_total > 0
        assert (config.parent / CHECKPOINT_NAME).read_bytes() == before
    finally:
        _close(service)


def test_ssh_reset_rejects_approval_race_and_keeps_checkpoint(tmp_path: Path):
    _, config = _fixture(tmp_path)
    service, _ = _live_runtime(config, checkpoint_default=True)
    _close(service)
    checkpoint = config.parent / CHECKPOINT_NAME
    before = checkpoint.read_bytes()

    def swap(_prompt):
        replacement = config.parent / "synthetic-replacement.tmp"
        replacement.write_bytes(before)
        replacement.chmod(0o600)
        replacement.replace(checkpoint)
        return "yes"

    with pytest.raises(MonitorSetupError) as caught:
        reset_default_checkpoint(config, ask=swap, emit=lambda _: None)
    assert caught.value.code == "CHECKPOINT_RESET_CHANGED"
    assert checkpoint.read_bytes() == before
