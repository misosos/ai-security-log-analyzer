"""SSH analysis uses the existing batch prefix meaning without new rules."""

from dataclasses import asdict
import asyncio
from datetime import timedelta
from http.client import HTTPConnection
import json
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

import pytest

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import assess_risk, correlate_attacks, detect_attacks
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring import analysis_accumulator as analysis_module
from app.live_monitoring.core import LiveTailRecord, LiveTailSession
from app.live_monitoring.parser_adapter import parse_live_records
from app.live_monitoring.publication import (
    LivePublicationBuffer, serialize_live_analysis_publication_event,
)
from app.live_monitoring.service import LiveMonitoringService
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState
from app.local_web import _live_runtime


def _line(second, result="Failed", user="SYNTHETIC_ACCOUNT", ip="198.51.100.23"):
    return (f"2026-01-02 03:04:{second:02d} sshd: {result} password "
            f"for {user} from {ip} port 5001 ssh2")


def test_ssh_accumulator_matches_every_trusted_batch_prefix():
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    events = []
    lines = tuple(_line(second) for second in range(1, 6)) + (_line(6, "Accepted"),)
    for revision, line in enumerate(lines, 1):
        parsed = parse_live_records("ssh", (
            LiveTailRecord("ssh", revision, line, len(line.encode("utf-8"))),
        ))
        proposal = detection.prepare(parsed)
        candidate = analysis.prepare(proposal)
        detection.commit(proposal)
        analysis.commit(candidate)
        events.append(parsed.outcomes[0].event)
        expected = assess_risk(correlate_attacks(events, detect_attacks(events)))
        assert analysis._state._results == expected["results"]
        assert analysis._state._projection == project_investigation_cases_from_analysis(expected)
        assert analysis.snapshot().revision == detection.snapshot().revision == revision
    safe = json.dumps(asdict(analysis.snapshot()), ensure_ascii=False) + repr(analysis)
    assert analysis.snapshot().source_role == "ssh"
    assert analysis.snapshot().relation_count == 2
    assert analysis.snapshot().case_count == 1
    for canary in ("SYNTHETIC_ACCOUNT", "198.51.100.23"):
        assert canary not in safe


def test_ssh_worker_commits_ordered_detection_and_analysis_publications(tmp_path):
    source = tmp_path / "SSH_PATH_CANARY.log"
    source.write_text(_line(0) + "\n", encoding="utf-8")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    worker = LiveProcessingWorker(session, detection, 16, 4096,
                                  analysis_accumulator=analysis)
    try:
        assert worker.step().status == "NO_DATA"
        with source.open("a", encoding="utf-8") as stream:
            for second in range(1, 6):
                stream.write(_line(second) + "\n")
            stream.write(_line(6, "Accepted") + "\n")
        result = worker.step()
        assert result.status == "PROCESSED"
        assert result.accumulator_revision == result.analysis_revision == 1
        assert analysis.snapshot().relation_count == 2
        assert analysis.snapshot().case_count == 1
        assert not session.snapshot().active_lease
        assert not analysis.snapshot().active_proposal
        published = worker.publication_buffer.replay_after(None).events
        assert tuple(item.event_type for item in published) == (
            "DETECTION_CHANGE", "ANALYSIS_CHANGE")
        assert published[0].revision == published[1].revision == 1
        wire = serialize_live_analysis_publication_event(published[1]).decode("utf-8")
        assert json.loads(wire)["source_role"] == "ssh"
        for canary in ("SYNTHETIC_ACCOUNT", "198.51.100.23", "SSH_PATH_CANARY"):
            assert canary not in wire + repr(worker) + repr(published)
    finally:
        worker.close()
    assert session._fd == -1


@pytest.mark.parametrize("lines", (
    (_line(1), _line(3, "Accepted"), _line(2, "Accepted")),
    (_line(1), _line(1).replace("port 5001", "port 5002"),
     _line(2, "Accepted")),
    (_line(1, "Accepted"), _line(2)),
    (_line(1), _line(2, "Accepted", user="OTHER")),
    (_line(1), _line(2, "Accepted", ip="198.51.100.24")),
    (_line(1, user="one"), _line(2, user="two"),
     _line(3, user="three"), _line(4, user="four"),
     _line(5, "Accepted", user="one")),
    (" ", "invalid", "2026-01-02 03:04:01 sshd: unrelated message", _line(2)),
))
def test_ssh_varied_prefixes_match_existing_batch_oracle(lines):
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    events = []
    for revision, line in enumerate(lines, 1):
        parsed = parse_live_records("ssh", (
            LiveTailRecord("ssh", revision, line, len(line.encode("utf-8"))),
        ))
        detection_proposal = detection.prepare(parsed)
        analysis_proposal = analysis.prepare(detection_proposal)
        detection.commit(detection_proposal)
        analysis.commit(analysis_proposal)
        events.extend(outcome.event for outcome in parsed.outcomes
                      if outcome.status == "PARSED")
        expected = assess_risk(correlate_attacks(events, detect_attacks(events)))
        assert analysis._state._results == expected["results"]
        assert analysis._state._projection == project_investigation_cases_from_analysis(expected)
        assert all(relation.relation_type != "successful_login_to_file_access"
                   for relation in analysis.snapshot().relations)
    if len(lines) == 5 and "one" in lines[0]:
        assert all(case.rule_id != "CASE-SPRAY-SUCCESS-01"
                   for case in analysis.snapshot().cases)
    if len(lines) == 3 and "port 5002" in lines[1]:
        assert analysis.snapshot().relation_count == 0


@pytest.mark.parametrize("stage,expected,state,detection_revision,analysis_revision,acknowledged", (
    ("correlation", "ANALYSIS_PREPARE_FAILED", LiveWorkerState.DEGRADED, 0, 0, 0),
    ("publication_prepare", "PUBLICATION_PREPARE_FAILED", LiveWorkerState.DEGRADED, 0, 0, 0),
    ("ack", "ACK_FAILURE", LiveWorkerState.FAILED, 0, 0, 0),
    ("detection_commit", "DETECTION_COMMIT_FAILED_AFTER_ACK", LiveWorkerState.FAILED, 0, 0, 1),
    ("analysis_commit", "ANALYSIS_COMMIT_FAILED_AFTER_DETECTION_COMMIT", LiveWorkerState.FAILED, 1, 0, 1),
    ("publication_commit", "PUBLICATION_FAILED_AFTER_ANALYSIS_COMMIT", LiveWorkerState.FAILED, 1, 1, 1),
))
def test_ssh_transaction_fault_boundaries(tmp_path, monkeypatch, stage, expected,
                                          state, detection_revision,
                                          analysis_revision, acknowledged):
    source = tmp_path / "PRIVATE_SOURCE_CANARY.log"
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    worker = LiveProcessingWorker(session, detection, 16, 4096,
                                  analysis_accumulator=analysis)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(_line(1, user="PRIVATE_ACCOUNT_CANARY") + "\n")

    def fault(*_args, **_kwargs):
        raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

    target, method = {
        "correlation": (analysis_module, "group_logs_by_ip"),
        "publication_prepare": (LivePublicationBuffer, "prepare_batch"),
        "ack": (LiveTailSession, "acknowledge_lease"),
        "detection_commit": (LiveDetectionAccumulator, "commit_prepared"),
        "analysis_commit": (LiveAnalysisAccumulator, "_install_candidate"),
        "publication_commit": (LivePublicationBuffer, "commit_prepared"),
    }[stage]
    monkeypatch.setattr(target, method, fault)
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == expected
        assert worker.snapshot().state is state
        assert detection.snapshot().revision == detection_revision
        assert analysis.snapshot().revision == analysis_revision
        assert session.snapshot().acknowledged_record_count == acknowledged
        assert worker.publication_buffer.snapshot().published_total == 0
        if state is LiveWorkerState.DEGRADED:
            assert session.snapshot().available_item_count == 1
            assert not session.snapshot().active_lease
            assert not detection.snapshot().active_proposal
            assert not analysis.snapshot().active_proposal
            assert worker.publication_buffer._active is None
            worker.resume_after_degraded()
        else:
            with pytest.raises(LiveWorkerError):
                worker.step()
        safe = repr(worker.snapshot()) + repr(caught.value)
        for canary in ("PRIVATE_SOURCE_CANARY", "PRIVATE_ACCOUNT_CANARY", "PRIVATE_EXCEPTION_CANARY"):
            assert canary not in safe
    finally:
        worker.close()


@pytest.mark.parametrize("extra_microsecond,correlated", ((0, True), (1, False)))
def test_ssh_typed_utc_microsecond_60_second_boundary(extra_microsecond, correlated):
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    first = None
    events = []
    for revision, line in enumerate((_line(1), _line(2, "Accepted")), 1):
        parsed = parse_live_records("ssh", (
            LiveTailRecord("ssh", revision, line, len(line.encode("utf-8"))),
        ))
        event = parsed.outcomes[0].event
        if revision == 1:
            first = event.timestamp.replace(microsecond=123456)
            event.timestamp = first
        else:
            event.timestamp = first + timedelta(seconds=60, microseconds=extra_microsecond)
        candidate_detection = detection.prepare(parsed)
        candidate_analysis = analysis.prepare(candidate_detection)
        detection.commit(candidate_detection)
        analysis.commit(candidate_analysis)
        events.append(event)
        oracle = assess_risk(correlate_attacks(events, detect_attacks(events)))
        assert analysis._state._results == oracle["results"]
        assert analysis._state._projection == project_investigation_cases_from_analysis(oracle)
    assert bool(analysis.snapshot().relation_count) is correlated


def test_ssh_noncanonical_subject_fails_before_ack_and_retains_fifo(tmp_path):
    source = tmp_path / "synthetic.log"
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detection, ())
    worker = LiveProcessingWorker(session, detection, 16, 4096,
                                  analysis_accumulator=analysis)
    with source.open("a", encoding="utf-8") as stream:
        stream.write(_line(1, ip="not-an-ip") + "\n")
    try:
        with pytest.raises(LiveWorkerError) as caught:
            worker.step()
        assert caught.value.code == "ANALYSIS_PREPARE_FAILED"
        assert worker.snapshot().state is LiveWorkerState.DEGRADED
        assert session.snapshot().available_item_count == 1
        assert session.snapshot().acknowledged_record_count == 0
        assert detection.snapshot().revision == analysis.snapshot().revision == 0
        assert "not-an-ip" not in repr(caught.value) + repr(worker.snapshot())
    finally:
        worker.close()


def test_ssh_status_snapshot_sse_replay_and_gap_are_safe(tmp_path):
    source = tmp_path / "PRIVATE_PATH_CANARY.log"
    source.write_bytes(b"existing line\n")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detection = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    worker = LiveProcessingWorker(session, detection, 16, 4096)
    service = LiveMonitoringService(worker)

    async def scenario():
        assert service.status().analysis_available is True
        assert service.status().source_role == "ssh"
        with source.open("a", encoding="utf-8") as stream:
            for second in range(1, 6):
                stream.write(_line(second) + "\n")
            stream.write(_line(6, "Accepted") + "\n")
        worker.step()
        status_wire = service.status().model_dump_json()
        connection = service.open_connection(None).stream()
        snapshot = await anext(connection)
        observation = await anext(connection)
        analysis = await anext(connection)
        assert b'"analysis_available":true' in snapshot
        assert b"event: observation_changes" in observation
        assert b"event: analysis_changes" in analysis
        assert b'"source_role":"ssh"' in analysis
        for canary in (b"PRIVATE_PATH_CANARY", b"SYNTHETIC_ACCOUNT", b"198.51.100.23"):
            assert canary not in status_wire.encode() + snapshot + observation + analysis
        await connection.aclose()
        assert service.status().active_connections == 0
        first_event_id = worker.publication_buffer.replay_after(None).events[0].event_id
        replay = service.open_connection(first_event_id).stream()
        assert b"event: snapshot" in await anext(replay)
        assert b"event: analysis_changes" in await anext(replay)
        await replay.aclose()
        future_id = first_event_id.rsplit("-", 1)[0] + "-999999"
        gap = service.open_connection(future_id).stream()
        gap_frame, recovery_snapshot = await anext(gap), await anext(gap)
        assert b"event: replay_gap" in gap_frame
        assert b"event: snapshot" in recovery_snapshot
        assert b'"analysis_available":true' in recovery_snapshot
        for canary in (b"PRIVATE_PATH_CANARY", b"SYNTHETIC_ACCOUNT", b"198.51.100.23"):
            assert canary not in gap_frame + recovery_snapshot
        await gap.aclose()
        await service.close()

    asyncio.run(scenario())
    assert session._fd == -1


def test_explicit_v1_ssh_runtime_binds_analysis_without_checkpoint(tmp_path):
    source = tmp_path / "PRIVATE_SOURCE_CANARY.log"
    source.write_text(_line(0) + "\n", encoding="utf-8")
    config = tmp_path / "PRIVATE_CONFIG_CANARY.json"
    config.write_text(json.dumps({
        "schema_version": "1", "source": {"role": "ssh", "path": str(source)},
        "start_policy": "FROM_END",
    }), encoding="utf-8")
    config.chmod(0o600)
    service, runner = _live_runtime(config)
    try:
        assert runner.state.value == "CREATED"
        assert service._worker._checkpoint is None
        assert service._worker.step().status == "NO_DATA"
        with source.open("a", encoding="utf-8") as stream:
            for second in range(1, 6):
                stream.write(_line(second) + "\n")
            stream.write(_line(6, "Accepted") + "\n")
        result = service._worker.step()
        assert result.analysis_revision == result.accumulator_revision == 1
        assert service.status().active_case_count == 1
        assert service.status().active_relation_count == 2
        assert "PRIVATE_SOURCE_CANARY" not in service.status().model_dump_json()
        assert "PRIVATE_CONFIG_CANARY" not in service.status().model_dump_json()
    finally:
        asyncio.run(service.close())
    assert service._worker._session._fd == -1


def test_ssh_loopback_runtime_append_sse_and_shutdown(tmp_path):
    source = tmp_path / "PRIVATE_SOURCE_CANARY.log"
    source.write_text(_line(0) + "\n", encoding="utf-8")
    config = tmp_path / "PRIVATE_CONFIG_CANARY.json"
    config.write_text(json.dumps({
        "schema_version": "1", "source": {"role": "ssh", "path": str(source)},
        "start_policy": "FROM_END",
    }), encoding="utf-8")
    config.chmod(0o600)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen(
        [sys.executable, "-m", "app.local_web", "--monitor-config", str(config),
         "--no-browser", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    def status():
        connection = HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/api/v1/live/status")
            response = connection.getresponse()
            assert response.status == 200
            return json.loads(response.read())
        finally:
            connection.close()

    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None
            try:
                initial = status()
                break
            except (OSError, AssertionError, ValueError):
                assert time.monotonic() < deadline, "bounded SSH server readiness failed"
                time.sleep(0.05)
        assert initial["source_role"] == "ssh"
        assert initial["analysis_available"] is True
        assert initial["latest_detection_revision"] == 0
        with source.open("a", encoding="utf-8") as stream:
            for second in range(1, 6):
                stream.write(_line(second) + "\n")
            stream.write(_line(6, "Accepted") + "\n")
        while True:
            current = status()
            if current["active_relation_count"] == 2 and current["active_case_count"] == 1:
                break
            assert time.monotonic() < deadline, "bounded SSH analysis wait failed"
            time.sleep(0.05)
        events = []
        with urlopen(f"http://127.0.0.1:{port}/api/v1/live/events", timeout=5) as stream:
            for _ in range(3):
                frame = bytearray()
                while True:
                    line = stream.readline()
                    assert line, "SSE closed before expected event"
                    frame.extend(line)
                    if line == b"\n":
                        break
                    assert len(frame) < 131072, "SSE frame exceeded test cap"
                events.append(bytes(frame))
        assert [next(line[7:].strip() for line in frame.splitlines()
                     if line.startswith(b"event: ")) for frame in events] == [
                         b"snapshot", b"observation_changes", b"analysis_changes"]
        safe = json.dumps(current).encode() + b"".join(events)
        for canary in (b"PRIVATE_SOURCE_CANARY", b"PRIVATE_CONFIG_CANARY",
                       b"SYNTHETIC_ACCOUNT", b"198.51.100.23"):
            assert canary not in safe
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            output, errors = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)
            raise AssertionError("SSH loopback shutdown deadline exceeded") from None
        assert process.returncode == 0
        for canary in ("PRIVATE_SOURCE_CANARY", "PRIVATE_CONFIG_CANARY",
                       "SYNTHETIC_ACCOUNT", "198.51.100.23"):
            assert canary not in output + errors
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", port)) != 0
