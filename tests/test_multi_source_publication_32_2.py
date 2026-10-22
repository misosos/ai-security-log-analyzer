"""The private pair must publish one bounded, role-aware public stream."""

from pathlib import Path
import asyncio
import json

import pytest

from app.live_monitoring.multi_source import open_internal_pair_runtime
from app.live_monitoring.pair_publication import attach_pair_publication
from app.live_monitoring.pair_publication import PairPublicationBuffer, PairPublicationError
from app.live_monitoring.pair_service import PairMonitoringService
from app.live_monitoring.pair_service import PairRunner
from app.live_monitoring.pair_http import create_internal_pair_app
from app.monitor_setup import create_monitor_pair_config


APP = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.9\n"
SSH = ("2026-01-02 03:04:05 sshd: Failed password for synthetic "
       "from 198.51.100.23 port 5001 ssh2\n")


def _pair(tmp_path: Path):
    application = tmp_path / "application.log"
    ssh = tmp_path / "ssh.log"
    application.write_text(APP, encoding="utf-8")
    ssh.write_text(SSH, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    runtime = open_internal_pair_runtime(config)
    publication = attach_pair_publication(runtime)
    service = PairMonitoringService(runtime, publication)
    return application, ssh, runtime, publication, service


def test_pair_status_is_closed_and_keeps_role_revisions_separate(tmp_path: Path):
    application, _, runtime, _, service = _pair(tmp_path)
    try:
        status = service.status().model_dump(mode="json")
        assert status["schema_version"] == "3"
        assert [role["role"] for role in status["roles"]] == ["application", "ssh"]
        assert status["service_state"] == "READY"
        assert all(role["detection_revision"] == 0 for role in status["roles"])
        assert "source_path" not in str(status)
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        runtime.cycle()
        changed = service.status().model_dump(mode="json")
        assert changed["roles"][0]["detection_revision"] == 1
        assert changed["roles"][1]["detection_revision"] == 0
    finally:
        runtime.close()


def test_pair_events_share_global_ids_and_keep_role_order(tmp_path: Path):
    application, ssh, runtime, publication, _ = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH * 5)
        runtime.cycle()
        replay = publication.replay_after(None)
        assert replay.status == "INITIAL"
        assert [event.source_role for event in replay.events] == ["application", "ssh"] or [
            event.source_role for event in replay.events] == ["application", "application", "ssh", "ssh"]
        ids = [int(event.event_id.rsplit("-", 1)[1]) for event in replay.events]
        assert ids == list(range(1, len(ids) + 1))
        for index, event in enumerate(replay.events):
            assert event.payload["source_role"] == event.source_role
            assert event.payload["event_id"] == event.event_id
            if event.event_type == "analysis_changes":
                assert replay.events[index - 1].event_type == "observation_changes"
                assert replay.events[index - 1].source_role == event.source_role
    finally:
        runtime.close()


def test_pair_replay_cursor_and_unknown_gap_are_role_aware(tmp_path: Path):
    application, _, runtime, publication, _ = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        runtime.cycle()
        first = publication.replay_after(None)
        assert first.events
        assert publication.replay_after(first.events[-1].event_id).events == ()
        gap = publication.replay_after("untrusted-cursor")
        assert gap.status == "GAP"
        assert gap.affected_roles == ("application", "ssh")
    finally:
        runtime.close()


def test_pair_projection_failure_releases_source_proposal_and_lease(tmp_path: Path, monkeypatch):
    application, _, runtime, publication, _ = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        def fail_projection(self, role, source):
            raise PairPublicationError("PAIR_PUBLICATION_FAILED")
        monkeypatch.setattr(PairPublicationBuffer, "prepare", fail_projection)
        with pytest.raises(Exception):
            runtime.cycle()
        worker = runtime.workers["application"]
        assert worker._publication._source._active is None
        assert worker._session.snapshot().active_lease is False
        assert publication.item_count == 0
    finally:
        runtime.close()


def test_one_role_only_idle_and_privacy(tmp_path: Path):
    application, ssh, runtime, publication, service = _pair(tmp_path)
    canaries = ("synthetic", "192.0.2.9", "198.51.100.23",
                str(application), str(ssh), application.name, ssh.name,
                "login_failed", "Failed password")
    try:
        assert runtime.cycle() == (("application", "NO_DATA"), ("ssh", "NO_DATA"))
        assert publication.item_count == 0
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH * 5)
        runtime.cycle()
        events = publication.replay_after(None).events
        assert events and {event.source_role for event in events} == {"ssh"}
        public = service.status().model_dump_json() + repr(publication) + repr(events)
        public += "".join(event.encoded.decode() for event in events)
        for canary in canaries:
            assert canary not in public
        assert service.status().roles[0].detection_revision == 0
        assert service.status().roles[1].detection_revision == 1
    finally:
        runtime.close()


def test_eviction_gap_identifies_only_affected_role(tmp_path: Path):
    application, _, runtime, publication, _ = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        runtime.cycle()
        first_id = publication.replay_after(None).events[0].event_id
        for _ in range(40):
            with application.open("a", encoding="utf-8") as stream:
                stream.write(APP)
            runtime.cycle()
        assert publication.evicted_total > 0
        gap = publication.replay_after(first_id)
        assert gap.status == "GAP" and gap.gap_code == "EVICTED_EVENT_ID"
        assert gap.affected_roles == ("application",)
        assert publication.item_count <= 32 and publication.byte_count <= 16384
    finally:
        runtime.close()


def test_sse_initial_snapshot_replay_and_slot_cleanup(tmp_path: Path):
    application, _, runtime, publication, service = _pair(tmp_path)
    async def check():
        try:
            connection = service.open_connection(None)
            stream = connection.stream()
            first = await anext(stream)
            assert b"event: snapshot\n" in first
            assert b'"schema_version":"3"' in first
            await stream.aclose()
            assert service.active_connections == 0
            with application.open("a", encoding="utf-8") as file:
                file.write(APP * 5)
            runtime.cycle()
            replay = service.open_connection(None)
            chunks = replay.stream()
            assert b"event: snapshot\n" in await anext(chunks)
            event = await anext(chunks)
            assert b"event: observation_changes\n" in event
            assert publication.earliest_event_id.encode() in event
            assert b"event: analysis_changes\n" in await anext(chunks)
            await chunks.aclose()
            assert service.active_connections == 0
        finally:
            await service.close()
    asyncio.run(check())


def test_internal_http_schema_excludes_private_runtime(tmp_path: Path):
    from fastapi.testclient import TestClient
    application = tmp_path / "application.log"
    ssh = tmp_path / "ssh.log"
    application.write_text(APP, encoding="utf-8")
    ssh.write_text(SSH, encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    app = create_internal_pair_app(config)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        response = client.get("/api/v1/live/status")
        assert response.status_code == 200
        assert response.json()["schema_version"] == "3"
        assert client.get("/api/health").json() == {"status": "ok"}
        schema = client.get("/openapi.json").text
        for forbidden in ("source_path", "inode", "offset", "checkpoint_name", str(application)):
            assert forbidden not in schema
    assert app.state.pair_service.active_connections == 0


@pytest.mark.parametrize("after_swap", [False, True])
def test_pair_swap_fault_fails_closed_without_partial_batch(tmp_path: Path, monkeypatch,
                                                            after_swap: bool):
    application, ssh, runtime, publication, service = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        with ssh.open("a", encoding="utf-8") as stream:
            stream.write(SSH * 5)
        original = PairPublicationBuffer._swap
        def fail_swap(self, proposal):
            if after_swap:
                original(self, proposal)
            raise RuntimeError("private-path account=canary ip=192.0.2.99 hostname=canary raw line")
        monkeypatch.setattr(PairPublicationBuffer, "_swap", fail_swap)
        with pytest.raises(Exception) as raised:
            runtime.cycle()
        assert "canary" not in str(raised.value) + repr(raised.value)
        assert runtime.state in ("FAILED", "DEGRADED")
        assert publication.item_count in (0, 2)
        assert publication.item_count == (2 if after_swap else 0)
        assert all(event.source_role == "application"
                   for event in publication.replay_after(None).events)
        assert runtime.workers["ssh"]._session.snapshot().available_item_count == 0
        assert service.status().service_state in ("FAILED", "DEGRADED")
    finally:
        runtime.close()


def test_pair_status_projection_fault_has_safe_http_error(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient
    application = tmp_path / "application.log"
    ssh = tmp_path / "ssh.log"
    application.write_text("", encoding="utf-8")
    ssh.write_text("", encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    app = create_internal_pair_app(config)
    original = PairMonitoringService.status
    def fail_status(self):
        raise RuntimeError("private-path account=canary ip=192.0.2.99 hostname=canary raw line")
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)) as client:
        monkeypatch.setattr(PairMonitoringService, "status", fail_status)
        response = client.get("/api/v1/live/status")
        assert response.status_code == 503
        assert response.json()["error_code"] == "LIVE_SERVICE_UNAVAILABLE"
        assert "canary" not in response.text and "private-path" not in response.text
        monkeypatch.setattr(PairMonitoringService, "status", original)


def test_pair_status_dto_rejects_extra_private_field(tmp_path: Path):
    _, _, runtime, _, service = _pair(tmp_path)
    try:
        public = service.status().model_dump(mode="json")
        public["roles"][0]["source_path"] = "/private/canary.log"
        from app.models.multi_source_live import PairStatusResponse
        with pytest.raises(Exception):
            PairStatusResponse.model_validate(public)
    finally:
        runtime.close()


def test_initial_runner_notify_fault_sets_terminal_safe_state(tmp_path: Path, monkeypatch):
    _, _, runtime, _, service = _pair(tmp_path)
    calls = 0
    async def fail_notify(self):
        nonlocal calls
        calls += 1
        raise RuntimeError("private-path account=canary ip=192.0.2.99 hostname=canary raw line")
    monkeypatch.setattr(PairMonitoringService, "notify_change", fail_notify)
    async def check():
        runner = PairRunner(service)
        await runner.run()
        assert service.status().service_state == "FAILED"
        assert service.status().fixed_error_code == "PAIR_RUNNER_FAILED"
        await runner.shutdown()
    try:
        asyncio.run(check())
        assert calls >= 1
    finally:
        runtime.close()


def test_pair_projection_rejects_new_private_serializer_field_before_ack(tmp_path: Path,
                                                                         monkeypatch):
    from app.live_monitoring import pair_publication
    application, _, runtime, publication, _ = _pair(tmp_path)
    original = pair_publication.serialize_live_publication_event
    def unsafe_serializer(event):
        payload = json.loads(original(event))
        payload["account"] = "PRIVATE_ACCOUNT_CANARY"
        return json.dumps(payload).encode()
    monkeypatch.setattr(pair_publication, "serialize_live_publication_event", unsafe_serializer)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        with pytest.raises(Exception):
            runtime.cycle()
        assert publication.item_count == 0
        assert runtime.workers["application"]._session.snapshot().active_lease is False
        assert runtime.workers["application"]._accumulator.snapshot().active_proposal is False
    finally:
        runtime.close()


def test_ssh_post_ack_publication_fault_keeps_application_commit(tmp_path: Path, monkeypatch):
    application, ssh, runtime, publication, service = _pair(tmp_path)
    with application.open("a", encoding="utf-8") as stream:
        stream.write(APP * 5)
    with ssh.open("a", encoding="utf-8") as stream:
        stream.write(SSH * 5)
    original = PairPublicationBuffer._swap
    def fault_ssh(self, proposal):
        if proposal.events and proposal.events[0].source_role == "ssh":
            raise RuntimeError("PRIVATE_SSH_EXCEPTION_CANARY")
        return original(self, proposal)
    monkeypatch.setattr(PairPublicationBuffer, "_swap", fault_ssh)
    try:
        with pytest.raises(Exception) as raised:
            runtime.cycle()
        assert "PRIVATE_SSH_EXCEPTION_CANARY" not in str(raised.value) + repr(raised.value)
        assert [event.source_role for event in publication.replay_after(None).events] == [
            "application", "application"]
        assert service.status().service_state in ("FAILED", "DEGRADED")
        assert runtime.workers["application"]._checkpoint._checkpoint.write_sequence == 1
        assert runtime.workers["ssh"]._session.snapshot().active_lease is False
    finally:
        runtime.close()


def test_two_event_combined_byte_limit_rejects_before_ack(tmp_path: Path, monkeypatch):
    from app.live_monitoring import pair_publication
    application, _, runtime, publication, _ = _pair(tmp_path)
    original = pair_publication._safe_bytes
    def wide(value):
        return original(value) + b" " * 8500
    monkeypatch.setattr(pair_publication, "_safe_bytes", wide)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        with pytest.raises(Exception):
            runtime.cycle()
        assert publication.item_count == 0
        worker = runtime.workers["application"]
        assert worker._session.snapshot().active_lease is False
        assert worker._accumulator.snapshot().active_proposal is False
        assert worker._analysis.snapshot().active_proposal is False
    finally:
        runtime.close()


def test_runner_failure_and_notify_failure_do_not_leak(tmp_path: Path, monkeypatch):
    from app.live_monitoring.multi_source import InternalPairRuntime
    _, _, runtime, _, service = _pair(tmp_path)
    calls = 0
    async def notify(self):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("PRIVATE_NOTIFY_CANARY")
    def fail_cycle(self):
        raise RuntimeError("PRIVATE_CYCLE_CANARY")
    monkeypatch.setattr(PairMonitoringService, "notify_change", notify)
    monkeypatch.setattr(InternalPairRuntime, "cycle", fail_cycle)
    async def check():
        runner = PairRunner(service)
        await runner.run()
        assert service.status().service_state == "FAILED"
        await runner.shutdown()
    try:
        asyncio.run(check())
    finally:
        runtime.close()


@pytest.mark.parametrize("field,value", [
    ("session_id", "PRIVATE_SESSION_CANARY"),
    ("earliest_event_id", "PRIVATE_EVENT_CANARY"),
])
def test_pair_status_rejects_invalid_public_ids(tmp_path: Path, field: str, value: str):
    from app.models.multi_source_live import PairStatusResponse
    application, _, runtime, _, service = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        runtime.cycle()
        public = service.status().model_dump(mode="json")
        public[field] = value
        with pytest.raises(Exception):
            PairStatusResponse.model_validate(public)
    finally:
        runtime.close()


def test_pair_snapshot_byte_ceiling_is_safe_http_failure(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient
    from app.live_monitoring import pair_service
    application, ssh = tmp_path / "application.log", tmp_path / "ssh.log"
    application.write_text("", encoding="utf-8")
    ssh.write_text("", encoding="utf-8")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_pair_config(application, ssh, config)
    app = create_internal_pair_app(config)
    with TestClient(app, base_url="http://127.0.0.1",
                    client=("127.0.0.1", 50000)) as client:
        monkeypatch.setattr(pair_service, "MAX_PAIR_SNAPSHOT_BYTES", 1)
        response = client.get("/api/v1/live/status")
        assert response.status_code == 503
        assert response.json()["error_code"] == "LIVE_SERVICE_UNAVAILABLE"
        assert "application.log" not in response.text


def test_pair_status_rejects_inconsistent_replay_count(tmp_path: Path):
    from app.models.multi_source_live import PairStatusResponse
    application, _, runtime, _, service = _pair(tmp_path)
    try:
        with application.open("a", encoding="utf-8") as stream:
            stream.write(APP * 5)
        runtime.cycle()
        public = service.status().model_dump(mode="json")
        assert public["available_event_count"] == 2
        public["available_event_count"] = 1
        with pytest.raises(Exception):
            PairStatusResponse.model_validate(public)
    finally:
        runtime.close()
