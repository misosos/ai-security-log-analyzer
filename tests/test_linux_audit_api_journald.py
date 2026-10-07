import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gc
import os
import threading
import weakref
from uuid import UUID

import pytest

import app.security.linux_audit_api_journald as journald_module
from app.security.linux_audit_api import (
    LinuxAuditApiAccessAuditEvent,
    prepare_linux_audit_api_access_audit_sink,
)
from app.security.linux_audit_api_journald import (
    LinuxAuditApiJournaldSinkError,
    create_linux_audit_api_journald_sink,
)


AUDIT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ANALYSIS_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
CANARY = "PRIVATE_JOURNALD_EVIDENCE_DO_NOT_EXPOSE"


class RecordingTransport(journald_module._JournaldTransport):
    def __init__(self, *, submit_error=None, close_error=None, mutate=False):
        self.submissions = []
        self.submit_error = submit_error
        self.close_error = close_error
        self.mutate = mutate
        self.close_calls = 0

    def submit(self, fields):
        self.submissions.append(dict(fields))
        if self.mutate:
            fields["MESSAGE"] = CANARY
        if self.submit_error is not None:
            raise self.submit_error

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class BlockingTransport(RecordingTransport):
    def __init__(self, target):
        super().__init__()
        self.target = target
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self._active = 0

    def submit(self, fields):
        with self._lock:
            self._active += 1
            if self._active == self.target:
                self.entered.set()
        self.release.wait()
        super().submit(fields)
        with self._lock:
            self._active -= 1


class FakeJournalSocket:
    def __init__(self, *, connect_error=None):
        self.connect_error = connect_error
        self.timeout = None
        self.connected_path = None
        self.payloads = []
        self.close_calls = 0

    def settimeout(self, value):
        self.timeout = value

    def connect(self, path):
        self.connected_path = path
        if self.connect_error is not None:
            raise self.connect_error

    def send(self, payload):
        self.payloads.append(payload)
        return len(payload)

    def close(self):
        self.close_calls += 1


def audit_event(category="analysis_completed"):
    contracts = {
        "authentication_failed": (401, None, None, None, "unknown"),
        "authorization_failed": (403, None, "audit-operator", None, "unknown"),
        "capacity_rejected": (429, None, "audit-operator", 0, "unknown"),
        "validation_failed": (400, None, "audit-operator", 1, "under_1_mib"),
        "analysis_completed": (200, ANALYSIS_ID, "audit-operator", 1, "under_1_mib"),
        "internal_failed": (500, None, "audit-operator", 1, "under_1_mib"),
        "cancelled": (499, None, "audit-operator", 1, "under_1_mib"),
    }
    status, analysis_id, principal_id, file_count, size_bucket = contracts[category]
    return LinuxAuditApiAccessAuditEvent(
        audit_event_id=AUDIT_ID,
        analysis_id=analysis_id,
        timestamp=NOW,
        principal_id=principal_id,
        endpoint="/api/analyze-linux-audit",
        method="POST",
        result_category=category,
        http_status=status,
        file_count=file_count,
        upload_size_bucket=size_bucket,
        duration_bucket="under_1s",
    )


def make_sink(transport=None):
    transport = transport or RecordingTransport()
    return (
        journald_module._create_linux_audit_api_journald_sink_for_transport(
            transport
        ),
        transport,
    )


def run_emit(sink, event=None):
    async def scenario():
        try:
            await sink.emit(event or audit_event())
        finally:
            await sink.close()

    asyncio.run(scenario())


async def release_tasks_and_close(sink, transport, tasks):
    transport.release.set()
    if tasks:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            2,
        )
    await asyncio.wait_for(sink.close(), 2)


def test_production_factory_fails_closed_without_journald(monkeypatch, capsys, caplog):
    def unavailable():
        raise journald_module._JournaldTransportError(CANARY)

    monkeypatch.setattr(
        journald_module._NativeJournaldTransport,
        "open",
        unavailable,
    )

    with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
        create_linux_audit_api_journald_sink()

    assert captured.value.code == "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED"
    assert str(captured.value) == "Linux Audit journald sink initialization failed."
    assert CANARY not in repr(captured.value)
    assert capsys.readouterr() == ("", "")
    assert CANARY not in caplog.text


def test_native_transport_uses_fixed_local_datagram_contract(monkeypatch):
    journal_socket = FakeJournalSocket()
    original_socket = journald_module.socket.socket

    def socket_factory(*args, **kwargs):
        if args == (
            journald_module.socket.AF_UNIX,
            journald_module.socket.SOCK_DGRAM,
        ) and not kwargs:
            return journal_socket
        return original_socket(*args, **kwargs)

    monkeypatch.setattr(journald_module.socket, "socket", socket_factory)
    sink = create_linux_audit_api_journald_sink()

    async def scenario():
        await sink.emit(audit_event())
        await sink.close()

    asyncio.run(scenario())

    assert journal_socket.timeout == journald_module.JOURNALD_SOCKET_TIMEOUT_SECONDS
    assert journal_socket.connected_path == "/run/systemd/journal/socket"
    assert len(journal_socket.payloads) == 1
    assert isinstance(journal_socket.payloads[0], bytes)
    assert journal_socket.close_calls == 1


def test_native_transport_closes_descriptor_when_connect_fails(monkeypatch):
    journal_socket = FakeJournalSocket(connect_error=OSError(CANARY))
    original_socket = journald_module.socket.socket

    def socket_factory(*args, **kwargs):
        if args == (
            journald_module.socket.AF_UNIX,
            journald_module.socket.SOCK_DGRAM,
        ) and not kwargs:
            return journal_socket
        return original_socket(*args, **kwargs)

    monkeypatch.setattr(
        journald_module.socket,
        "socket",
        socket_factory,
    )

    with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
        create_linux_audit_api_journald_sink()

    assert captured.value.code == "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED"
    assert journal_socket.close_calls == 1
    assert CANARY not in str(captured.value)


def test_sink_conforms_to_existing_contract_and_has_safe_repr():
    sink, _ = make_sink()

    assert prepare_linux_audit_api_access_audit_sink(sink) is sink
    assert repr(sink) == "LinuxAuditApiJournaldSink()"
    assert not hasattr(sink, "transport")
    assert not hasattr(sink, "events")
    asyncio.run(sink.close())


@pytest.mark.parametrize(
    "category",
    (
        "authentication_failed",
        "authorization_failed",
        "capacity_rejected",
        "validation_failed",
        "analysis_completed",
        "internal_failed",
        "cancelled",
    ),
)
def test_every_existing_result_category_has_one_explicit_projection(category):
    sink, transport = make_sink()

    run_emit(sink, audit_event(category))

    assert len(transport.submissions) == 1
    assert transport.submissions[0]["LINUX_AUDIT_RESULT_CATEGORY"] == category


def test_projection_has_exact_fixed_allowlist_and_values():
    sink, transport = make_sink()

    run_emit(sink)

    assert tuple(transport.submissions[0]) == journald_module._JOURNAL_FIELD_NAMES
    assert transport.submissions[0] == {
        "MESSAGE": "Linux Audit API access audit event",
        "PRIORITY": "5",
        "SYSLOG_IDENTIFIER": "ai-security-log-analyzer",
        "LINUX_AUDIT_EVENT_SCHEMA_VERSION": "1",
        "LINUX_AUDIT_AUDIT_EVENT_ID": str(AUDIT_ID),
        "LINUX_AUDIT_ANALYSIS_ID": str(ANALYSIS_ID),
        "LINUX_AUDIT_TIMESTAMP_UTC": "2026-10-07T12:00:00.000000Z",
        "LINUX_AUDIT_PRINCIPAL_ID": "audit-operator",
        "LINUX_AUDIT_ENDPOINT": "/api/analyze-linux-audit",
        "LINUX_AUDIT_HTTP_METHOD": "POST",
        "LINUX_AUDIT_RESULT_CATEGORY": "analysis_completed",
        "LINUX_AUDIT_HTTP_STATUS": "200",
        "LINUX_AUDIT_FILE_COUNT": "1",
        "LINUX_AUDIT_UPLOAD_SIZE_BUCKET": "under_1_mib",
        "LINUX_AUDIT_DURATION_BUCKET": "under_1s",
    }
    assert all(not name.startswith("_") for name in transport.submissions[0])


def test_projection_uses_absent_marker_only_for_contractual_optional_fields():
    sink, transport = make_sink()

    run_emit(sink, audit_event("authentication_failed"))

    fields = transport.submissions[0]
    assert fields["LINUX_AUDIT_ANALYSIS_ID"] == "-"
    assert fields["LINUX_AUDIT_PRINCIPAL_ID"] == "-"
    assert fields["LINUX_AUDIT_FILE_COUNT"] == "-"


def test_transport_gets_new_mapping_and_cannot_mutate_source_event():
    source = audit_event()
    sink, transport = make_sink(RecordingTransport(mutate=True))

    run_emit(sink, source)

    assert source == audit_event()
    assert source.principal_id == "audit-operator"
    assert transport.submissions[0]["MESSAGE"] != CANARY


def test_arbitrary_event_attribute_is_not_passed_through():
    source = audit_event()
    object.__setattr__(source, "raw_records", CANARY)
    sink, transport = make_sink()

    run_emit(sink, source)

    rendered = repr(transport.submissions[0])
    assert CANARY not in rendered
    assert "raw_records" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("http_status", True),
        ("file_count", True),
        ("principal_id", "audit\noperator"),
        ("principal_id", "audit\x00operator"),
        ("principal_id", "opérator"),
        ("principal_id", "a" * 65),
        ("result_category", "unknown_category"),
        ("upload_size_bucket", "unknown"),
        ("duration_bucket", "instant"),
    ),
)
def test_tampered_event_contract_is_rejected_before_submission(field, value):
    source = audit_event()
    object.__setattr__(source, field, value)
    sink, transport = make_sink()

    with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
        run_emit(sink, source)

    assert captured.value.code == "LINUX_AUDIT_JOURNALD_INVALID_EVENT"
    assert transport.submissions == []
    assert value.__repr__() not in str(captured.value)


def test_exact_event_type_is_required():
    class EventSubclass(LinuxAuditApiAccessAuditEvent):
        pass

    values = {
        name: getattr(audit_event(), name)
        for name in audit_event().__dataclass_fields__
    }
    subclass = EventSubclass(**values)
    sink, transport = make_sink()

    for invalid in (object(), subclass):
        with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
            run_emit(sink, invalid)
        assert captured.value.code == "LINUX_AUDIT_JOURNALD_INVALID_EVENT"
    assert transport.submissions == []


def test_native_encoding_is_bounded_and_rejects_invalid_fields():
    fields = journald_module._project_journal_fields(audit_event())
    payload = journald_module._encode_journal_fields(fields)

    assert len(payload) <= journald_module.JOURNALD_MAX_PAYLOAD_BYTES
    assert payload.startswith(b"MESSAGE=Linux Audit API access audit event\n")
    assert payload.endswith(b"LINUX_AUDIT_DURATION_BUCKET=under_1s\n")

    for invalid in (
        {**fields, "MESSAGE": "line\nbreak"},
        {**fields, "MESSAGE": "nul\x00value"},
        {**fields, "MESSAGE": "x" * (journald_module.JOURNALD_MAX_FIELD_VALUE_BYTES + 1)},
        {**fields, "ARBITRARY": "metadata"},
    ):
        with pytest.raises(LinuxAuditApiJournaldSinkError):
            journald_module._encode_journal_fields(invalid)


def test_duplicate_events_are_submitted_without_retry_or_deduplication():
    sink, transport = make_sink()

    async def scenario():
        try:
            await sink.emit(audit_event())
            await sink.emit(audit_event())
        finally:
            await sink.close()

    asyncio.run(scenario())

    assert len(transport.submissions) == 2
    assert transport.submissions[0] == transport.submissions[1]


def test_sink_does_not_retain_the_source_event_after_submission():
    source = audit_event()
    reference = weakref.ref(source)
    sink, transport = make_sink()

    run_emit(sink, source)
    del source
    gc.collect()

    assert reference() is None
    assert len(transport.submissions) == 1


def test_submission_failure_is_bounded_has_no_retry_and_can_close(capsys, caplog):
    transport = RecordingTransport(
        submit_error=journald_module._JournaldTransportError(CANARY)
    )
    sink, _ = make_sink(transport)

    async def scenario():
        with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
            await sink.emit(audit_event())
        await sink.close()
        return captured.value

    error = asyncio.run(scenario())

    assert error.code == "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
    assert str(error) == "Linux Audit journald submission failed."
    assert len(transport.submissions) == 1
    assert transport.close_calls == 1
    assert CANARY not in repr(error)
    assert capsys.readouterr() == ("", "")
    assert CANARY not in caplog.text


def test_concurrent_direct_submissions_complete_without_an_event_queue():
    transport = BlockingTransport(target=2)
    sink, _ = make_sink(transport)

    async def scenario():
        tasks = [asyncio.create_task(sink.emit(audit_event())) for _ in range(2)]
        try:
            assert await asyncio.to_thread(transport.entered.wait, 1)
        finally:
            await release_tasks_and_close(sink, transport, tasks)

    asyncio.run(scenario())

    assert len(transport.submissions) == 2
    assert transport.close_calls == 1


def test_concurrent_submission_bound_fails_closed_without_queueing():
    transport = BlockingTransport(
        target=journald_module.JOURNALD_MAX_CONCURRENT_SUBMISSIONS
    )
    sink, _ = make_sink(transport)

    async def scenario():
        asyncio.get_running_loop().set_default_executor(
            ThreadPoolExecutor(max_workers=1)
        )
        tasks = [
            asyncio.create_task(sink.emit(audit_event()))
            for _ in range(journald_module.JOURNALD_MAX_CONCURRENT_SUBMISSIONS)
        ]
        try:
            assert await asyncio.to_thread(transport.entered.wait, 1)
            with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
                await sink.emit(audit_event())
            return captured.value
        finally:
            await release_tasks_and_close(sink, transport, tasks)

    error = asyncio.run(scenario())

    assert error.code == "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
    assert len(transport.submissions) == journald_module.JOURNALD_MAX_CONCURRENT_SUBMISSIONS


def test_separate_sinks_have_independent_submission_executors():
    blocked_transport = BlockingTransport(
        target=journald_module.JOURNALD_MAX_CONCURRENT_SUBMISSIONS
    )
    blocked_sink, _ = make_sink(blocked_transport)
    independent_sink, independent_transport = make_sink()

    async def scenario():
        asyncio.get_running_loop().set_default_executor(
            ThreadPoolExecutor(max_workers=1)
        )
        tasks = [
            asyncio.create_task(blocked_sink.emit(audit_event()))
            for _ in range(journald_module.JOURNALD_MAX_CONCURRENT_SUBMISSIONS)
        ]
        try:
            assert await asyncio.to_thread(blocked_transport.entered.wait, 1)
            await independent_sink.emit(audit_event())
            assert len(independent_transport.submissions) == 1
        finally:
            await release_tasks_and_close(
                blocked_sink,
                blocked_transport,
                tasks,
            )
            await asyncio.wait_for(independent_sink.close(), 2)

    asyncio.run(scenario())


def test_blocking_submission_cleanup_runs_after_an_assertion_failure():
    transport = BlockingTransport(target=1)
    sink, _ = make_sink(transport)

    async def scenario():
        task = asyncio.create_task(sink.emit(audit_event()))
        failure_observed = False
        try:
            assert await asyncio.to_thread(transport.entered.wait, 1)
            raise AssertionError("synthetic test assertion")
        except AssertionError:
            failure_observed = True
        finally:
            await release_tasks_and_close(sink, transport, [task])
        return failure_observed

    assert asyncio.run(scenario()) is True
    assert len(transport.submissions) == 1
    assert transport.close_calls == 1


def test_cancellation_propagates_and_close_waits_for_blocking_submission():
    transport = BlockingTransport(target=1)
    sink, _ = make_sink(transport)

    async def scenario():
        task = asyncio.create_task(sink.emit(audit_event()))
        try:
            assert await asyncio.to_thread(transport.entered.wait, 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            await release_tasks_and_close(sink, transport, [task])

    asyncio.run(scenario())

    assert len(transport.submissions) == 1
    assert transport.close_calls == 1


def test_close_is_idempotent_and_emit_after_close_is_fixed_failure():
    sink, transport = make_sink()

    async def scenario():
        await sink.close()
        await sink.close()
        with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
            await sink.emit(audit_event())
        return captured.value

    error = asyncio.run(scenario())

    assert error.code == "LINUX_AUDIT_JOURNALD_SINK_CLOSED"
    assert transport.close_calls == 1
    assert transport.submissions == []


def test_close_after_success_and_close_failure_are_bounded():
    good_sink, good_transport = make_sink()

    async def successful():
        await good_sink.emit(audit_event())
        await good_sink.close()

    asyncio.run(successful())
    assert good_transport.close_calls == 1

    bad_transport = RecordingTransport(
        close_error=journald_module._JournaldTransportError(CANARY)
    )
    bad_sink, _ = make_sink(bad_transport)
    with pytest.raises(LinuxAuditApiJournaldSinkError) as captured:
        asyncio.run(bad_sink.close())
    assert captured.value.code == "LINUX_AUDIT_JOURNALD_SHUTDOWN_FAILED"
    assert CANARY not in str(captured.value)


def test_sink_has_no_environment_dependency(monkeypatch):
    monkeypatch.setenv("JOURNAL_STREAM", CANARY)
    monkeypatch.setenv("JOURNALD_SOCKET", CANARY)
    sink, transport = make_sink()

    run_emit(sink)

    assert len(transport.submissions) == 1
    assert CANARY not in repr(transport.submissions)
    assert os.environ["JOURNAL_STREAM"] == CANARY
