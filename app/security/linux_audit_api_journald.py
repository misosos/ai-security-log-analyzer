import asyncio
import re
import socket
import threading
from abc import ABC, abstractmethod
from datetime import timezone

from app.security.linux_audit_api import (
    LinuxAuditApiAccessAuditContractError,
    LinuxAuditApiAccessAuditEvent,
    LinuxAuditApiAccessAuditSink,
)


JOURNALD_MAX_FIELD_VALUE_BYTES = 256
JOURNALD_MAX_PAYLOAD_BYTES = 4096
JOURNALD_MAX_CONCURRENT_SUBMISSIONS = 8
JOURNALD_SOCKET_TIMEOUT_SECONDS = 2.0
JOURNALD_SUBMISSION_TIMEOUT_SECONDS = 3.0
JOURNALD_CLOSE_TIMEOUT_SECONDS = 5.0

_JOURNAL_SOCKET_PATH = "/run/systemd/journal/socket"
_JOURNAL_MESSAGE = "Linux Audit API access audit event"
_JOURNAL_PRIORITY = "5"
_JOURNAL_IDENTIFIER = "ai-security-log-analyzer"
_JOURNAL_SCHEMA_VERSION = "1"
_ABSENT_VALUE = "-"
_FIELD_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_JOURNAL_FIELD_NAMES = (
    "MESSAGE",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "LINUX_AUDIT_EVENT_SCHEMA_VERSION",
    "LINUX_AUDIT_AUDIT_EVENT_ID",
    "LINUX_AUDIT_ANALYSIS_ID",
    "LINUX_AUDIT_TIMESTAMP_UTC",
    "LINUX_AUDIT_PRINCIPAL_ID",
    "LINUX_AUDIT_ENDPOINT",
    "LINUX_AUDIT_HTTP_METHOD",
    "LINUX_AUDIT_RESULT_CATEGORY",
    "LINUX_AUDIT_HTTP_STATUS",
    "LINUX_AUDIT_FILE_COUNT",
    "LINUX_AUDIT_UPLOAD_SIZE_BUCKET",
    "LINUX_AUDIT_DURATION_BUCKET",
)
_ERRORS = {
    "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED": (
        "Linux Audit journald sink initialization failed."
    ),
    "LINUX_AUDIT_JOURNALD_INVALID_EVENT": (
        "Linux Audit journald event is invalid."
    ),
    "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED": (
        "Linux Audit journald submission failed."
    ),
    "LINUX_AUDIT_JOURNALD_SINK_CLOSED": (
        "Linux Audit journald sink is closed."
    ),
    "LINUX_AUDIT_JOURNALD_SHUTDOWN_FAILED": (
        "Linux Audit journald sink shutdown failed."
    ),
}


class LinuxAuditApiJournaldSinkError(RuntimeError):

    def __init__(self, code: str):
        message = _ERRORS.get(code)
        if message is None:
            code = "LINUX_AUDIT_JOURNALD_INVALID_EVENT"
            message = _ERRORS[code]
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self):
        return f"LinuxAuditApiJournaldSinkError(code={self.code!r})"


class _JournaldTransportError(RuntimeError):
    pass


class _JournaldTransport(ABC):

    @abstractmethod
    def submit(self, fields: dict[str, str]) -> None:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError


class _NativeJournaldTransport(_JournaldTransport):
    __slots__ = ("__close_lock", "__socket")

    def __init__(self, journal_socket: socket.socket):
        self.__socket = journal_socket
        self.__close_lock = threading.Lock()

    @classmethod
    def open(cls):
        journal_socket = None
        try:
            journal_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            journal_socket.settimeout(JOURNALD_SOCKET_TIMEOUT_SECONDS)
            journal_socket.connect(_JOURNAL_SOCKET_PATH)
        except OSError:
            if journal_socket is not None:
                try:
                    journal_socket.close()
                except OSError:
                    pass
            raise _JournaldTransportError() from None
        return cls(journal_socket)

    def submit(self, fields: dict[str, str]) -> None:
        payload = _encode_journal_fields(fields)
        try:
            submitted = self.__socket.send(payload)
        except OSError:
            raise _JournaldTransportError() from None
        if submitted != len(payload):
            raise _JournaldTransportError()

    def close(self) -> None:
        with self.__close_lock:
            journal_socket = self.__socket
            if journal_socket is None:
                return
            self.__socket = None
            try:
                journal_socket.close()
            except OSError:
                raise _JournaldTransportError() from None


def _sink_error(code: str) -> LinuxAuditApiJournaldSinkError:
    return LinuxAuditApiJournaldSinkError(code)


def _validate_event(
    event: LinuxAuditApiAccessAuditEvent,
) -> LinuxAuditApiAccessAuditEvent:
    if type(event) is not LinuxAuditApiAccessAuditEvent:
        raise _sink_error("LINUX_AUDIT_JOURNALD_INVALID_EVENT")
    try:
        return LinuxAuditApiAccessAuditEvent(
            audit_event_id=event.audit_event_id,
            analysis_id=event.analysis_id,
            timestamp=event.timestamp,
            principal_id=event.principal_id,
            endpoint=event.endpoint,
            method=event.method,
            result_category=event.result_category,
            http_status=event.http_status,
            file_count=event.file_count,
            upload_size_bucket=event.upload_size_bucket,
            duration_bucket=event.duration_bucket,
        )
    except LinuxAuditApiAccessAuditContractError:
        raise _sink_error("LINUX_AUDIT_JOURNALD_INVALID_EVENT") from None


def _project_journal_fields(
    event: LinuxAuditApiAccessAuditEvent,
) -> dict[str, str]:
    validated = _validate_event(event)
    fields = {
        "MESSAGE": _JOURNAL_MESSAGE,
        "PRIORITY": _JOURNAL_PRIORITY,
        "SYSLOG_IDENTIFIER": _JOURNAL_IDENTIFIER,
        "LINUX_AUDIT_EVENT_SCHEMA_VERSION": _JOURNAL_SCHEMA_VERSION,
        "LINUX_AUDIT_AUDIT_EVENT_ID": str(validated.audit_event_id),
        "LINUX_AUDIT_ANALYSIS_ID": (
            str(validated.analysis_id)
            if validated.analysis_id is not None
            else _ABSENT_VALUE
        ),
        "LINUX_AUDIT_TIMESTAMP_UTC": (
            validated.timestamp.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        ),
        "LINUX_AUDIT_PRINCIPAL_ID": (
            validated.principal_id
            if validated.principal_id is not None
            else _ABSENT_VALUE
        ),
        "LINUX_AUDIT_ENDPOINT": validated.endpoint,
        "LINUX_AUDIT_HTTP_METHOD": validated.method,
        "LINUX_AUDIT_RESULT_CATEGORY": validated.result_category,
        "LINUX_AUDIT_HTTP_STATUS": str(validated.http_status),
        "LINUX_AUDIT_FILE_COUNT": (
            str(validated.file_count)
            if validated.file_count is not None
            else _ABSENT_VALUE
        ),
        "LINUX_AUDIT_UPLOAD_SIZE_BUCKET": (
            validated.upload_size_bucket
        ),
        "LINUX_AUDIT_DURATION_BUCKET": validated.duration_bucket,
    }
    _validate_journal_fields(fields)
    return fields


def _validate_journal_fields(fields: dict[str, str]) -> None:
    if type(fields) is not dict or tuple(fields) != _JOURNAL_FIELD_NAMES:
        raise _sink_error("LINUX_AUDIT_JOURNALD_INVALID_EVENT")
    for field_name in _JOURNAL_FIELD_NAMES:
        value = fields[field_name]
        if (
            type(field_name) is not str
            or _FIELD_NAME_PATTERN.fullmatch(field_name) is None
            or field_name.startswith("_")
            or type(value) is not str
            or not value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            or len(value.encode("utf-8")) > JOURNALD_MAX_FIELD_VALUE_BYTES
        ):
            raise _sink_error("LINUX_AUDIT_JOURNALD_INVALID_EVENT")


def _encode_journal_fields(fields: dict[str, str]) -> bytes:
    _validate_journal_fields(fields)
    payload = bytearray()
    for field_name in _JOURNAL_FIELD_NAMES:
        payload.extend(field_name.encode("ascii"))
        payload.extend(b"=")
        payload.extend(fields[field_name].encode("utf-8"))
        payload.extend(b"\n")
    if len(payload) > JOURNALD_MAX_PAYLOAD_BYTES:
        raise _JournaldTransportError()
    return bytes(payload)


def _consume_background_task(task: asyncio.Task) -> None:
    try:
        task.exception()
    except asyncio.CancelledError:
        pass


class LinuxAuditApiJournaldSink(LinuxAuditApiAccessAuditSink):
    __slots__ = (
        "__background_tasks",
        "__close_lock",
        "__in_flight",
        "__in_flight_zero",
        "__state",
        "__state_lock",
        "__transport",
    )

    def __init__(self, transport: _JournaldTransport):
        if not isinstance(transport, _JournaldTransport):
            raise _sink_error(
                "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED"
            )
        self.__transport = transport
        self.__state_lock = threading.Lock()
        self.__state = "open"
        self.__in_flight = 0
        self.__in_flight_zero = threading.Event()
        self.__in_flight_zero.set()
        self.__close_lock = asyncio.Lock()
        self.__background_tasks = set()

    def __repr__(self):
        return "LinuxAuditApiJournaldSink()"

    def _begin_submission(self) -> None:
        with self.__state_lock:
            if self.__state == "closed" or self.__state == "closing":
                raise _sink_error("LINUX_AUDIT_JOURNALD_SINK_CLOSED")
            if self.__state == "failed":
                raise _sink_error(
                    "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
                )
            if self.__in_flight >= JOURNALD_MAX_CONCURRENT_SUBMISSIONS:
                self.__state = "failed"
                raise _sink_error(
                    "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
                )
            self.__in_flight += 1
            self.__in_flight_zero.clear()

    def _finish_submission(self) -> None:
        with self.__state_lock:
            if self.__in_flight <= 0:
                self.__state = "failed"
                return
            self.__in_flight -= 1
            if self.__in_flight == 0:
                self.__in_flight_zero.set()

    def _mark_failed(self) -> None:
        with self.__state_lock:
            if self.__state == "open":
                self.__state = "failed"

    def _submit(self, fields: dict[str, str]) -> None:
        try:
            result = self.__transport.submit(fields)
            if result is not None:
                raise _JournaldTransportError()
        finally:
            self._finish_submission()

    def _track_background_task(self, task: asyncio.Task) -> None:
        self.__background_tasks.add(task)

        def finished(completed: asyncio.Task) -> None:
            self.__background_tasks.discard(completed)
            _consume_background_task(completed)

        task.add_done_callback(finished)

    async def emit(self, event: LinuxAuditApiAccessAuditEvent) -> None:
        fields = _project_journal_fields(event)
        self._begin_submission()
        operation = asyncio.create_task(asyncio.to_thread(self._submit, fields))
        try:
            await asyncio.wait_for(
                asyncio.shield(operation),
                timeout=JOURNALD_SUBMISSION_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            self._mark_failed()
            self._track_background_task(operation)
            raise
        except TimeoutError:
            self._mark_failed()
            self._track_background_task(operation)
            raise _sink_error(
                "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
            ) from None
        except _JournaldTransportError:
            self._mark_failed()
            raise _sink_error(
                "LINUX_AUDIT_JOURNALD_SUBMISSION_FAILED"
            ) from None

    async def close(self) -> None:
        async with self.__close_lock:
            with self.__state_lock:
                if self.__state == "closed":
                    return
                self.__state = "closing"

            completed = await asyncio.to_thread(
                self.__in_flight_zero.wait,
                JOURNALD_CLOSE_TIMEOUT_SECONDS,
            )
            if not completed:
                raise _sink_error(
                    "LINUX_AUDIT_JOURNALD_SHUTDOWN_FAILED"
                )

            operation = asyncio.create_task(
                asyncio.to_thread(self.__transport.close)
            )
            try:
                await asyncio.wait_for(
                    asyncio.shield(operation),
                    timeout=JOURNALD_CLOSE_TIMEOUT_SECONDS,
                )
            except asyncio.CancelledError:
                self._track_background_task(operation)
                raise
            except TimeoutError:
                self._track_background_task(operation)
                raise _sink_error(
                    "LINUX_AUDIT_JOURNALD_SHUTDOWN_FAILED"
                ) from None
            except _JournaldTransportError:
                raise _sink_error(
                    "LINUX_AUDIT_JOURNALD_SHUTDOWN_FAILED"
                ) from None

            with self.__state_lock:
                self.__state = "closed"


def create_linux_audit_api_journald_sink() -> LinuxAuditApiJournaldSink:
    try:
        transport = _NativeJournaldTransport.open()
    except _JournaldTransportError:
        raise _sink_error(
            "LINUX_AUDIT_JOURNALD_INITIALIZATION_FAILED"
        ) from None
    return LinuxAuditApiJournaldSink(transport)


def _create_linux_audit_api_journald_sink_for_transport(
    transport: _JournaldTransport,
) -> LinuxAuditApiJournaldSink:
    return LinuxAuditApiJournaldSink(transport)
