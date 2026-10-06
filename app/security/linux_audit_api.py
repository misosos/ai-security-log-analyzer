import asyncio
import base64
import hashlib
import inspect
import math
import re
import secrets
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID, uuid4 as _audit_uuid4

from fastapi import Depends, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr


LINUX_AUDIT_ANALYZE_PERMISSION = "linux-audit:analyze"
LINUX_AUDIT_AUTHENTICATION_ERROR_CODE = (
    "LINUX_AUDIT_AUTHENTICATION_REQUIRED"
)
LINUX_AUDIT_AUTHENTICATION_ERROR_STATUS = 401
LINUX_AUDIT_AUTHENTICATION_ERROR_MESSAGE = (
    "Authentication is required."
)
LINUX_AUDIT_AUTHORIZATION_ERROR_CODE = "LINUX_AUDIT_ACCESS_DENIED"
LINUX_AUDIT_AUTHORIZATION_ERROR_STATUS = 403
LINUX_AUDIT_AUTHORIZATION_ERROR_MESSAGE = "Access is denied."
LINUX_AUDIT_BUSY_ERROR_CODE = "LINUX_AUDIT_ANALYSIS_BUSY"
LINUX_AUDIT_BUSY_ERROR_STATUS = 429
LINUX_AUDIT_BUSY_ERROR_MESSAGE = (
    "Linux Audit analysis capacity is unavailable."
)
LINUX_AUDIT_AUDIT_FAILED_ERROR_CODE = (
    "LINUX_AUDIT_ACCESS_AUDIT_FAILED"
)
LINUX_AUDIT_AUDIT_FAILED_ERROR_STATUS = 500
LINUX_AUDIT_AUDIT_FAILED_ERROR_MESSAGE = (
    "Linux Audit access audit could not be completed."
)

_CONFIGURATION_ERROR_MESSAGE = (
    "Linux Audit API security configuration is invalid."
)
_LIMITER_CONTRACT_ERROR_MESSAGE = (
    "Linux Audit analysis capacity state is invalid."
)
_AUDIT_CONTRACT_ERROR_MESSAGE = (
    "Linux Audit access audit contract is invalid."
)
_AUDIT_EMISSION_FAILURE_NOTE = (
    "Linux Audit access audit emission failed."
)
_TOKEN_LENGTH = 43
_TOKEN_BYTES = 32
_MAX_AUTHORIZATION_HEADER_BYTES = 256
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_PRINCIPAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_AUTHORIZATION_PATTERN = re.compile(
    r"Bearer [A-Za-z0-9_-]{43}",
    flags=re.IGNORECASE,
)
_V1_PERMISSIONS = frozenset((LINUX_AUDIT_ANALYZE_PERMISSION,))
_AUDIT_ENDPOINT = "/api/analyze-linux-audit"
_AUDIT_METHOD = "POST"
_AUDIT_CATEGORIES = frozenset((
    "authentication_failed",
    "authorization_failed",
    "capacity_rejected",
    "validation_failed",
    "analysis_completed",
    "internal_failed",
    "cancelled",
))
_UPLOAD_SIZE_BUCKETS = frozenset((
    "unknown",
    "under_1_mib",
    "1_to_10_mib",
    "over_10_mib",
))
_DURATION_BUCKETS = frozenset((
    "unknown",
    "under_1s",
    "1_to_5s",
    "over_5s",
))
_VALIDATION_HTTP_STATUSES = frozenset((400, 409, 413, 415, 422))
_ONE_MIB = 1024 * 1024
_TEN_MIB = 10 * 1024 * 1024
_AUDIT_RECORDER_STATE_KEY = "linux_audit_api_access_audit_recorder"

AuditResultCategory = Literal[
    "authentication_failed",
    "authorization_failed",
    "capacity_rejected",
    "validation_failed",
    "analysis_completed",
    "internal_failed",
    "cancelled",
]
UploadSizeBucket = Literal[
    "unknown",
    "under_1_mib",
    "1_to_10_mib",
    "over_10_mib",
]
DurationBucket = Literal[
    "unknown",
    "under_1s",
    "1_to_5s",
    "over_5s",
]


@dataclass(frozen=True)
class LinuxAuditApiSecurityConfig:
    operator_token: SecretStr = field(repr=False)
    principal_id: str
    max_concurrent_analyses: int


@dataclass(frozen=True)
class PreparedLinuxAuditApiSecurity:
    principal_id: str
    max_concurrent_analyses: int
    permissions: frozenset[str]
    _operator_token_digest: bytes = field(repr=False)


@dataclass(frozen=True)
class AuthenticatedLinuxAuditPrincipal:
    principal_id: str
    permissions: frozenset[str]


@dataclass(frozen=True, repr=False)
class LinuxAuditApiAccessAuditEvent:
    audit_event_id: UUID
    analysis_id: UUID | None
    timestamp: datetime
    principal_id: str | None
    endpoint: Literal["/api/analyze-linux-audit"]
    method: Literal["POST"]
    result_category: AuditResultCategory
    http_status: int
    file_count: int | None
    upload_size_bucket: UploadSizeBucket
    duration_bucket: DurationBucket

    def __post_init__(self):
        if (
            type(self.audit_event_id) is not UUID
            or (
                self.analysis_id is not None
                and type(self.analysis_id) is not UUID
            )
            or type(self.timestamp) is not datetime
            or self.timestamp.tzinfo is not timezone.utc
            or (
                self.principal_id is not None
                and (
                    type(self.principal_id) is not str
                    or _PRINCIPAL_PATTERN.fullmatch(
                        self.principal_id
                    ) is None
                )
            )
            or type(self.endpoint) is not str
            or self.endpoint != _AUDIT_ENDPOINT
            or type(self.method) is not str
            or self.method != _AUDIT_METHOD
            or type(self.result_category) is not str
            or self.result_category not in _AUDIT_CATEGORIES
            or type(self.http_status) is not int
            or (
                self.file_count is not None
                and (
                    type(self.file_count) is not int
                    or self.file_count < 0
                )
            )
            or type(self.upload_size_bucket) is not str
            or self.upload_size_bucket not in _UPLOAD_SIZE_BUCKETS
            or type(self.duration_bucket) is not str
            or self.duration_bucket not in _DURATION_BUCKETS
        ):
            raise LinuxAuditApiAccessAuditContractError()
        self._validate_category_contract()

    def _validate_category_contract(self):
        category = self.result_category
        if category == "authentication_failed":
            valid = (
                self.http_status == 401
                and self.principal_id is None
                and self.file_count is None
                and self.analysis_id is None
                and self.upload_size_bucket == "unknown"
            )
        elif category == "authorization_failed":
            valid = (
                self.http_status == 403
                and self.principal_id is not None
                and self.file_count is None
                and self.analysis_id is None
                and self.upload_size_bucket == "unknown"
            )
        elif category == "capacity_rejected":
            valid = (
                self.http_status == 429
                and self.principal_id is not None
                and self.file_count is not None
                and self.analysis_id is None
                and self.upload_size_bucket == "unknown"
            )
        elif category == "validation_failed":
            valid = (
                self.http_status in _VALIDATION_HTTP_STATUSES
                and self.principal_id is not None
                and self.file_count is not None
                and self.analysis_id is None
            )
        elif category == "analysis_completed":
            valid = (
                self.http_status == 200
                and self.principal_id is not None
                and self.file_count is not None
                and self.analysis_id is not None
                and self.upload_size_bucket != "unknown"
            )
        elif category == "internal_failed":
            valid = (
                self.http_status == 500
                and self.principal_id is not None
                and self.file_count is not None
                and self.analysis_id is None
            )
        else:
            valid = self.http_status == 499 and self.analysis_id is None

        if not valid:
            raise LinuxAuditApiAccessAuditContractError()

    def __repr__(self):
        return "LinuxAuditApiAccessAuditEvent()"


class LinuxAuditApiAccessAuditSink(ABC):

    @abstractmethod
    async def emit(self, event: LinuxAuditApiAccessAuditEvent) -> None:
        raise NotImplementedError


class LinuxAuditApiSecurityConfigurationError(ValueError):

    def __init__(self):
        super().__init__(_CONFIGURATION_ERROR_MESSAGE)


class LinuxAuditApiAuthenticationError(ValueError):

    def __init__(self):
        super().__init__(LINUX_AUDIT_AUTHENTICATION_ERROR_MESSAGE)
        self.code = LINUX_AUDIT_AUTHENTICATION_ERROR_CODE
        self.status_code = LINUX_AUDIT_AUTHENTICATION_ERROR_STATUS
        self.message = LINUX_AUDIT_AUTHENTICATION_ERROR_MESSAGE


class LinuxAuditApiAuthorizationError(ValueError):

    def __init__(self):
        super().__init__(LINUX_AUDIT_AUTHORIZATION_ERROR_MESSAGE)
        self.code = LINUX_AUDIT_AUTHORIZATION_ERROR_CODE
        self.status_code = LINUX_AUDIT_AUTHORIZATION_ERROR_STATUS
        self.message = LINUX_AUDIT_AUTHORIZATION_ERROR_MESSAGE


class LinuxAuditApiAccessAuditContractError(RuntimeError):

    def __init__(self):
        super().__init__(_AUDIT_CONTRACT_ERROR_MESSAGE)


class LinuxAuditApiAccessAuditFailedError(RuntimeError):

    def __init__(self):
        super().__init__(LINUX_AUDIT_AUDIT_FAILED_ERROR_MESSAGE)
        self.code = LINUX_AUDIT_AUDIT_FAILED_ERROR_CODE
        self.status_code = LINUX_AUDIT_AUDIT_FAILED_ERROR_STATUS
        self.message = LINUX_AUDIT_AUDIT_FAILED_ERROR_MESSAGE


class LinuxAuditAnalysisBusyError(RuntimeError):

    def __init__(self):
        super().__init__(LINUX_AUDIT_BUSY_ERROR_MESSAGE)
        self.code = LINUX_AUDIT_BUSY_ERROR_CODE
        self.status_code = LINUX_AUDIT_BUSY_ERROR_STATUS
        self.message = LINUX_AUDIT_BUSY_ERROR_MESSAGE


class LinuxAuditAnalysisLimiterContractError(RuntimeError):

    def __init__(self):
        super().__init__(_LIMITER_CONTRACT_ERROR_MESSAGE)


class _LinuxAuditAnalysisLease:
    __slots__ = ("_entered", "_finished", "_limiter")

    def __init__(self, limiter: "LinuxAuditAnalysisLimiter"):
        self._limiter = limiter
        self._entered = False
        self._finished = False

    async def __aenter__(self):
        if self._entered or self._finished:
            raise LinuxAuditAnalysisLimiterContractError()
        self._limiter._acquire()
        self._entered = True
        return None

    async def __aexit__(self, exc_type, exc_value, traceback):
        if not self._entered or self._finished:
            raise LinuxAuditAnalysisLimiterContractError()
        self._finished = True
        try:
            self._limiter._release()
        except LinuxAuditAnalysisLimiterContractError as release_error:
            if exc_value is None:
                raise
            exc_value.add_note(str(release_error))
        return False


class LinuxAuditAnalysisLimiter:
    __slots__ = ("__capacity", "__in_use")

    def __init__(self, capacity: int):
        if type(capacity) is not int or not 1 <= capacity <= 4:
            raise _configuration_error()
        self.__capacity = capacity
        self.__in_use = 0

    def __repr__(self):
        return "LinuxAuditAnalysisLimiter()"

    def acquire(self):
        return _LinuxAuditAnalysisLease(self)

    def _acquire(self):
        self._validate_state()
        if self.__in_use == self.__capacity:
            raise LinuxAuditAnalysisBusyError()
        self.__in_use += 1

    def _release(self):
        self._validate_state()
        if self.__in_use == 0:
            raise LinuxAuditAnalysisLimiterContractError()
        self.__in_use -= 1

    def _validate_state(self):
        if (
            type(self.__capacity) is not int
            or type(self.__in_use) is not int
            or not 1 <= self.__capacity <= 4
            or not 0 <= self.__in_use <= self.__capacity
        ):
            raise LinuxAuditAnalysisLimiterContractError()


def _upload_size_bucket(size_bytes: object) -> UploadSizeBucket:
    if type(size_bytes) is not int or size_bytes < 0:
        raise LinuxAuditApiAccessAuditContractError()
    if size_bytes < _ONE_MIB:
        return "under_1_mib"
    if size_bytes <= _TEN_MIB:
        return "1_to_10_mib"
    return "over_10_mib"


def _duration_bucket(elapsed_seconds: object) -> DurationBucket:
    if (
        type(elapsed_seconds) not in (int, float)
        or not math.isfinite(elapsed_seconds)
        or elapsed_seconds < 0
    ):
        raise LinuxAuditApiAccessAuditContractError()
    if elapsed_seconds < 1:
        return "under_1s"
    if elapsed_seconds < 5:
        return "1_to_5s"
    return "over_5s"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LinuxAuditApiAccessAuditRecorder:
    __slots__ = (
        "__audit_event_id",
        "__file_count",
        "__monotonic",
        "__principal_id",
        "__sink",
        "__started_at",
        "__terminal_attempted",
        "__upload_size_bucket",
        "__utc_now",
    )

    def __init__(
        self,
        sink: LinuxAuditApiAccessAuditSink,
        *,
        audit_event_id: UUID,
        started_at: float,
        utc_now: Callable[[], datetime],
        monotonic: Callable[[], float],
    ):
        if (
            not isinstance(sink, LinuxAuditApiAccessAuditSink)
            or type(audit_event_id) is not UUID
            or type(started_at) not in (int, float)
            or not math.isfinite(started_at)
            or not callable(utc_now)
            or not callable(monotonic)
        ):
            raise LinuxAuditApiAccessAuditContractError()
        self.__sink = sink
        self.__audit_event_id = audit_event_id
        self.__started_at = float(started_at)
        self.__utc_now = utc_now
        self.__monotonic = monotonic
        self.__principal_id = None
        self.__file_count = None
        self.__upload_size_bucket = "unknown"
        self.__terminal_attempted = False

    def __repr__(self):
        return "LinuxAuditApiAccessAuditRecorder()"

    @property
    def terminal_attempted(self) -> bool:
        return self.__terminal_attempted

    def set_principal_id(self, principal_id: str) -> None:
        if (
            self.__terminal_attempted
            or type(principal_id) is not str
            or _PRINCIPAL_PATTERN.fullmatch(principal_id) is None
            or self.__principal_id is not None
        ):
            raise LinuxAuditApiAccessAuditContractError()
        self.__principal_id = principal_id

    def set_file_count(self, file_count: int) -> None:
        if (
            self.__terminal_attempted
            or type(file_count) is not int
            or file_count < 0
            or self.__file_count is not None
        ):
            raise LinuxAuditApiAccessAuditContractError()
        self.__file_count = file_count

    def set_upload_size_bytes(self, size_bytes: int) -> None:
        if (
            self.__terminal_attempted
            or self.__upload_size_bucket != "unknown"
        ):
            raise LinuxAuditApiAccessAuditContractError()
        self.__upload_size_bucket = _upload_size_bucket(size_bytes)

    async def emit(
        self,
        *,
        result_category: AuditResultCategory,
        http_status: int,
        analysis_id: UUID | None = None,
    ) -> None:
        if self.__terminal_attempted:
            raise LinuxAuditApiAccessAuditContractError()
        self.__terminal_attempted = True

        timestamp = self.__utc_now()
        ended_at = self.__monotonic()
        if type(ended_at) not in (int, float):
            raise LinuxAuditApiAccessAuditContractError()
        event = LinuxAuditApiAccessAuditEvent(
            audit_event_id=self.__audit_event_id,
            analysis_id=analysis_id,
            timestamp=timestamp,
            principal_id=self.__principal_id,
            endpoint=_AUDIT_ENDPOINT,
            method=_AUDIT_METHOD,
            result_category=result_category,
            http_status=http_status,
            file_count=self.__file_count,
            upload_size_bucket=self.__upload_size_bucket,
            duration_bucket=_duration_bucket(
                ended_at - self.__started_at
            ),
        )
        result = await self.__sink.emit(event)
        if result is not None:
            raise LinuxAuditApiAccessAuditContractError()


AuditRecorderFactory = Callable[[], LinuxAuditApiAccessAuditRecorder]


def prepare_linux_audit_api_access_audit_sink(
    sink: LinuxAuditApiAccessAuditSink,
) -> LinuxAuditApiAccessAuditSink:
    if (
        not isinstance(sink, LinuxAuditApiAccessAuditSink)
        or not inspect.iscoroutinefunction(type(sink).emit)
    ):
        raise _configuration_error()
    return sink


def create_linux_audit_access_audit_recorder_factory(
    sink: LinuxAuditApiAccessAuditSink,
) -> AuditRecorderFactory:
    prepared_sink = prepare_linux_audit_api_access_audit_sink(sink)

    def create_recorder() -> LinuxAuditApiAccessAuditRecorder:
        return LinuxAuditApiAccessAuditRecorder(
            prepared_sink,
            audit_event_id=_audit_uuid4(),
            started_at=time.monotonic(),
            utc_now=_utc_now,
            monotonic=time.monotonic,
        )

    return create_recorder


def get_linux_audit_access_audit_recorder(
    request: Request,
) -> LinuxAuditApiAccessAuditRecorder:
    recorder = getattr(
        request.state,
        _AUDIT_RECORDER_STATE_KEY,
        None,
    )
    if type(recorder) is not LinuxAuditApiAccessAuditRecorder:
        raise LinuxAuditApiAccessAuditContractError()
    return recorder


async def emit_linux_audit_cancellation_preserving(
    recorder: LinuxAuditApiAccessAuditRecorder,
    cancellation: asyncio.CancelledError,
) -> None:
    if type(recorder) is not LinuxAuditApiAccessAuditRecorder:
        cancellation.add_note(_AUDIT_EMISSION_FAILURE_NOTE)
        return
    if recorder.terminal_attempted:
        return
    try:
        await recorder.emit(
            result_category="cancelled",
            http_status=499,
        )
    except Exception:
        cancellation.add_note(_AUDIT_EMISSION_FAILURE_NOTE)


def _configuration_error() -> LinuxAuditApiSecurityConfigurationError:
    return LinuxAuditApiSecurityConfigurationError()


def _authentication_error() -> LinuxAuditApiAuthenticationError:
    return LinuxAuditApiAuthenticationError()


def _decode_canonical_token(value: object) -> bytes | None:
    if type(value) is not str or len(value) != _TOKEN_LENGTH:
        return None
    if _TOKEN_PATTERN.fullmatch(value) is None:
        return None

    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return None

    if len(decoded) != _TOKEN_BYTES:
        return None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode(
        "ascii"
    )
    if canonical != value:
        return None
    return decoded


def prepare_linux_audit_api_security(
    config: LinuxAuditApiSecurityConfig,
) -> PreparedLinuxAuditApiSecurity:
    if type(config) is not LinuxAuditApiSecurityConfig:
        raise _configuration_error()
    if type(config.operator_token) is not SecretStr:
        raise _configuration_error()

    token_bytes = _decode_canonical_token(
        config.operator_token.get_secret_value()
    )
    if token_bytes is None:
        raise _configuration_error()
    if (
        type(config.principal_id) is not str
        or _PRINCIPAL_PATTERN.fullmatch(config.principal_id) is None
    ):
        raise _configuration_error()
    if (
        type(config.max_concurrent_analyses) is not int
        or not 1 <= config.max_concurrent_analyses <= 4
    ):
        raise _configuration_error()

    return PreparedLinuxAuditApiSecurity(
        principal_id=config.principal_id,
        max_concurrent_analyses=config.max_concurrent_analyses,
        permissions=_V1_PERMISSIONS,
        _operator_token_digest=hashlib.sha256(token_bytes).digest(),
    )


def authenticate_linux_audit_token(
    prepared: PreparedLinuxAuditApiSecurity,
    presented_token: object,
) -> AuthenticatedLinuxAuditPrincipal:
    if type(prepared) is not PreparedLinuxAuditApiSecurity:
        raise _authentication_error()

    token_bytes = _decode_canonical_token(presented_token)
    if token_bytes is None:
        raise _authentication_error()

    presented_digest = hashlib.sha256(token_bytes).digest()
    if not secrets.compare_digest(
        presented_digest,
        prepared._operator_token_digest,
    ):
        raise _authentication_error()

    return AuthenticatedLinuxAuditPrincipal(
        principal_id=prepared.principal_id,
        permissions=prepared.permissions,
    )


def authorize_linux_audit_analysis(
    principal: AuthenticatedLinuxAuditPrincipal,
) -> AuthenticatedLinuxAuditPrincipal:
    if (
        type(principal) is not AuthenticatedLinuxAuditPrincipal
        or type(principal.permissions) is not frozenset
        or LINUX_AUDIT_ANALYZE_PERMISSION not in principal.permissions
    ):
        raise LinuxAuditApiAuthorizationError()
    return principal


AuthenticationDependency = Callable[
    ...,
    Awaitable[AuthenticatedLinuxAuditPrincipal],
]
AuthorizationDependency = Callable[
    ...,
    Awaitable[AuthenticatedLinuxAuditPrincipal],
]


def create_linux_audit_authentication_dependency(
    prepared: PreparedLinuxAuditApiSecurity,
    recorder_factory: AuditRecorderFactory,
) -> AuthenticationDependency:
    if (
        type(prepared) is not PreparedLinuxAuditApiSecurity
        or not callable(recorder_factory)
    ):
        raise _configuration_error()

    bearer = HTTPBearer(
        auto_error=False,
        scheme_name="LinuxAuditOperatorBearer",
        description="Operator bearer credential for Linux Audit analysis.",
    )

    async def authenticate(
        request: Request,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Security(bearer),
        ],
    ) -> AuthenticatedLinuxAuditPrincipal:
        try:
            recorder = recorder_factory()
            if type(recorder) is not LinuxAuditApiAccessAuditRecorder:
                raise LinuxAuditApiAccessAuditContractError()
            setattr(request.state, _AUDIT_RECORDER_STATE_KEY, recorder)
        except Exception:
            raise LinuxAuditApiAccessAuditFailedError() from None

        try:
            authorization_values = request.headers.getlist(
                "authorization"
            )
            if len(authorization_values) != 1:
                raise _authentication_error()

            authorization_value = authorization_values[0]
            try:
                encoded_header = authorization_value.encode("ascii")
            except UnicodeEncodeError:
                raise _authentication_error() from None

            if (
                len(encoded_header) > _MAX_AUTHORIZATION_HEADER_BYTES
                or _AUTHORIZATION_PATTERN.fullmatch(
                    authorization_value
                ) is None
                or credentials is None
                or credentials.scheme.casefold() != "bearer"
            ):
                raise _authentication_error()

            principal = authenticate_linux_audit_token(
                prepared,
                credentials.credentials,
            )
            recorder.set_principal_id(principal.principal_id)
            return principal
        except LinuxAuditApiAuthenticationError:
            try:
                await recorder.emit(
                    result_category="authentication_failed",
                    http_status=401,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise LinuxAuditApiAccessAuditFailedError() from None
            raise
        except asyncio.CancelledError as cancellation:
            await emit_linux_audit_cancellation_preserving(
                recorder,
                cancellation,
            )
            raise
        except LinuxAuditApiAccessAuditContractError:
            raise LinuxAuditApiAccessAuditFailedError() from None

    return authenticate


def create_linux_audit_authorization_dependency(
    authentication_dependency: AuthenticationDependency,
) -> AuthorizationDependency:
    if not callable(authentication_dependency):
        raise _configuration_error()

    async def authorize(
        request: Request,
        principal: Annotated[
            AuthenticatedLinuxAuditPrincipal,
            Depends(authentication_dependency),
        ],
    ) -> AuthenticatedLinuxAuditPrincipal:
        recorder = get_linux_audit_access_audit_recorder(request)
        try:
            return authorize_linux_audit_analysis(principal)
        except LinuxAuditApiAuthorizationError:
            try:
                await recorder.emit(
                    result_category="authorization_failed",
                    http_status=403,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise LinuxAuditApiAccessAuditFailedError() from None
            raise
        except asyncio.CancelledError as cancellation:
            await emit_linux_audit_cancellation_preserving(
                recorder,
                cancellation,
            )
            raise

    return authorize
