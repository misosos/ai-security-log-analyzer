import base64
import hashlib
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated

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

_CONFIGURATION_ERROR_MESSAGE = (
    "Linux Audit API security configuration is invalid."
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
) -> AuthenticationDependency:
    if type(prepared) is not PreparedLinuxAuditApiSecurity:
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
        authorization_values = request.headers.getlist("authorization")
        if len(authorization_values) != 1:
            raise _authentication_error()

        authorization_value = authorization_values[0]
        try:
            encoded_header = authorization_value.encode("ascii")
        except UnicodeEncodeError:
            raise _authentication_error() from None

        if (
            len(encoded_header) > _MAX_AUTHORIZATION_HEADER_BYTES
            or _AUTHORIZATION_PATTERN.fullmatch(authorization_value) is None
            or credentials is None
            or credentials.scheme.casefold() != "bearer"
        ):
            raise _authentication_error()

        return authenticate_linux_audit_token(
            prepared,
            credentials.credentials,
        )

    return authenticate


def create_linux_audit_authorization_dependency(
    authentication_dependency: AuthenticationDependency,
) -> AuthorizationDependency:
    if not callable(authentication_dependency):
        raise _configuration_error()

    async def authorize(
        principal: Annotated[
            AuthenticatedLinuxAuditPrincipal,
            Depends(authentication_dependency),
        ],
    ) -> AuthenticatedLinuxAuditPrincipal:
        return authorize_linux_audit_analysis(principal)

    return authorize
