import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from app.security.linux_audit_api import (
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
    prepare_linux_audit_api_security,
)


LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES = 128

_BOOTSTRAP_ERRORS = {
    "INVALID_LINUX_AUDIT_SECURITY_BOOTSTRAP_CONFIG": (
        "Linux Audit API security bootstrap configuration is invalid."
    ),
    "LINUX_AUDIT_SECURITY_SECRET_UNAVAILABLE": (
        "Linux Audit API security credential is unavailable."
    ),
    "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE": (
        "Linux Audit API security credential file is unsafe."
    ),
    "INVALID_LINUX_AUDIT_SECURITY_SECRET_ENCODING": (
        "Linux Audit API security credential encoding is invalid."
    ),
    "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT": (
        "Linux Audit API security credential format is invalid."
    ),
    "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED": (
        "Linux Audit API security credential could not be read."
    ),
}
_ACCEPTED_PERMISSION_MODES = frozenset((0o400, 0o600))
_PATH_RUNTIME_TYPE = type(Path())


@dataclass(frozen=True, repr=False)
class LinuxAuditApiSecurityBootstrapConfig:
    secret_file: Path
    principal_id: str
    max_concurrent_analyses: int

    def __repr__(self):
        return "LinuxAuditApiSecurityBootstrapConfig()"


class LinuxAuditApiSecurityBootstrapError(ValueError):

    def __init__(self, code: str):
        message = _BOOTSTRAP_ERRORS.get(code)
        if message is None:
            code = "INVALID_LINUX_AUDIT_SECURITY_BOOTSTRAP_CONFIG"
            message = _BOOTSTRAP_ERRORS[code]
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self):
        return (
            "LinuxAuditApiSecurityBootstrapError("
            f"code={self.code!r})"
        )


def _bootstrap_error(code: str) -> LinuxAuditApiSecurityBootstrapError:
    return LinuxAuditApiSecurityBootstrapError(code)


def _is_private_regular_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) in _ACCEPTED_PERMISSION_MODES
    )


def _same_file_identity(
    before_open: os.stat_result,
    after_open: os.stat_result,
) -> bool:
    return (
        before_open.st_dev == after_open.st_dev
        and before_open.st_ino == after_open.st_ino
    )


def _secret_open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _read_bounded_secret(descriptor: int) -> bytearray:
    content = bytearray()
    read_limit = LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES + 1
    while len(content) < read_limit:
        chunk = os.read(descriptor, read_limit - len(content))
        if not chunk:
            break
        content.extend(chunk)
    return content


def _read_open_secret(
    descriptor: int,
    before_open: os.stat_result,
) -> bytearray:
    try:
        after_open = os.fstat(descriptor)
    except OSError:
        raise _bootstrap_error(
            "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED"
        ) from None

    if (
        not _same_file_identity(before_open, after_open)
        or not _is_private_regular_file(after_open)
    ):
        raise _bootstrap_error(
            "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE"
        )
    if after_open.st_size > LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES:
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
        )

    try:
        return _read_bounded_secret(descriptor)
    except OSError:
        raise _bootstrap_error(
            "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED"
        ) from None


def _decode_secret(content: bytearray) -> str:
    if (
        not content
        or len(content) > LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES
        or b"\x00" in content
        or b"\r" in content
    ):
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
        )

    try:
        value = content.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_ENCODING"
        ) from None

    if value.endswith("\n"):
        if value.count("\n") != 1:
            raise _bootstrap_error(
                "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
            )
        value = value[:-1]
    elif "\n" in value:
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
        )

    if not value or value != value.strip(" \t"):
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
        )
    return value


def load_linux_audit_api_security_config(
    bootstrap_config: LinuxAuditApiSecurityBootstrapConfig,
) -> LinuxAuditApiSecurityConfig:
    if type(bootstrap_config) is not LinuxAuditApiSecurityBootstrapConfig:
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_BOOTSTRAP_CONFIG"
        )
    secret_file = bootstrap_config.secret_file
    if (
        type(secret_file) is not _PATH_RUNTIME_TYPE
        or not secret_file.is_absolute()
    ):
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_BOOTSTRAP_CONFIG"
        )

    try:
        before_open = os.lstat(secret_file)
    except OSError:
        raise _bootstrap_error(
            "LINUX_AUDIT_SECURITY_SECRET_UNAVAILABLE"
        ) from None
    if not _is_private_regular_file(before_open):
        raise _bootstrap_error(
            "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE"
        )

    try:
        descriptor = os.open(secret_file, _secret_open_flags())
    except OSError:
        raise _bootstrap_error(
            "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED"
        ) from None

    content = None
    try:
        content = _read_open_secret(descriptor, before_open)
    finally:
        had_error = sys.exc_info()[0] is not None
        close_failed = False
        try:
            os.close(descriptor)
        except OSError:
            close_failed = True
        if close_failed and not had_error:
            if content is not None:
                content.clear()
            raise _bootstrap_error(
                "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED"
            ) from None

    try:
        token = _decode_secret(content)
    finally:
        content.clear()

    security_config = LinuxAuditApiSecurityConfig(
        operator_token=SecretStr(token),
        principal_id=bootstrap_config.principal_id,
        max_concurrent_analyses=(
            bootstrap_config.max_concurrent_analyses
        ),
    )
    token = None
    try:
        prepare_linux_audit_api_security(security_config)
    except LinuxAuditApiSecurityConfigurationError:
        raise _bootstrap_error(
            "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT"
        ) from None
    return security_config
