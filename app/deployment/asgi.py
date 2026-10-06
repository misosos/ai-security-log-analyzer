import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI

if TYPE_CHECKING:
    from app.deployment.linux_audit_api import LinuxAuditApiProductionConfig


CREDENTIALS_DIRECTORY_ENVIRONMENT_VARIABLE = "CREDENTIALS_DIRECTORY"
PRINCIPAL_ID_ENVIRONMENT_VARIABLE = "LINUX_AUDIT_API_PRINCIPAL_ID"
MAX_CONCURRENT_ANALYSES_ENVIRONMENT_VARIABLE = (
    "LINUX_AUDIT_API_MAX_CONCURRENT_ANALYSES"
)
LINUX_AUDIT_API_CREDENTIAL_FILENAME = "linux-audit-api-operator-token"

_REQUIRED_ENVIRONMENT_VARIABLES = (
    CREDENTIALS_DIRECTORY_ENVIRONMENT_VARIABLE,
    PRINCIPAL_ID_ENVIRONMENT_VARIABLE,
    MAX_CONCURRENT_ANALYSES_ENVIRONMENT_VARIABLE,
)
_CANONICAL_CONCURRENCY_VALUES = frozenset(("1", "2", "3", "4"))
_ERRORS = {
    "MISSING_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION": (
        "Linux Audit API deployment configuration is missing."
    ),
    "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION": (
        "Linux Audit API deployment configuration is invalid."
    ),
    "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED": (
        "Linux Audit API deployment application construction failed."
    ),
}


class LinuxAuditApiDeploymentError(RuntimeError):

    def __init__(self, code: str):
        message = _ERRORS.get(code)
        if message is None:
            code = "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED"
            message = _ERRORS[code]
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self):
        return f"LinuxAuditApiDeploymentError(code={self.code!r})"


def _deployment_error(code: str) -> LinuxAuditApiDeploymentError:
    return LinuxAuditApiDeploymentError(code)


def _read_required_environment_values(
    environment: Mapping[str, str],
) -> tuple[str, str, str]:
    if not isinstance(environment, Mapping):
        raise _deployment_error(
            "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )

    values = tuple(
        environment.get(name) for name in _REQUIRED_ENVIRONMENT_VARIABLES
    )
    if any(value is None for value in values):
        raise _deployment_error(
            "MISSING_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )
    if any(type(value) is not str or not value for value in values):
        raise _deployment_error(
            "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )
    return values


def _credential_path(credentials_directory: str) -> Path:
    if (
        credentials_directory != credentials_directory.strip()
        or "\x00" in credentials_directory
        or "\n" in credentials_directory
        or "\r" in credentials_directory
    ):
        raise _deployment_error(
            "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )
    directory = Path(credentials_directory)
    if not directory.is_absolute():
        raise _deployment_error(
            "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )
    return directory / LINUX_AUDIT_API_CREDENTIAL_FILENAME


def _parse_linux_audit_api_deployment_environment(
    environment: Mapping[str, str],
) -> "LinuxAuditApiProductionConfig":
    (
        credentials_directory,
        principal_id,
        concurrency_value,
    ) = _read_required_environment_values(environment)
    if concurrency_value not in _CANONICAL_CONCURRENCY_VALUES:
        raise _deployment_error(
            "INVALID_LINUX_AUDIT_API_DEPLOYMENT_CONFIGURATION"
        )

    secret_file = _credential_path(credentials_directory)
    from app.deployment.linux_audit_api import LinuxAuditApiProductionConfig

    return LinuxAuditApiProductionConfig(
        secret_file=secret_file,
        principal_id=principal_id,
        max_concurrent_analyses=int(concurrency_value),
    )


def _construct_linux_audit_api_production_app(
    config: "LinuxAuditApiProductionConfig",
) -> FastAPI:
    from app.deployment.linux_audit_api import (
        LinuxAuditApiProductionBootstrapError,
        create_linux_audit_api_production_app,
    )

    try:
        return create_linux_audit_api_production_app(config)
    except LinuxAuditApiProductionBootstrapError:
        raise _deployment_error(
            "LINUX_AUDIT_API_DEPLOYMENT_CONSTRUCTION_FAILED"
        ) from None


def create_linux_audit_api_app() -> FastAPI:
    config = _parse_linux_audit_api_deployment_environment(os.environ)
    return _construct_linux_audit_api_production_app(config)
