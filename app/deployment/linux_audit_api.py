import asyncio
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api import create_app
from app.bootstrap.linux_audit_api import (
    LinuxAuditApiSecurityBootstrapConfig,
    LinuxAuditApiSecurityBootstrapError,
    load_linux_audit_api_security_config,
)
from app.security.linux_audit_api import (
    LinuxAuditApiSecurityConfigurationError,
)
from app.security.linux_audit_api_journald import (
    LinuxAuditApiJournaldSink,
    LinuxAuditApiJournaldSinkError,
    create_linux_audit_api_journald_sink,
)


LinuxAuditApiReadinessPhase = Literal[
    "starting",
    "ready",
    "stopping",
    "stopped",
    "failed",
]

_READINESS_STATE_ATTRIBUTE = "_linux_audit_api_readiness_controller"
_INTERNAL_READINESS_PATH = "/internal/readiness"
_ERRORS = {
    "INVALID_LINUX_AUDIT_API_PRODUCTION_CONFIG": (
        "Linux Audit API production configuration is invalid."
    ),
    "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED": (
        "Linux Audit API production initialization failed."
    ),
    "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR": (
        "Linux Audit API production lifecycle is invalid."
    ),
    "LINUX_AUDIT_API_PRODUCTION_SHUTDOWN_FAILED": (
        "Linux Audit API production shutdown failed."
    ),
}


@dataclass(frozen=True, repr=False)
class LinuxAuditApiProductionConfig:
    secret_file: Path
    principal_id: str
    max_concurrent_analyses: int

    def __repr__(self):
        return "LinuxAuditApiProductionConfig()"


@dataclass(frozen=True)
class LinuxAuditApiReadiness:
    phase: LinuxAuditApiReadinessPhase
    ready: bool

    def __post_init__(self):
        if (
            type(self.phase) is not str
            or self.phase
            not in {"starting", "ready", "stopping", "stopped", "failed"}
            or type(self.ready) is not bool
            or self.ready != (self.phase == "ready")
        ):
            raise LinuxAuditApiProductionBootstrapError(
                "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR"
            )


class LinuxAuditApiProductionBootstrapError(RuntimeError):

    def __init__(self, code: str):
        message = _ERRORS.get(code)
        if message is None:
            code = "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
            message = _ERRORS[code]
        super().__init__(message)
        self.code = code
        self.message = message

    def __repr__(self):
        return (
            "LinuxAuditApiProductionBootstrapError("
            f"code={self.code!r})"
        )


class _LinuxAuditApiReadinessController:
    __slots__ = ("__lock", "__phase")

    def __init__(self):
        self.__lock = threading.Lock()
        self.__phase: LinuxAuditApiReadinessPhase = "starting"

    def snapshot(self) -> LinuxAuditApiReadiness:
        with self.__lock:
            phase = self.__phase
        return LinuxAuditApiReadiness(
            phase=phase,
            ready=phase == "ready",
        )

    def mark_ready(self) -> None:
        self._transition("starting", "ready")

    def mark_stopping(self) -> None:
        self._transition("ready", "stopping")

    def mark_stopped(self) -> None:
        self._transition("stopping", "stopped")

    def mark_failed(self) -> None:
        with self.__lock:
            self.__phase = "failed"

    def _transition(
        self,
        expected: LinuxAuditApiReadinessPhase,
        target: LinuxAuditApiReadinessPhase,
    ) -> None:
        with self.__lock:
            if self.__phase != expected:
                self.__phase = "failed"
                raise LinuxAuditApiProductionBootstrapError(
                    "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR"
                )
            self.__phase = target


def _cleanup_partially_constructed_sink(
    sink: LinuxAuditApiJournaldSink,
) -> None:
    try:
        sink._close_before_lifespan()
    except LinuxAuditApiJournaldSinkError:
        pass


def _install_production_lifespan(
    application: FastAPI,
    sink: LinuxAuditApiJournaldSink,
) -> None:
    if (
        type(application) is not FastAPI
        or type(sink) is not LinuxAuditApiJournaldSink
    ):
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        )
    controller = _LinuxAuditApiReadinessController()
    setattr(application.state, _READINESS_STATE_ATTRIBUTE, controller)

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        controller.mark_ready()
        try:
            yield
        except asyncio.CancelledError:
            controller.mark_failed()
            raise
        finally:
            current = controller.snapshot().phase
            if current == "ready":
                controller.mark_stopping()
            elif current != "stopping":
                controller.mark_failed()
                if current != "failed":
                    raise LinuxAuditApiProductionBootstrapError(
                        "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR"
                    )
            try:
                await sink.close()
            except asyncio.CancelledError:
                controller.mark_failed()
                raise
            except LinuxAuditApiJournaldSinkError:
                controller.mark_failed()
                raise LinuxAuditApiProductionBootstrapError(
                    "LINUX_AUDIT_API_PRODUCTION_SHUTDOWN_FAILED"
                ) from None
            if controller.snapshot().phase == "stopping":
                controller.mark_stopped()

    application.router.lifespan_context = lifespan


def _install_internal_readiness_route(application: FastAPI) -> None:
    if type(application) is not FastAPI:
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        )
    if any(
        getattr(route, "path", None) == _INTERNAL_READINESS_PATH
        for route in application.routes
    ):
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        )

    async def readiness_probe() -> JSONResponse:
        try:
            readiness = get_linux_audit_api_readiness(application)
        except LinuxAuditApiProductionBootstrapError:
            readiness = LinuxAuditApiReadiness(
                phase="failed",
                ready=False,
            )
        if readiness.ready:
            status_code = 200
            status = "ready"
        else:
            status_code = 503
            status = "not_ready"
        return JSONResponse(
            status_code=status_code,
            content={"status": status},
            headers={"Cache-Control": "no-store"},
        )

    application.add_api_route(
        _INTERNAL_READINESS_PATH,
        readiness_probe,
        methods=["GET"],
        include_in_schema=False,
        name="linux_audit_api_internal_readiness",
    )


def create_linux_audit_api_production_app(
    config: LinuxAuditApiProductionConfig,
) -> FastAPI:
    if type(config) is not LinuxAuditApiProductionConfig:
        raise LinuxAuditApiProductionBootstrapError(
            "INVALID_LINUX_AUDIT_API_PRODUCTION_CONFIG"
        )

    bootstrap_config = LinuxAuditApiSecurityBootstrapConfig(
        secret_file=config.secret_file,
        principal_id=config.principal_id,
        max_concurrent_analyses=config.max_concurrent_analyses,
    )
    try:
        security_config = load_linux_audit_api_security_config(
            bootstrap_config
        )
    except LinuxAuditApiSecurityBootstrapError:
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        ) from None

    try:
        sink = create_linux_audit_api_journald_sink()
    except LinuxAuditApiJournaldSinkError:
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        ) from None

    try:
        application = create_app(
            enable_linux_audit_api=True,
            linux_audit_api_security=security_config,
            linux_audit_api_audit_sink=sink,
        )
        _install_production_lifespan(application, sink)
        _install_internal_readiness_route(application)
    except asyncio.CancelledError:
        _cleanup_partially_constructed_sink(sink)
        raise
    except LinuxAuditApiSecurityConfigurationError:
        _cleanup_partially_constructed_sink(sink)
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        ) from None
    except LinuxAuditApiProductionBootstrapError:
        _cleanup_partially_constructed_sink(sink)
        raise
    except Exception:
        _cleanup_partially_constructed_sink(sink)
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_INITIALIZATION_FAILED"
        ) from None
    return application


def get_linux_audit_api_readiness(
    application: FastAPI,
) -> LinuxAuditApiReadiness:
    if type(application) is not FastAPI:
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR"
        )
    controller = getattr(
        application.state,
        _READINESS_STATE_ATTRIBUTE,
        None,
    )
    if type(controller) is not _LinuxAuditApiReadinessController:
        raise LinuxAuditApiProductionBootstrapError(
            "LINUX_AUDIT_API_PRODUCTION_LIFECYCLE_ERROR"
        )
    return controller.snapshot()
