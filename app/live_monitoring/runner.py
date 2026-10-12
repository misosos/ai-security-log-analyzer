"""One event-loop-owned polling task; no thread, retry, or implicit resume."""

import asyncio
from dataclasses import dataclass
from enum import Enum

from app.live_monitoring.service import LiveMonitoringService
from app.live_monitoring.worker import LiveWorkerError, LiveWorkerState


POLL_INTERVAL_SECONDS = 0.5  # Development cadence, not a detection or latency SLA.
SHUTDOWN_TIMEOUT_SECONDS = 5.0


class LiveRunnerState(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class LiveRunnerError(ValueError):
    _CODES = frozenset(("INVALID_RUNNER", "RUNNER_ALREADY_STARTED", "RUNNER_FAILED",
                        "SHUTDOWN_TIMEOUT"))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "RUNNER_FAILED"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"LiveRunnerError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LiveRunnerSnapshot:
    schema_version: str
    state: LiveRunnerState
    step_revision: int
    poll_interval_seconds: float
    fixed_error_code: str | None


class LiveMonitoringRunner:
    """The sole caller of worker.step(); all service access uses the same loop."""

    __slots__ = ("_service", "_interval", "_stop", "_state", "_error_code", "_task")

    def __init__(self, service: LiveMonitoringService, *,
                 poll_interval_seconds: float = POLL_INTERVAL_SECONDS):
        if (type(service) is not LiveMonitoringService or service._runner_bound
            or service.status().service_state != "READY"
            or type(poll_interval_seconds) not in (int, float)
            or not 0 < poll_interval_seconds <= POLL_INTERVAL_SECONDS):
            raise LiveRunnerError("INVALID_RUNNER")
        service._runner_bound = True
        self._service = service
        self._interval = float(poll_interval_seconds)
        self._stop = asyncio.Event()
        self._state = LiveRunnerState.CREATED
        self._error_code: str | None = None
        self._task: asyncio.Task | None = None

    def __repr__(self) -> str:
        return f"LiveMonitoringRunner(state={self._state.value!r})"

    @property
    def state(self) -> LiveRunnerState:
        return self._state

    @property
    def error_code(self) -> str | None:
        return self._error_code

    def snapshot(self) -> LiveRunnerSnapshot:
        return LiveRunnerSnapshot("1", self._state, self._service._worker.snapshot().step_revision,
                                  self._interval, self._error_code)

    async def _wait_next(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
        except TimeoutError:
            pass

    async def _terminal(self, state: LiveRunnerState, code: str) -> None:
        self._state = state
        self._error_code = code
        try:
            await self._service.set_runner_state(state.value, code)
        except Exception:
            # Keep the fixed terminal state even if notification itself fails.
            self._service._runner_state = state.value
            self._service._runner_code = code

    async def run(self) -> None:
        if self._state is not LiveRunnerState.CREATED:
            raise LiveRunnerError("RUNNER_ALREADY_STARTED")
        self._task = asyncio.current_task()
        self._state = LiveRunnerState.RUNNING
        await self._service.set_runner_state("RUNNING")
        try:
            while not self._stop.is_set():
                try:
                    before = self._service.publication_buffer.snapshot().published_total
                    result = self._service._worker.step()
                    after = self._service.publication_buffer.snapshot().published_total
                except LiveWorkerError:
                    try:
                        worker_state = self._service._worker.snapshot().state
                    except Exception:
                        worker_state = LiveWorkerState.FAILED
                    if worker_state is LiveWorkerState.DEGRADED:
                        await self._terminal(LiveRunnerState.DEGRADED, "LIVE_RUNNER_DEGRADED")
                    else:
                        await self._terminal(LiveRunnerState.FAILED, "LIVE_RUNNER_FAILED")
                    return
                except Exception:
                    await self._terminal(LiveRunnerState.FAILED, "LIVE_RUNNER_FAILED")
                    return
                if result.status not in ("NO_DATA", "PROCESSED"):
                    await self._terminal(LiveRunnerState.FAILED, "LIVE_RUNNER_FAILED")
                    return
                if after > before:
                    try:
                        await self._service.notify_change()
                    except Exception:
                        await self._terminal(LiveRunnerState.FAILED, "LIVE_RUNNER_FAILED")
                        return
                await self._wait_next()
        except asyncio.CancelledError:
            raise
        finally:
            if self._state is LiveRunnerState.RUNNING:
                self._state = LiveRunnerState.STOPPED

    def request_stop(self) -> None:
        if self._state in (LiveRunnerState.CREATED, LiveRunnerState.RUNNING):
            self._state = LiveRunnerState.STOPPING
            self._service._runner_state = "STOPPING"
        self._stop.set()

    async def shutdown(self, timeout_seconds: float = SHUTDOWN_TIMEOUT_SECONDS) -> None:
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= SHUTDOWN_TIMEOUT_SECONDS:
            raise LiveRunnerError("INVALID_RUNNER")
        self.request_stop()
        timed_out = False
        if self._task is not None and self._task is not asyncio.current_task() and not self._task.done():
            done, _ = await asyncio.wait((self._task,), timeout=timeout_seconds)
            if not done:
                timed_out = True
                self._task.cancel()
                await asyncio.wait((self._task,), timeout=0.1)
        try:
            await self._service.close()
        except Exception:
            self._state = LiveRunnerState.FAILED
            self._error_code = "LIVE_RUNNER_FAILED"
            raise LiveRunnerError("RUNNER_FAILED") from None
        self._state = LiveRunnerState.STOPPED
        if timed_out:
            self._error_code = "LIVE_SHUTDOWN_TIMEOUT"
            raise LiveRunnerError("SHUTDOWN_TIMEOUT") from None
