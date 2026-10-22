"""Internal, single-caller application/SSH runtime. No API or CLI binding."""

import asyncio
import os
from pathlib import Path
from time import monotonic
from types import MappingProxyType

from app.analyzer.risk import load_account_metadata
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.checkpoint import LiveCheckpointManager
from app.live_monitoring.config import LiveMonitorConfig, load_live_monitor_pair_config
from app.live_monitoring.core import open_live_tail_session
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.worker import LiveProcessingWorker, LiveWorkerState


ROLES = ("application", "ssh")
POLL_INTERVAL_SECONDS = 0.5  # Development cadence, not a latency SLA.
SOFT_CYCLE_BUDGET_SECONDS = 0.1  # Admission only; a worker step cannot be interrupted.


class MultiSourceRuntimeError(ValueError):
    _CODES = frozenset(("PAIR_START_FAILED", "PAIR_SOURCE_DUPLICATE", "PAIR_STOPPED",
                        "PAIR_DEGRADED", "PAIR_FAILED", "PAIR_BUSY", "PAIR_CLOSE_FAILED"))

    def __init__(self, code: str):
        self.code = code if code in self._CODES else "PAIR_FAILED"
        message = ("두 로그의 내부 실행을 시작할 수 없습니다." if self.code == "PAIR_START_FAILED"
                   else "두 로그의 내부 작업을 완료할 수 없습니다.")
        super().__init__(f"{self.code}: {message}")

    def __repr__(self) -> str:
        return f"MultiSourceRuntimeError(code={self.code!r})"


def _close_manager(manager: LiveCheckpointManager) -> bool:
    """Release both owned descriptors even if the normal close stops early."""
    try:
        manager.close()
        return False
    except Exception:
        for name in ("_lock_fd", "_parent_fd"):
            descriptor = getattr(manager, name, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                    setattr(manager, name, -1)
                except Exception:
                    pass
        manager._closed = manager._lock_fd < 0 and manager._parent_fd < 0
        return True


def _close_session(session) -> bool:
    try:
        session.close()
        return False
    except Exception:
        try:
            session._close_descriptor()
        except Exception:
            pass
        try:
            session._queue.clear()
        except Exception:
            pass
        session._active_lease = None
        session._attempts.clear()
        session._partial = b""
        session._pending_chunk = b""
        return True


def _close_worker(worker: LiveProcessingWorker) -> bool:
    try:
        worker.close()
        return False
    except Exception:
        # Worker.close() may have stopped at any one of these resources.
        failed = True
        for resource in (worker._analysis, worker._checkpoint, worker._session,
                         worker._publication, worker._accumulator):
            if resource is None:
                continue
            if resource is worker._checkpoint:
                failed |= _close_manager(resource)
            elif resource is worker._session:
                failed |= _close_session(resource)
            else:
                try:
                    resource.close()
                except Exception:
                    failed = True
        return failed


class InternalPairRuntime:
    """Two independent worker chains; only cycle() may advance either one."""

    __slots__ = ("workers", "_first", "_state", "_in_cycle", "_stop", "_run_owner",
                 "_run_started")

    def __init__(self, workers: dict[str, LiveProcessingWorker]):
        if tuple(workers) != ROLES or any(type(worker) is not LiveProcessingWorker
                                          for worker in workers.values()):
            raise MultiSourceRuntimeError("PAIR_START_FAILED")
        self.workers = MappingProxyType(dict(workers))
        self._first = 0
        self._state = "READY"
        self._in_cycle = False
        self._stop = asyncio.Event()
        self._run_owner = None
        self._run_started = False

    @property
    def state(self) -> str:
        return self._state

    def __repr__(self) -> str:
        return f"InternalPairRuntime(state={self._state!r})"

    def cycle(self) -> tuple[tuple[str, str], ...]:
        if self._state != "READY" or self._stop.is_set():
            raise MultiSourceRuntimeError("PAIR_STOPPED" if self._state == "STOPPED"
                                          or self._stop.is_set()
                                          else "PAIR_DEGRADED" if self._state == "DEGRADED"
                                          else "PAIR_FAILED")
        if self._run_owner is not None:
            try:
                caller = asyncio.current_task()
            except RuntimeError:
                caller = None
            if caller is not self._run_owner:
                raise MultiSourceRuntimeError("PAIR_BUSY")
        if self._in_cycle:
            raise MultiSourceRuntimeError("PAIR_BUSY")
        self._in_cycle = True
        try:
            for worker in self.workers.values():
                if worker.snapshot().state is not LiveWorkerState.READY:
                    self._state = "FAILED"
                    raise MultiSourceRuntimeError("PAIR_FAILED")
            order = ROLES[self._first:] + ROLES[:self._first]
            self._first = 1 - self._first
            results = []
            started = monotonic()
            for role in order:
                if results and monotonic() - started >= SOFT_CYCLE_BUDGET_SECONDS:
                    break
                worker = self.workers[role]
                try:
                    result = worker.step()
                except Exception:
                    try:
                        state = worker.snapshot().state
                    except Exception:
                        state = LiveWorkerState.FAILED
                    self._state = "DEGRADED" if state is LiveWorkerState.DEGRADED else "FAILED"
                    raise MultiSourceRuntimeError("PAIR_DEGRADED" if self._state == "DEGRADED"
                                                  else "PAIR_FAILED") from None
                if result.status not in ("NO_DATA", "PROCESSED"):
                    self._state = "FAILED"
                    raise MultiSourceRuntimeError("PAIR_FAILED")
                results.append((role, result.status))
            return tuple(results)
        finally:
            self._in_cycle = False

    async def run(self) -> None:
        """Poll without a busy loop; caller owns the one event loop and shutdown."""
        if self._run_started or self._state != "READY":
            raise MultiSourceRuntimeError("PAIR_BUSY")
        self._run_started = True
        self._run_owner = asyncio.current_task()
        try:
            while self._state == "READY" and not self._stop.is_set():
                self.cycle()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=POLL_INTERVAL_SECONDS)
                except TimeoutError:
                    pass
        finally:
            self._run_owner = None

    def request_stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        if self._state == "STOPPED":
            return
        self.request_stop()
        failed = False
        for role in reversed(ROLES):
            failed |= _close_worker(self.workers[role])
        self._state = "FAILED" if failed else "STOPPED"
        if failed:
            raise MultiSourceRuntimeError("PAIR_CLOSE_FAILED")


def open_internal_pair_runtime(config_path: Path) -> InternalPairRuntime:
    """Load v3 privately, acquire role locks in order, then open both tails."""
    config = load_live_monitor_pair_config(config_path)
    managers = []
    workers = {}
    sessions = []
    fresh_checkpoints = set()
    try:
        for source in config.sources:
            manager = LiveCheckpointManager(config_path, source)
            managers.append(manager)
            if manager.committed_offset is None:
                fresh_checkpoints.add(manager)
        metadata = load_account_metadata()
        account_context = tuple((account, value["privilege"]) for account, value in metadata.items())
        for source, checkpoint in zip(config.sources, managers, strict=True):
            session = open_live_tail_session(LiveMonitorConfig(source.source_role, source.source_path),
                                             start_offset=checkpoint.committed_offset)
            sessions.append(session)
        if sessions[0]._identity == sessions[1]._identity:
            raise MultiSourceRuntimeError("PAIR_SOURCE_DUPLICATE")
        for source, checkpoint, session in zip(config.sources, managers, sessions, strict=True):
            detection = LiveDetectionAccumulator(source.source_role, 256, 256 * 1024)
            analysis = LiveAnalysisAccumulator(detection, account_context)
            worker = LiveProcessingWorker(session, detection, 16, 4096,
                                          analysis_accumulator=analysis)
            workers[source.source_role] = worker
            checkpoint.initialize_or_restore(worker)
            worker._checkpoint = checkpoint
        # Catch a config replacement during the two-source construction.
        if load_live_monitor_pair_config(config_path) != config:
            raise MultiSourceRuntimeError("PAIR_START_FAILED")
        return InternalPairRuntime(workers)
    except Exception as error:
        cleanup_failed = False
        for manager in reversed(managers):
            if (manager in fresh_checkpoints and manager._checkpoint is not None
                and manager._checkpoint.write_sequence == 0):
                try:
                    manager.reset_after_approval(manager._reset_identity())
                except Exception:
                    # Leave an orphan for manual review rather than guessing.
                    cleanup_failed = True
        for worker in reversed(tuple(workers.values())):
            cleanup_failed |= _close_worker(worker)
        for session in reversed(sessions):
            cleanup_failed |= _close_session(session)
        for manager in reversed(managers):
            cleanup_failed |= _close_manager(manager)
        code = (error.code if isinstance(error, MultiSourceRuntimeError) and not cleanup_failed
                else "PAIR_START_FAILED")
        raise MultiSourceRuntimeError(code) from None
