"""Single-caller, explicit-step orchestration of trusted live records."""

from dataclasses import dataclass
from enum import Enum

from app.live_monitoring.core import (
    MAX_COUNTER, MAX_QUEUE_BYTES, MAX_QUEUE_ITEMS, LiveTailSession,
    LiveTailSnapshot,
)
from app.live_monitoring.parser_adapter import (
    LiveParseBatch, LiveParseOutcome, parse_live_records,
)


class LiveWorkerState(str, Enum):
    READY = "READY"
    RUNNING_STEP = "RUNNING_STEP"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


_TRANSITIONS = {
    LiveWorkerState.READY: frozenset((LiveWorkerState.RUNNING_STEP, LiveWorkerState.STOPPING)),
    LiveWorkerState.RUNNING_STEP: frozenset((LiveWorkerState.READY, LiveWorkerState.DEGRADED, LiveWorkerState.FAILED)),
    LiveWorkerState.DEGRADED: frozenset((LiveWorkerState.READY, LiveWorkerState.STOPPING, LiveWorkerState.FAILED)),
    LiveWorkerState.FAILED: frozenset((LiveWorkerState.STOPPING,)),
    LiveWorkerState.STOPPING: frozenset((LiveWorkerState.STOPPED, LiveWorkerState.FAILED)),
    LiveWorkerState.STOPPED: frozenset(),
}

_MESSAGES = {
    "INVALID_SESSION": "live session 형식을 확인하십시오.",
    "INVALID_LIMIT": "worker 처리 상한을 확인하십시오.",
    "SESSION_ALREADY_OWNED": "session은 이미 worker에 연결됐습니다.",
    "INVALID_STATE": "현재 worker 상태에서 요청을 처리할 수 없습니다.",
    "OPERATION_AFTER_CLOSE": "닫힌 worker는 처리할 수 없습니다.",
    "POLL_FAILURE": "로그 읽기가 중단됐습니다. session을 종료하고 다시 시작하십시오.",
    "LEASE_FAILURE": "기록 소유권을 확인할 수 없습니다. session을 종료하십시오.",
    "PROCESSING_FAILURE": "처리가 중단됐습니다. 명시적으로 복구하거나 종료하십시오.",
    "OWNERSHIP_FAILURE": "기록 소유권을 확인할 수 없습니다. session을 종료하십시오.",
    "INVARIANT_FAILURE": "worker 결과의 일관성을 확인할 수 없습니다.",
    "COUNTER_LIMIT": "worker 집계 상한에 도달했습니다.",
    "CLOSE_FAILURE": "worker 종료를 확인할 수 없습니다.",
}


class LiveWorkerError(ValueError):
    """Fixed public diagnostic; never include source data or internal exceptions."""

    def __init__(self, code: str):
        if type(code) is not str or code not in _MESSAGES:
            code = "INVARIANT_FAILURE"
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LiveWorkerError(code={self.code!r})"


def _add(left: int, right: int) -> int:
    if type(left) is not int or type(right) is not int or not 0 <= left <= MAX_COUNTER or not 0 <= right <= MAX_COUNTER - left:
        raise LiveWorkerError("COUNTER_LIMIT")
    return left + right


@dataclass(frozen=True, slots=True)
class LiveWorkerStepResult:
    schema_version: str
    step_revision: int
    status: str
    polled_record_count: int
    leased_record_count: int
    parsed_count: int
    ignored_count: int
    rejected_count: int
    acknowledged_count: int
    released_count: int
    queue_remaining_count: int
    fixed_warning_codes: tuple[str, ...]
    fixed_error_code: str | None

    def __post_init__(self) -> None:
        counts = (self.step_revision, self.polled_record_count, self.leased_record_count,
                  self.parsed_count, self.ignored_count, self.rejected_count,
                  self.acknowledged_count, self.released_count, self.queue_remaining_count)
        if (self.schema_version != "1" or self.status not in ("NO_DATA", "PROCESSED")
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.step_revision < 1 or self.queue_remaining_count > MAX_QUEUE_ITEMS
            or self.parsed_count + self.ignored_count + self.rejected_count != self.leased_record_count
            or self.acknowledged_count != self.leased_record_count
            or (self.status == "NO_DATA" and (self.polled_record_count or self.leased_record_count))
            or (self.status == "PROCESSED" and not self.leased_record_count)
            or type(self.fixed_warning_codes) is not tuple or self.fixed_warning_codes
            or self.fixed_error_code is not None):
            raise LiveWorkerError("INVARIANT_FAILURE")


@dataclass(frozen=True, slots=True)
class LiveWorkerSnapshot:
    schema_version: str
    state: LiveWorkerState
    step_revision: int
    successful_step_count: int
    no_data_step_count: int
    degraded_step_count: int
    failed_step_count: int
    total_parsed: int
    total_ignored: int
    total_rejected: int
    total_acknowledged: int
    total_released: int
    session: LiveTailSnapshot
    fixed_warning_codes: tuple[str, ...]
    fixed_error_code: str | None

    def __post_init__(self) -> None:
        counts = (self.step_revision, self.successful_step_count, self.no_data_step_count,
                  self.degraded_step_count, self.failed_step_count, self.total_parsed,
                  self.total_ignored, self.total_rejected, self.total_acknowledged,
                  self.total_released)
        if (self.schema_version != "1" or type(self.state) is not LiveWorkerState
            or type(self.session) is not LiveTailSnapshot
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.total_parsed + self.total_ignored + self.total_rejected != self.total_acknowledged
            or type(self.fixed_warning_codes) is not tuple
            or any(code not in _MESSAGES for code in self.fixed_warning_codes)
            or (self.fixed_error_code is not None and self.fixed_error_code not in _MESSAGES)):
            raise LiveWorkerError("INVARIANT_FAILURE")


def _validate_batch(batch: LiveParseBatch, role: str, records: tuple) -> None:
    if (type(batch) is not LiveParseBatch or batch.source_role != role
        or type(batch.outcomes) is not tuple or len(batch.outcomes) != len(records)
        or any(type(outcome) is not LiveParseOutcome for outcome in batch.outcomes)
        or tuple(outcome.sequence for outcome in batch.outcomes) != tuple(record.sequence for record in records)
        or any(type(value) is not int or value < 0 for value in (
            batch.parsed_count, batch.ignored_count, batch.rejected_count))
        or batch.parsed_count != sum(outcome.status == "PARSED" for outcome in batch.outcomes)
        or batch.ignored_count != sum(outcome.status == "IGNORED" for outcome in batch.outcomes)
        or batch.rejected_count != sum(outcome.status == "REJECTED" for outcome in batch.outcomes)
        or batch.parsed_count + batch.ignored_count + batch.rejected_count != len(records)):
        raise LiveWorkerError("INVARIANT_FAILURE")


class LiveProcessingWorker:
    """Own one session by convention; not safe for concurrent or mixed direct use."""

    __slots__ = ("_session", "_max_records", "_max_bytes", "_state", "_revision",
                 "_successful", "_no_data", "_degraded", "_failed", "_parsed",
                 "_ignored", "_rejected", "_acknowledged", "_released", "_error_code")

    def __init__(self, session: LiveTailSession, max_lease_records: int, max_lease_bytes: int):
        if type(session) is not LiveTailSession:
            raise LiveWorkerError("INVALID_SESSION")
        if (type(max_lease_records) is not int or not 1 <= max_lease_records <= MAX_QUEUE_ITEMS
            or type(max_lease_bytes) is not int or not 1 <= max_lease_bytes <= MAX_QUEUE_BYTES):
            raise LiveWorkerError("INVALID_LIMIT")
        snapshot = session.snapshot()
        if (snapshot.state != "RUNNING" or snapshot.active_lease
            or snapshot.acknowledged_record_count or snapshot.released_lease_count):
            raise LiveWorkerError("INVALID_SESSION")
        if session._worker_bound:
            raise LiveWorkerError("SESSION_ALREADY_OWNED")
        session._worker_bound = True
        self._session = session
        self._max_records = max_lease_records
        self._max_bytes = max_lease_bytes
        self._state = LiveWorkerState.READY
        self._revision = 0
        self._successful = self._no_data = self._degraded = self._failed = 0
        self._parsed = self._ignored = self._rejected = 0
        self._acknowledged = self._released = 0
        self._error_code: str | None = None

    def __repr__(self) -> str:
        return f"LiveProcessingWorker(state={self._state.value!r}, step_revision={self._revision})"

    def _transition(self, state: LiveWorkerState) -> None:
        if state not in _TRANSITIONS[self._state]:
            raise LiveWorkerError("INVALID_STATE")
        self._state = state

    def _fail(self, code: str) -> None:
        self._failed = _add(self._failed, 1)
        self._error_code = code
        self._transition(LiveWorkerState.FAILED)
        raise LiveWorkerError(code) from None

    def _fail_ownership(self) -> None:
        # The session's terminal transition closes its FD without settling the lease.
        try:
            if self._session.snapshot().state == "RUNNING":
                self._session._fail("INTERNAL_OWNERSHIP_FAILURE")
        except Exception:
            pass  # Worker still fails closed; never reconstruct queue ownership.
        self._fail("OWNERSHIP_FAILURE")

    def step(self) -> LiveWorkerStepResult:
        if self._state == LiveWorkerState.STOPPED:
            raise LiveWorkerError("OPERATION_AFTER_CLOSE")
        if self._state != LiveWorkerState.READY:
            raise LiveWorkerError("INVALID_STATE")
        revision = _add(self._revision, 1)
        self._transition(LiveWorkerState.RUNNING_STEP)
        self._revision = revision
        try:
            polled = self._session.poll_once()
            available = self._session.snapshot().available_item_count
        except Exception:
            self._fail("POLL_FAILURE")
        if type(polled) is not int or polled < 0 or type(available) is not int:
            self._fail("POLL_FAILURE")
        if not available:
            self._no_data = _add(self._no_data, 1)
            result = LiveWorkerStepResult("1", revision, "NO_DATA", polled, 0, 0, 0, 0, 0, 0, 0, (), None)
            self._transition(LiveWorkerState.READY)
            return result
        try:
            lease = self._session.lease_records(self._max_records, self._max_bytes)
        except Exception:
            self._fail("LEASE_FAILURE")
        if lease is None:
            self._fail("LEASE_FAILURE")
        try:
            batch = parse_live_records(self._session.source_role, lease.records)
            _validate_batch(batch, self._session.source_role, lease.records)
            next_successful = _add(self._successful, 1)
            next_parsed = _add(self._parsed, batch.parsed_count)
            next_ignored = _add(self._ignored, batch.ignored_count)
            next_rejected = _add(self._rejected, batch.rejected_count)
            next_acknowledged = _add(self._acknowledged, lease.item_count)
            resident = self._session.snapshot()
            if not resident.active_lease or resident.leased_item_count != lease.item_count:
                raise LiveWorkerError("INVARIANT_FAILURE")
            result = LiveWorkerStepResult("1", revision, "PROCESSED", polled, lease.item_count,
                                          batch.parsed_count, batch.ignored_count, batch.rejected_count,
                                          lease.item_count, 0, resident.available_item_count, (), None)
            next_released = _add(self._released, lease.item_count)
            next_degraded = _add(self._degraded, 1)
        except Exception:
            try:
                self._session.release_lease(lease)
            except Exception:
                self._fail_ownership()
            self._released = next_released if "next_released" in locals() else _add(self._released, lease.item_count)
            self._degraded = next_degraded if "next_degraded" in locals() else _add(self._degraded, 1)
            self._error_code = "PROCESSING_FAILURE"
            self._transition(LiveWorkerState.DEGRADED)
            raise LiveWorkerError("PROCESSING_FAILURE") from None
        try:
            self._session.acknowledge_lease(lease)
        except Exception:
            self._fail_ownership()
        self._successful, self._parsed, self._ignored = next_successful, next_parsed, next_ignored
        self._rejected, self._acknowledged = next_rejected, next_acknowledged
        self._transition(LiveWorkerState.READY)
        return result

    def resume_after_degraded(self) -> None:
        if self._state != LiveWorkerState.DEGRADED:
            raise LiveWorkerError("INVALID_STATE")
        try:
            session = self._session.snapshot()
            if session.state != "RUNNING" or session.active_lease or session.leased_item_count:
                self._fail("OWNERSHIP_FAILURE")
        except LiveWorkerError:
            raise
        except Exception:
            self._fail("OWNERSHIP_FAILURE")
        self._error_code = None
        self._transition(LiveWorkerState.READY)

    def snapshot(self) -> LiveWorkerSnapshot:
        return LiveWorkerSnapshot("1", self._state, self._revision, self._successful,
                                  self._no_data, self._degraded, self._failed, self._parsed,
                                  self._ignored, self._rejected, self._acknowledged,
                                  self._released, self._session.snapshot(),
                                  (self._error_code,) if self._error_code else (), self._error_code)

    def close(self) -> None:
        if self._state == LiveWorkerState.STOPPED:
            return
        if self._state == LiveWorkerState.RUNNING_STEP:
            raise LiveWorkerError("INVALID_STATE")
        self._transition(LiveWorkerState.STOPPING)
        try:
            self._session.close()
        except Exception:
            self._error_code = "CLOSE_FAILURE"
            self._transition(LiveWorkerState.FAILED)
            raise LiveWorkerError("CLOSE_FAILURE") from None
        self._transition(LiveWorkerState.STOPPED)
