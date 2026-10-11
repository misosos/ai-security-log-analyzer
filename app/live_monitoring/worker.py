"""Single-caller, explicit-step orchestration of trusted live records."""

from dataclasses import dataclass, replace
from enum import Enum

from app.live_monitoring.core import (
    MAX_COUNTER, MAX_QUEUE_BYTES, MAX_QUEUE_ITEMS, LiveTailSession,
    LiveTailSnapshot,
)
from app.live_monitoring.parser_adapter import (
    LiveParseBatch, LiveParseOutcome, parse_live_records,
)
from app.live_monitoring.detection_accumulator import (
    LiveDetectionAccumulator, LiveDetectionSnapshot,
)
from app.live_monitoring.publication import LivePublicationBuffer, LivePublicationSnapshot


class LiveWorkerState(str, Enum):
    READY = "READY"
    RUNNING_STEP = "RUNNING_STEP"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


_TRANSITIONS = {
    LiveWorkerState.READY: frozenset((LiveWorkerState.RUNNING_STEP, LiveWorkerState.STOPPING,
                                    LiveWorkerState.FAILED)),
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
    "INVALID_ACCUMULATOR": "detection accumulator 형식을 확인하십시오.",
    "ACCUMULATOR_ALREADY_OWNED": "accumulator는 이미 worker에 연결됐습니다.",
    "ACK_FAILURE": "queue acknowledgement를 확인할 수 없습니다. 종료하십시오.",
    "PROPOSAL_ABORT_FAILURE": "detection proposal 정산을 확인할 수 없습니다. 종료하십시오.",
    "DETECTION_COMMIT_FAILED_AFTER_ACK": "일부 로그가 탐지 상태에 반영되지 않았을 수 있습니다. 종료하십시오.",
    "PUBLICATION_FAILED_AFTER_DETECTION_COMMIT": "확정된 탐지 변경이 게시되지 않았을 수 있습니다. 종료하십시오.",
    "WORKER_AGGREGATE_FAILED_AFTER_PUBLICATION": "게시 후 worker 집계를 확인할 수 없습니다. 종료하십시오.",
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
    accumulator_revision: int = 0
    created_count: int = 0
    updated_count: int = 0
    no_longer_matches_count: int = 0
    active_observation_count: int = 0
    publication_event_id: str | None = None

    def __post_init__(self) -> None:
        counts = (self.step_revision, self.polled_record_count, self.leased_record_count,
                  self.parsed_count, self.ignored_count, self.rejected_count,
                  self.acknowledged_count, self.released_count, self.queue_remaining_count,
                  self.accumulator_revision, self.created_count, self.updated_count,
                  self.no_longer_matches_count, self.active_observation_count)
        if (self.schema_version != "1" or self.status not in ("NO_DATA", "PROCESSED")
            or any(type(value) is not int or not 0 <= value <= MAX_COUNTER for value in counts)
            or self.step_revision < 1 or self.queue_remaining_count > MAX_QUEUE_ITEMS
            or self.parsed_count + self.ignored_count + self.rejected_count != self.leased_record_count
            or self.acknowledged_count != self.leased_record_count
            or (self.status == "NO_DATA" and (self.polled_record_count or self.leased_record_count))
            or (self.status == "PROCESSED" and not self.leased_record_count)
            or type(self.fixed_warning_codes) is not tuple or self.fixed_warning_codes
            or self.publication_event_id is not None and (
                type(self.publication_event_id) is not str
                or not self.publication_event_id.startswith("LIVE-EVENT-"))
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
    accumulator: LiveDetectionSnapshot | None = None
    post_ack_commit_failure_count: int = 0
    uncommitted_after_ack_record_count: int = 0
    publication: LivePublicationSnapshot | None = None
    potentially_unpublished_revision_count: int = 0
    post_publication_aggregate_failure_count: int = 0

    def __post_init__(self) -> None:
        counts = (self.step_revision, self.successful_step_count, self.no_data_step_count,
                  self.degraded_step_count, self.failed_step_count, self.total_parsed,
                  self.total_ignored, self.total_rejected, self.total_acknowledged,
                  self.total_released, self.post_ack_commit_failure_count,
                  self.uncommitted_after_ack_record_count,
                  self.potentially_unpublished_revision_count,
                  self.post_publication_aggregate_failure_count)
        if (self.schema_version != "1" or type(self.state) is not LiveWorkerState
            or type(self.session) is not LiveTailSnapshot
            or type(self.accumulator) is not LiveDetectionSnapshot
            or type(self.publication) is not LivePublicationSnapshot
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
                 "_ignored", "_rejected", "_acknowledged", "_released", "_error_code",
                 "_accumulator", "_post_ack_failures", "_uncommitted_after_ack",
                 "_last_acc_snapshot", "_publication", "_potentially_unpublished",
                 "_post_publication_aggregate_failures")

    def __init__(self, session: LiveTailSession, detection_accumulator: LiveDetectionAccumulator,
                 max_lease_records: int, max_lease_bytes: int):
        if type(session) is not LiveTailSession:
            raise LiveWorkerError("INVALID_SESSION")
        if type(detection_accumulator) is not LiveDetectionAccumulator:
            raise LiveWorkerError("INVALID_ACCUMULATOR")
        if (type(max_lease_records) is not int or not 1 <= max_lease_records <= MAX_QUEUE_ITEMS
            or type(max_lease_bytes) is not int or not 1 <= max_lease_bytes <= MAX_QUEUE_BYTES):
            raise LiveWorkerError("INVALID_LIMIT")
        snapshot = session.snapshot()
        if (snapshot.state != "RUNNING" or snapshot.active_lease
            or snapshot.acknowledged_record_count or snapshot.released_lease_count):
            raise LiveWorkerError("INVALID_SESSION")
        if session._worker_bound:
            raise LiveWorkerError("SESSION_ALREADY_OWNED")
        accumulator_snapshot = detection_accumulator.snapshot()
        if (detection_accumulator.source_role != session.source_role
            or accumulator_snapshot.closed or accumulator_snapshot.active_proposal
            or accumulator_snapshot.revision or accumulator_snapshot.history_record_count):
            raise LiveWorkerError("INVALID_ACCUMULATOR")
        if detection_accumulator._worker_bound:
            raise LiveWorkerError("ACCUMULATOR_ALREADY_OWNED")
        publication = LivePublicationBuffer(detection_accumulator)
        session._worker_bound = True
        detection_accumulator._worker_bound = True
        self._session = session
        self._accumulator = detection_accumulator
        self._publication = publication
        self._max_records = max_lease_records
        self._max_bytes = max_lease_bytes
        self._state = LiveWorkerState.READY
        self._revision = 0
        self._successful = self._no_data = self._degraded = self._failed = 0
        self._parsed = self._ignored = self._rejected = 0
        self._acknowledged = self._released = 0
        self._error_code: str | None = None
        self._post_ack_failures = self._uncommitted_after_ack = 0
        self._potentially_unpublished = self._post_publication_aggregate_failures = 0
        self._last_acc_snapshot = accumulator_snapshot

    @property
    def publication_buffer(self) -> LivePublicationBuffer:
        return self._publication

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
            result = LiveWorkerStepResult("1", revision, "NO_DATA", polled, 0, 0, 0, 0, 0, 0, 0, (), None,
                                          self._last_acc_snapshot.revision, 0, 0, 0,
                                          self._last_acc_snapshot.active_observation_count)
            self._transition(LiveWorkerState.READY)
            return result
        try:
            lease = self._session.lease_records(self._max_records, self._max_bytes)
        except Exception:
            self._fail("LEASE_FAILURE")
        if lease is None:
            self._fail("LEASE_FAILURE")
        proposal = None
        try:
            batch = parse_live_records(self._session.source_role, lease.records)
            _validate_batch(batch, self._session.source_role, lease.records)
            proposal = self._accumulator.prepare(batch)
            self._accumulator.prevalidate(proposal)
            next_successful = _add(self._successful, 1)
            next_parsed = _add(self._parsed, batch.parsed_count)
            next_ignored = _add(self._ignored, batch.ignored_count)
            next_rejected = _add(self._rejected, batch.rejected_count)
            next_acknowledged = _add(self._acknowledged, lease.item_count)
            next_released = _add(self._released, lease.item_count)
            next_degraded = _add(self._degraded, 1)
            resident = self._session.snapshot()
            if not resident.active_lease or resident.leased_item_count != lease.item_count:
                raise LiveWorkerError("INVARIANT_FAILURE")
            changes = proposal._change_set.changes
            result = LiveWorkerStepResult("1", revision, "PROCESSED", polled, lease.item_count,
                                          batch.parsed_count, batch.ignored_count, batch.rejected_count,
                                          lease.item_count, 0, resident.available_item_count, (), None,
                                          proposal.proposal_revision,
                                          sum(change.change_type == "CREATED" for change in changes),
                                          sum(change.change_type == "UPDATED" for change in changes),
                                          sum(change.change_type == "NO_LONGER_MATCHES" for change in changes),
                                          proposal._active_observation_count)
        except Exception:
            if proposal is not None:
                try:
                    self._accumulator.abort(proposal)
                except Exception:
                    self._fail("PROPOSAL_ABORT_FAILURE")
            try:
                self._session.release_lease(lease)
            except Exception:
                self._fail_ownership()
            self._released = next_released if "next_released" in locals() else _add(self._released, lease.item_count)
            self._degraded = next_degraded if "next_degraded" in locals() else _add(self._degraded, 1)
            self._error_code = "PROCESSING_FAILURE"
            self._transition(LiveWorkerState.DEGRADED)
            raise LiveWorkerError("PROCESSING_FAILURE") from None
        last_confirmed_detection = self._accumulator._committed
        try:
            self._session.acknowledge_lease(lease)
        except Exception:
            # A fault injected after the queue settled may raise from this call.
            # Never release in either case; classify an observable settled ack
            # as a terminal post-ack integrity gap.
            try:
                settled = (self._session.snapshot().acknowledged_record_count
                           == resident.acknowledged_record_count + lease.item_count)
            except Exception:
                settled = False
            if settled:
                self._accumulator._fail_after_ack(last_confirmed_detection)
                self._post_ack_failures = _add(self._post_ack_failures, 1)
                self._uncommitted_after_ack = _add(self._uncommitted_after_ack, lease.item_count)
                self._fail("DETECTION_COMMIT_FAILED_AFTER_ACK")
            try:
                self._accumulator.abort(proposal)
            except Exception:
                self._fail("PROPOSAL_ABORT_FAILURE")
            try:
                if self._session.snapshot().state == "RUNNING":
                    self._session._fail("INTERNAL_OWNERSHIP_FAILURE")
            except Exception:
                pass
            self._fail("ACK_FAILURE")
        try:
            self._accumulator.commit_prepared(proposal)
        except Exception:
            self._accumulator._fail_after_ack(last_confirmed_detection)
            self._post_ack_failures = _add(self._post_ack_failures, 1)
            self._uncommitted_after_ack = _add(self._uncommitted_after_ack, lease.item_count)
            self._fail("DETECTION_COMMIT_FAILED_AFTER_ACK")
        try:
            change_set = self._accumulator.latest_change_set()
            event = self._publication.publish(change_set)
        except Exception:
            # Detection and queue are committed. Never release, roll back or retry.
            self._last_acc_snapshot = proposal._committed_snapshot
            self._potentially_unpublished = _add(self._potentially_unpublished, 1)
            self._fail("PUBLICATION_FAILED_AFTER_DETECTION_COMMIT")
        previous_counters = (self._successful, self._parsed, self._ignored,
                             self._rejected, self._acknowledged)
        try:
            if event is not None:
                result = replace(result, publication_event_id=event.event_id)
            self._successful, self._parsed, self._ignored = next_successful, next_parsed, next_ignored
            self._rejected, self._acknowledged = next_rejected, next_acknowledged
            self._transition(LiveWorkerState.READY)
            self._last_acc_snapshot = proposal._committed_snapshot
        except Exception:
            (self._successful, self._parsed, self._ignored,
             self._rejected, self._acknowledged) = previous_counters
            self._last_acc_snapshot = proposal._committed_snapshot
            self._post_publication_aggregate_failures = _add(self._post_publication_aggregate_failures, 1)
            self._fail("WORKER_AGGREGATE_FAILED_AFTER_PUBLICATION")
        return result

    def resume_after_degraded(self) -> None:
        if self._state != LiveWorkerState.DEGRADED:
            raise LiveWorkerError("INVALID_STATE")
        try:
            session = self._session.snapshot()
            accumulator = self._accumulator.snapshot()
            if (session.state != "RUNNING" or session.active_lease or session.leased_item_count
                or accumulator.active_proposal or accumulator.closed):
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
                                  (self._error_code,) if self._error_code else (), self._error_code,
                                  self._last_acc_snapshot, self._post_ack_failures,
                                  self._uncommitted_after_ack, self._publication.snapshot(),
                                  self._potentially_unpublished,
                                  self._post_publication_aggregate_failures)

    def close(self) -> None:
        if self._state == LiveWorkerState.STOPPED:
            return
        if self._state == LiveWorkerState.RUNNING_STEP:
            raise LiveWorkerError("INVALID_STATE")
        self._transition(LiveWorkerState.STOPPING)
        try:
            self._session.close()
            self._publication.close()
            self._accumulator.close()
            self._last_acc_snapshot = self._accumulator.snapshot()
        except Exception:
            self._error_code = "CLOSE_FAILURE"
            self._transition(LiveWorkerState.FAILED)
            raise LiveWorkerError("CLOSE_FAILURE") from None
        self._transition(LiveWorkerState.STOPPED)
