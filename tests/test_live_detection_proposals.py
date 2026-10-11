"""Proposal ownership and transaction boundaries are explicit."""

from dataclasses import replace

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveDetectionError, LiveParseBatch, LiveParseOutcome,
    LiveTailRecord, parse_live_records,
)
from app.live_monitoring import detection_accumulator as module


LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1"


def batch(sequence=1):
    record = LiveTailRecord("application", sequence, LINE, len(LINE.encode()))
    return parse_live_records("application", (record,))


def test_abort_preserves_committed_state_and_same_batch_can_retry():
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    before = accumulator.snapshot()
    first = accumulator.prepare(batch())
    assert accumulator.snapshot().active_proposal
    accumulator.abort(first)
    assert accumulator.snapshot() == before
    retry = accumulator.prepare(batch())
    assert retry._proposal_id > first._proposal_id
    accumulator.commit(retry)
    assert accumulator.snapshot().revision == 1
    assert accumulator.snapshot().history_record_count == 1


def test_only_one_active_proposal_and_double_settlement_rejected():
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    proposal = accumulator.prepare(batch())
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch(2))
    assert raised.value.code == "ACTIVE_PROPOSAL_EXISTS"
    accumulator.commit(proposal)
    for operation in (accumulator.commit, accumulator.abort):
        with pytest.raises(LiveDetectionError) as raised:
            operation(proposal)
        assert raised.value.code == "DOUBLE_SETTLEMENT"


def test_foreign_stale_and_forged_proposals():
    first = LiveDetectionAccumulator("application", 3, 4096)
    second = LiveDetectionAccumulator("application", 3, 4096)
    proposal = first.prepare(batch())
    with pytest.raises(LiveDetectionError) as raised:
        second.commit(proposal)
    assert raised.value.code == "FOREIGN_PROPOSAL"
    forged = replace(proposal, _history_bytes=proposal._history_bytes + 1)
    with pytest.raises(LiveDetectionError) as raised:
        first.commit(forged)
    assert raised.value.code == "FORGED_PROPOSAL"
    assert first.snapshot().history_record_count == 0
    first.abort(proposal)
    current = first.prepare(batch())
    with pytest.raises(LiveDetectionError) as raised:
        first.commit(proposal)
    assert raised.value.code == "STALE_PROPOSAL"
    first.abort(current)


def test_revision_mismatch_keeps_committed_state_unchanged():
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    proposal = accumulator.prepare(batch())
    forged = replace(proposal, proposal_revision=2)
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.commit(forged)
    assert raised.value.code == "REVISION_MISMATCH"
    assert accumulator.snapshot().revision == 0
    accumulator.abort(proposal)


def test_detector_failure_has_no_partial_state_or_active_proposal(monkeypatch):
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    before = accumulator.snapshot()

    def broken(_events):
        raise RuntimeError("private detector diagnostic")

    monkeypatch.setattr(module, "detect_attacks", broken)
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch())
    assert raised.value.code == "UNEXPECTED_DETECTOR_FAILURE"
    assert accumulator.snapshot() == before
    assert not accumulator.snapshot().active_proposal


def test_invalid_detector_result_fails_before_active_proposal(monkeypatch):
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    monkeypatch.setattr(module, "detect_attacks", lambda _events: {"unexpected": object()})
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch())
    assert raised.value.code == "DETECTION_INVARIANT_FAILURE"
    assert accumulator.snapshot().revision == 0
    assert not accumulator.snapshot().active_proposal


def test_detector_called_once_for_parsed_and_never_for_empty(monkeypatch):
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    original = module.detect_attacks
    calls = 0

    def counting(events):
        nonlocal calls
        calls += 1
        return original(events)

    monkeypatch.setattr(module, "detect_attacks", counting)
    accumulator.commit(accumulator.prepare(batch()))
    assert calls == 1
    ignored = LiveParseBatch("application", (LiveParseOutcome(2, "IGNORED"),), 0, 1, 0)
    accumulator.commit(accumulator.prepare(ignored))
    assert calls == 1


def test_unbound_method_rejects_wrong_accumulator_runtime_type():
    with pytest.raises(LiveDetectionError) as raised:
        LiveDetectionAccumulator.prepare(object(), batch())
    assert raised.value.code == "INVALID_ARGUMENT"


def test_prepare_does_not_call_parser_worker_correlation_or_risk(monkeypatch):
    from app.analyzer import pipeline
    from app.live_monitoring import parser_adapter, worker

    def forbidden(*_args, **_kwargs):
        raise AssertionError("forbidden integration call")

    parsed = batch()  # Build input before installing the isolation spies.
    monkeypatch.setattr(pipeline, "load_normalized_logs", forbidden)
    monkeypatch.setattr(pipeline, "correlate_attacks", forbidden)
    monkeypatch.setattr(pipeline, "assess_risk", forbidden)
    monkeypatch.setattr(parser_adapter, "parse_live_records", forbidden)
    monkeypatch.setattr(worker.LiveProcessingWorker, "step", forbidden)
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    accumulator.commit(accumulator.prepare(parsed))
    assert accumulator.snapshot().history_record_count == 1
