"""Bounded history contains every parsed event and never silently evicts."""

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveDetectionError, LiveParseBatch, LiveParseOutcome,
    LiveTailRecord, parse_live_records,
)


LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1"


def batch(role="application", lines=(LINE,), start=1):
    records = tuple(LiveTailRecord(role, start + index, line, len(line.encode()))
                    for index, line in enumerate(lines))
    return parse_live_records(role, records)


@pytest.mark.parametrize("role", ("application", "ssh", "access"))
def test_all_three_roles_have_empty_privacy_safe_state(role):
    accumulator = LiveDetectionAccumulator(role, 4, 4096)
    snapshot = accumulator.snapshot()
    assert snapshot.source_role == role
    assert snapshot.history_record_count == 0
    assert snapshot.subject_count == 0
    assert not snapshot.active_proposal


@pytest.mark.parametrize("role", ("linux_audit", "unknown", 1, None))
def test_unsupported_role_is_fixed(role):
    with pytest.raises(LiveDetectionError) as raised:
        LiveDetectionAccumulator(role, 1, 1)
    assert raised.value.code == "UNSUPPORTED_SOURCE_ROLE"


@pytest.mark.parametrize("limits", ((True, 4), (0, 4), (1, False), (1, 0), (-1, 4)))
def test_limits_are_exact_positive_ints(limits):
    with pytest.raises(LiveDetectionError) as raised:
        LiveDetectionAccumulator("application", *limits)
    assert raised.value.code == "INVALID_HISTORY_LIMIT"


def test_prepare_does_not_commit_and_parsed_only_enters_history():
    accumulator = LiveDetectionAccumulator("application", 4, 4096)
    mixed = batch(lines=(LINE, "   ", "malformed timestamp"))
    before = accumulator.snapshot()
    proposal = accumulator.prepare(mixed)
    assert accumulator.snapshot().revision == before.revision
    assert accumulator.snapshot().history_record_count == 0
    assert accumulator.snapshot().active_proposal
    assert proposal.safe_summary().history_record_count == 1
    assert proposal.safe_summary().history_byte_count == len(LINE.encode())
    assert (proposal.safe_summary().parsed_input_count,
            proposal.safe_summary().ignored_input_count,
            proposal.safe_summary().rejected_input_count) == (1, 1, 1)
    committed = accumulator.commit(proposal)
    assert committed.revision == 1
    assert (committed.total_parsed, committed.total_ignored, committed.total_rejected) == (1, 1, 1)
    assert committed.history_record_count == 1
    assert committed.history_byte_count == len(LINE.encode())


def test_no_event_batch_commits_counts_without_detector_reexecution(monkeypatch):
    from app.live_monitoring import detection_accumulator as module

    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    monkeypatch.setattr(module, "detect_attacks", lambda *_: (_ for _ in ()).throw(AssertionError("called")))
    proposal = accumulator.prepare(batch(lines=(" ", "malformed timestamp")))
    assert proposal.safe_summary().history_record_count == 0
    snapshot = accumulator.commit(proposal)
    assert snapshot.revision == 1
    assert (snapshot.total_ignored, snapshot.total_rejected) == (1, 1)


def test_exact_item_and_byte_limits_then_full_overflow_without_eviction():
    byte_limit = len(LINE.encode())
    accumulator = LiveDetectionAccumulator("application", 1, byte_limit)
    accumulator.commit(accumulator.prepare(batch()))
    before = accumulator.snapshot()
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch(start=2))
    assert raised.value.code == "HISTORY_LIMIT_EXCEEDED"
    assert accumulator.snapshot() == before
    assert not accumulator.snapshot().active_proposal

    short = LiveDetectionAccumulator("application", 2, byte_limit - 1)
    with pytest.raises(LiveDetectionError) as raised:
        short.prepare(batch())
    assert raised.value.code == "HISTORY_LIMIT_EXCEEDED"
    assert short.snapshot().history_record_count == 0


def test_byte_accounting_is_utf8_encoded_length():
    unicode_line = LINE + " note=한글"
    accumulator = LiveDetectionAccumulator("application", 1, len(unicode_line.encode()))
    proposal = accumulator.prepare(batch(lines=(unicode_line,)))
    assert proposal.safe_summary().history_byte_count == len(unicode_line.encode())
    accumulator.commit(proposal)


def test_second_event_byte_overflow_preserves_first_committed_prefix():
    accumulator = LiveDetectionAccumulator("application", 3, len(LINE.encode()) * 2 - 1)
    accumulator.commit(accumulator.prepare(batch()))
    before = accumulator.snapshot()
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch(start=2))
    assert raised.value.code == "HISTORY_LIMIT_EXCEEDED"
    assert accumulator.snapshot() == before


@pytest.mark.parametrize(("field", "value", "code"), (
    ("raw", 7, "INVALID_RAW_FIELD"),
    ("raw", "invalid-\ud800", "INVALID_RAW_FIELD"),
    ("source", "access_log", "UNEXPECTED_EVENT_TYPE"),
    ("src_ip", [], "UNEXPECTED_EVENT_TYPE"),
))
def test_mutated_trusted_event_is_rejected_before_detector(field, value, code):
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    parsed = batch()
    setattr(parsed.outcomes[0].event, field, value)
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(parsed)
    assert raised.value.code == code
    assert accumulator.snapshot().revision == 0


def test_wrong_batch_type_role_and_sequence_fail_closed():
    accumulator = LiveDetectionAccumulator("application", 4, 4096)
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare([])
    assert raised.value.code == "INVALID_PARSE_BATCH"
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(parse_live_records("application", ()))
    assert raised.value.code == "INVALID_PARSE_BATCH"
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch("ssh", ("2026-01-02 03:04:05 sshd: unrelated message",)))
    assert raised.value.code == "SOURCE_MISMATCH"
    accumulator.commit(accumulator.prepare(batch()))
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(batch(start=1))
    assert raised.value.code == "INVALID_PARSE_BATCH"


def test_forged_batch_count_does_not_enter_history():
    accumulator = LiveDetectionAccumulator("application", 2, 4096)
    actual = batch()
    # A trusted caller can bypass a frozen dataclass constructor; revalidate at ingress.
    object.__setattr__(actual, "parsed_count", 0)
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(actual)
    assert raised.value.code == "INVALID_PARSE_BATCH"
    assert accumulator.snapshot().revision == 0
