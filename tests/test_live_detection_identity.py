"""Session-local observation IDs describe detector slots, never people."""

from copy import deepcopy
from dataclasses import replace

from app.live_monitoring import LiveDetectionAccumulator, LiveTailRecord, parse_live_records
from app.live_monitoring import detection_accumulator as module
from app.models.schemas import DetectionResult


def batch(sequence, second, ip="192.0.2.1"):
    line = f"2026-01-02 03:04:{second:02d} INFO login_failed user=synthetic ip={ip}"
    record = LiveTailRecord("application", sequence, line, len(line.encode()))
    return parse_live_records("application", (record,))


def test_created_updated_no_longer_matches_and_reactivation():
    accumulator = LiveDetectionAccumulator("application", 20, 10000)
    for number in range(1, 6):
        accumulator.commit(accumulator.prepare(batch(number, number)))
    created = accumulator.latest_change_set().changes
    assert len(created) == 1
    assert created[0].change_type == "CREATED"
    assert created[0].observation_id == "LIVE-OBS-000001"
    assert created[0].observation_revision == 1
    accumulator.commit(accumulator.prepare(batch(6, 6)))
    changed = accumulator.latest_change_set().changes
    assert len(changed) == 1
    assert changed[0].change_type == "UPDATED"
    assert changed[0].observation_id == created[0].observation_id
    assert changed[0].observation_revision == 2
    # A far-future failure widens the full-session min/max window; no eviction.
    line = "2026-01-02 03:10:00 INFO login_failed user=synthetic ip=192.0.2.1"
    parsed = parse_live_records("application", (LiveTailRecord("application", 7, line, len(line.encode())),))
    accumulator.commit(accumulator.prepare(parsed))
    inactive = accumulator.latest_change_set().changes
    assert inactive[0].change_type == "NO_LONGER_MATCHES"
    assert inactive[0].state == "NO_LONGER_MATCHES_CURRENT_RESULT"
    assert inactive[0].observation_id == created[0].observation_id
    assert accumulator.snapshot().active_observation_count == 0

    # Characterize reactivation policy without altering the production detector.
    candidate = deepcopy(accumulator._detection)
    candidate["192.0.2.1"]["detections"]["brute_force"] = accumulator._observations[0]._detection
    observations, next_id, changeset, active_count = module._prepare_observations(
        accumulator._observations, candidate, accumulator._next_observation_id,
        accumulator.snapshot().revision + 1,
        replace(accumulator.latest_change_set().safe_summary,
                proposal_revision=accumulator.snapshot().revision + 1),
    )
    assert next_id == 1 and active_count == 1
    assert observations[0].observation_id == created[0].observation_id
    assert changeset.changes[0].change_type == "UPDATED"
    assert changeset.changes[0].observation_revision == 4


def test_unchanged_canonical_result_has_no_change_and_evidence_order_matters():
    accumulator = LiveDetectionAccumulator("application", 10, 10000)
    for number in range(1, 6):
        accumulator.commit(accumulator.prepare(batch(number, number)))
    prior = accumulator._observations
    candidate = deepcopy(accumulator._detection)
    _, next_id, changeset, active_count = module._prepare_observations(
        prior, candidate, accumulator._next_observation_id, 6,
        replace(accumulator.latest_change_set().safe_summary, proposal_revision=6),
    )
    assert changeset.changes == ()
    assert next_id == 1 and active_count == 1
    slot = candidate["192.0.2.1"]["detections"]["brute_force"]
    assert type(slot) is DetectionResult
    slot.evidence.reverse()
    _, _, changed, _ = module._prepare_observations(
        prior, candidate, accumulator._next_observation_id, 6,
        replace(accumulator.latest_change_set().safe_summary, proposal_revision=6),
    )
    if len(slot.evidence) > 1:
        assert changed.changes[0].change_type == "UPDATED"


def test_multiple_subject_ids_are_monotonic_not_subject_derived():
    accumulator = LiveDetectionAccumulator("application", 20, 10000)
    sequence = 1
    for ip in ("192.0.2.2", "192.0.2.1"):
        for second in range(5):
            accumulator.commit(accumulator.prepare(batch(sequence, second, ip)))
            sequence += 1
    ids = tuple(item.observation_id for item in accumulator._observations)
    assert ids == ("LIVE-OBS-000001", "LIVE-OBS-000002")
    assert all("192.0.2" not in item for item in ids)
