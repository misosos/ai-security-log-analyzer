"""Committed-only bounded publication and deterministic replay."""

from dataclasses import asdict, replace
import json

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LivePublicationBuffer, LiveTailRecord,
    parse_live_records, serialize_live_publication_event,
    serialize_live_publication_snapshot,
)
from app.live_monitoring.publication import LivePublicationError


def line(second: int | str, suffix: str = "") -> str:
    clock = second if type(second) is str and ":" in second else f"03:04:{second:02d}"
    return (f"2026-01-02 {clock} INFO login_failed "
            f"user=synthetic ip=192.0.2.1{suffix}")


def committed(accumulator, *lines, start=1):
    records = tuple(LiveTailRecord("application", start + index, text,
                                   len(text.encode())) for index, text in enumerate(lines))
    batch = parse_live_records("application", records)
    proposal = accumulator.prepare(batch)
    accumulator.commit(proposal)
    return accumulator.latest_change_set()


def setup(*, items=32, bytes_limit=16384):
    accumulator = LiveDetectionAccumulator("application", 64, 65536)
    buffer = LivePublicationBuffer(accumulator, max_items=items, max_bytes=bytes_limit)
    return accumulator, buffer


def test_session_transport_ids_are_browser_safe_and_process_distinct(monkeypatch):
    import app.live_monitoring.publication as publication

    monkeypatch.setattr(publication, "_NEXT_SESSION_NUMBER", 0)
    monkeypatch.setattr(publication, "_PROCESS_SESSION_BASE", None)
    monkeypatch.setattr(publication.secrets, "randbelow", lambda limit: limit - 1)
    _, first = setup()
    _, second = setup()
    first_number = int(first.session_id.removeprefix("LIVE-SESSION-"))
    second_number = int(second.session_id.removeprefix("LIVE-SESSION-"))
    assert first_number < second_number <= (1 << 53) - 1
    assert first.replay_after(
        f"LIVE-EVENT-{second_number:06d}-000001"
    ).gap_code == "FOREIGN_SESSION"

    monkeypatch.setattr(publication, "_PROCESS_SESSION_BASE", None)
    monkeypatch.setattr(publication.secrets, "randbelow", lambda limit: 0)
    _, next_process = setup()
    assert next_process.session_id != first.session_id


def test_session_entropy_failure_has_fixed_safe_error(monkeypatch):
    import app.live_monitoring.publication as publication

    monkeypatch.setattr(publication, "_PROCESS_SESSION_BASE", None)

    def unavailable(_limit):
        raise OSError("private entropy failure canary")

    monkeypatch.setattr(publication.secrets, "randbelow", unavailable)
    with pytest.raises(LivePublicationError) as raised:
        setup()
    assert raised.value.code == "INVALID_BUFFER_ARGUMENT"
    assert "private entropy failure canary" not in repr(raised.value)
    assert "private entropy failure canary" not in str(raised.value)


def publish_changes(accumulator, buffer, count=7):
    events = []
    timestamps = [0, 1, 2, 3, 4, "03:03:59", "03:03:58"][:count]
    for index, timestamp in enumerate(timestamps):
        change = committed(accumulator, line(timestamp), start=index + 1)
        event = buffer.publish(change)
        if event is not None:
            events.append(event)
    return events


def test_exact_input_bound_committed_revision_and_empty_policy():
    accumulator, buffer = setup()
    for bad in ({}, [], (), None, object()):
        with pytest.raises(LivePublicationError):
            buffer.publish(bad)
    assert buffer.replay_after(None).status == "INITIAL"
    proposal = accumulator.prepare(parse_live_records("application", (
        LiveTailRecord("application", 1, line(0), len(line(0).encode())),)))
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(proposal._change_set)
    assert raised.value.code == "UNCOMMITTED_CHANGE_SET"
    accumulator.commit(proposal)
    assert buffer.publish(accumulator.latest_change_set()) is None
    assert buffer.snapshot().latest_committed_detection_revision == 1
    assert buffer.snapshot().published_total == 0
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(accumulator.latest_change_set())
    assert raised.value.code == "DUPLICATE_REVISION"


def test_limit_types_and_serializer_types_fail_closed():
    for item_limit, byte_limit in ((True, 100), (1, False), (0, 100), (1, 0),
                                   (33, 100), (1, 16385)):
        with pytest.raises(LivePublicationError) as raised:
            LivePublicationBuffer(LiveDetectionAccumulator("application", 8, 8192),
                                  max_items=item_limit, max_bytes=byte_limit)
        assert raised.value.code == "INVALID_BUFFER_ARGUMENT"
    with pytest.raises(LivePublicationError):
        serialize_live_publication_event({})
    with pytest.raises(LivePublicationError):
        serialize_live_publication_snapshot({})


def test_publish_replay_and_exact_serialized_byte_accounting():
    accumulator, buffer = setup()
    first, second, third = publish_changes(accumulator, buffer, 7)
    assert first.event_id.endswith("-000001")
    assert second.event_id.endswith("-000002")
    assert third.event_id.endswith("-000003")
    assert first.session_id == buffer.session_id
    assert first.created_count == 1
    assert second.updated_count == third.updated_count == 1
    assert buffer.snapshot().byte_count == sum(len(serialize_live_publication_event(e))
                                               for e in (first, second, third))
    assert buffer.replay_after(None).events == (first, second, third)
    replay = buffer.replay_after(first.event_id)
    assert replay.status == "REPLAY" and replay.events == (second, third)
    assert buffer.replay_after(third.event_id).events == ()
    assert json.loads(serialize_live_publication_snapshot(buffer.snapshot()))["published_total"] == 3
    assert b"192.0.2.1" not in serialize_live_publication_event(first)


def test_item_and_byte_eviction_and_gap():
    accumulator, buffer = setup(items=2)
    events = publish_changes(accumulator, buffer, 7)
    snap = buffer.snapshot()
    assert (snap.item_count, snap.published_total, snap.evicted_total) == (2, 3, 1)
    assert snap.earliest_available_event_id == events[1].event_id
    assert buffer.replay_after(events[0].event_id).gap_code == "EVICTED_EVENT_ID"
    assert buffer.snapshot().replay_gap_total == 1

    accumulator2, buffer2 = setup()
    initial = publish_changes(accumulator2, buffer2, 5)[0]
    event_size = len(serialize_live_publication_event(initial))
    accumulator3, buffer3 = setup(bytes_limit=event_size)
    events3 = publish_changes(accumulator3, buffer3, 6)
    assert len(events3) == 2
    assert buffer3.snapshot().evicted_total == 1
    assert buffer3.snapshot().byte_count == len(serialize_live_publication_event(events3[1]))


def test_oversized_event_and_foreign_or_malformed_replay():
    accumulator, buffer = setup(bytes_limit=1)
    for index in range(4):
        assert buffer.publish(committed(accumulator, line(index), start=index + 1)) is None
    change = committed(accumulator, line(4), start=5)
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(change)
    assert raised.value.code == "EVENT_TOO_LARGE"
    assert buffer.snapshot().rejected_oversized_total == 1
    assert buffer.snapshot().published_total == 0

    _, other = setup()
    for supplied, expected in (
        ("bad", "MALFORMED_EVENT_ID"),
        ("LIVE-EVENT-999999-000001", "FOREIGN_SESSION"),
        (f"LIVE-EVENT-{other.session_id.removeprefix('LIVE-SESSION-')}-000001", "FOREIGN_SESSION"),
        (f"LIVE-EVENT-{buffer.session_id.removeprefix('LIVE-SESSION-')}-000001", "FUTURE_EVENT_ID"),
    ):
        assert buffer.replay_after(supplied).gap_code == expected


def test_revision_gap_foreign_and_close_contract():
    accumulator, buffer = setup()
    first = committed(accumulator, line(0))
    second = committed(accumulator, line(1), start=2)
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(second)
    assert raised.value.code == "REVISION_GAP"
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(replace(first))
    assert raised.value.code == "UNCOMMITTED_CHANGE_SET"
    _, foreign = setup()
    with pytest.raises(LivePublicationError):
        foreign.publish(second)
    buffer.close()
    buffer.close()
    assert buffer.snapshot().state == "CLOSED"
    assert buffer._accumulator is None
    assert buffer.replay_after(None).gap_code == "BUFFER_CLOSED"
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(second)
    assert raised.value.code == "BUFFER_CLOSED"


def test_privacy_repr_errors_and_scalar_tree(capsys):
    secret = "PRIVATE_CANARY_argv_account_path_query"
    accumulator, buffer = setup()
    for index in range(5):
        raw = line(index, f" note={secret}").replace("user=synthetic", f"user={secret}")
        change = committed(accumulator, raw, start=index + 1)
        event = buffer.publish(change)
    snapshots = (buffer.snapshot(), buffer.replay_after(None), event,
                 serialize_live_publication_event(event),
                 serialize_live_publication_snapshot(buffer.snapshot()),
                 asdict(event), asdict(buffer.snapshot()))
    with pytest.raises(LivePublicationError) as raised:
        buffer.publish(change)
    for value in (*snapshots, raised.value, buffer):
        assert secret not in repr(value)
        assert secret not in str(value)
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
