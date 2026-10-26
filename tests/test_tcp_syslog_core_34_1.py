from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json

from hypothesis import given, settings, strategies as st
import pytest

from app.log_collection.framing import OctetCountingDecoder, ValidatedFrame
from app.log_collection.models import (
    CollectionCoreError,
    CollectionErrorCode,
    CollectionState,
    TcpCollectionConfig,
)
from app.log_collection.queue import BoundedEventQueue


def _config(**overrides):
    values = {
        "schema_version": "tcp-syslog-config/v1",
        "source_role": "application",
        "transport": "tcp_syslog_octet_counting",
        "bind_scope": "loopback_only",
        "max_connections": 2,
        "max_prefix_digits": 6,
        "max_frame_bytes": 128,
        "max_connection_buffer_bytes": 135,
        "max_queue_events": 8,
        "max_queue_bytes": 1024,
        "invalid_frame_action": "close_connection",
        "incomplete_frame_action": "reject_on_close",
    }
    values.update(overrides)
    return TcpCollectionConfig(**values)


def test_config_is_closed_immutable_and_safe_on_invalid_input():
    config = _config(source_role="ssh")
    assert config.source_role == "ssh"
    with pytest.raises(FrozenInstanceError):
        config.max_frame_bytes = 1
    with pytest.raises(CollectionCoreError) as raised:
        _config(source_role="ACCOUNT_PRIVATE_CANARY")
    assert raised.value.code == CollectionErrorCode.INVALID_CONFIG
    assert "ACCOUNT_PRIVATE_CANARY" not in str(raised.value) + repr(raised.value)

    mapping = config.to_dict()
    mapping["unexpected"] = "PRIVATE_CANARY"
    with pytest.raises(CollectionCoreError) as raised:
        TcpCollectionConfig.from_mapping(mapping)
    assert raised.value.code == CollectionErrorCode.INVALID_CONFIG
    assert "PRIVATE_CANARY" not in str(raised.value) + repr(raised.value)


@pytest.mark.parametrize("role", ["access", "other", "ssh\nprivate"])
def test_config_rejects_unsupported_roles(role):
    with pytest.raises(CollectionCoreError) as raised:
        _config(source_role=role)
    assert raised.value.code == CollectionErrorCode.INVALID_CONFIG
    assert role not in str(raised.value)


@pytest.mark.parametrize("field,value", [
    ("max_connections", True), ("max_connections", 0), ("max_connections", 3),
    ("max_prefix_digits", False), ("max_frame_bytes", 128.0),
    ("max_queue_events", -1), ("max_queue_bytes", 0),
    ("max_connection_buffer_bytes", 134),
])
def test_config_rejects_wrong_types_and_contradictory_limits(field, value):
    with pytest.raises(CollectionCoreError) as raised:
        _config(**{field: value})
    assert raised.value.code == CollectionErrorCode.INVALID_CONFIG


def test_json_config_loader_rejects_duplicate_keys_and_hides_parse_input():
    with pytest.raises(CollectionCoreError) as duplicate:
        TcpCollectionConfig.from_json(
            '{"schema_version":"tcp-syslog-config/v1",'
            '"schema_version":"PRIVATE_CANARY"}'
        )
    assert duplicate.value.code == CollectionErrorCode.INVALID_CONFIG
    assert "PRIVATE_CANARY" not in str(duplicate.value) + repr(duplicate.value)


def test_octet_counting_decodes_exact_payloads_and_multiple_frames():
    decoder = OctetCountingDecoder(_config())
    result = decoder.feed(b"5 hello11 hello world")
    assert tuple(frame.payload for frame in result.frames) == ("hello", "hello world")
    assert tuple(frame.payload_byte_count for frame in result.frames) == (5, 11)
    assert result.buffered_bytes == 0
    assert result.terminal is False


@pytest.mark.parametrize("bad", [
    b" hello", b"+1 x", b"-1 x", b"01 x", b"0 ", b"1\tx", b"1\nx",
    b"1  x", b"129 x", b"999999999999999999999999 x", b"x x",
])
def test_malformed_prefix_is_terminal_and_never_echoed(bad):
    decoder = OctetCountingDecoder(_config())
    result = decoder.feed(bad)
    assert result.terminal is True
    assert result.error_category in {
        CollectionErrorCode.INVALID_PREFIX,
        CollectionErrorCode.PREFIX_TOO_LONG,
        CollectionErrorCode.FRAME_TOO_LARGE,
    }
    assert result.buffered_bytes == 0
    assert result.to_dict()["error_category"] == result.error_category.value
    assert "ACCOUNT_PRIVATE_CANARY" not in repr(result)


@pytest.mark.parametrize("payload,code", [
    (b"\xff", CollectionErrorCode.INVALID_UTF8),
    (b"a\x00b", CollectionErrorCode.FORBIDDEN_CONTROL),
    (b"a\x01b", CollectionErrorCode.FORBIDDEN_CONTROL),
    (b"a\x7fb", CollectionErrorCode.FORBIDDEN_CONTROL),
])
def test_payload_validation_fails_closed(payload, code):
    decoder = OctetCountingDecoder(_config())
    result = decoder.feed(str(len(payload)).encode() + b" " + payload)
    assert result.error_category == code
    assert result.terminal
    assert result.frames == ()


def test_payload_is_not_trimmed_or_unicode_normalized():
    payload = " e\u0301 "
    result = OctetCountingDecoder(_config()).feed(
        str(len(payload.encode())).encode() + b" " + payload.encode()
    )
    assert result.frames[0].payload == payload


def test_canary_is_only_available_on_ephemeral_frame_not_safe_representations():
    canary = "account-canary 192.0.2.99 host.invalid /private/sample.log token-canary"
    payload = canary.encode()
    result = OctetCountingDecoder(_config()).feed(str(len(payload)).encode() + b" " + payload)
    frame = result.frames[0]
    queue = BoundedEventQueue(_config())
    item = queue.enqueue(frame)
    safe = repr(frame) + repr(item) + repr(result) + repr(queue.snapshot())
    safe += json.dumps(_config().new_status().snapshot().to_dict(), sort_keys=True)
    assert canary not in safe
    assert item.payload == canary


def test_oversized_input_chunk_fails_without_unbounded_frame_result():
    decoder = OctetCountingDecoder(_config())
    result = decoder.feed(b"1 x" * 100)
    assert result.error_category == CollectionErrorCode.CONNECTION_BUFFER_FULL
    assert result.terminal and result.frames == () and result.buffered_bytes == 0


def test_partial_frame_is_bounded_and_close_reports_incomplete():
    decoder = OctetCountingDecoder(_config())
    first = decoder.feed(b"5 he")
    assert first.frames == ()
    assert first.buffered_bytes == 2
    assert first.awaiting_bytes == 3
    closed = decoder.close()
    assert closed.terminal
    assert closed.error_category == CollectionErrorCode.INCOMPLETE_FRAME
    assert closed.buffered_bytes == 0
    assert decoder.close() == closed
    assert decoder.feed(b"llo").error_category == CollectionErrorCode.DECODER_CLOSED


def test_prefix_only_slowloris_is_bounded_and_rejected_at_limit():
    decoder = OctetCountingDecoder(_config(max_prefix_digits=3,
                                            max_connection_buffer_bytes=132,
                                            max_frame_bytes=128))
    assert decoder.feed(b"1").buffered_bytes == 1
    assert decoder.feed(b"2").buffered_bytes == 2
    assert decoder.feed(b"3").buffered_bytes == 3
    result = decoder.feed(b"4")
    assert result.error_category == CollectionErrorCode.PREFIX_TOO_LONG
    assert result.buffered_bytes == 0


def test_feed_after_malformed_frame_is_closed_and_idempotent():
    decoder = OctetCountingDecoder(_config())
    malformed = decoder.feed(b"x")
    assert malformed.error_category == CollectionErrorCode.INVALID_PREFIX
    assert decoder.feed(b"1 a").error_category == CollectionErrorCode.DECODER_CLOSED
    assert decoder.close().buffered_bytes == 0


@settings(max_examples=80, database=None, derandomize=True)
@given(payload=st.text(
    alphabet=st.characters(blacklist_categories=("Cc", "Cs")),
    min_size=1,
    max_size=120,
))
def test_all_chunk_splits_produce_identical_validated_frame(payload):
    encoded = payload.encode("utf-8")
    wire = str(len(encoded)).encode("ascii") + b" " + encoded
    for split in range(len(wire) + 1):
        decoder = OctetCountingDecoder(_config())
        first = decoder.feed(wire[:split])
        second = decoder.feed(wire[split:])
        assert tuple(frame.payload for frame in first.frames + second.frames) == (payload,)
        assert first.error_category is None and second.error_category is None
        assert first.buffered_bytes <= 135 and second.buffered_bytes <= 135


@settings(max_examples=80, database=None, derandomize=True)
@given(chunks=st.lists(st.binary(max_size=32), min_size=0, max_size=24))
def test_arbitrary_bytes_never_exceed_connection_buffer(chunks):
    decoder = OctetCountingDecoder(_config())
    for chunk in chunks:
        result = decoder.feed(chunk)
        assert 0 <= result.buffered_bytes <= 135
        if result.terminal:
            break
    assert decoder.snapshot().buffered_bytes <= 135


def test_queue_enforces_event_and_byte_caps_fifo_and_safe_repr():
    queue = BoundedEventQueue(_config(max_queue_events=2, max_queue_bytes=5))
    decoder = OctetCountingDecoder(_config())
    frames = decoder.feed(b"3 abc2 de").frames
    first = queue.enqueue(frames[0])
    second = queue.enqueue(frames[1])
    assert (first.receipt_id, second.receipt_id) == (1, 2)
    assert queue.snapshot().queued_events == 2
    assert queue.snapshot().queued_bytes == 5
    assert "abc" not in repr(first) + repr(queue.snapshot())
    with pytest.raises(CollectionCoreError) as raised:
        queue.enqueue(frames[0])
    assert raised.value.code == CollectionErrorCode.QUEUE_FULL
    snapshot = queue.snapshot()
    assert (snapshot.accepted_count, snapshot.rejected_count, snapshot.dequeued_count) == (2, 1, 0)
    assert queue.dequeue().payload == "abc"
    assert queue.dequeue().payload == "de"
    assert (queue.snapshot().queued_events, queue.snapshot().queued_bytes) == (0, 0)


def test_queue_rejects_byte_overflow_without_partial_enqueue_or_receipt_gap():
    queue = BoundedEventQueue(_config(max_queue_events=8, max_queue_bytes=4))
    frame = ValidatedFrame(source_role="application", payload="12345", payload_byte_count=5)
    with pytest.raises(CollectionCoreError) as raised:
        queue.enqueue(frame)
    assert raised.value.code == CollectionErrorCode.QUEUE_FULL
    assert queue.snapshot().accepted_count == 0
    assert queue.snapshot().rejected_count == 1
    assert queue.enqueue(ValidatedFrame("application", "ok", 2)).receipt_id == 1


def test_queue_close_counts_pending_as_dropped_and_is_idempotent():
    queue = BoundedEventQueue(_config())
    frame = OctetCountingDecoder(_config()).feed(b"3 abc").frames[0]
    queue.enqueue(frame)
    queue.close()
    queue.close()
    snapshot = queue.snapshot()
    assert snapshot.queued_events == 0
    assert snapshot.queued_bytes == 0
    assert snapshot.dropped_count == 1
    with pytest.raises(CollectionCoreError) as raised:
        queue.enqueue(frame)
    assert raised.value.code == CollectionErrorCode.QUEUE_CLOSED


def test_queue_admission_fault_is_sanitized_and_does_not_accept(monkeypatch):
    queue = BoundedEventQueue(_config())
    frame = OctetCountingDecoder(_config()).feed(b"3 abc").frames[0]

    def fail(_item):
        raise RuntimeError("ACCOUNT_PRIVATE_CANARY /secret/path")

    monkeypatch.setattr(BoundedEventQueue, "_admit_item", lambda _self, item: fail(item))
    with pytest.raises(CollectionCoreError) as raised:
        queue.enqueue(frame)
    assert raised.value.code == CollectionErrorCode.INTERNAL_FAILURE
    assert "CANARY" not in str(raised.value) + repr(raised.value)
    snapshot = queue.snapshot()
    assert (snapshot.accepted_count, snapshot.rejected_count, snapshot.queued_events) == (0, 1, 0)


def test_queue_partial_admission_fault_rolls_back_without_receipt_gap(monkeypatch):
    queue = BoundedEventQueue(_config())
    frame = OctetCountingDecoder(_config()).feed(b"3 abc").frames[0]

    def append_then_fail(self, item):
        self._items.append(item)
        raise RuntimeError("PRIVATE_CANARY")

    monkeypatch.setattr(BoundedEventQueue, "_admit_item", append_then_fail)
    with pytest.raises(CollectionCoreError) as raised:
        queue.enqueue(frame)
    assert raised.value.code == CollectionErrorCode.INTERNAL_FAILURE
    assert queue.snapshot().queued_events == 0
    assert queue.snapshot().accepted_count == 0
    monkeypatch.undo()
    assert queue.enqueue(frame).receipt_id == 1


def test_dequeue_fault_does_not_report_completion_or_mutate_head(monkeypatch):
    queue = BoundedEventQueue(_config())
    frame = OctetCountingDecoder(_config()).feed(b"3 abc").frames[0]
    queue.enqueue(frame)

    def fail(_self):
        raise RuntimeError("PRIVATE_CANARY")

    monkeypatch.setattr(BoundedEventQueue, "_dequeue_head", fail)
    with pytest.raises(CollectionCoreError) as raised:
        queue.dequeue()
    assert raised.value.code == CollectionErrorCode.INTERNAL_FAILURE
    assert queue.snapshot().dequeued_count == 0
    assert queue.snapshot().queued_events == 1


def test_decoder_internal_failure_is_fixed_and_terminal(monkeypatch):
    decoder = OctetCountingDecoder(_config())

    def fail(_buffer, _data):
        raise RuntimeError("INTERNAL_EXCEPTION_CANARY")

    monkeypatch.setattr("app.log_collection.framing._append_payload", fail)
    result = decoder.feed(b"3 abc")
    assert result.error_category == CollectionErrorCode.INTERNAL_FAILURE
    assert result.terminal and result.buffered_bytes == 0
    assert "INTERNAL_EXCEPTION_CANARY" not in repr(result) + str(result.error_category)


def test_decoder_utf8_fault_is_fixed_and_terminal(monkeypatch):
    decoder = OctetCountingDecoder(_config())

    def fail(_payload):
        raise RuntimeError("RAW_INTERNAL_CANARY")

    monkeypatch.setattr("app.log_collection.framing._decode_payload", fail)
    result = decoder.feed(b"3 abc")
    assert result.error_category == CollectionErrorCode.INTERNAL_FAILURE
    assert result.terminal and result.buffered_bytes == 0
    assert "RAW_INTERNAL_CANARY" not in repr(result)


def test_queue_close_cleanup_fault_releases_references_and_is_terminal(monkeypatch):
    queue = BoundedEventQueue(_config())
    frame = OctetCountingDecoder(_config()).feed(b"3 abc").frames[0]
    queue.enqueue(frame)

    def fail(_self):
        raise RuntimeError("ACCOUNT_PRIVATE_CANARY /private/path")

    monkeypatch.setattr(BoundedEventQueue, "_clear_items", fail)
    with pytest.raises(CollectionCoreError) as raised:
        queue.close()
    assert raised.value.code == CollectionErrorCode.INTERNAL_FAILURE
    assert "CANARY" not in str(raised.value) + repr(raised.value)
    snapshot = queue.snapshot()
    assert snapshot.closed and snapshot.queued_events == snapshot.queued_bytes == 0
    assert snapshot.dropped_count == 1
    queue.close()


def test_invalid_queue_item_is_rejected_and_does_not_consume_receipt_id():
    queue = BoundedEventQueue(_config())
    bad = ValidatedFrame("ssh", "private", 7)
    with pytest.raises(CollectionCoreError):
        queue.enqueue(bad)
    frame = OctetCountingDecoder(_config()).feed(b"2 ok").frames[0]
    assert queue.enqueue(frame).receipt_id == 1
    assert queue.snapshot().rejected_count == 1


@pytest.mark.parametrize("frame", [
    ValidatedFrame("application", "x", True),
    ValidatedFrame("application", "x" * 129, 129),
])
def test_queue_revalidates_frame_size_and_byte_count(frame):
    queue = BoundedEventQueue(_config())
    with pytest.raises(CollectionCoreError):
        queue.enqueue(frame)
    assert queue.snapshot().accepted_count == 0
    assert queue.snapshot().rejected_count == 1


def test_status_dto_is_closed_safe_and_transitions_are_closed():
    status = _config().new_status()
    assert status.snapshot().state == CollectionState.STARTING
    status.transition(CollectionState.READY)
    status.record_accepted(datetime(2026, 1, 1, tzinfo=timezone.utc))
    snapshot = status.snapshot()
    wire = json.dumps(snapshot.to_dict(), sort_keys=True)
    assert snapshot.accepted_frames == 1
    assert snapshot.last_success_at == "2026-01-01T00:00:00.000000Z"
    assert "payload" not in wire and "bind_address" not in wire
    with pytest.raises(CollectionCoreError) as raised:
        status.transition(CollectionState.STARTING)
    assert raised.value.code == CollectionErrorCode.INVALID_STATE
    status.transition(CollectionState.STOPPED)
    assert status.snapshot().active_connections == 0


def test_status_rejects_active_connection_over_limit_and_failure_cannot_recover():
    status = _config().new_status()
    status.transition(CollectionState.FAILED, error_category=CollectionErrorCode.INTERNAL_FAILURE)
    with pytest.raises(CollectionCoreError):
        status.transition(CollectionState.READY)
    status.transition(CollectionState.STOPPED)
    with pytest.raises(CollectionCoreError):
        status.set_active_connections(1)


def test_status_counters_and_queue_usage_are_bounded_and_dropped_starts_at_zero():
    status = _config().new_status()
    status.set_queue_usage(8, 1024)
    status.record_rejected()
    assert status.snapshot().dropped_frames == 0
    assert status.snapshot().rejected_frames == 1
    with pytest.raises(CollectionCoreError):
        status.set_queue_usage(9, 0)
    status.record_dropped()
    assert status.snapshot().dropped_frames == 1


def test_status_internal_exception_is_not_exposed(monkeypatch):
    status = _config().new_status()

    def fail():
        raise RuntimeError("PRIVATE_EXCEPTION_CANARY")

    monkeypatch.setattr(type(status), "_build_snapshot", lambda _self: fail())
    with pytest.raises(CollectionCoreError) as raised:
        status.snapshot()
    assert raised.value.code == CollectionErrorCode.INTERNAL_FAILURE
    assert "PRIVATE_EXCEPTION_CANARY" not in str(raised.value) + repr(raised.value)
