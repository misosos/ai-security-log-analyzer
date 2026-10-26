import json
import os
import time

import pytest
from hypothesis import given, strategies as st

from app.log_collection.jsonl_adapter import (
    AdapterErrorCode,
    AdapterState,
    BoundedJsonLinesQueue,
    JsonLinesDecoder,
    JsonlAdapterConfig,
    JsonlAdapterError,
    safe_status_snapshot,
)


def envelope(payload="synthetic record", *, role="application", alias="collector-1",
             sequence=None, retry=False):
    return {
        "schema_version": 1,
        "source_role": role,
        "payload": payload,
        "collector_instance_alias": alias,
        "sequence_hint": sequence,
        "retry_hint": retry,
    }


def line(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def test_decoder_returns_only_complete_lines_and_supports_arbitrary_chunking():
    raw = line(envelope("hello")) + line(envelope("안녕", sequence="seq-2", retry=True))
    expected = ["hello", "안녕"]
    for split in range(len(raw) + 1):
        decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
        first = decoder.feed(raw[:split])
        second = decoder.feed(raw[split:])
        assert [item.payload for item in first.records + second.records] == expected
        assert first.error_category is second.error_category is None
        assert decoder.close().error_category is None


def test_closed_schema_validation_rejects_duplicate_unknown_constant_and_role_mismatch():
    config = JsonlAdapterConfig(source_role="application")
    decoder = JsonLinesDecoder(config)
    cases = (
        (b'{"schema_version":1,"schema_version":1}\n', AdapterErrorCode.DUPLICATE_KEY),
        (line({**envelope(), "extra": "private"}), AdapterErrorCode.UNKNOWN_FIELD),
        (b'{"schema_version":NaN}\n', AdapterErrorCode.INVALID_JSON),
        (line(envelope(role="ssh")), AdapterErrorCode.ROLE_MISMATCH),
        (line({**envelope(), "schema_version": True}), AdapterErrorCode.INVALID_SCHEMA),
    )
    for raw, expected in cases:
        result = decoder.feed(raw)
        assert result.terminal
        assert result.error_category is expected
        decoder = JsonLinesDecoder(config)


@pytest.mark.parametrize("raw,code", [
    (b"\xff\n", AdapterErrorCode.INVALID_UTF8),
    (b"\xef\xbb\xbf{}\n", AdapterErrorCode.INVALID_JSON),
    (b"\n", AdapterErrorCode.INVALID_JSON),
    (b"{}\r\n", AdapterErrorCode.INVALID_JSON),
    (b'{"schema_version":Infinity}\n', AdapterErrorCode.INVALID_JSON),
])
def test_malformed_lines_fail_closed_without_exposing_input(raw, code):
    result = JsonLinesDecoder(JsonlAdapterConfig(source_role="ssh")).feed(raw)
    assert result.error_category is code
    assert result.terminal
    assert "\xff" not in str(result) + repr(result)


def test_payload_controls_and_utf8_byte_limit_are_rejected_not_repaired():
    config = JsonlAdapterConfig(source_role="application", max_payload_bytes=6)
    decoder = JsonLinesDecoder(config)
    assert decoder.feed(line(envelope("안녕"))).records[0].payload == "안녕"
    rejected = JsonLinesDecoder(config).feed(line(envelope("a\nb")))
    assert rejected.error_category is AdapterErrorCode.FORBIDDEN_CONTROL
    oversized = JsonLinesDecoder(config).feed(line(envelope("🙂🙂")))
    assert oversized.error_category is AdapterErrorCode.PAYLOAD_TOO_LARGE
    with pytest.raises(ValueError):
        "\ud800".encode("utf-8", errors="strict")


def test_record_byte_limit_includes_delimiter_and_partial_record_is_bounded():
    config = JsonlAdapterConfig(source_role="application", max_record_bytes=256,
                                max_payload_bytes=1, max_connection_buffer_bytes=256)
    decoder = JsonLinesDecoder(config)
    result = decoder.feed(b"{" * 256)
    assert result.error_category is AdapterErrorCode.RECORD_TOO_LARGE
    assert result.buffered_bytes == 0
    assert result.terminal
    partial = JsonLinesDecoder(config).feed(b"{" * 100)
    assert partial.buffered_bytes <= config.max_connection_buffer_bytes
    assert JsonLinesDecoder(config).close().error_category is None


def test_eof_with_partial_record_is_rejected_and_decoder_close_is_idempotent():
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="ssh"))
    decoder.feed(b'{"schema_version":1')
    first = decoder.close()
    assert first.error_category is AdapterErrorCode.INCOMPLETE_RECORD
    assert first.terminal and first.buffered_bytes == 0
    assert decoder.close() == first
    assert decoder.feed(b"{}\n").error_category is AdapterErrorCode.DECODER_CLOSED


def test_envelope_repr_and_safe_result_hide_payload_alias_and_sequence():
    secretish = "canary-payload-host-ip-path-token"
    result = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(
        line(envelope(secretish, alias="safe-alias", sequence="opaque-sequence"))
    )
    item = result.records[0]
    safe = json.dumps(result.to_dict(), sort_keys=True) + repr(result) + repr(item)
    assert secretish not in safe
    assert "opaque-sequence" not in safe
    assert "safe-alias" not in safe
    assert secretish == item.payload


def test_queue_enforces_event_and_byte_limits_fifo_and_safe_snapshot():
    config = JsonlAdapterConfig(source_role="application", max_queue_events=2,
                                max_queue_bytes=10)
    decoder = JsonLinesDecoder(config)
    records = decoder.feed(line(envelope("1234", alias="c")) +
                           line(envelope("5678", alias="c"))).records
    queue = BoundedJsonLinesQueue(config)
    first = queue.enqueue(records[0])
    second = queue.enqueue(records[1])
    assert first.receipt_id == 1 and second.receipt_id == 2
    with pytest.raises(JsonlAdapterError) as error:
        queue.enqueue(records[0])
    assert getattr(error.value, "code", None) is AdapterErrorCode.QUEUE_FULL
    snapshot = queue.snapshot()
    assert snapshot.queued_events == 2 and snapshot.queued_bytes == 10
    assert "1234" not in repr(snapshot) + json.dumps(snapshot.to_dict())
    status = safe_status_snapshot(config, snapshot, state=AdapterState.READY,
                                  error_category=AdapterErrorCode.QUEUE_FULL)
    safe_status = repr(status) + json.dumps(status.to_dict(), sort_keys=True)
    assert "1234" not in safe_status and "collector-1" not in safe_status
    assert "collector-jsonl-status/v1" in safe_status
    assert queue.dequeue().payload == "1234"
    assert queue.dequeue().payload == "5678"
    assert queue.snapshot().accepted == 2
    assert queue.snapshot().dequeued == 2
    assert queue.enqueue(records[0]).receipt_id == 3


def test_queue_close_counts_pending_as_dropped_and_is_idempotent():
    config = JsonlAdapterConfig(source_role="ssh")
    record = JsonLinesDecoder(config).feed(line(envelope("ssh synthetic", role="ssh"))).records[0]
    queue = BoundedJsonLinesQueue(config)
    queue.enqueue(record)
    queue.close()
    queue.close()
    snapshot = queue.snapshot()
    assert snapshot.closed and snapshot.queued_events == 0
    assert snapshot.accepted == 1 and snapshot.dequeued == 0 and snapshot.dropped == 1
    with pytest.raises(JsonlAdapterError) as error:
        queue.enqueue(record)
    assert getattr(error.value, "code", None) is AdapterErrorCode.QUEUE_CLOSED


def test_queue_byte_limit_rejects_whole_next_record_without_advancing_receipt_id():
    config = JsonlAdapterConfig(source_role="application", max_queue_events=5,
                                max_queue_bytes=9)
    records = JsonLinesDecoder(config).feed(
        line(envelope("1234", alias="c")) + line(envelope("5678", alias="c"))
    ).records
    queue = BoundedJsonLinesQueue(config)
    first = queue.enqueue(records[0])
    with pytest.raises(JsonlAdapterError) as error:
        queue.enqueue(records[1])
    assert getattr(error.value, "code", None) is AdapterErrorCode.QUEUE_FULL
    assert queue.snapshot().queued_events == 1
    assert queue.snapshot().queued_bytes == 5
    assert queue.snapshot().accepted == 1 and queue.snapshot().rejected == 1
    assert queue.dequeue().receipt_id == first.receipt_id
    assert queue.enqueue(records[1]).receipt_id == first.receipt_id + 1


def test_config_rejects_bool_float_unbounded_and_invalid_role_with_safe_repr():
    for kwargs in (
        {"max_record_bytes": True}, {"max_payload_bytes": 1.0},
        {"max_queue_events": 10**9}, {"source_role": "access"}, {"source_role": []},
    ):
        with pytest.raises(ValueError):
            JsonlAdapterConfig(**{"source_role": "application", **kwargs})
    config = JsonlAdapterConfig(source_role="ssh")
    assert "127.0.0.1" not in repr(config) and "port" not in repr(config)


@given(st.lists(st.sampled_from([0x00, 0x0A, 0x7F, 0x80, 0xFF, ord("{"), ord("}")]),
                max_size=4096).map(bytes))
def test_arbitrary_bytes_never_exceed_decoder_buffer_bound(data):
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    for start in range(0, len(data), 17):
        result = decoder.feed(data[start:start + 17])
        assert result.buffered_bytes <= decoder.config.max_connection_buffer_bytes
        if result.terminal:
            break


@given(st.lists(st.sampled_from(["ASCII fixture", "로그 합성", "🙂 boundary", "colon:value"]),
                min_size=1, max_size=8))
def test_concatenated_jsonl_records_preserve_order(payloads):
    # Fixed synthetic values keep failing examples safe and reproducible.
    raw = b"".join(line(envelope(payload)) for payload in payloads)
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    output = []
    for byte in raw:
        result = decoder.feed(bytes([byte]))
        assert result.buffered_bytes <= decoder.config.max_connection_buffer_bytes
        if result.error_category is None:
            output.extend(item.payload for item in result.records)
        else:
            break
    assert output == payloads


@given(
    st.sampled_from(["ASCII fixture", "로그 합성", "🙂 boundary", "a\\nb"]),
    st.lists(st.integers(min_value=1, max_value=17), min_size=1, max_size=40),
)
def test_hypothesis_chunk_boundaries_preserve_utf8_record(payload, widths):
    # Fixed synthetic values keep a failing Hypothesis example safe to print.
    raw = line(envelope(payload))
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    records = []
    offset = 0
    for width in widths:
        if offset >= len(raw):
            break
        result = decoder.feed(raw[offset:offset + width])
        offset += width
        assert result.buffered_bytes <= decoder.config.max_connection_buffer_bytes
        records.extend(result.records)
        assert result.error_category is None
    if offset < len(raw):
        result = decoder.feed(raw[offset:])
        records.extend(result.records)
        assert result.error_category is None
    assert [item.payload for item in records] == [payload]


@given(st.sampled_from(["안녕", "🙂 boundary"]))
def test_hypothesis_exercises_every_utf8_multibyte_split_point(payload):
    raw = line(envelope(payload))
    for split in range(len(raw) + 1):
        decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
        left = decoder.feed(raw[:split])
        right = decoder.feed(raw[split:])
        assert left.error_category is None and right.error_category is None
        assert [item.payload for item in left.records + right.records] == [payload]


def test_exact_record_limit_succeeds_and_one_byte_over_fails():
    config = JsonlAdapterConfig(source_role="application")
    raw = line(envelope("x" * config.max_payload_bytes))
    padding = config.max_record_bytes - len(raw)
    exact = raw[:-2] + b" " * padding + raw[-2:]
    assert len(exact) == config.max_record_bytes
    result = JsonLinesDecoder(config).feed(exact)
    assert result.error_category is None and len(result.records) == 1
    too_long = raw[:-2] + b" " * (padding + 1) + raw[-2:]
    assert len(too_long) == config.max_record_bytes + 1
    result = JsonLinesDecoder(config).feed(too_long)
    assert result.error_category is AdapterErrorCode.RECORD_TOO_LARGE
    assert result.buffered_bytes == 0 and result.terminal


def test_missing_fields_non_finite_overflow_and_unpaired_surrogates_are_rejected():
    config = JsonlAdapterConfig(source_role="application")
    missing = line({key: value for key, value in envelope().items() if key != "retry_hint"})
    huge_float = b'{"schema_version":1e999}\n'
    surrogate = json.dumps(envelope("x"), separators=(",", ":")).replace(
        '"payload":"x"', '"payload":"\\ud800"'
    ).encode() + b"\n"
    cases = (
        (missing, AdapterErrorCode.INVALID_SCHEMA),
        (b'{"schema_version":Infinity}\n', AdapterErrorCode.INVALID_JSON),
        (huge_float, AdapterErrorCode.INVALID_JSON),
        (surrogate, AdapterErrorCode.INVALID_UTF8),
    )
    for raw, expected in cases:
        result = JsonLinesDecoder(config).feed(raw)
        assert result.error_category is expected
        assert result.terminal and result.buffered_bytes == 0


def test_synthetic_canaries_are_absent_from_errors_repr_status_and_logs(caplog):
    canaries = (
        "acct-canary", "192.0.2.10", "2001:db8::5", "host-canary.invalid",
        "input-canary.log", "/tmp/synth-canary", "credential-canary",
        "internal-exception-canary", "raw-message-canary",
    )
    payload = " ".join(canaries)
    config = JsonlAdapterConfig(source_role="application")
    decoder = JsonLinesDecoder(config)
    event = decoder.feed(line(envelope(payload, alias="alias-canary", sequence="sequence-canary"))).records[0]
    queue = BoundedJsonLinesQueue(config)
    queue.enqueue(event)
    status = safe_status_snapshot(config, queue.snapshot(), state=AdapterState.READY)
    bad = JsonLinesDecoder(config).feed(
        line({**envelope("safe"), "unexpected": canaries[0]})
    )
    outward = " ".join((str(JsonlAdapterError(bad.error_category)), repr(JsonlAdapterError(bad.error_category)),
                        repr(event), repr(queue.snapshot()), repr(status), json.dumps(status.to_dict()),
                        json.dumps(bad.to_dict()), " ".join(record.getMessage() for record in caplog.records)))
    assert all(value not in outward for value in (*canaries, "alias-canary", "sequence-canary"))
    assert event.payload == payload


def test_safe_status_and_errors_are_timezone_independent_byte_for_byte(monkeypatch):
    config = JsonlAdapterConfig(source_role="ssh")
    queue = BoundedJsonLinesQueue(config)
    outputs = []
    old_tz = os.environ.get("TZ")
    try:
        for zone in ("UTC", "Asia/Seoul"):
            monkeypatch.setenv("TZ", zone)
            time.tzset()
            status = safe_status_snapshot(config, queue.snapshot(), state=AdapterState.FAILED,
                                          error_category=AdapterErrorCode.INVALID_JSON)
            outputs.append(json.dumps(status.to_dict(), sort_keys=True, separators=(",", ":")).encode()
                           + str(JsonlAdapterError(AdapterErrorCode.INVALID_JSON)).encode())
    finally:
        if old_tz is None:
            monkeypatch.delenv("TZ", raising=False)
        else:
            monkeypatch.setenv("TZ", old_tz)
        time.tzset()
    assert outputs[0] == outputs[1]


def test_adapter_module_has_no_io_or_analysis_integration_imports():
    from pathlib import Path

    source = Path(__file__).parents[1] / "app" / "log_collection" / "jsonl_adapter.py"
    text = source.read_text(encoding="utf-8")
    for forbidden in ("import socket", "import asyncio", "import subprocess", "open(",
                      "create_connection", "parser", "checkpoint", "publication", "restricted_report"):
        assert forbidden not in text


def test_one_feed_has_a_bounded_number_of_returned_events():
    raw = b"".join(line(envelope("x")) for _ in range(33))
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    result = decoder.feed(raw)
    # A batch cap must not partially accept a caller's chunk and silently lose
    # its unconsumed suffix: reject the whole oversized batch before parsing.
    assert result.records == ()
    assert result.error_category is AdapterErrorCode.FEED_EVENT_LIMIT
    assert result.terminal
    assert decoder.validated_records == 0


def test_jsonl_batch_boundary_accepts_32_records_and_rejects_33_atomically():
    raw = b"".join(line(envelope("synthetic")) for _ in range(32))
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    result = decoder.feed(raw)
    assert len(result.records) == 32
    assert result.error_category is None
    assert decoder.validated_records == 32

    next_decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    overflow = next_decoder.feed(raw + line(envelope("synthetic")))
    assert overflow.records == ()
    assert overflow.error_category is AdapterErrorCode.FEED_EVENT_LIMIT
    assert next_decoder.validated_records == 0
