import json
from pathlib import Path
import re

import pytest

from app.log_collection.jsonl_adapter import (
    AdapterErrorCode,
    JsonLinesDecoder,
    JsonlAdapterConfig,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/vector_jsonl_35_4a"
KEYS = (
    "schema_version",
    "source_role",
    "payload",
    "collector_instance_alias",
    "sequence_hint",
    "retry_hint",
)


@pytest.mark.parametrize("name,role", [
    ("application_ascii.jsonl", "application"),
    ("application_korean.jsonl", "application"),
    ("ssh_ascii.jsonl", "ssh"),
    ("ssh_korean.jsonl", "ssh"),
])
def test_expected_wire_fixtures_are_exact_six_key_jsonl(name, role):
    raw = (FIXTURES / name).read_bytes()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    obj = json.loads(raw[:-1])
    assert tuple(obj) == KEYS
    result = JsonLinesDecoder(JsonlAdapterConfig(source_role=role)).feed(raw)
    assert result.error_category is None
    assert len(result.records) == 1
    assert result.records[0].payload_byte_count == len(obj["payload"].encode("utf-8"))


def test_boundary_and_refusal_fixtures_follow_adapter_byte_contract():
    exact = {
        "schema_version": 1,
        "source_role": "application",
        "payload": "x" * 8192,
        "collector_instance_alias": "vector-pilot",
        "sequence_hint": None,
        "retry_hint": False,
    }
    line = json.dumps(exact, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    accepted = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(line)
    assert accepted.error_category is None
    assert accepted.records[0].payload_byte_count == 8192

    over = dict(exact, payload="x" * 8193)
    rejected = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(
        json.dumps(over, separators=(",", ":")).encode() + b"\n"
    )
    assert rejected.error_category is AdapterErrorCode.PAYLOAD_TOO_LARGE

    invalid_utf8 = (
        b'{"schema_version":1,"source_role":"application","payload":"\xff",'
        b'"collector_instance_alias":"vector-pilot","sequence_hint":null,"retry_hint":false}\n'
    )
    bad_utf8 = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(invalid_utf8)
    assert bad_utf8.error_category is AdapterErrorCode.INVALID_UTF8

    control = dict(exact, payload="tab\tinside")
    bad_control = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(
        json.dumps(control, separators=(",", ":")).encode() + b"\n"
    )
    assert bad_control.error_category is AdapterErrorCode.FORBIDDEN_CONTROL


def test_config_candidate_has_no_duplicate_json_keys_and_only_synthetic_paths():
    path = FIXTURES / "vector_candidate.yaml"
    pairs = []

    def reject_duplicate(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result

    config = json.loads(path.read_text(), object_pairs_hook=reject_duplicate)
    assert config["sources"]["synthetic_file"]["include"] == [
        "/run/vector-pilot/input.log"
    ]
    assert config["sinks"]["jsonl_adapter"]["address"] == "127.0.0.1:39091"
    assert config["api"]["enabled"] is False
    assert set(config["sources"]) == {"synthetic_file"}
    assert set(config["transforms"]) == {"adapter_envelope"}
    assert set(config["sinks"]) == {"jsonl_adapter"}
    transform = config["transforms"]["adapter_envelope"]["source"]
    generated_keys = tuple(re.findall(r'"([a-z_]+)"\s*:', transform))
    assert generated_keys == KEYS
    assert "exec" not in config["sources"] and "exec" not in config["sinks"]
    sink = config["sinks"]["jsonl_adapter"]
    assert sink["framing"]["method"] == "newline_delimited"
    assert sink["encoding"]["codec"] == "json"
    assert sink["buffer"] == {"type": "memory", "max_events": 128, "when_full": "block"}
    assert sink["healthcheck"]["enabled"] is False
    assert sink["acknowledgements"]["enabled"] is True
    assert "$" not in path.read_text()


def test_duplicate_mapping_key_in_json_yaml_subset_is_rejected():
    duplicate_yaml_subset = '{"api":{"enabled":false,"enabled":true}}'

    def reject_duplicate(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    with pytest.raises(ValueError, match="duplicate key"):
        json.loads(duplicate_yaml_subset, object_pairs_hook=reject_duplicate)


def test_escaped_quote_backslash_and_32_33_record_feed_boundary():
    payload = 'quoted "text" and \\ path'
    envelope = {
        "schema_version": 1,
        "source_role": "application",
        "payload": payload,
        "collector_instance_alias": "vector-pilot",
        "sequence_hint": None,
        "retry_hint": False,
    }
    wire = json.dumps(envelope, separators=(",", ":")).encode() + b"\n"
    decoded = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(wire)
    assert decoded.records[0].payload == payload

    one = wire
    decoder = JsonLinesDecoder(JsonlAdapterConfig(source_role="application"))
    batch32 = decoder.feed(one * 32)
    assert batch32.error_category is None and len(batch32.records) == 32
    batch33 = JsonLinesDecoder(JsonlAdapterConfig(source_role="application")).feed(one * 33)
    assert batch33.error_category is AdapterErrorCode.FEED_EVENT_LIMIT
    assert batch33.records == ()
