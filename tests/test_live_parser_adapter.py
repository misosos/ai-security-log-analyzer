from datetime import datetime, timezone

import pytest

from app.live_monitoring import LiveParseError, LiveTailRecord, parse_live_records
from app.models.schemas import NormalizedEvent


APP_LINE = "2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1"
SSH_LINE = "2026-01-02 03:04:05 sshd: Failed password for synthetic from 192.0.2.1"
ACCESS_LINE = '192.0.2.1 - - [02/Jan/2026:03:04:05 +0900] "GET /safe HTTP/1.1" 200 1'


def _record(role: str, sequence: int, payload: str) -> LiveTailRecord:
    return LiveTailRecord(role, sequence, payload, len(payload.encode("utf-8")))


@pytest.mark.parametrize(("role", "line"), (
    ("application", APP_LINE), ("ssh", SSH_LINE), ("access", ACCESS_LINE),
))
def test_known_role_parses_existing_registry_event(role, line):
    result = parse_live_records(role, (_record(role, 7, line),))
    assert result.source_role == role
    assert (result.parsed_count, result.ignored_count, result.rejected_count) == (1, 0, 0)
    assert result.outcomes[0].sequence == 7
    assert result.outcomes[0].status == "PARSED"
    assert type(result.outcomes[0].event) is NormalizedEvent
    assert result.outcomes[0].event.timestamp == datetime(2026, 1, 1, 18, 4, 5, tzinfo=timezone.utc)


def test_blank_and_access_none_remain_visible_ignored_outcomes():
    result = parse_live_records("access", (
        _record("access", 1, " \t "), _record("access", 3, "unsupported request"),
    ))
    assert (result.parsed_count, result.ignored_count, result.rejected_count) == (0, 2, 0)
    assert tuple((item.sequence, item.status, item.event) for item in result.outcomes) == (
        (1, "IGNORED", None), (3, "IGNORED", None),
    )


@pytest.mark.parametrize(("role", "line", "code"), (
    ("application", "malformed timestamp", "MALFORMED_APPLICATION_RECORD"),
    ("ssh", "malformed timestamp", "MALFORMED_SSH_RECORD"),
    ("access", '192.0.2.1 - - [not-a-date] "GET / HTTP/1.1" 200 1', "MALFORMED_ACCESS_RECORD"),
))
def test_expected_parser_exceptions_are_rejected_not_ignored(role, line, code):
    result = parse_live_records(role, (_record(role, 1, line),))
    assert (result.parsed_count, result.ignored_count, result.rejected_count) == (0, 0, 1)
    assert result.outcomes[0].status == "REJECTED"
    assert result.outcomes[0].fixed_reason_code == code
    assert result.outcomes[0].event is None


@pytest.mark.parametrize(("source", "records", "code"), (
    ("application", [], "INVALID_BATCH_TYPE"),
    ("APPLICATION", (), "UNSUPPORTED_ROLE"),
    ("linux_audit", (), "UNSUPPORTED_ROLE"),
    ("application", ("not a record",), "INVALID_RECORD_TYPE"),
    ("application", (_record("ssh", 1, SSH_LINE),), "MIXED_SOURCE_ROLE"),
    ("application", (_record("application", 1, APP_LINE), _record("application", 1, APP_LINE)), "DUPLICATE_SEQUENCE"),
    ("application", (_record("application", 2, APP_LINE), _record("application", 1, APP_LINE)), "DECREASING_SEQUENCE"),
))
def test_batch_contract_fails_before_partial_parse(source, records, code, monkeypatch):
    from app.live_monitoring import parser_adapter

    calls = []
    original = parser_adapter.registry.get_parser

    def counted(role):
        calls.append(role)
        return original(role)

    monkeypatch.setattr(parser_adapter.registry, "get_parser", counted)
    with pytest.raises(LiveParseError) as raised:
        parse_live_records(source, records)
    assert raised.value.code == code
    assert calls == []


def test_sequence_gaps_are_allowed_and_order_is_not_sorted():
    records = (_record("application", 2, APP_LINE), _record("application", 9, APP_LINE))
    result = parse_live_records("application", records)
    assert tuple(item.sequence for item in result.outcomes) == (2, 9)
    assert len(result.outcomes) == result.parsed_count + result.ignored_count + result.rejected_count


def test_parser_and_normalizer_call_counts(monkeypatch):
    from app.live_monitoring import parser_adapter

    original_get = parser_adapter.registry.get_parser
    original_normalize = parser_adapter.normalize_to_utc
    counts = {"dispatch": 0, "parse": 0, "normalize": 0}

    def get_parser(role):
        counts["dispatch"] += 1
        parser = original_get(role)

        def parse(line, zone):
            counts["parse"] += 1
            return parser(line, zone)

        return parse

    def normalize(timestamp):
        counts["normalize"] += 1
        return original_normalize(timestamp)

    monkeypatch.setattr(parser_adapter.registry, "get_parser", get_parser)
    monkeypatch.setattr(parser_adapter, "normalize_to_utc", normalize)
    result = parse_live_records("access", (
        _record("access", 1, " "),
        _record("access", 2, "unsupported request"),
        _record("access", 3, ACCESS_LINE),
    ))
    assert tuple(item.status for item in result.outcomes) == ("IGNORED", "IGNORED", "PARSED")
    assert counts == {"dispatch": 2, "parse": 2, "normalize": 1}


def test_unexpected_parser_result_and_failure_are_bounded(monkeypatch):
    from app.live_monitoring import parser_adapter

    monkeypatch.setattr(parser_adapter.registry, "get_parser", lambda _role: lambda _line, _zone: "wrong")
    with pytest.raises(LiveParseError) as raised:
        parse_live_records("application", (_record("application", 1, APP_LINE),))
    assert raised.value.code == "UNEXPECTED_PARSER_RESULT"

    def broken(_role):
        raise RuntimeError("PRIVATE_INTERNAL_CANARY")

    monkeypatch.setattr(parser_adapter.registry, "get_parser", broken)
    with pytest.raises(LiveParseError) as raised:
        parse_live_records("application", (_record("application", 1, APP_LINE),))
    assert raised.value.code == "UNEXPECTED_PARSER_FAILURE"
    assert "PRIVATE_INTERNAL_CANARY" not in str(raised.value)
    assert raised.value.__cause__ is None


def test_normalization_failure_is_whole_batch_error(monkeypatch):
    from app.live_monitoring import parser_adapter

    monkeypatch.setattr(parser_adapter, "normalize_to_utc", lambda _timestamp: (_ for _ in ()).throw(ValueError("PRIVATE_CANARY")))
    with pytest.raises(LiveParseError) as raised:
        parse_live_records("application", (_record("application", 1, APP_LINE),))
    assert raised.value.code == "UTC_NORMALIZATION_FAILURE"
    assert "PRIVATE_CANARY" not in repr(raised.value)


def test_adapter_never_uses_loader_filesystem_or_analysis_pipeline(monkeypatch):
    import builtins
    from pathlib import Path
    import app.analyzer.pipeline as pipeline

    def forbidden(*_args, **_kwargs):
        raise AssertionError("forbidden path was invoked")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(pipeline, "load_normalized_logs", forbidden)
    monkeypatch.setattr(pipeline, "detect_attacks", forbidden)
    monkeypatch.setattr(pipeline, "correlate_attacks", forbidden)
    result = parse_live_records("application", (_record("application", 1, APP_LINE),))
    assert result.parsed_count == 1


def test_reordered_input_changes_only_order_not_individual_parse_meaning():
    lines = (
        "2026-01-02 03:04:05 INFO login_failed user=one ip=192.0.2.1",
        "2026-01-02 03:04:06 INFO user_login user=two ip=192.0.2.2",
        "2026-01-02 03:04:07 INFO login_failed user=three ip=192.0.2.3",
    )
    first = parse_live_records("application", tuple(
        _record("application", index, line) for index, line in enumerate(lines, 1)
    ))
    second = parse_live_records("application", tuple(
        _record("application", index, line) for index, line in enumerate(reversed(lines), 1)
    ))
    assert tuple(item.event.raw for item in first.outcomes) == lines
    assert tuple(item.event.raw for item in second.outcomes) == tuple(reversed(lines))
    assert {item.event.raw: item.event.timestamp for item in first.outcomes} == {
        item.event.raw: item.event.timestamp for item in second.outcomes
    }
