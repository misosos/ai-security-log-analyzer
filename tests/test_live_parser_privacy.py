import json
import pprint

import pytest

from app.live_monitoring import LiveParseError, LiveTailRecord, parse_live_records


def _record(role: str, sequence: int, payload: str) -> LiveTailRecord:
    return LiveTailRecord(role, sequence, payload, len(payload.encode("utf-8")))


def test_parsed_event_is_trusted_but_batch_and_outcome_repr_are_safe(capsys, caplog):
    account = "ACCOUNT_CANARY_PHASE121"
    line = f"2026-01-02 03:04:05 INFO user_login user={account} ip=192.0.2.1"
    result = parse_live_records("application", (_record("application", 1, line),))
    assert result.outcomes[0].event.user == account
    public_surfaces = (
        repr(result), str(result), repr(result.outcomes),
        pprint.pformat(result), json.dumps(result, default=str),
        capsys.readouterr().out, capsys.readouterr().err, caplog.text,
    )
    assert all(account not in surface and line not in surface for surface in public_surfaces)
    with pytest.raises(TypeError):
        json.dumps(result)


def test_ignored_rejected_and_errors_do_not_retain_raw_payload():
    canary = "RAW_CANARY_PHASE121"
    ignored = parse_live_records("access", (_record("access", 1, f"{canary} unsupported"),))
    rejected = parse_live_records("application", (_record("application", 1, canary),))
    assert ignored.outcomes[0].event is None
    assert ignored.outcomes[0].fixed_reason_code is None
    assert rejected.outcomes[0].event is None
    assert rejected.outcomes[0].fixed_reason_code == "MALFORMED_APPLICATION_RECORD"
    for value in (repr(ignored), repr(rejected), str(ignored), str(rejected)):
        assert canary not in value
    try:
        parse_live_records("unexpected role " + canary, ())
    except LiveParseError as error:
        assert canary not in str(error) + repr(error)
    else:
        pytest.fail("unknown source role was accepted")


def test_no_parser_adapter_public_route_or_import_side_effect():
    import inspect
    from app.live_monitoring import parser_adapter

    source = inspect.getsource(parser_adapter)
    for forbidden in (
        "from app.detector", "from app.correlation", "from app.analyzer.pipeline",
        "from app.analyzer.risk", "FastAPI", "StreamingResponse", "print(",
        "open(", "Path.open(",
    ):
        assert forbidden not in source
