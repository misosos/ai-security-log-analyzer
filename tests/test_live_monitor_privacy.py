from dataclasses import asdict
from dataclasses import replace
import json
from pathlib import Path
import pprint

import pytest
from fastapi.encoders import jsonable_encoder

from app.live_monitoring import LiveMonitorConfig, LiveMonitorError, open_live_tail_session
from app.live_monitoring.core import LiveTailRecord, MAX_COUNTER, _bounded_increment


def test_record_and_session_repr_and_public_snapshot_do_not_expose_canaries(tmp_path, capsys, caplog):
    private_dir = (tmp_path / "PRIVATE_DIRECTORY_CANARY").resolve()
    private_dir.mkdir()
    source = private_dir / "PRIVATE_FILENAME_CANARY.log"
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("access", source))
    private_line = (
        "ACCOUNT_CANARY IP_CANARY HTTP_PATH_CANARY?QUERY_CANARY=1 "
        "CREDENTIAL_CANARY"
    )
    with source.open("ab") as target:
        target.write(private_line.encode() + b"\nPARTIAL_CANARY")
    try:
        assert session.poll_once() == 1
        lease = session.lease_records(1, 2048)
        record = lease.records[0]
        assert record.payload == private_line  # trusted parser access only
        outputs = (
            repr(record), str(record), repr((record,)), repr([record]),
            pprint.pformat({"item": record}), repr(session), str(session),
            repr(session.snapshot()), str(session.snapshot()),
            repr(asdict(session.snapshot())), json.dumps(asdict(session.snapshot())),
            repr(jsonable_encoder(session.snapshot())),
            json.dumps(record, default=str),
            repr(session._queue),
            capsys.readouterr().out, capsys.readouterr().err, caplog.text,
        )
        for canary in (
            "PRIVATE_DIRECTORY_CANARY", "PRIVATE_FILENAME_CANARY", "ACCOUNT_CANARY",
            "IP_CANARY", "HTTP_PATH_CANARY", "QUERY_CANARY", "CREDENTIAL_CANARY",
            "PARTIAL_CANARY",
        ):
            assert all(canary not in value for value in outputs)
        with pytest.raises(TypeError):
            json.dumps(record)
        with pytest.raises(ValueError) as encoder_failure:
            jsonable_encoder(record)
        assert private_line not in repr(encoder_failure.value)
        session.acknowledge_lease(lease)
    finally:
        session.close()


def test_error_str_repr_never_include_input_or_exception(tmp_path):
    source = (tmp_path / "PRIVATE_SOURCE_CANARY.log").resolve()
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("application", source))
    with source.open("ab") as target:
        target.write(b"PRIVATE_PAYLOAD_CANARY\xff\n")
    with pytest.raises(LiveMonitorError) as raised:
        session.poll_once()
    assert raised.value.code == "INVALID_UTF8"
    for value in (str(raised.value), repr(raised.value), repr(session), repr(session.snapshot())):
        assert "PRIVATE_SOURCE_CANARY" not in value
        assert "PRIVATE_PAYLOAD_CANARY" not in value
    session.close()


def test_wrong_scalar_types_and_counter_boundary_fail_closed():
    with pytest.raises(LiveMonitorError):
        LiveTailRecord("application", True, "x", 1)
    with pytest.raises(LiveMonitorError):
        LiveTailRecord("application", 1, "x", True)
    with pytest.raises(LiveMonitorError):
        _bounded_increment(True)
    assert _bounded_increment(MAX_COUNTER - 1) == MAX_COUNTER
    with pytest.raises(LiveMonitorError) as raised:
        _bounded_increment(MAX_COUNTER)
    assert raised.value.code == "COUNTER_LIMIT"


def test_public_snapshot_rejects_bool_as_int_and_unknown_warning(tmp_path):
    source = (tmp_path / "input.log").resolve()
    source.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source))
    try:
        snapshot = session.snapshot()
        with pytest.raises(LiveMonitorError):
            replace(snapshot, queue_item_count=True)
        with pytest.raises(LiveMonitorError):
            replace(snapshot, warning_codes=("ACCOUNT_CANARY",))
        with pytest.raises(LiveMonitorError):
            replace(snapshot, queue_byte_count=MAX_COUNTER + 1)
    finally:
        session.close()


def test_core_has_no_forbidden_analysis_or_web_imports():
    import inspect
    import app.live_monitoring.config as config_module
    import app.live_monitoring.core as core_module

    source = inspect.getsource(config_module) + inspect.getsource(core_module)
    for forbidden in (
        "from app.main import analyze", "app.detector", "app.correlation",
        "app.analyzer.risk", "app.analyzer.incident_case", "FastAPI",
        "StreamingResponse", "EventSource", "app.analyzer.llm",
    ):
        assert forbidden not in source
