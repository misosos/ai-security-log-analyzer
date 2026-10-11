"""Lease payload is trusted-only; status, repr and errors are input-free."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import pprint

import pytest

from app.live_monitoring import LiveMonitorConfig, LiveMonitorError, open_live_tail_session


def test_lease_repr_snapshot_and_errors_hide_payload_canaries(tmp_path, capsys, caplog):
    private = (tmp_path / "PRIVATE_DIRECTORY_CANARY").resolve()
    private.mkdir()
    path = private / "PRIVATE_FILENAME_CANARY.log"
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("access", path))
    raw = "ACCOUNT_CANARY 192.0.2.77 /PRIVATE_PATH_CANARY?QUERY_CANARY=TOKEN_CANARY"
    with path.open("ab") as stream:
        stream.write((raw + "\n").encode())
    try:
        session.poll_once()
        lease = session.lease_records(1, 2048)
        assert lease.records[0].payload == raw  # Explicit trusted parser access.
        forged = replace(lease, lease_id=lease.lease_id + 99)
        with pytest.raises(LiveMonitorError) as raised:
            session.acknowledge_lease(forged)
        surfaces = (
            repr(session), str(session), repr(lease), str(lease),
            pprint.pformat(lease), repr(session.snapshot()),
            json.dumps(asdict(session.snapshot()), sort_keys=True),
            str(raised.value), repr(raised.value), capsys.readouterr().out,
            capsys.readouterr().err, caplog.text,
        )
        for canary in (
            "PRIVATE_DIRECTORY_CANARY", "PRIVATE_FILENAME_CANARY", "ACCOUNT_CANARY",
            "PRIVATE_PATH_CANARY", "QUERY_CANARY", "TOKEN_CANARY",
        ):
            assert all(canary not in value for value in surfaces)
        with pytest.raises(TypeError):
            json.dumps(lease)
    finally:
        session.close()


def test_lease_snapshot_rejects_bool_and_invariant_mismatch(tmp_path):
    path = (tmp_path / "source.log").resolve()
    path.write_bytes(b"")
    session = open_live_tail_session(LiveMonitorConfig("ssh", path))
    try:
        snapshot = session.snapshot()
        with pytest.raises(LiveMonitorError):
            replace(snapshot, available_item_count=True)
        with pytest.raises(LiveMonitorError):
            replace(snapshot, active_lease=1)
        with pytest.raises(LiveMonitorError):
            replace(snapshot, queue_item_count=1)
    finally:
        session.close()
