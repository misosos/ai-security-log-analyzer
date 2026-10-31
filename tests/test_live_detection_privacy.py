"""Only explicit count summaries may cross the live detection boundary."""

from dataclasses import asdict
import logging

import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveDetectionError, LiveTailRecord, parse_live_records,
)
from app.live_monitoring import detection_accumulator as module


def test_account_ip_path_query_raw_and_exception_are_absent_from_safe_surfaces(capsys, caplog, monkeypatch):
    account = "acct-cypress-731"
    ip = "198.51.100.217"
    path = "/private-route-juniper-462"
    query = "token=violet-385"
    user_agent = "agent-amber-947"
    credential = "credential-hazel-163"
    source_path = "private-source-maple-254"
    filename = "upload-cedar-819.log"
    line = (f'{ip} - - [02/Jan/2026:03:04:05 +0900] '
            f'"GET {path}?{query} HTTP/1.1" 200 1 "-" '
            f'"{user_agent} {credential} {account} {source_path} {filename}"')
    record = LiveTailRecord("access", 1, line, len(line.encode()))
    batch = parse_live_records("access", (record,))
    accumulator = LiveDetectionAccumulator("access", 2, 4096)
    caplog.set_level(logging.DEBUG)
    proposal = accumulator.prepare(batch)
    safe = repr(accumulator) + repr(proposal) + repr(proposal.safe_summary())
    safe += repr(accumulator.snapshot()) + str(asdict(proposal.safe_summary()))
    accumulator.commit(proposal)
    safe += repr(accumulator.snapshot()) + str(asdict(accumulator.snapshot()))

    def broken(_events):
        raise RuntimeError("private-detector-detail-674")

    monkeypatch.setattr(module, "detect_attacks", broken)
    second = LiveTailRecord("access", 2, line, len(line.encode()))
    with pytest.raises(LiveDetectionError) as raised:
        accumulator.prepare(parse_live_records("access", (second,)))
    safe += str(raised.value) + repr(raised.value)
    output = capsys.readouterr()
    safe += output.out + output.err + caplog.text
    for value in (account, ip, path, query, user_agent, credential, source_path,
                  filename, line, "private-detector-detail-674"):
        assert value not in safe


def test_trusted_history_is_explicitly_not_a_public_projection():
    line = "2026-01-02 03:04:05 INFO login_failed user=internal-citron-428 ip=192.0.2.8"
    record = LiveTailRecord("application", 1, line, len(line.encode()))
    accumulator = LiveDetectionAccumulator("application", 1, 1024)
    proposal = accumulator.prepare(parse_live_records("application", (record,)))
    assert "internal-citron-428" in proposal._history[0].raw
    assert "internal-citron-428" not in repr(proposal)
    accumulator.commit(proposal)
    assert "internal-citron-428" not in repr(accumulator)
