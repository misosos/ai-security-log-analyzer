"""Bounded synthetic properties; no user log, default config, or example database."""

from collections import deque
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from hypothesis import given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule
import pytest

from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveMonitorError,
    LiveProcessingWorker, LiveTailRecord, open_live_tail_session,
    parse_live_records,
)
from app.live_monitoring.core import MAX_LINE_BYTES, MAX_QUEUE_BYTES, MAX_QUEUE_ITEMS, LiveTailSession
from app.live_monitoring.publication import (
    serialize_live_analysis_publication_event, serialize_live_publication_event,
    serialize_live_publication_snapshot,
)
from app.live_monitoring.worker import LiveWorkerError


_ROLE = st.sampled_from(("application", "ssh", "access"))
_TOKEN = st.text(alphabet="abcXYZ_가", min_size=1, max_size=6)


@settings(max_examples=60, database=None, derandomize=False)
@given(role=_ROLE, kind=st.sampled_from(("valid", "optional", "blank", "malformed", "fractional")),
       token=_TOKEN, second=st.sampled_from((0, 1, 5, 59)))
def test_bounded_role_parser_outcome_and_utc_repeatability(role, kind, token, second):
    stamp = f"2026-01-02 03:04:{second:02d}"
    if role == "application":
        line = (f"{stamp} INFO login_failed user={token} ip=192.0.2.11"
                + (" service=synthetic application=test" if kind == "optional" else ""))
        source = "application"
    elif role == "ssh":
        line = (f"{stamp} sshd: Failed password for {token} from 192.0.2.11"
                + (" port 2200 ssh2" if kind == "optional" else ""))
        source = "ssh"
    else:
        line = (f'192.0.2.11 - - [02/Jan/2026:03:04:{second:02d} +0900] '
                f'"GET /synthetic?item={token} HTTP/1.1" 200 '
                + ("-" if kind == "optional" else "1"))
        source = "access_log"
    if kind == "blank":
        line, expected = " \t ", "IGNORED"
    elif kind == "malformed":
        line = line.replace("2026-01-02", "not-a-date").replace("02/Jan/2026", "not-a-date")
        expected = "REJECTED"
    elif kind == "fractional":
        line = line.replace(f":{second:02d}", f":{second:02d}.123456", 1)
        expected = "REJECTED"
    else:
        expected = "PARSED"
    assert len(line.encode("utf-8")) <= MAX_LINE_BYTES
    record = LiveTailRecord(role, 1, line, len(line.encode("utf-8")))
    first = parse_live_records(role, (record,))
    again = parse_live_records(role, (record,))
    assert first == again
    assert first.outcomes[0].status == expected
    assert (first.parsed_count, first.ignored_count, first.rejected_count) == (
        int(expected == "PARSED"), int(expected == "IGNORED"), int(expected == "REJECTED"),
    )
    if expected == "PARSED":
        event = first.outcomes[0].event
        assert event.source == source
        assert event.timestamp == datetime(2026, 1, 1, 18, 4, second, tzinfo=timezone.utc)
        assert event.timestamp.microsecond == 0
        assert event.raw == line


@settings(max_examples=35, database=None, derandomize=False)
@given(role=_ROLE, width=st.sampled_from((0, 1, 1023, 2047, 2048, 2049)),
       ending=st.sampled_from((b"\n", b"\r\n", b"")), invalid=st.booleans())
def test_tail_byte_boundary_partial_lf_and_strict_utf8(role, width, ending, invalid):
    # One short synthetic file per example; never an actual source or default config.
    with TemporaryDirectory(prefix="property-tail-") as directory:
        source = (Path(directory) / "synthetic.log").resolve()
        source.write_bytes(b"old line\n")
        session = open_live_tail_session(LiveMonitorConfig(role, source))
        body = (b"a" * width) + (b"\xff" if invalid else b"")
        try:
            with source.open("ab") as stream:
                stream.write(body + ending)
            if not ending:
                if len(body) > MAX_LINE_BYTES:
                    with pytest.raises(LiveMonitorError) as raised:
                        session.poll_once()
                    assert raised.value.code == "PARTIAL_BUFFER_EXCEEDED"
                else:
                    assert session.poll_once() == 0
                    assert session.snapshot().partial_buffer_byte_count == len(body)
                return
            if len(body) + int(ending == b"\r\n") > MAX_LINE_BYTES or invalid:
                with pytest.raises(LiveMonitorError) as raised:
                    session.poll_once()
                assert raised.value.code == (
                    "LINE_TOO_LONG" if len(body) + int(ending == b"\r\n") > MAX_LINE_BYTES
                    else "INVALID_UTF8"
                )
                assert session.snapshot().state == "FAILED"
            else:
                assert session.poll_once() == 1
                lease = session.lease_records(1, MAX_QUEUE_BYTES)
                assert lease.records[0].payload == "a" * width
                assert lease.records[0].byte_count == width
                assert lease.records[0]._end_offset == len(b"old line\n") + len(body + ending)
                session.acknowledge_lease(lease)
        finally:
            session.close()


class QueueLeaseMachine(RuleBasedStateMachine):
    """A file-byte/FIFO oracle, deliberately separate from the production deque."""

    def __init__(self):
        super().__init__()
        self.temp = TemporaryDirectory(prefix="property-lease-")
        self.path = (Path(self.temp.name) / "synthetic.log").resolve()
        self.path.write_bytes(b"old ignored line\n")
        self.session = open_live_tail_session(LiveMonitorConfig("application", self.path))
        self.unframed = b""
        self.queue = deque()
        self.next_sequence = 1
        self.processed = 0
        self.acknowledged = 0
        self.releases = 0
        self.active = None
        self.selected = ()
        self.settled = None
        self.closed = False
        self.failed = False

    @precondition(lambda self: not self.closed and not self.failed and len(self.unframed) < 850)
    @rule(token=st.text(alphabet="abcXYZ_", min_size=1, max_size=8),
          count=st.integers(min_value=1, max_value=16),
          ending=st.sampled_from((b"\n", b"\r\n", b"")))
    def append(self, token, count, ending):
        self._append_bytes((token.encode("ascii") + ending) * count)

    @precondition(lambda self: not self.closed and not self.failed and len(self.unframed) < 850)
    @rule(width=st.sampled_from((512, 700)), count=st.integers(min_value=1, max_value=4))
    def append_wide(self, width, count):
        # Reaches the independent 16 KiB queue byte cap before 32 items.
        self._append_bytes(((b"x" * width) + b"\n") * count)

    def _append_bytes(self, data):
        with self.path.open("ab") as stream:
            stream.write(data)
        self.unframed += data

    @precondition(lambda self: not self.closed and not self.failed)
    @rule()
    def poll(self):
        remaining = self.unframed
        accepted = 0
        overflow = False
        while accepted < 16 and b"\n" in remaining:
            line, remaining = remaining.split(b"\n", 1)
            payload = line.removesuffix(b"\r").decode("ascii")
            if len(self.queue) == MAX_QUEUE_ITEMS or sum(item[2] for item in self.queue) + len(payload) > MAX_QUEUE_BYTES:
                overflow = True
                break
            self.queue.append((self.next_sequence, payload, len(payload)))
            self.next_sequence += 1
            self.processed += 1
            accepted += 1
        if overflow:
            with pytest.raises(LiveMonitorError) as raised:
                self.session.poll_once()
            assert raised.value.code == "QUEUE_OVERFLOW"
            self.failed = True
        else:
            assert self.session.poll_once() == accepted
            self.unframed = remaining

    @precondition(lambda self: not self.closed and not self.failed and self.active is None)
    @rule(limit=st.integers(min_value=1, max_value=8),
          byte_limit=st.sampled_from((1, 8, 128, 512, 700, 2048, MAX_QUEUE_BYTES)))
    def lease(self, limit, byte_limit):
        if not self.queue:
            assert self.session.lease_records(limit, byte_limit) is None
            return
        chosen = []
        size = 0
        for item in self.queue:
            if len(chosen) == limit or size + item[2] > byte_limit:
                break
            chosen.append(item)
            size += item[2]
        if not chosen:
            with pytest.raises(LiveMonitorError) as raised:
                self.session.lease_records(limit, byte_limit)
            assert raised.value.code == "LEASE_LIMIT_TOO_SMALL"
            return
        self.active = self.session.lease_records(limit, byte_limit)
        self.selected = tuple(chosen)
        assert tuple((record.sequence, record.payload, record.byte_count)
                     for record in self.active.records) == self.selected

    @precondition(lambda self: not self.closed and not self.failed and self.active is not None)
    @rule()
    def release(self):
        self.session.release_lease(self.active)
        self.settled = self.active
        self.active = None
        self.selected = ()
        self.releases += 1

    @precondition(lambda self: not self.closed and not self.failed and self.active is not None)
    @rule()
    def acknowledge(self):
        self.session.acknowledge_lease(self.active)
        for expected in self.selected:
            assert self.queue.popleft() == expected
        self.acknowledged += len(self.selected)
        self.settled = self.active
        self.active = None
        self.selected = ()

    @precondition(lambda self: not self.closed and not self.failed and self.active is not None)
    @rule()
    def refuse_foreign_and_duplicate_active_lease(self):
        with pytest.raises(LiveMonitorError) as raised:
            self.session.lease_records(1, 128)
        assert raised.value.code == "ACTIVE_LEASE_EXISTS"
        foreign = replace(self.active, _owner_token=self.active._owner_token + 1)
        with pytest.raises(LiveMonitorError) as raised:
            self.session.acknowledge_lease(foreign)
        assert raised.value.code == "FOREIGN_LEASE"

    @precondition(lambda self: not self.closed and not self.failed and self.settled is not None)
    @rule()
    def refuse_stale_settlement(self):
        for settle in (self.session.acknowledge_lease, self.session.release_lease):
            with pytest.raises(LiveMonitorError) as raised:
                settle(self.settled)
            assert raised.value.code in {
                "STALE_LEASE", "ACK_AFTER_ACK", "RELEASE_AFTER_ACK",
                "ACK_AFTER_RELEASE", "RELEASE_AFTER_RELEASE",
            }

    @precondition(lambda self: not self.closed)
    @rule()
    def close(self):
        self.session.close()
        self.closed = True
        self.queue.clear()
        self.active = None
        self.selected = ()

    @precondition(lambda self: self.closed)
    @rule()
    def refuse_after_close(self):
        with pytest.raises(LiveMonitorError):
            self.session.poll_once()
        with pytest.raises(LiveMonitorError):
            self.session.lease_records(1, 128)
        self.session.close()  # idempotent only

    @invariant()
    def accounting_is_reference_fifo(self):
        snapshot = self.session.snapshot()
        queue_items = tuple(self.queue)
        queue_bytes = sum(item[2] for item in queue_items)
        leased_count = len(self.selected)
        leased_bytes = sum(item[2] for item in self.selected)
        assert snapshot.queue_item_count == len(queue_items)
        assert snapshot.queue_byte_count == queue_bytes
        assert snapshot.available_item_count == len(queue_items) - leased_count
        assert snapshot.available_byte_count == queue_bytes - leased_bytes
        assert snapshot.leased_item_count == leased_count
        assert snapshot.leased_byte_count == leased_bytes
        assert snapshot.active_lease == (self.active is not None)
        assert snapshot.acknowledged_record_count == self.acknowledged
        assert snapshot.released_lease_count == self.releases
        assert snapshot.processed_complete_line_count == self.processed
        assert len(queue_items) <= MAX_QUEUE_ITEMS and queue_bytes <= MAX_QUEUE_BYTES
        assert tuple(item[0] for item in queue_items) == tuple(range(
            self.acknowledged + 1, self.acknowledged + len(queue_items) + 1,
        ))
        assert snapshot.state == ("STOPPED" if self.closed else "FAILED" if self.failed else "RUNNING")
        assert "old ignored line" not in repr(snapshot)

    def teardown(self):
        self.session.close()
        self.temp.cleanup()


TestQueueLeaseMachine = QueueLeaseMachine.TestCase
TestQueueLeaseMachine.settings = settings(
    max_examples=35, stateful_step_count=24, database=None, derandomize=False,
)


@settings(max_examples=25, database=None, derandomize=False)
@given(suffix=st.integers(min_value=10_000, max_value=99_999))
def test_public_projection_excludes_combined_synthetic_canaries(suffix):
    account = f"ACCOUNT_CANARY_{suffix}"
    ip = f"192.0.2.{suffix % 200 + 1}"
    path_marker = f"PATH_CANARY_{suffix}"
    query_marker = f"QUERY_CANARY_{suffix}"
    raw_marker = f"RAW_CANARY_{suffix}"
    filename_marker = f"FILENAME_CANARY_{suffix}"
    exception_marker = f"EXCEPTION_CANARY_{suffix}"
    canaries = (account, ip, path_marker, query_marker, raw_marker,
                filename_marker, exception_marker)
    with TemporaryDirectory(prefix="property-private-") as directory:
        source = (Path(directory) / f"{filename_marker}.log").resolve()
        source.write_bytes(b"old private line\n")
        session = open_live_tail_session(LiveMonitorConfig("application", source))
        detector = LiveDetectionAccumulator("application", 256, 256 * 1024)
        worker = LiveProcessingWorker(session, detector, 16, 4096)
        try:
            lines = [
                f"2026-01-02 03:04:{second:02d} INFO login_failed user={account} ip={ip} "
                f"path=/{path_marker} query={query_marker} marker={raw_marker}"
                for second in range(5)
            ]
            lines.append(f"2026-01-02 03:04:05 INFO user_login user={account} ip={ip}")
            with source.open("ab") as stream:
                stream.write(("\n".join(lines) + "\n").encode("utf-8"))
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = worker.step()
            snapshot = worker.snapshot()
            publication = worker.publication_buffer.snapshot()
            events = worker.publication_buffer.replay_after(None).events
            public = (repr(worker), repr(result), repr(snapshot),
                      repr(asdict(snapshot)), json.dumps(asdict(snapshot), default=str),
                      repr(publication), json.dumps(asdict(publication), default=str),
                      serialize_live_publication_snapshot(publication).decode())
            for event in events:
                wire = (serialize_live_publication_event(event) if event.event_type == "DETECTION_CHANGE"
                        else serialize_live_analysis_publication_event(event))
                public += (repr(event), repr(asdict(event)), json.dumps(asdict(event), default=str), wire.decode())
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with patch.object(LiveTailSession, "poll_once", side_effect=RuntimeError(exception_marker)):
                    with pytest.raises(LiveWorkerError) as raised:
                        worker.step()
            assert raised.value.code == "POLL_FAILURE"
            public += (str(raised.value), repr(raised.value), repr(worker.snapshot()))
            public += (stdout.getvalue(), stderr.getvalue())
            for canary in canaries:
                assert all(canary not in value for value in public)
                assert all(canary[: max(8, len(canary) - 2)] not in value for value in public)
                assert all(sha256(canary.encode()).hexdigest() not in value for value in public)
            assert raw_marker in detector._history[0].raw  # trusted state remains distinct
        finally:
            worker.close()
