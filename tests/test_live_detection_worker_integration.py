"""Detection is prepared before queue acknowledgement, then committed once."""

from app.analyzer.pipeline import detect_attacks
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveMonitorConfig, LiveProcessingWorker,
    open_live_tail_session,
)


def make_worker(tmp_path, role="application", *, history=64, lease=16):
    path = tmp_path / "synthetic.log"
    path.write_bytes(b"old line\n")
    session = open_live_tail_session(LiveMonitorConfig(role, path.resolve()))
    accumulator = LiveDetectionAccumulator(role, history, 65536)
    return path, session, accumulator, LiveProcessingWorker(session, accumulator, lease, 4096)


def append(path, *lines):
    with path.open("ab") as stream:
        stream.write(("\n".join(lines) + "\n").encode())


def auth(second, kind="login_failed", ip="192.0.2.1"):
    clock = second if type(second) is str else f"03:04:{second:02d}"
    return f"2026-01-02 {clock} INFO {kind} user=synthetic ip={ip}"


def test_application_prefix_ack_commit_identity(tmp_path):
    path, session, accumulator, worker = make_worker(tmp_path)
    try:
        assert worker.step().status == "NO_DATA"
        append(path, *(auth(index) for index in range(4)))
        below = worker.step()
        assert below.created_count == 0
        assert below.accumulator_revision == 1
        assert session.snapshot().queue_item_count == 0
        append(path, auth(4))
        created = worker.step()
        assert created.created_count == 1
        first = accumulator.latest_change_set().changes[0]
        assert first.observation_id == "LIVE-OBS-000001"
        assert first.observation_revision == 1
        # Earlier out-of-order event changes the earliest qualifying window.
        append(path, auth("03:03:59"))
        changed = worker.step()
        assert changed.updated_count == 1
        second = accumulator.latest_change_set().changes[0]
        assert second.observation_id == first.observation_id
        assert second.observation_revision == 2
        assert accumulator._detection == detect_attacks(list(accumulator._history))
        assert worker.snapshot().total_acknowledged == 6
        assert not accumulator.snapshot().active_proposal
    finally:
        worker.close()
    assert session._fd == -1
    assert accumulator.snapshot().closed


def test_ignored_and_rejected_increment_revision_without_detection_change(tmp_path):
    path, session, accumulator, worker = make_worker(tmp_path)
    try:
        append(path, "   ", "bad timestamp")
        result = worker.step()
        assert (result.parsed_count, result.ignored_count, result.rejected_count) == (0, 1, 1)
        assert (result.created_count, result.updated_count, result.no_longer_matches_count) == (0, 0, 0)
        assert accumulator.snapshot().revision == 1
        assert worker.step().accumulator_revision == 1
    finally:
        worker.close()


def test_ssh_and_access_use_existing_detection_pipeline(tmp_path):
    for role, line in (
        ("ssh", "2026-01-02 03:04:05 sshd: Failed password for synthetic from 192.0.2.1"),
        ("access", '192.0.2.1 - - [02/Jan/2026:03:04:05 +0900] "GET /x?file=../a HTTP/1.1" 404 1'),
    ):
        folder = tmp_path / role
        folder.mkdir()
        path, _, accumulator, worker = make_worker(folder, role)
        try:
            append(path, line)
            result = worker.step()
            assert result.parsed_count == 1
            assert accumulator._detection == detect_attacks(list(accumulator._history))
            if role == "access":
                assert result.created_count == 1
        finally:
            worker.close()
