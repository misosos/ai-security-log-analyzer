"""Every committed prefix has the exact existing batch detector meaning."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.analyzer.pipeline import detect_attacks, load_normalized_logs
from app.live_monitoring import (
    LiveDetectionAccumulator, LiveTailRecord, parse_live_records,
)


def auth(second, user="synthetic", ip="192.0.2.1", kind="login_failed"):
    return f"2026-01-02 03:04:{second:02d} INFO {kind} user={user} ip={ip}"


def ssh(second, user="synthetic", ip="192.0.2.1", kind="Failed"):
    return f"2026-01-02 03:04:{second:02d} sshd: {kind} password for {user} from {ip}"


def web(second, target, status=404, ip="192.0.2.1"):
    return f'{ip} - - [02/Jan/2026:03:04:{second:02d} +0900] "GET {target} HTTP/1.1" {status} 1'


def run_prefix_parity(role, lines):
    accumulator = LiveDetectionAccumulator(role, len(lines) + 1, 1_000_000)
    committed_events = []
    summaries = []
    for sequence, line in enumerate(lines, 1):
        record = LiveTailRecord(role, sequence, line, len(line.encode()))
        parsed = parse_live_records(role, (record,))
        proposal = accumulator.prepare(parsed)
        committed_events.extend(outcome.event for outcome in parsed.outcomes if outcome.status == "PARSED")
        expected = detect_attacks(list(committed_events))
        if proposal._detection != expected:
            pytest.fail("fixed prefix detection parity mismatch", pytrace=False)
        if tuple(proposal._detection) != tuple(expected):
            pytest.fail("fixed subject ordering parity mismatch", pytrace=False)
        if any(tuple(proposal._detection[ip]["detections"]) != tuple(expected[ip]["detections"])
               for ip in expected):
            pytest.fail("fixed detection ordering parity mismatch", pytrace=False)
        snapshot = accumulator.commit(proposal)
        if accumulator._detection != expected:
            pytest.fail("fixed committed detection parity mismatch", pytrace=False)
        assert snapshot.history_record_count == len(committed_events)
        summaries.append(proposal.safe_summary())
    return accumulator, tuple(summaries)


def test_application_brute_below_exact_above_and_old_failure_no_eviction():
    lines = tuple(auth(second) for second in (0, 5, 10, 15, 20, 25))
    _, summaries = run_prefix_parity("application", lines)
    counts = [dict(summary.detected_type_counts)["brute_force"] for summary in summaries]
    assert counts == [0, 0, 0, 0, 1, 1]
    over_window = ("2026-01-02 03:00:00 INFO login_failed user=synthetic ip=192.0.2.1",) + lines[:5]
    _, summaries = run_prefix_parity("application", over_window)
    # 오래된 추가 실패가 있어도 뒤의 5회/20초 창은 독립적으로 평가한다.
    assert dict(summaries[-1].detected_type_counts)["brute_force"] == 1


def test_application_spray_success_multiple_subjects_and_out_of_order():
    lines = (
        auth(12, "one"), auth(3, "two"), auth(7, "three"), auth(18, "one"),
        auth(21, "one", "192.0.2.2"), auth(25, "one", kind="user_login"),
    )
    _, summaries = run_prefix_parity("application", lines)
    assert dict(summaries[3].detected_type_counts)["password_spraying_like"] == 1
    assert summaries[-1].subject_count == 2
    _, reversed_summaries = run_prefix_parity("application", tuple(reversed(lines)))
    assert reversed_summaries[-1].history_record_count == len(lines)


def test_ssh_prefixes_preserve_parser_event_and_brute_meaning():
    lines = tuple(ssh(second) for second in (0, 1, 2, 3, 4, 5)) + (
        ssh(6, kind="Accepted"),
        "2026-01-02 03:04:07 sshd: unrelated message",
    )
    _, summaries = run_prefix_parity("ssh", lines)
    assert dict(summaries[4].detected_type_counts)["brute_force"] == 1
    assert summaries[-1].history_record_count == len(lines)


def test_access_prefixes_cover_all_five_web_types_and_scan_boundaries():
    targets = (
        "/download?file=../../etc/passwd",
        "/search?id=%27%20or%201%3D1",
        "/search?q=%3Cscript%3E",
        "/.env",
        "/resource-five",
        "/resource-six",
        "/safe",
    )
    lines = tuple(web(index, target, 404 if index < 3 else 200)
                  for index, target in enumerate(targets))
    _, summaries = run_prefix_parity("access", lines)
    last = dict(summaries[-1].detected_type_counts)
    for kind in ("path_traversal", "sql_injection_like", "xss_like",
                 "sensitive_resource_probing_like", "web_scanning_like"):
        assert last[kind] == 1
    assert dict(summaries[4].detected_type_counts)["web_scanning_like"] == 0
    assert dict(summaries[5].detected_type_counts)["web_scanning_like"] == 1


def test_scan_repeated_target_and_exact_60_second_boundary():
    repeated = tuple(web(second, "/same", 404) for second in range(6))
    _, summaries = run_prefix_parity("access", repeated)
    assert dict(summaries[-1].detected_type_counts)["web_scanning_like"] == 0
    base = datetime(2026, 1, 2, 3, 4, 0)
    timed = []
    for index, delta in enumerate((0, 10, 20, 30, 40, 60)):
        stamp = base + timedelta(seconds=delta)
        timed.append(f'192.0.2.1 - - [{stamp:%d/%b/%Y:%H:%M:%S} +0900] "GET /item-{index} HTTP/1.1" {404 if index < 3 else 200} 1')
    _, summaries = run_prefix_parity("access", tuple(timed))
    assert dict(summaries[-1].detected_type_counts)["web_scanning_like"] == 1


def test_batch_order_dependence_is_characterized_not_changed():
    first = web(1, "/one?file=../a")
    second = web(2, "/two?file=../b")
    forward, _ = run_prefix_parity("access", (first, second))
    reverse, _ = run_prefix_parity("access", (second, first))
    # The legacy path-traversal slot is overwritten by the last matching input.
    assert forward._detection != reverse._detection


@pytest.mark.parametrize(("role", "fixture"), (
    ("application", "sample_logs/brute_force.log"),
    ("ssh", "sample_logs/ssh_auth.log"),
    ("access", "sample_logs/web_shell.log"),
))
def test_existing_fixture_parser_and_detection_prefix_parity(role, fixture):
    path = Path(fixture)
    lines = tuple(path.read_text(encoding="utf-8").splitlines())
    accumulator, _ = run_prefix_parity(role, lines)
    expected_events = tuple(load_normalized_logs(({"source": role, "path": path},)))
    if accumulator._history != expected_events:
        pytest.fail("fixed fixture parser parity mismatch", pytrace=False)
    if accumulator._detection != detect_attacks(list(expected_events)):
        pytest.fail("fixed fixture detector parity mismatch", pytrace=False)
