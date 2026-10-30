"""SSH live-analysis gate: characterize existing batch meaning before wiring it."""

from dataclasses import asdict
from datetime import timedelta
import json

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError, project_investigation_cases_from_analysis,
)
from app.analyzer.pipeline import assess_risk, correlate_attacks, detect_attacks
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator, LiveAnalysisError
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring import LiveMonitorConfig, LiveProcessingWorker, open_live_tail_session
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records
from app.live_monitoring.publication import serialize_live_publication_snapshot


def _ssh(second: int, outcome: str, *, user: str = "synthetic", ip: str = "192.0.2.10",
         port: int = 5001, method: str = "password") -> str:
    return (f"2026-01-02 03:04:{second:02d} sshd: {outcome} {method} for "
            f"{user} from {ip} port {port} ssh2")


def _prefixes(lines: tuple[str, ...], *, timestamp_change=None):
    detector = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    events = []
    outcomes = []
    analyses = []
    for sequence, line in enumerate(lines, 1):
        record = LiveTailRecord("ssh", sequence, line, len(line.encode("utf-8")))
        parsed = parse_live_records("ssh", (record,))
        if timestamp_change is not None:
            timestamp_change(sequence, parsed)
        proposal = detector.prepare(parsed)
        events.extend(item.event for item in parsed.outcomes if item.status == "PARSED")
        from app.main import _analyze_normalized_logs_with_context
        from app.investigation_role_snapshot_36_4 import (
            AnalysisSourceRoleSnapshot, AnalysisWithSourceRoleSnapshot,
        )

        analysis, contexts, owner = _analyze_normalized_logs_with_context(events)
        expected_detection = detect_attacks(events)
        assert proposal._detection == expected_detection
        detector.commit(proposal)
        assert detector._detection == expected_detection
        run = AnalysisWithSourceRoleSnapshot(
            analysis, AnalysisSourceRoleSnapshot.from_events(analysis, tuple(events)),
            contexts, owner,
        )
        projection = project_investigation_cases_from_analysis(run)
        outcomes.append(parsed.outcomes[0].status)
        analyses.append((analysis, projection))
    return detector, tuple(outcomes), tuple(analyses)


def test_ssh_batch_prefix_brute_relation_risk_and_case_contract():
    lines = tuple(_ssh(second, "Failed") for second in (1, 2, 3, 4, 5))
    lines += (_ssh(6, "Accepted"),)
    detector, outcomes, prefixes = _prefixes(lines)
    assert outcomes == ("PARSED",) * len(lines)
    assert not prefixes[3][0]["results"]["192.0.2.10"]["detections"]["brute_force"].is_detected
    last = prefixes[-1][0]["results"]["192.0.2.10"]
    assert last["detections"]["brute_force"].is_detected
    assert last["correlation"]["authentication"]["type"] == "failed_to_successful_login"
    assert last["correlation"]["brute_force_to_success"]["type"] == (
        "brute_force_to_successful_login")
    assert last["correlation"]["post_authentication"]["is_correlated"] is False
    assert last["risk_level"] == "MEDIUM"
    assert last["risk_factors"]["confidence"]["level"] == "HIGH"
    brute_cases = [case for case in prefixes[-1][1].cases
                   if case.rule_code == "CASE-BRUTE-SUCCESS-01"]
    assert len(brute_cases) == 1
    # Preserve the existing public projection's count meaning; it is not the
    # live safe DTO's relation_count-minus-one supporting count.
    assert brute_cases[0].row.supporting_relation_count == 2
    assert brute_cases[0].row.observation_count == 3
    assert detector.snapshot().history_record_count == len(lines)


def test_ssh_nearest_tie_boundary_and_source_isolation_remain_batch_meaning():
    lines = (
        _ssh(1, "Failed"), _ssh(3, "Accepted"), _ssh(2, "Accepted"),
        _ssh(4, "Accepted", user="other"),
        _ssh(5, "Accepted", ip="192.0.2.11"),
    )
    _, _, prefixes = _prefixes(lines)
    auth = prefixes[-1][0]["results"]["192.0.2.10"]["correlation"]["authentication"]
    assert auth["is_correlated"] and auth["success_timestamp"].second == 2
    assert len(prefixes[-1][0]["results"]) == 2

    tie = (_ssh(1, "Failed", port=5001), _ssh(1, "Failed", port=5002),
           _ssh(2, "Accepted"))
    _, _, prefixes = _prefixes(tie)
    assert not prefixes[-1][0]["results"]["192.0.2.10"]["correlation"][
        "authentication"]["is_correlated"]

    first = []

    def exact_boundary(sequence, parsed):
        event = parsed.outcomes[0].event
        if sequence == 1:
            event.timestamp = event.timestamp.replace(microsecond=123456)
            first.append(event.timestamp)
        else:
            event.timestamp = first[0] + timedelta(seconds=60)

    _, _, prefixes = _prefixes((_ssh(1, "Failed"), _ssh(2, "Accepted")),
                               timestamp_change=exact_boundary)
    assert prefixes[-1][0]["results"]["192.0.2.10"]["correlation"][
        "authentication"]["time_delta_seconds"] == 60


def test_ssh_parser_outcomes_and_initial_analysis_boundary_are_explicit():
    lines = (" ", "not a timestamp", "2026-01-02 03:04:01 sshd: unrelated message",
             _ssh(2, "Failed"))
    detector, outcomes, prefixes = _prefixes(lines)
    assert outcomes == ("IGNORED", "REJECTED", "PARSED", "PARSED")
    assert detector.snapshot().history_record_count == 2
    assert not prefixes[-1][0]["results"]["192.0.2.10"]["correlation"][
        "authentication"]["is_correlated"]
    with pytest.raises(LiveAnalysisError) as caught:
        LiveAnalysisAccumulator(detector, ())
    assert caught.value.code == "LIVE_ANALYSIS_REVISION_MISMATCH"


def test_ssh_spray_is_independent_and_raw_microseconds_are_not_supported():
    lines = tuple(_ssh(index, "Failed", user=user) for index, user in enumerate(
        ("one", "two", "three", "four"), 1)) + (_ssh(5, "Accepted", user="one"),)
    _, _, prefixes = _prefixes(lines)
    last = prefixes[-1][0]["results"]["192.0.2.10"]
    assert last["detections"]["password_spray"].is_detected
    assert last["correlation"]["password_spray_to_success"]["is_correlated"]
    assert all(case.rule_code != "CASE-SPRAY-SUCCESS-01" for case in prefixes[-1][1].cases)

    raw_microsecond = (_ssh(1, "Failed").replace("03:04:01", "03:04:01.123456"),)
    _, outcomes, _ = _prefixes(raw_microsecond)
    assert outcomes == ("REJECTED",)


def test_ssh_worker_analysis_public_state_is_private(tmp_path):
    source = tmp_path / "SSH_PATH_CANARY.log"
    source.write_text(_ssh(0, "Failed") + "\n", encoding="utf-8")
    session = open_live_tail_session(LiveMonitorConfig("ssh", source.resolve()))
    detector = LiveDetectionAccumulator("ssh", 256, 256 * 1024)
    worker = LiveProcessingWorker(session, detector, 16, 4096)
    try:
        with source.open("a", encoding="utf-8") as output:
            for second in range(1, 6):
                output.write(_ssh(second, "Failed", user="SSH_ACCOUNT_CANARY",
                                  ip="198.51.100.7") + "\n")
        result = worker.step()
        assert result.accumulator_revision == 1
        assert worker._analysis is not None
        snapshot = worker.publication_buffer.snapshot()
        assert snapshot.analysis is not None
        safe = json.dumps(asdict(snapshot), default=str) + repr(worker) + repr(result)
        wire = serialize_live_publication_snapshot(snapshot).decode("utf-8")
        assert json.loads(wire)["analysis"]["analysis_available"] is True
        safe += wire
        for canary in ("SSH_ACCOUNT_CANARY", "198.51.100.7", "SSH_PATH_CANARY"):
            assert canary not in safe
    finally:
        worker.close()
    assert session._fd == -1


def test_ssh_noncanonical_subject_must_not_be_silently_projected():
    line = _ssh(1, "Failed", ip="not-an-ip")
    parsed = parse_live_records("ssh", (
        LiveTailRecord("ssh", 1, line, len(line.encode("utf-8"))),
    ))
    assert parsed.outcomes[0].status == "PARSED"
    events = (parsed.outcomes[0].event,)
    analysis = assess_risk(correlate_attacks(events, detect_attacks(events)))
    with pytest.raises(IncidentCaseAdapterError) as caught:
        project_investigation_cases_from_analysis(analysis)
    assert caught.value.code == "unsupported_result_shape"
    assert "not-an-ip" not in str(caught.value)


@pytest.mark.parametrize("lines", (
    (_ssh(1, "Accepted"), _ssh(2, "Failed")),
    (_ssh(1, "Failed"), _ssh(2, "Accepted", user="other")),
    (_ssh(1, "Failed"), _ssh(2, "Accepted", ip="192.0.2.11")),
))
def test_ssh_unjoined_authentication_stays_independent(lines):
    _, _, prefixes = _prefixes(lines)
    for result in prefixes[-1][0]["results"].values():
        assert not result["correlation"]["authentication"]["is_correlated"]


def test_ssh_beyond_60_seconds_has_no_relation():
    first = []

    def outside_boundary(sequence, parsed):
        event = parsed.outcomes[0].event
        if sequence == 1:
            first.append(event.timestamp)
        else:
            event.timestamp = first[0] + timedelta(seconds=60, microseconds=1)

    _, _, prefixes = _prefixes((_ssh(1, "Failed"), _ssh(2, "Accepted")),
                               timestamp_change=outside_boundary)
    assert not prefixes[-1][0]["results"]["192.0.2.10"]["correlation"][
        "authentication"]["is_correlated"]
