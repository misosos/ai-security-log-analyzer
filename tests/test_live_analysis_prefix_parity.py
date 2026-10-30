"""Trusted full-prefix oracle comparisons retain every batch semantic field."""

from datetime import timedelta

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import assess_risk, correlate_attacks, detect_attacks
from app.detector.brute_force import select_brute_window_contexts
from app.investigation_role_snapshot_36_4 import (
    AnalysisSourceRoleSnapshot,
    AnalysisWithSourceRoleSnapshot,
)
from app.analyzer.risk import load_account_metadata
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records


def _line(second, event, user="alice", ip="192.0.2.10"):
    return f"2026-01-02 03:04:{second:02d} INFO {event} user={user} ip={ip}"


def _metadata():
    return tuple((key, value["privilege"])
                 for key, value in load_account_metadata().items())


def _exercise(lines, transform=None):
    detector = LiveDetectionAccumulator("application", 256, 256 * 1024)
    analysis = LiveAnalysisAccumulator(detector, _metadata())
    prefix = []
    for sequence, line in enumerate(lines, 1):
        record = LiveTailRecord("application", sequence, line, len(line.encode()))
        parsed = parse_live_records("application", (record,))
        if transform is not None:
            transform(sequence, parsed, prefix)
        proposal = detector.prepare(parsed)
        analysis_proposal = analysis.prepare(proposal)
        detector.commit(proposal)
        analysis.commit(analysis_proposal)
        prefix.extend(item.event for item in parsed.outcomes if item.status == "PARSED")
        oracle_detection = detect_attacks(prefix)
        assert detector._detection == oracle_detection
        oracle = assess_risk(correlate_attacks(prefix, oracle_detection))
        trusted = analysis._state
        assert trusted._results == oracle["results"]
        oracle_run = AnalysisWithSourceRoleSnapshot(
            oracle,
            AnalysisSourceRoleSnapshot.from_events(oracle, tuple(prefix)),
            select_brute_window_contexts(prefix),
        )
        assert trusted._projection == project_investigation_cases_from_analysis(oracle_run)
        assert trusted._assembly.cases == tuple(trusted._assembly.cases)
        assert analysis.snapshot().revision == sequence
    detector.close()
    analysis.close()
    return trusted


def test_authentication_and_brute_prefixes_match_full_batch():
    _exercise(tuple(_line(second, "login_failed") for second in range(1, 6))
              + (_line(6, "user_login"), _line(8, "login_failed")))


def test_out_of_order_multiple_subjects_and_ignored_rejected_prefixes():
    _exercise((
        _line(20, "login_failed", "alice", "192.0.2.10"),
        "   ",
        _line(19, "user_login", "alice", "192.0.2.10"),
        "malformed timestamp",
        _line(10, "login_failed", "bob", "192.0.2.11"),
        _line(11, "user_login", "bob", "192.0.2.11"),
        _line(30, "user_login", "alice", "192.0.2.10"),
    ))


def test_nearest_success_and_partial_file_access_are_batch_equal():
    _exercise((
        _line(1, "login_failed"),
        _line(2, "user_login"),
        _line(3, "user_login"),
        _line(4, "file_access"),
    ))


def test_exact_window_microseconds_and_beyond_window_match_batch():
    first_timestamp = []
    def transform(sequence, batch, _prefix):
        event = batch.outcomes[0].event
        if sequence == 1:
            event.timestamp = event.timestamp.replace(microsecond=123456)
            first_timestamp.append(event.timestamp)
        elif sequence == 2:
            event.timestamp = first_timestamp[0] + timedelta(seconds=60)
        else:
            event.timestamp = first_timestamp[0] + timedelta(seconds=60, microseconds=1)
    _exercise((_line(1, "login_failed"), _line(2, "user_login"),
               _line(3, "user_login")), transform)


def test_accounts_and_ips_do_not_join_across_subjects():
    _exercise((
        _line(1, "login_failed", "alice", "192.0.2.10"),
        _line(2, "user_login", "bob", "192.0.2.10"),
        _line(3, "user_login", "alice", "192.0.2.11"),
        _line(4, "user_login", "alice", "192.0.2.10"),
    ))


def test_outside_60_seconds_has_no_authentication_relation():
    first_timestamp = []
    def transform(sequence, batch, _prefix):
        event = batch.outcomes[0].event
        if sequence == 1:
            first_timestamp.append(event.timestamp)
        else:
            event.timestamp = first_timestamp[0] + timedelta(seconds=60, microseconds=1)
    trusted = _exercise((_line(1, "login_failed"),
                         _line(2, "user_login")), transform)
    assert not trusted._results["192.0.2.10"]["correlation"]["authentication"]["is_correlated"]


def test_exact_duplicate_endpoint_does_not_create_ambiguous_relation():
    trusted = _exercise((_line(1, "login_failed"), _line(2, "user_login"),
                         _line(1, "login_failed")))
    assert trusted._results["192.0.2.10"]["correlation"]["authentication"]["is_correlated"]


def test_success_before_failure_is_not_reinterpreted_as_transition():
    trusted = _exercise((_line(1, "user_login"), _line(2, "login_failed")))
    assert not trusted._results["192.0.2.10"]["correlation"]["authentication"]["is_correlated"]


def test_spray_relation_stays_independent_and_no_spray_case_is_created():
    trusted = _exercise((
        _line(1, "login_failed", "alice"),
        _line(2, "login_failed", "bob"),
        _line(3, "login_failed", "admin"),
        _line(4, "login_failed", "guest"),
        _line(5, "user_login", "alice"),
    ))
    assert trusted._results["192.0.2.10"]["correlation"]["password_spray_to_success"]["is_correlated"]
    assert all(case.rule_id != "CASE-SPRAY-SUCCESS-01" for case in trusted._assembly.cases)
    assert trusted._assembly.unsupported_case_rules[0].status_code == (
        "NO_GO_UNTYPED_PRODUCTION_TARGET_MEMBERSHIP")
