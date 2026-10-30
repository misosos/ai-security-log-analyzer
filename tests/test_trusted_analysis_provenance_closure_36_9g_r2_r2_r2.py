"""Phase 36.9G-R2-R2-R2 독립 provenance 및 소비자 경계 검증."""

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.analyzer.pipeline import load_normalized_logs
from app.detector.brute_force import (
    AnalysisRunOwner,
    select_brute_window_contexts,
)
from app.investigation_role_snapshot_36_4 import (
    AnalysisSourceRoleSnapshot,
    AnalysisWithSourceRoleSnapshot,
)
from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
from app.live_monitoring.core import LiveTailRecord
from app.live_monitoring.detection_accumulator import LiveDetectionAccumulator
from app.live_monitoring.parser_adapter import parse_live_records
from app.main import _analyze_normalized_logs_with_context, analyze_with_source_role_snapshot


SUBJECT = "198.51.100.21"
ACCOUNT = "synthetic_user_a"
SOURCE = "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log"


def _analysis_run():
    return analyze_with_source_role_snapshot(({"source": "application", "path": SOURCE},))


def _metadata():
    from app.analyzer.risk import load_account_metadata

    return tuple((key, value["privilege"]) for key, value in load_account_metadata().items())


def _app_line(second: int, event: str, user: str = ACCOUNT) -> str:
    stamp = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc) + timedelta(seconds=second)
    return f"{stamp:%Y-%m-%d %H:%M:%S} INFO {event} user={user} ip={SUBJECT}"


def test_pipeline_stages_cannot_be_skipped_or_rebound_and_public_run_is_valid():
    run = _analysis_run()
    owner = run.run_owner
    subject = run.analysis["results"][SUBJECT]

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._bind_detection_results(run.analysis["results"])
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._bind_correlated_analysis(run.analysis)
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._bind_risk_analysis(run.analysis)
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._create_analysis_result(run.analysis)

    assert owner.is_bound_to(run.analysis)
    assert subject["features"]["failure_count"] == 6
    assert subject["features"]["window_seconds"] == 70
    assert subject["detections"]["brute_force"].evidence[0].value == 5
    projection = project_investigation_cases_from_analysis(run)
    assert projection.summary.case_count == 1
    case = projection.cases[0]
    assert case.rule_code == "CASE-BRUTE-SUCCESS-01"
    detection_observation = case.timeline_entries[0]
    assert detection_observation.start_time.canonical_utc == run.brute_window_contexts[
        SUBJECT
    ].start_utc
    assert detection_observation.end_time.canonical_utc == run.brute_window_contexts[
        SUBJECT
    ].end_utc
    assert tuple(item.value for item in detection_observation.evidence) == (5, 1, 20.0)
    brute_relation = next(
        item for item in case.timeline_entries if item.category == "SUPPORTED_RELATION"
    )
    assert brute_relation.start_time.canonical_utc == run.brute_window_contexts[SUBJECT].end_utc
    assert brute_relation.end_time.canonical_utc == datetime(
        2026, 10, 30, 0, 1, 20, tzinfo=timezone.utc,
    )


def test_prior_finalized_results_cannot_be_relabelled_as_a_new_owned_run():
    old = _analysis_run()
    new = _analysis_run()
    assert project_investigation_cases_from_analysis(new).summary.case_count == 1

    # Consumer-visible mutation mirrors accidental result reuse after another
    # run was finalized. The new owner must cease to attest the modified result.
    new.analysis["results"] = old.analysis["results"]
    assert not new.run_owner.is_bound_to(new.analysis)
    with pytest.raises(IncidentCaseAdapterError):
        project_investigation_cases_from_analysis(new)
    assert project_investigation_cases_from_analysis(old).summary.case_count == 1


def test_application_and_ssh_parser_events_share_only_the_same_account_window(tmp_path):
    app_path = tmp_path / "app.log"
    ssh_path = tmp_path / "ssh.log"
    app_path.write_text(
        "\n".join(_app_line(second, "login_failed") for second in (0, 10, 20)) + "\n",
        encoding="utf-8",
    )
    ssh_path.write_text(
        "\n".join(
            f"2026-10-30 09:00:{second:02d} sshd Failed password for {ACCOUNT} "
            f"from {SUBJECT} port {22000 + second} ssh2"
            for second in (5, 15)
        ) + "\n",
        encoding="utf-8",
    )

    events = load_normalized_logs((
        {"source": "application", "path": str(app_path)},
        {"source": "ssh", "path": str(ssh_path)},
    ))
    owner = AnalysisRunOwner()
    contexts = select_brute_window_contexts(events, owner)
    assert len(events) == 5
    assert {event.source for event in events} == {"application", "ssh"}
    assert all(event.timestamp.utcoffset().total_seconds() == 0 for event in events)
    assert contexts[SUBJECT].failure_count == 5
    assert contexts[SUBJECT].start_utc == datetime(2026, 10, 30, 0, 0, tzinfo=timezone.utc)
    assert contexts[SUBJECT].end_utc == datetime(2026, 10, 30, 0, 0, 20, tzinfo=timezone.utc)
    analysis, selected, owner = _analyze_normalized_logs_with_context(events)
    subject_result = analysis["results"][SUBJECT]
    assert subject_result["detections"]["brute_force"].is_detected is True
    assert selected[SUBJECT].failure_count == 5
    wrapped = AnalysisWithSourceRoleSnapshot(
        analysis,
        AnalysisSourceRoleSnapshot.from_events(analysis, tuple(events)),
        selected,
        owner,
    )
    assert project_investigation_cases_from_analysis(wrapped).summary.case_count == 0


def test_offset_equivalent_events_and_reversed_order_select_identical_window():
    utc = timezone.utc
    seoul = timezone(timedelta(hours=9))
    base_utc = datetime(2026, 10, 30, 0, 0, tzinfo=utc)
    times = (
        base_utc,
        base_utc + timedelta(seconds=5),
        base_utc + timedelta(seconds=10),
        base_utc + timedelta(seconds=15),
        base_utc + timedelta(seconds=20),
    )
    # Alternate equivalent offset representations while preserving instants.
    events = []
    for index, instant in enumerate(times):
        stamp = instant.astimezone(seoul if index % 2 else utc)
        events.append(_synthetic_failure(stamp))

    forward = select_brute_window_contexts(events)[SUBJECT]
    reverse = select_brute_window_contexts(tuple(reversed(events)))[SUBJECT]
    assert (forward.start_utc, forward.end_utc, forward.failure_count) == (
        base_utc, base_utc + timedelta(seconds=20), 5,
    )
    assert (reverse.start_utc, reverse.end_utc, reverse.failure_count) == (
        forward.start_utc, forward.end_utc, forward.failure_count,
    )


def _synthetic_failure(timestamp):
    from app.models.schemas import NormalizedEvent

    return NormalizedEvent(
        timestamp=timestamp,
        event_type="login_failed",
        source="application",
        user=ACCOUNT,
        src_ip=SUBJECT,
        dst_ip=None,
        application="synthetic-auth",
        protocol=None,
        user_agent=None,
        raw="synthetic event",
    )


def test_live_and_static_analysis_match_for_late_noise_success_prefixes():
    lines = tuple(_app_line(second, "login_failed") for second in (0, 5, 10, 15, 20))
    lines += (_app_line(70, "login_failed"), _app_line(80, "user_login"))
    detector = LiveDetectionAccumulator("application", 32, 32768)
    live = LiveAnalysisAccumulator(detector, _metadata())
    prefix = []

    for sequence, line in enumerate(lines, 1):
        record = LiveTailRecord("application", sequence, line, len(line.encode()))
        parsed = parse_live_records("application", (record,))
        detection_proposal = detector.prepare(parsed)
        analysis_proposal = live.prepare(detection_proposal)
        detector.commit(detection_proposal)
        snapshot = live.commit(analysis_proposal)
        prefix.extend(item.event for item in parsed.outcomes if item.status == "PARSED")

        static_result, contexts, owner = _analyze_normalized_logs_with_context(prefix)
        wrapped = AnalysisWithSourceRoleSnapshot(
            static_result,
            AnalysisSourceRoleSnapshot.from_events(static_result, tuple(prefix)),
            contexts,
            owner,
        )
        static = static_result["results"][SUBJECT]
        live_result = live._state._results[SUBJECT]
        assert live_result["detections"]["brute_force"] == static["detections"]["brute_force"]
        assert live_result["features"] == static["features"]
        assert live_result["correlation"] == static["correlation"]
        assert snapshot.revision == sequence
        assert (snapshot.case_count > 0) == (
            project_investigation_cases_from_analysis(wrapped).summary.case_count > 0
        )

    assert live._state._results[SUBJECT]["correlation"]["brute_force_to_success"][
        "failure_timestamp"
    ] == datetime(2026, 10, 30, 0, 0, 20, tzinfo=timezone.utc)
    assert live.snapshot().case_count == 1
    live.close()
