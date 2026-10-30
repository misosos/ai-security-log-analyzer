"""분석 실행별 Brute Context 소유권 계약."""

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.investigation_role_snapshot_36_4 import AnalysisWithSourceRoleSnapshot
from app.main import analyze_with_source_role_snapshot


SYNTHETIC_SOURCE = {
    "source": "application",
    "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
}


def _run():
    return analyze_with_source_role_snapshot((dict(SYNTHETIC_SOURCE),))


def test_equal_inputs_get_distinct_owners_and_each_normal_case_projects():
    run_a = _run()
    run_b = _run()

    assert run_a.run_owner is not run_b.run_owner
    assert project_investigation_cases_from_analysis(run_a).summary.case_count == 1
    assert project_investigation_cases_from_analysis(run_b).summary.case_count == 1


@pytest.mark.parametrize("target", ("a", "b"))
def test_context_from_either_run_cannot_be_repacked_for_the_other(target):
    run_a = _run()
    run_b = _run()
    analysis_target, role_target = (
        (run_a.analysis, run_a.source_roles)
        if target == "a"
        else (run_b.analysis, run_b.source_roles)
    )
    foreign_contexts = (
        run_b.brute_window_contexts if target == "a" else run_a.brute_window_contexts
    )

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        AnalysisWithSourceRoleSnapshot(
            analysis_target,
            role_target,
            foreign_contexts,
        )


def test_subject_adapter_rejects_foreign_owner_even_when_called_without_wrapper():
    from app.analyzer.incident_case_adapter import build_incident_case_subject_inputs

    run_a = _run()
    run_b = _run()
    with pytest.raises(IncidentCaseAdapterError):
        build_incident_case_subject_inputs(
            run_b.analysis["results"],
            brute_window_contexts=run_a.brute_window_contexts,
            run_owner=run_a.run_owner,
            bound_analysis=run_b.analysis,
        )


def test_same_normalized_event_objects_reanalyzed_under_new_owner_are_isolated():
    from app.main import _analyze_normalized_logs_with_context
    from app.parser.registry import get_parser, get_timezone
    from app.parser.time_utils import normalize_to_utc
    from app.loader.file_loader import load_log_lines

    parser = get_parser("application")
    events = [
        parser(line, get_timezone("application"))
        for line in load_log_lines(SYNTHETIC_SOURCE["path"])
    ]
    for event in events:
        event.timestamp = normalize_to_utc(event.timestamp)
    run_a = _analyze_normalized_logs_with_context(events)
    run_b = _analyze_normalized_logs_with_context(events)

    assert run_a[2] is not run_b[2]
    assert run_a[2].is_bound_to(run_a[0])
    assert run_b[2].is_bound_to(run_b[0])
    assert run_a[2].is_bound_to(run_b[0]) is False


def test_same_event_objects_do_not_authorize_cross_run_correlation_context():
    from app.correlation.attack_chain import correlate_brute_force_to_success
    from app.main import _analyze_normalized_logs_with_context
    from app.parser.registry import get_parser, get_timezone
    from app.parser.time_utils import normalize_to_utc
    from app.loader.file_loader import load_log_lines

    parser = get_parser("application")
    events = [parser(line, get_timezone("application"))
              for line in load_log_lines(SYNTHETIC_SOURCE["path"])]
    for event in events:
        event.timestamp = normalize_to_utc(event.timestamp)

    run_a = _analyze_normalized_logs_with_context(events)
    run_b = _analyze_normalized_logs_with_context(events)
    context_a = run_a[1]["198.51.100.21"]
    detection_a = run_a[0]["results"]["198.51.100.21"]["detections"]["brute_force"]

    valid = correlate_brute_force_to_success(
        events,
        detection_a,
        window_context=context_a,
        run_owner=run_a[2],
    )
    cross_run = correlate_brute_force_to_success(
        events,
        detection_a,
        window_context=context_a,
        run_owner=run_b[2],
    )
    assert valid["is_correlated"] is True
    assert cross_run["is_correlated"] is False


def test_replacing_context_drops_run_owner_and_fails_validation():
    from dataclasses import replace

    from app.detector.brute_force import validate_brute_window_context

    run = _run()
    context = run.brute_window_contexts["198.51.100.21"]
    copied = replace(context)
    with pytest.raises(ValueError, match="invalid_brute_window_context"):
        validate_brute_window_context(copied)


def test_owner_and_context_representations_are_redacted():
    run = _run()
    owner = run.run_owner
    context = run.brute_window_contexts["198.51.100.21"]
    for rendered in (repr(owner), str(owner), repr(context), repr(run)):
        assert "synthetic_user_a" not in rendered
        assert "198.51.100.21" not in rendered
        assert "0x" not in rendered
