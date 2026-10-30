"""Analysis 결과와 run owner의 단일 결속 및 consumer 경계 회귀."""

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    build_incident_case_subject_inputs,
    project_investigation_cases_from_analysis,
)
from app.detector.brute_force import AnalysisRunOwner, is_owned_analysis_result
from app.investigation_role_snapshot_36_4 import (
    AnalysisSourceRoleSnapshot,
    AnalysisWithSourceRoleSnapshot,
)
from app.main import analyze, analyze_with_source_role_snapshot


SOURCE = {
    "source": "application",
    "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
}


def _run():
    return analyze_with_source_role_snapshot((dict(SOURCE),))


def test_run_owner_creates_exactly_one_private_analysis_mapping():
    run = _run()
    owner = run.run_owner
    analysis = run.analysis

    assert is_owned_analysis_result(analysis, owner)
    assert owner.is_bound_to(analysis)
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._create_analysis_result(analysis)
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._bind_analysis({"results": {}, "global_correlation": {}})


def test_distinct_run_cannot_claim_or_repackage_an_existing_analysis():
    run_a = _run()
    owner_b = AnalysisRunOwner()

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner_b._bind_analysis(run_a.analysis)

    run_b = _run()
    analysis_b = run_b.analysis
    roles_b = run_b.source_roles

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        AnalysisWithSourceRoleSnapshot(
            run_a.analysis,
            run_a.source_roles,
            run_a.brute_window_contexts,
            owner_b,
        )
    assert project_investigation_cases_from_analysis(run_a).summary.case_count == 1
    assert analysis_b is not run_a.analysis
    assert roles_b.is_bound_to(analysis_b)


def test_same_owner_cannot_be_rebound_and_distinct_runs_are_independent():
    run_a = _run()
    run_b = _run()

    assert run_a.analysis is not run_b.analysis
    assert run_a.run_owner is not run_b.run_owner
    assert run_a.run_owner.is_bound_to(run_a.analysis)
    assert run_b.run_owner.is_bound_to(run_b.analysis)
    assert run_a.run_owner.is_bound_to(run_b.analysis) is False
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        run_a.run_owner._bind_analysis(run_b.analysis)


def test_case_adapter_direct_boundary_rejects_unowned_window_context():
    run = _run()
    subject = next(iter(run.analysis["results"].values()))

    with pytest.raises(IncidentCaseAdapterError):
        build_incident_case_subject_inputs(
            {next(iter(run.analysis["results"])): subject},
            brute_window_contexts=run.brute_window_contexts,
            run_owner=AnalysisRunOwner(),
            bound_analysis=run.analysis,
        )


def test_owned_metadata_does_not_change_public_analysis_mapping_or_repr():
    run = _run()
    public_result = analyze((dict(SOURCE),))

    assert isinstance(run.analysis, dict)
    assert set(run.analysis) == {"results", "global_correlation"}
    assert type(public_result) is dict
    assert set(public_result) == {"results", "global_correlation"}
    assert "AnalysisRunOwner" not in repr(run.analysis)
    assert "BruteWindowContext" not in repr(run.analysis)
    assert "synthetic_user_a" not in repr(run)
    assert project_investigation_cases_from_analysis(run).summary.case_count == 1
