"""R2에서 독립 확인하는 Analysis↔Owner 단일 결속 계약."""

import pytest

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import load_normalized_logs
from app.detector.brute_force import AnalysisRunOwner, select_brute_window_contexts
from app.investigation_role_snapshot_36_4 import AnalysisWithSourceRoleSnapshot
from app.main import analyze_with_source_role_snapshot


SOURCE = {
    "source": "application",
    "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
}


def _run():
    return analyze_with_source_role_snapshot((dict(SOURCE),))


def test_current_run_wrapper_accepts_its_own_context_and_projects_case():
    run = _run()

    assert project_investigation_cases_from_analysis(run).summary.case_count == 1


def test_one_owner_cannot_bind_two_analysis_objects():
    owner = AnalysisRunOwner()

    analysis = owner._create_analysis_result()
    analysis.update({"analysis": "synthetic-a"})
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner._bind_analysis({"analysis": "synthetic-b"})


def test_an_analysis_cannot_be_claimed_by_a_second_distinct_owner():
    """다른 Owner로 재결속하면 같은 Analysis의 서로 다른 실행이 수용된다."""
    run_a = _run()
    events_b = load_normalized_logs((dict(SOURCE),))
    owner_b = AnalysisRunOwner()

    # Analysis는 기존 객체를 사후 전달해 Owner를 붙이는 대신, Owner가
    # 새 private mapping을 만들 때만 해당 실행에 결속된다.
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner_b._bind_analysis(run_a.analysis)

    contexts_b = select_brute_window_contexts(events_b, owner_b)
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        AnalysisWithSourceRoleSnapshot(
            run_a.analysis,
            run_a.source_roles,
            contexts_b,
            owner_b,
        )
    assert project_investigation_cases_from_analysis(run_a).summary.case_count == 1
