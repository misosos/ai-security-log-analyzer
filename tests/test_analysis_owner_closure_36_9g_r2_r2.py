"""R2-R2 독립 검사: 새 owned mapping에 이전 실행의 결과를 복사하는 우회."""

from copy import deepcopy

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
import pytest

from app.main import analyze_with_source_role_snapshot


SOURCE = {
    "source": "application",
    "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
}


def test_repacked_prior_analysis_results_do_not_gain_new_run_provenance():
    """새 실행 mapping에 과거 Results를 복사해도 Case 입력으로 승인하지 않는다."""
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    run_b = analyze_with_source_role_snapshot((dict(SOURCE),))

    # 정상적인 독립 실행은 자기 결과로 계속 Case를 만든다.
    assert project_investigation_cases_from_analysis(run_b).summary.case_count == 1
    assert run_a.analysis["results"] == run_b.analysis["results"]

    # R2에서 문제였던 빈 Owner mapping에 내용을 복사하는 행위를 기존
    # Owner B의 완성 mapping에서 재현한다. Consumer 경계는 사후 교체를 거부한다.
    run_b.analysis["results"] = deepcopy(run_a.analysis["results"])
    with pytest.raises(IncidentCaseAdapterError):
        project_investigation_cases_from_analysis(run_b)
