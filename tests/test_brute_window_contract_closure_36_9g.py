"""36.9G 독립 사후 계약 검사."""

import pytest

from app.analyzer.incident_case_adapter import (
    IncidentCaseAdapterError,
    project_investigation_cases_from_analysis,
)
from app.investigation_role_snapshot_36_4 import AnalysisWithSourceRoleSnapshot
from app.main import analyze_with_source_role_snapshot


def _analyze_fixture():
    return analyze_with_source_role_snapshot(({
        "source": "application",
        "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
    },))


def test_case_adapter_rejects_context_reused_from_another_analysis_run():
    """값이 같은 새 분석에 이전 실행의 event capability를 붙이지 않는다."""
    previous_run = _analyze_fixture()
    current_run = _analyze_fixture()

    with pytest.raises((IncidentCaseAdapterError, ValueError), match="invalid_analysis_context|Incident case adapter failed"):
        reused_context = AnalysisWithSourceRoleSnapshot(
            current_run.analysis,
            current_run.source_roles,
            previous_run.brute_window_contexts,
        )
        project_investigation_cases_from_analysis(reused_context)
