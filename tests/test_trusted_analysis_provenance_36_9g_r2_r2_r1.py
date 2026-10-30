"""Detector 산출물부터 Consumer까지 실행 provenance가 유지되는지 검사한다."""

import pytest

from app.analyzer.incident_case_adapter import project_investigation_cases_from_analysis
from app.analyzer.pipeline import (
    assess_risk,
    correlate_attacks,
    detect_attacks_with_context,
    load_normalized_logs,
)
from app.detector.brute_force import AnalysisRunOwner
from app.main import analyze_with_source_role_snapshot


SOURCE = {
    "source": "application",
    "path": "sample_logs/brute_window_evaluation/bf_late_noise_then_success.log",
}


def _events():
    return load_normalized_logs((dict(SOURCE),))


def test_same_input_reanalysis_is_independent_and_both_cases_remain_valid():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    run_b = analyze_with_source_role_snapshot((dict(SOURCE),))

    assert run_a.analysis["results"] == run_b.analysis["results"]
    assert run_a.analysis["results"] is not run_b.analysis["results"]
    assert run_a.run_owner is not run_b.run_owner
    assert project_investigation_cases_from_analysis(run_a).summary.case_count == 1
    assert project_investigation_cases_from_analysis(run_b).summary.case_count == 1


def test_owner_b_cannot_finalize_analysis_a_without_its_detector_and_correlation_stages():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    owner_b = AnalysisRunOwner()
    detections_b, _ = detect_attacks_with_context(_events(), owner_b)

    assert not owner_b._matches_detection_results(run_a.analysis["results"])
    assert detections_b is not run_a.analysis["results"]
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner_b._create_analysis_result(run_a.analysis)


def test_replacing_a_current_detection_with_an_old_result_breaks_run_provenance():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    owner_b = AnalysisRunOwner()
    events_b = _events()
    detections_b, contexts_b = detect_attacks_with_context(events_b, owner_b)
    subject = next(iter(detections_b))
    detections_b[subject]["detections"]["brute_force"] = (
        run_a.analysis["results"][subject]["detections"]["brute_force"]
    )

    assert not owner_b._matches_detection_results(detections_b)
    analysis_b = correlate_attacks(
        events_b, detections_b, contexts_b, run_owner=owner_b,
    )
    assert analysis_b["results"][subject]["correlation"][
        "brute_force_to_success"
    ]["is_correlated"] is False
    with pytest.raises(ValueError, match="invalid_analysis_context"):
        owner_b._create_analysis_result(analysis_b)


def test_changing_a_detector_feature_after_its_stage_breaks_run_provenance():
    owner = AnalysisRunOwner()
    events = _events()
    detections, _ = detect_attacks_with_context(events, owner)
    subject = next(iter(detections))
    detections[subject]["features"]["failure_count"] += 1

    assert not owner._matches_detection_results(detections)


def test_old_correlation_mapping_cannot_replace_current_run_correlation():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    events_b = _events()
    owner_b = AnalysisRunOwner()
    detections_b, contexts_b = detect_attacks_with_context(events_b, owner_b)
    analysis_b = correlate_attacks(
        events_b, detections_b, contexts_b, run_owner=owner_b,
    )
    subject = next(iter(analysis_b["results"]))
    analysis_b["results"][subject]["correlation"] = run_a.analysis[
        "results"
    ][subject]["correlation"]

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        assess_risk(analysis_b, run_owner=owner_b)


def test_old_correlation_relation_cannot_be_inserted_under_current_mapping():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    events_b = _events()
    owner_b = AnalysisRunOwner()
    detections_b, contexts_b = detect_attacks_with_context(events_b, owner_b)
    analysis_b = correlate_attacks(
        events_b, detections_b, contexts_b, run_owner=owner_b,
    )
    subject = next(iter(analysis_b["results"]))
    analysis_b["results"][subject]["correlation"]["brute_force_to_success"] = (
        run_a.analysis["results"][subject]["correlation"][
            "brute_force_to_success"
        ]
    )

    with pytest.raises(ValueError, match="invalid_analysis_context"):
        assess_risk(analysis_b, run_owner=owner_b)


def test_finalized_analysis_mutation_invalidates_case_binding():
    run_a = analyze_with_source_role_snapshot((dict(SOURCE),))
    run_b = analyze_with_source_role_snapshot((dict(SOURCE),))
    subject = next(iter(run_b.analysis["results"]))
    run_b.analysis["results"][subject]["correlation"] = run_a.analysis[
        "results"
    ][subject]["correlation"]

    assert not run_b.run_owner.is_bound_to(run_b.analysis)


def test_normal_pipeline_brute_relation_remains_bound_to_its_window():
    run = analyze_with_source_role_snapshot((dict(SOURCE),))
    relation = run.analysis["results"]["198.51.100.21"]["correlation"][
        "brute_force_to_success"
    ]

    assert relation["is_correlated"] is True
    assert relation["failure_timestamp"] == run.brute_window_contexts[
        "198.51.100.21"
    ].end_utc
    assert relation["time_delta_seconds"] == 60
    assert project_investigation_cases_from_analysis(run).summary.case_count == 1
