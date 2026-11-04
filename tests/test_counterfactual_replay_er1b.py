import json
from pathlib import Path
import socket

import pytest

from app.evaluation.counterfactual_comparison import (
    ComparisonState,
    RunObservation,
    compare_runs,
    validate_reason_codes,
)
from app.evaluation.counterfactual_replay import (
    CounterfactualCorpusError,
    CounterfactualReplayError,
    canonical_json,
    run_corpus,
)


def _observation(**overrides):
    values = {
        "detector_id": "brute_force",
        "policy_id": "brute_force_production_v1",
        "source": "application",
        "parser_profile": "application_auth_v1",
        "parser_state": "VERIFIED",
        "detection_state": "DETECTED",
        "comparison_scope": "target_source_ip",
        "subject_present": True,
        "label_provenance": True,
        "evidence_bound": True,
        "execution_complete": True,
    }
    values.update(overrides)
    return RunObservation(**values)


@pytest.mark.parametrize(
    ("baseline", "variant", "expected"),
    [
        ("DETECTED", "DETECTED", ComparisonState.PRESERVED),
        ("DETECTED", "NOT_DETECTED", ComparisonState.LOST),
        ("NOT_DETECTED", "DETECTED", ComparisonState.GAINED),
        ("NOT_DETECTED", "NOT_DETECTED", ComparisonState.UNCHANGED_ABSENT),
    ],
)
def test_comparison_maps_only_complete_bound_verified_runs(baseline, variant, expected):
    result = compare_runs(
        _observation(detection_state=baseline),
        _observation(detection_state=variant),
    )
    assert result.state is expected


def test_comparison_fails_closed_for_partial_rejected_missing_subject_and_provenance():
    assert compare_runs(
        _observation(parser_state="PARTIAL"),
        _observation(parser_state="PARTIAL"),
    ).state is ComparisonState.UNDETERMINED
    rejected = compare_runs(
        _observation(parser_state="REJECTED", detection_state="NOT_EVALUATED", subject_present=False),
        _observation(),
    )
    assert rejected.state is ComparisonState.INCOMPARABLE
    assert "PARSER_REJECTED" in rejected.reason_codes
    missing = compare_runs(
        _observation(),
        _observation(subject_present=False, detection_state="NOT_EVALUATED"),
    )
    assert missing.state is ComparisonState.INCOMPARABLE
    assert compare_runs(
        _observation(evidence_bound=False), _observation(),
    ).state is ComparisonState.UNDETERMINED
    assert compare_runs(
        _observation(label_provenance=False), _observation(),
    ).state is ComparisonState.UNDETERMINED


@pytest.mark.parametrize(
    ("right", "reason"),
    [
        ({"detector_id": "password_spraying_like"}, "DETECTOR_VERSION_MISMATCH"),
        ({"policy_id": "other"}, "POLICY_MISMATCH"),
        ({"source": "ssh"}, "SOURCE_SCOPE_MISMATCH"),
        ({"parser_profile": "different"}, "PARSER_PROFILE_MISMATCH"),
        ({"comparison_scope": "whole_source"}, "INPUT_SCOPE_MISMATCH"),
    ],
)
def test_comparison_marks_known_scope_mismatch_incomparable(right, reason):
    result = compare_runs(_observation(), _observation(**right))
    assert result.state is ComparisonState.INCOMPARABLE
    assert reason in result.reason_codes


def test_execution_failure_is_never_no_detection():
    result = compare_runs(
        _observation(detection_state="EXECUTION_FAILED", execution_complete=False),
        _observation(),
    )
    assert result.state is ComparisonState.UNDETERMINED
    assert "EXECUTION_INCOMPLETE" in result.reason_codes


def test_unknown_enum_and_conflicting_rejected_state_are_rejected():
    with pytest.raises(CounterfactualReplayError) as caught:
        compare_runs(_observation(parser_state="UNKNOWN"), _observation())
    assert str(caught.value) == "INVALID_INTERNAL_CONTRACT"
    with pytest.raises(CounterfactualReplayError) as caught:
        compare_runs(
            _observation(parser_state="REJECTED", detection_state="DETECTED"),
            _observation(),
        )
    assert str(caught.value) == "INVALID_INTERNAL_CONTRACT"


def test_unknown_reason_code_is_rejected():
    with pytest.raises(CounterfactualReplayError) as caught:
        validate_reason_codes(("PRIVATE_CANARY",))
    assert str(caught.value) == "INVALID_INTERNAL_CONTRACT"
    assert "PRIVATE_CANARY" not in repr(caught.value)


def test_production_replay_executes_synthetic_corpus_with_private_run_separation():
    report = run_corpus()
    assert report.schema_version == 1
    assert report.scenario_count == 16
    assert len(report.results) == 16
    assert all(row.baseline_parser_state == "VERIFIED" for row in report.results)
    assert {row.variant_parser_state for row in report.results} == {
        "VERIFIED", "PARTIAL", "REJECTED",
    }
    assert all(row.label_validation_baseline in {"MATCH", "MISMATCH"} for row in report.results)
    for row in report.results:
        if row.scenario_id.endswith("change_ip"):
            assert row.comparison_state == "LOST"
            assert row.variant_facts.target_failure_count > 0
    assert report.counts["parser_baseline"] == {
        "VERIFIED": 16, "PARTIAL": 0, "REJECTED": 0, "NOT_EVALUATED": 0,
    }
    assert report.counts["parser_variant"] == {
        "VERIFIED": 13, "PARTIAL": 2, "REJECTED": 1, "NOT_EVALUATED": 0,
    }
    assert report.counts["detector_variant"]["NOT_EVALUATED"] == 1
    assert report.counts["comparison"]["INCOMPARABLE"] >= 1
    assert set(report.counts["comparison"]) == {
        "PRESERVED", "LOST", "GAINED", "UNCHANGED_ABSENT", "INCOMPARABLE", "UNDETERMINED",
    }
    assert report.counts["excluded_comparisons"]["count"] == (
        report.counts["comparison"]["INCOMPARABLE"]
        + report.counts["comparison"]["UNDETERMINED"]
    )
    assert report.counts["reason_codes"]["PARSER_REJECTED"] == 1
    assert report.counts["reason_codes"]["REQUIRED_FIELD_MISSING"] == 2


def test_canonical_output_is_stable_and_contains_no_sensitive_values():
    first = canonical_json(run_corpus())
    second = canonical_json(run_corpus())
    assert first == second
    decoded = json.loads(first)
    assert decoded["schema_version"] == 1
    for forbidden in (
        "192.0.2.", "198.51.100.", "203.0.113.",
        "synthetic_user_", "2026-11-04", "/tmp/", "raw",
    ):
        assert forbidden not in first.decode("utf-8")
    assert len(first) <= 64 * 1024


def test_detector_replay_exception_is_fixed_and_never_echoed(monkeypatch):
    from app.evaluation import counterfactual_replay as replay

    monkeypatch.setattr(
        replay,
        "analyze_with_source_role_snapshot",
        lambda _sources: (_ for _ in ()).throw(RuntimeError("ER1B_PRIVATE_CANARY")),
    )
    report = replay.run_scenario(replay.load_corpus()[0])
    assert report.baseline_detection_state == "EXECUTION_FAILED"
    assert report.variant_detection_state == "EXECUTION_FAILED"
    assert report.comparison_state == "UNDETERMINED"
    assert "ANALYSIS_EXECUTION_FAILED" in report.reason_codes
    assert "ER1B_PRIVATE_CANARY" not in repr(report)


def test_unexpected_parser_execution_failure_is_not_rejected(monkeypatch):
    from app.evaluation import counterfactual_corpus as corpus
    from app.evaluation import counterfactual_replay as replay

    monkeypatch.setattr(
        corpus,
        "_parse_fixture",
        lambda _source, _data: (_ for _ in ()).throw(
            CounterfactualCorpusError("parser_execution_failed"),
        ),
    )
    row = replay.run_scenario(replay.load_corpus()[0])
    assert row.baseline_parser_state == "NOT_EVALUATED"
    assert row.baseline_detection_state == "NOT_EVALUATED"
    assert row.comparison_state == "UNDETERMINED"
    assert "ANALYSIS_EXECUTION_FAILED" in row.reason_codes


def test_cli_emits_canonical_json_and_rejects_arguments_without_echo(capsys):
    from app.evaluation.counterfactual_replay_cli import main

    assert main([]) == 0
    captured = capsys.readouterr()
    output = captured.out.encode("utf-8")
    assert output == canonical_json(run_corpus())
    assert captured.err == ""
    assert main(["ER1B_PRIVATE_CANARY"]) == 2
    rejected = capsys.readouterr()
    assert rejected.out == ""
    assert rejected.err == "INVALID_INTERNAL_CONTRACT\n"
    assert "ER1B_PRIVATE_CANARY" not in rejected.err


def test_baseline_and_variant_use_distinct_production_owners_and_temp_inputs(monkeypatch):
    from app.evaluation import counterfactual_replay as replay
    from app.evaluation.counterfactual_corpus import load_corpus
    from app.detector.brute_force import brute_window_context_owner

    original = replay.analyze_with_source_role_snapshot
    runs = []

    def capture(source_configs):
        bundle = original(source_configs)
        runs.append((source_configs[0]["path"], bundle))
        return bundle

    monkeypatch.setattr(replay, "analyze_with_source_role_snapshot", capture)
    scenario = next(item for item in load_corpus() if item.scenario_id == "bf_app_exact60_reorder")
    replay.run_scenario(scenario)

    assert len(runs) == 2
    assert runs[0][0] != runs[1][0]
    assert all(not Path(path).exists() for path, _ in runs)
    baseline_bundle, variant_bundle = runs[0][1], runs[1][1]
    assert baseline_bundle.run_owner is not variant_bundle.run_owner
    assert baseline_bundle.run_owner.is_bound_to(baseline_bundle.analysis)
    assert variant_bundle.run_owner.is_bound_to(variant_bundle.analysis)
    baseline_context = baseline_bundle.brute_window_contexts[scenario.target_subject]
    variant_context = variant_bundle.brute_window_contexts[scenario.target_subject]
    assert brute_window_context_owner(baseline_context) is baseline_bundle.run_owner
    assert brute_window_context_owner(variant_context) is variant_bundle.run_owner
    baseline_detection = baseline_bundle.analysis["results"][scenario.target_subject]["detections"]["brute_force"]
    assert baseline_bundle.run_owner._has_brute_detection(
        scenario.target_subject, baseline_detection,
    )
    assert not variant_bundle.run_owner._has_brute_detection(
        scenario.target_subject, baseline_detection,
    )
    assert brute_window_context_owner(variant_context) is not baseline_bundle.run_owner


def test_parser_prevalidation_and_production_replay_receive_identical_bytes(monkeypatch):
    from app.evaluation import counterfactual_corpus as corpus
    from app.evaluation import counterfactual_replay as replay

    parser_inputs = []
    production_inputs = []
    original_parser = corpus._parse_fixture
    original_analysis = replay.analyze_with_source_role_snapshot

    def capture_parser(source, data):
        parser_inputs.append(data)
        return original_parser(source, data)

    def capture_analysis(source_configs):
        production_inputs.append(Path(source_configs[0]["path"]).read_bytes())
        return original_analysis(source_configs)

    monkeypatch.setattr(corpus, "_parse_fixture", capture_parser)
    monkeypatch.setattr(replay, "analyze_with_source_role_snapshot", capture_analysis)
    scenario = next(item for item in corpus.load_corpus() if item.scenario_id == "bf_app_exact60_reorder")

    replay.run_scenario(scenario)

    assert len(parser_inputs) == len(production_inputs) == 2
    assert parser_inputs[0] == production_inputs[0]
    assert parser_inputs[1] == production_inputs[1]


def test_replay_never_attempts_network_or_writes_to_console(monkeypatch, capsys):
    attempts = []

    def deny_connect(_socket, *_args, **_kwargs):
        attempts.append("connect")
        raise AssertionError("network disabled")

    monkeypatch.setattr(socket.socket, "connect", deny_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_connect)
    run_corpus()
    captured = capsys.readouterr()
    assert attempts == []
    assert captured.out == ""
    assert captured.err == ""
