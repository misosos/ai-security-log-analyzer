"""Independent, synthetic characterization of Spray correlation semantics."""

import json

import pytest

from app.evaluation.spray_correlation_semantics import (
    CORPUS_ROOT,
    SemanticEvaluationError,
    evaluate,
    load_scenarios,
    render_json,
    render_text,
)


def test_semantic_corpus_is_independent_closed_and_large_enough():
    scenarios = load_scenarios()
    assert len(scenarios) >= 24
    assert len({row["id"] for row in scenarios}) == len(scenarios)
    assert len({row["fixture"] for row in scenarios}) == len(scenarios)
    assert all(row["behavioral_pattern"] in {
        "PATTERN_PRESENT", "PATTERN_ABSENT", "PATTERN_UNDETERMINED",
    } for row in scenarios)
    assert all(row["relationship_interpretation"] for row in scenarios)
    assert CORPUS_ROOT.name == "spray_correlation_semantics"


def test_c0_actual_and_gate_open_are_separate_and_production_stays_unchanged():
    result = evaluate()
    rows = {row["scenario_id"]: row for row in result["scenarios"]}
    late = rows["late_noise_window_outside_pair"]
    assert late["c0_actual"]["detection_gate"] is False
    assert late["c0_actual"]["correlated"] is False
    assert late["c0_gate_open"]["correlated"] is True
    assert late["c0_gate_open"]["failure_offset_seconds"] == 90
    assert late["c0_gate_open"]["success_offset_seconds"] == 95
    assert result["production_changed"] is False


def test_c1_and_c2_match_the_existing_r3_prototype_and_keep_member_endpoints():
    result = evaluate()
    rows = {row["scenario_id"]: row for row in result["scenarios"]}
    late = rows["late_noise_window_outside_pair"]
    assert late["c1"]["correlated"] is False
    assert late["c2"]["correlated"] is False
    after = rows["same_account_success_after_completion"]
    assert after["c1"]["failure_is_window_member"] is True
    assert after["c2"]["failure_is_window_member"] is True
    assert after["c1"]["correlated"] is True
    assert after["c2"]["correlated"] is True


def test_pre_completion_and_equal_window_end_success_have_distinct_semantics():
    rows = {row["scenario_id"]: row for row in evaluate()["scenarios"]}
    before_end = rows["same_account_success_before_completion"]
    assert before_end["c1"]["correlated"] is True
    assert before_end["c2"]["correlated"] is False
    at_end = rows["success_at_window_end"]
    assert at_end["c1"]["correlated"] is True
    assert at_end["c2"]["correlated"] is False


def test_multi_account_ambiguity_missing_user_and_source_scope_are_explicit():
    rows = {row["scenario_id"]: row for row in evaluate()["scenarios"]}
    assert rows["success_for_nonmember_account"]["c1"]["correlated"] is False
    assert rows["multiple_success_accounts_tie"]["c1"]["reason"] == "ambiguous_pair"
    assert rows["missing_member_account_known_pair"]["c1"]["correlated"] is True
    assert rows["missing_member_account_known_pair"]["c2"]["reason"] == "missing_account"
    assert rows["mixed_source_same_username"]["semantic_flags"]["cross_source_identity_unverified"] is True


def test_time_anchor_inequalities_and_microsecond_boundary_are_checked():
    summary = evaluate()
    assert summary["time_anchor_analysis"]["end_pass_member_failure_fail_possible"] is True
    assert summary["time_anchor_analysis"]["member_failure_pass_end_fail_possible"] is False
    assert summary["time_anchor_analysis"]["failure_before_success_implies_end_not_later"] is True
    assert summary["time_anchor_analysis"]["end_60_seconds_plus_microsecond"] == "rejected"


def test_c3_preserves_generic_transition_separately_without_spray_association():
    rows = {row["scenario_id"]: row for row in evaluate()["scenarios"]}
    row = rows["same_account_success_before_completion"]
    assert row["generic_auth_transition"]["correlated"] is True
    assert row["c3"]["pattern_success_association"] is False
    assert row["c3"]["pattern_observed"] is True


def test_corpus_labels_are_not_derived_from_policy_results():
    result = evaluate()
    for row in result["scenarios"]:
        assert row["label_source"] == "manifest"
        assert row["policy_result_used_for_label"] is False
    assert "relationship" in result["label_dimensions"]


def test_text_json_are_stable_redacted_and_production_boundary_is_explicit():
    first = evaluate()
    second = evaluate()
    assert first == second
    rendered = render_json(first)
    assert json.loads(rendered) == first
    assert render_text(first) == render_text(second)
    for secret in ("spray_", "192.0.2.", "198.51.100.", "203.0.113.", "raw="):
        assert secret not in rendered
        assert secret not in render_text(first)
    assert first["production_changed"] is False
    assert first["network_used"] is False


def test_closed_manifest_and_fixture_boundary_reject_path_traversal(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":1,"data_scope":"synthetic-only","scenarios":[],"extra":true}', encoding="utf-8")
    with pytest.raises(SemanticEvaluationError, match="invalid_manifest"):
        load_scenarios(manifest)


def test_duplicate_json_key_and_non_finite_constant_are_rejected(tmp_path):
    for body in (
        '{"schema_version":1,"schema_version":1,"data_scope":"synthetic-only","scenarios":[]}',
        '{"schema_version":NaN,"data_scope":"synthetic-only","scenarios":[]}',
    ):
        manifest = tmp_path / "manifest.json"
        manifest.write_text(body, encoding="utf-8")
        with pytest.raises(SemanticEvaluationError):
            load_scenarios(manifest)


def test_manifest_rejects_traversal_duplicate_fixture_and_symlink(tmp_path):
    manifest = tmp_path / "manifest.json"
    row = dict(load_scenarios()[0])
    row.pop("_fixture_rows")
    row["fixtures"] = [{"line_count": 1, "path": "../outside.log", "source": "application"}]
    manifest.write_text(json.dumps({"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [row]}), encoding="utf-8")
    with pytest.raises(SemanticEvaluationError):
        load_scenarios(manifest)
    link = tmp_path / "linked.log"
    target = tmp_path / "real.log"
    target.write_text("synthetic", encoding="utf-8")
    link.symlink_to(target)
    row["fixtures"] = [{"line_count": 1, "path": link.name, "source": "application"}]
    manifest.write_text(json.dumps({"schema_version": 1, "data_scope": "synthetic-only", "scenarios": [row]}), encoding="utf-8")
    with pytest.raises(SemanticEvaluationError):
        load_scenarios(manifest)


def test_production_analysis_does_not_import_semantic_evaluator():
    from pathlib import Path

    production_sources = (
        Path("app/analyzer/pipeline.py"), Path("app/correlation/attack_chain.py"),
        Path("app/analyzer/risk.py"),
    )
    for path in production_sources:
        assert "spray_correlation_semantics" not in path.read_text(encoding="utf-8")


def test_anchor_summary_exposes_inequality_and_rejects_microsecond_overrun():
    result = evaluate()
    timing = result["time_anchor_analysis"]
    assert "t_f < t_success" in timing["definitions"]["C1"]
    assert "t_e < t_success" in timing["definitions"]["C2"]
    assert timing["end_pass_member_failure_fail_possible"] is True
    assert timing["member_failure_pass_end_fail_possible"] is False
    rows = {row["scenario_id"]: row for row in result["scenarios"]}
    assert rows["success_60_seconds_plus_one_microsecond"]["c1"]["correlated"] is False
    assert rows["window_end_and_member_delta_exactly_sixty"]["c2"]["correlated"] is True


def test_cli_summary_keeps_parser_observation_and_context_labels_separate():
    result = evaluate()
    assert set(result["label_counts"]) >= {
        "behavioral_pattern", "operational_context", "parser_status",
        "relationship_interpretation", "ambiguity",
    }
    assert result["consumer_impact"]["case_rule_activated"] is False
    assert result["consumer_impact"]["risk_policy_changed"] is False


def test_window_end_anchor_rejects_precompletion_even_when_member_pair_is_valid():
    rows = {row["scenario_id"]: row for row in evaluate()["scenarios"]}
    row = rows["member_failure_passes_before_window_end"]
    assert row["c1"]["correlated"] is True
    assert row["c2"]["correlated"] is False
    assert row["semantic_flags"]["pre_completion_association"] is True


def test_end_delta_can_pass_while_account_specific_member_delta_fails():
    row = next(
        item for item in evaluate()["scenarios"]
        if item["scenario_id"] == "end_anchor_pass_member_failure_limit_fails"
    )
    assert row["c1"]["correlated"] is False
    assert row["c2"]["correlated"] is False
    assert row["labels"]["relationship_interpretation"] == "END_ANCHOR_PASS_MEMBER_DELTA_FAIL"


def test_multiple_success_tie_and_missing_account_fail_closed_in_c2():
    rows = {row["scenario_id"]: row for row in evaluate()["scenarios"]}
    assert rows["multiple_success_accounts_tie"]["c1"]["reason"] == "ambiguous_pair"
    assert rows["multiple_success_accounts_tie"]["c2"]["reason"] == "ambiguous_pair"
    assert rows["missing_member_account_known_pair"]["c1"]["correlated"] is True
    assert rows["missing_member_account_known_pair"]["c2"]["reason"] == "missing_account"


def test_gate_open_pair_and_generic_transition_are_observations_not_compromise():
    result = evaluate()
    row = next(x for x in result["scenarios"] if x["scenario_id"] == "late_noise_window_outside_pair")
    assert row["c0_gate_open"]["failure_offset_seconds"] == 90
    assert row["c0_gate_open"]["success_offset_seconds"] == 95
    assert row["semantic_flags"]["out_of_window_endpoint"] is True
    assert row["c3"]["pattern_success_association"] is False
    assert result["recommendation"] != "PRODUCTION_GO"
