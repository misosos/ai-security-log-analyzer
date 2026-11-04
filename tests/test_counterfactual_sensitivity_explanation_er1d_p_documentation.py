import json
from pathlib import Path

from app.evaluation.counterfactual_corpus import (
    _thaw,
    load_corpus,
    load_fixture,
    prepare_scenario,
)
from app.evaluation.counterfactual_mutation import apply_mutation


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "counterfactual_sensitivity_explanation_design_er1d_p.md"
INDEX = ROOT / "docs" / "index.md"


def test_er1d_p_design_freezes_evidence_layers_schema_and_human_gate():
    text = DOC.read_text(encoding="utf-8")
    for heading in (
        "## 1. Executive Summary",
        "## 2. Start SHA / CI Gate",
        "## 3. Existing System Analysis",
        "## 5. Four-Layer Evidence Model",
        "## 11. Proposed Closed Explanation Schema",
        "## 12. Scenario-Based Validation Matrix",
        "## 14. Independent Human Review Gate",
        "## 17. Final Decision",
    ):
        assert heading in text

    for term in (
        "Direct Input Mutation",
        "Observed Feature Delta",
        "Policy Predicate Evaluation",
        "Detector Observation",
        "DIRECT_INPUT_CHANGE",
        "DERIVED_FEATURE_CHANGE",
        "POLICY_CONDITION_CHANGE",
        "DETECTOR_OBSERVATION_CHANGE",
        "INSUFFICIENT_EVIDENCE",
        "INCOMPARABLE",
        "UNDETERMINED",
        "INDEPENDENT_HUMAN_REVIEW_PENDING",
        "MANUAL_APPROVAL_REQUIRED",
        "ER_1D_IMPLEMENTATION_HOLD",
        "12988ec065c66901eb4036454fb24e52ef52c2bc435e65ea73b42d9846957c92",
        "Detection ≠ Confirmed Compromise",
        "Correlation ≠ Causation",
        "No Detection ≠ Safe",
        "Counterfactual Change ≠ Real-world Evasion Success",
        "NIST SP 800-86",
        "MITRE ATT&CK",
        "실제 사용자 자료: `NO_GO`",
        "조직 운영: `NO_GO`",
        "자동 대응: `NO_GO`",
    ):
        assert term in text

    for field in (
        "schema_version",
        "scenario_id",
        "detector_id",
        "policy_id",
        "mutation_type",
        "parser_states",
        "detection_states",
        "comparison_state",
        "direct_input_changes",
        "observed_feature_deltas",
        "policy_predicates",
        "evidence_binding_status",
        "explanation_claims",
        "uncertainty_codes",
    ):
        assert f"`{field}`" in text

    for corpus in ("counterfactual", "counterfactual_holdout"):
        manifest = json.loads((ROOT / "sample_logs" / corpus / "manifest.json").read_text(encoding="utf-8"))
        for scenario in manifest["scenarios"]:
            assert scenario["scenario_id"] in text


def test_er1d_p_design_distinguishes_policy_scope_and_noncausal_claims():
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "brute_force_production_v1",
        "password_spray_whole_span_production_v1",
        "선택 Sliding Window",
        "전체 실패 span",
        "BruteWindowContext",
        "AnalysisRunOwner",
        "Parser REJECTED",
        "PARTIAL",
        "EXECUTION_FAILED",
        "유일한 원인",
        "공격자가 탐지를 성공적으로 우회함",
        "실제 Brute Force 공격임이 확인됨",
        "NIST",
        "MITRE",
        "2026-11-04",
    ):
        assert required in text


def test_er1d_p_documentation_is_indexed():
    assert "counterfactual_sensitivity_explanation_design_er1d_p.md" in INDEX.read_text(encoding="utf-8")


def test_er1d_p_brute_boundary_inputs_exist_but_safe_window_projection_does_not():
    scenarios = {item.scenario_id: item for item in load_corpus()}
    remove = scenarios["bf_app_remove_failure"]
    add = scenarios["bf_app_add_failure"]

    remove_prepared = prepare_scenario(remove)
    remove_base = dict(remove_prepared.baseline_event_facts)
    remove_variant = dict(remove_prepared.event_facts)
    assert remove_prepared.baseline_parser_disposition == "VERIFIED"
    assert remove_prepared.parser_disposition == "VERIFIED"
    assert (remove_base["target_failure_count"], remove_base["target_failure_span_seconds"]) == (5, 40.0)
    assert (remove_variant["target_failure_count"], remove_variant["target_failure_span_seconds"]) == (4, 30.0)
    assert remove.baseline_expected_behavioral_pattern == "PATTERN_PRESENT"
    assert remove.expected_behavioral_pattern == "PATTERN_ABSENT"

    add_prepared = prepare_scenario(add)
    add_base = dict(add_prepared.baseline_event_facts)
    add_variant = dict(add_prepared.event_facts)
    assert add_prepared.baseline_parser_disposition == "VERIFIED"
    assert add_prepared.parser_disposition == "VERIFIED"
    assert (add_base["target_failure_count"], add_base["target_failure_span_seconds"]) == (4, 30.0)
    assert (add_variant["target_failure_count"], add_variant["target_failure_span_seconds"]) == (5, 40.0)
    assert add.baseline_expected_behavioral_pattern == "PATTERN_ABSENT"
    assert add.expected_behavioral_pattern == "PATTERN_PRESENT"

    for scenario in (remove, add):
        baseline = load_fixture(scenario.baseline_fixture_id)
        variant = apply_mutation(
            baseline,
            source=scenario.source,
            mutation_type=scenario.mutation_type,
            mutation_target=scenario.mutation_target,
            mutation_parameters=_thaw(scenario.mutation_parameters),
        )
        assert baseline != variant

    text = DOC.read_text(encoding="utf-8")
    assert "입력 수준 경계 사례" in text
    assert "safe projection은 구현되지 않았다" in text
    assert "No current fixture demonstrates a verified Brute selected-window count changing exactly 5→4" not in text
