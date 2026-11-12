"""Real fixed-input API projections rendered by the dependency-free UI component.

The tiny DOM below tests text and replacement only; actual browser checks remain
separate from these component tests.
"""

import json
from pathlib import Path
import subprocess

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.evaluation.counterfactual_corpus import load_corpus, load_fixture, _thaw
from app.evaluation.counterfactual_mutation import apply_mutation


ROOT = Path(__file__).resolve().parents[1]
COMPLETE_LIMIT = "모든 탐지에 필요한 정보가 갖춰졌거나 탐지 평가가 완료됐다는 뜻은 아닙니다."
NO_RESULT = "입력이 거부되어 이 요청의 분석 결과는 생성되지 않았습니다."
RETAINED = "인식한 줄의 분석 결과는 유지됩니다."

# Execute the production renderer, without adding a DOM or browser dependency.
RENDER = r"""
const fs = require('node:fs');
const vm = require('node:vm');
class Node {
  constructor(value = '') { this.value = value; this.children = []; }
  set textContent(value) { this.value = value; this.children = []; }
  get textContent() { return this.value + this.children.map(n => n.textContent).join(''); }
  get childElementCount() { return this.children.length; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.value = ''; this.children = nodes; }
}
const document = {createElement: () => new Node(), createTextNode: v => new Node(v)};
const window = {};
vm.runInNewContext(fs.readFileSync('frontend/input-quality-ui-36-12b.js', 'utf8'),
  {document, window});
const steps = JSON.parse(fs.readFileSync(0, 'utf8'));
const container = new Node();
const outputs = steps.map(step => {
  container.id = step.rejected ? 'error-input-quality-36-12b' : 'input-quality-summary-36-12b';
  window.inputQualityUi36_12b.render(container, step.quality, null,
    {requestRejected: step.rejected});
  return {text: container.textContent, hidden: container.hidden};
});
process.stdout.write(JSON.stringify(outputs));
"""


def _render(*steps):
    result = subprocess.run(
        ["node", "-e", RENDER], input=json.dumps(steps), text=True,
        cwd=ROOT, capture_output=True, check=True, timeout=10,
    )
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def fixed_responses():
    selected = {"bf_app_remove_failure", "bf_app_partial_account",
                "spray_ssh_rejected_timestamp"}
    responses = {}
    for scenario in load_corpus():
        if scenario.scenario_id not in selected:
            continue
        baseline = load_fixture(scenario.baseline_fixture_id)
        variant = apply_mutation(
            baseline, source=scenario.source, mutation_type=scenario.mutation_type,
            mutation_target=scenario.mutation_target,
            mutation_parameters=_thaw(scenario.mutation_parameters),
        )
        # Each pair stays within the existing request budget.
        with TestClient(create_app(), base_url="http://127.0.0.1:8000",
                        client=("127.0.0.1", 50000)) as client:
            for role, raw in (("baseline", baseline), ("variant", variant)):
                response = client.post("/api/v1/investigations/text", json={
                    "schema_version": 1, "source": scenario.source,
                    "log_text": raw.decode("utf-8"),
                })
                responses[scenario.scenario_id, role] = response
    return responses


@pytest.mark.parametrize("scenario_id,role,observations,lines", [
    ("bf_app_remove_failure", "baseline", 1, 5),
    ("bf_app_remove_failure", "variant", 0, 4),
    ("bf_app_partial_account", "variant", 0, 5),
])
def test_complete_means_row_recognition_not_detector_readiness(
    fixed_responses, scenario_id, role, observations, lines,
):
    response = fixed_responses[scenario_id, role]
    assert response.status_code == 200
    result = response.json()["result"]
    quality = result["input_quality"]
    assert quality["aggregate"]["recognition_status"] == "complete"
    assert quality["aggregate"]["recognized_lines"] == lines
    assert len(result["independent_observations"]) == observations
    assert result["report_export"]["html"]
    if observations:
        observation = result["independent_observations"][0]
        assert observation["display_type"] == "Brute Force"
        assert [entry["value"] for entry in observation["evidence"]] == [5, 1, 40]
        assert observation["start_time"]["display_utc"] == "2026-11-04T00:00:00Z"
        assert observation["end_time"]["display_utc"] == "2026-11-04T00:00:40Z"
    rendered, = _render({"quality": quality, "rejected": False})
    assert not rendered["hidden"]
    assert "모두 인식" in rendered["text"]
    assert COMPLETE_LIMIT in rendered["text"]
    assert NO_RESULT not in rendered["text"]


def _rejected_quality(responses):
    response = responses["spray_ssh_rejected_timestamp", "variant"]
    assert response.status_code == 400
    body = response.json()
    assert body["error_code"] == "PARSER_INCOMPATIBLE"
    assert "result" not in body and "report_export" not in body
    quality = body["input_quality"]
    assert quality["aggregate"]["recognition_status"] == "partial"
    assert quality["aggregate"]["recognized_lines"] == 3
    assert quality["aggregate"]["unrecognized_lines"] == 1
    assert quality["aggregate"]["reason_counts"]["invalid_timestamp"] == 1
    return quality


def test_rejection_does_not_claim_analysis_results_exist(fixed_responses):
    quality = _rejected_quality(fixed_responses)
    rendered, = _render({"quality": quality, "rejected": True})
    assert not rendered["hidden"]
    assert "일부 인식" in rendered["text"]
    assert "올바르지 않은 시각" in rendered["text"]
    assert "3/4줄 인식" in rendered["text"]
    assert NO_RESULT in rendered["text"]
    assert RETAINED not in rendered["text"]


def test_result_context_preserves_existing_partial_analysis_meaning(fixed_responses):
    # Component-only context check; this does not claim the rejected API ran analysis.
    quality = _rejected_quality(fixed_responses)
    result, rejected, cleared = _render(
        {"quality": quality, "rejected": False},
        {"quality": quality, "rejected": True},
        {"quality": None, "rejected": False},
    )
    assert RETAINED in result["text"] and NO_RESULT not in result["text"]
    assert NO_RESULT in rejected["text"] and RETAINED not in rejected["text"]
    assert cleared == {"text": "", "hidden": True}
