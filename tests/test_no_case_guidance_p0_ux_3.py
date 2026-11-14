"""Static manual guidance, exercised with the existing fixed synthetic inputs."""

from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess

from fastapi.testclient import TestClient
import pytest

from app.api import create_app
from app.evaluation.counterfactual_corpus import load_corpus, load_fixture, _thaw
from app.evaluation.counterfactual_mutation import apply_mutation
import app.local_investigation_api as local


ROOT = Path(__file__).resolve().parents[1]


class _Guidance(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.nodes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id") == "result-empty":
            self.active = True
        if self.active:
            self.nodes.append((tag, attrs))

    def handle_endtag(self, tag):
        if self.active and tag == "section":
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.text.append(data.strip())


def test_no_case_guidance_is_hidden_semantic_static_manual_procedure():
    guidance = _Guidance()
    guidance.feed((ROOT / "frontend/index.html").read_text(encoding="utf-8"))
    tag, attrs = guidance.nodes[0]
    assert tag == "section" and "hidden" in attrs
    assert attrs["aria-labelledby"] == "result-empty-heading"
    assert ("h3", {"id": "result-empty-heading"}) in guidance.nodes
    assert [tag for tag, _ in guidance.nodes].count("ol") == 1
    assert [tag for tag, _ in guidance.nodes].count("li") == 3
    assert not {"a", "button", "input", "script", "form"}.intersection(
        tag for tag, _ in guidance.nodes
    )
    text = " ".join(guidance.text)
    for phrase in (
        "다음 조사 단계",
        "수집 범위·인식 범위와 누락 가능성을 확인하세요",
        "원문에서 IP·계정·시각별 인증 실패 분포를 확인하세요",
        "집계 단위·임계값·시간 범위와 대조하세요",
        "결과가 없다는 것은 안전을 뜻하지 않습니다",
        "입력 인식 완료는 전체 규칙 평가 완료가 아닙니다",
        "직접 수행할 조사 작업",
        "프로그램이 계정 누락이나 탐지 조건 미충족을 확인한 결과가 아닙니다",
    ):
        assert phrase in text


def _fixed_input(scenario_id, *, variant=True):
    scenario = next(item for item in load_corpus() if item.scenario_id == scenario_id)
    raw = load_fixture(scenario.baseline_fixture_id)
    if variant:
        raw = apply_mutation(
            raw, source=scenario.source, mutation_type=scenario.mutation_type,
            mutation_target=scenario.mutation_target,
            mutation_parameters=_thaw(scenario.mutation_parameters),
        )
    return {"schema_version": 1, "source": scenario.source, "log_text": raw.decode("utf-8")}


def _client():
    return TestClient(create_app(), base_url="http://127.0.0.1:8000",
                      client=("127.0.0.1", 50000))


def test_fixed_no_case_success_positive_rejection_and_failure_transitions(monkeypatch):
    if shutil.which("node") is None:
        pytest.skip("Node unavailable; static guidance remains covered")
    with _client() as client:
        sample = client.post("/api/v1/investigations/sample")
        assert sample.status_code == 200
        empty = []
        for label, scenario_id in (
            ("T03", "bf_app_change_account"), ("T04", "bf_app_partial_account"),
        ):
            payload = _fixed_input(scenario_id)
            response = client.post("/api/v1/investigations/text", json=payload)
            assert response.status_code == 200
            result = response.json()["result"]
            assert result["cases"] == result["independent_observations"] == []
            assert "result-empty-heading" not in response.text
            assert "수집 범위·인식 범위와 누락 가능성을 확인하세요" not in response.text
            assert "원문에서 IP·계정·시각별 인증 실패 분포를 확인하세요" not in response.text
            assert "집계 단위·임계값·시간 범위와 대조하세요" not in response.text
            empty.append({"label": label, "log_text": payload["log_text"], "response": response.json()})
        assert empty[0]["response"] == empty[1]["response"]
        payload = _fixed_input("bf_app_change_account", variant=False)
        response = client.post("/api/v1/investigations/text", json=payload)
        assert response.status_code == 200
        result = response.json()["result"]
        assert result["cases"] == [] and len(result["independent_observations"]) == 1
        assert [item["value"] for item in result["independent_observations"][0]["evidence"]] == [5, 1, 40]
        positive = {"log_text": payload["log_text"], "response": response.json()}
        rejected = _fixed_input("spray_ssh_rejected_timestamp")
        response = client.post("/api/v1/investigations/text", json=rejected)
        assert response.status_code == 400
        assert response.json()["error_code"] == "PARSER_INCOMPATIBLE"
        errors = [{"status": 400, "log_text": empty[0]["log_text"], "response": response.json()}]

    async def failed_worker(*_args, **_kwargs):
        return local._error("ANALYSIS_FAILED")

    with monkeypatch.context() as patch:
        patch.setattr(local, "_run_worker", failed_worker)
        with _client() as client:
            response = client.post("/api/v1/investigations/text", json=payload)
        assert response.status_code == 500
        assert response.json()["error_code"] == "ANALYSIS_FAILED"
        errors.append({"status": 500, "log_text": payload["log_text"], "response": response.json()})

    outcome = subprocess.run(
        ["node", str(ROOT / "tests/web_ui_behavior.cjs")],
        input=json.dumps({"sample": sample.json(), "noCase": {
            "empty": empty, "positive": positive, "errors": errors,
        }}), text=True, capture_output=True, cwd=ROOT, timeout=20, check=False,
    )
    assert outcome.returncode == 0, outcome.stderr
    assert outcome.stdout == "renderer logic verified\n"
