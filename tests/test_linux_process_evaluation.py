"""Linux category labels are independent of the 79 IP-based scenarios."""

from dataclasses import replace
import json
import os
import subprocess
import sys

import pytest

from app.evaluation.linux_process import (
    LINUX_PROCESS_SCENARIOS, LinuxProcessEvaluationError,
    evaluate_linux_process,
)

def _cli(*args: str, tz: str = "UTC") -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["TZ"] = tz
    return subprocess.run([sys.executable, "-m", "app.evaluation", *args],
                          capture_output=True, text=True, check=False, env=environment)


def test_fixed_linux_corpus_and_category_counts():
    result = evaluate_linux_process()
    assert (result.scenario_count, result.passed_scenarios, result.failed_scenarios) == (21, 21, 0)
    assert [(item.expected_observation_count, item.actual_observation_count,
             item.false_category_assignment, item.missed_category_assignment)
            for item in result.category_metrics] == [
                (4, 4, 0, 0), (4, 4, 0, 0), (3, 3, 0, 0), (4, 4, 0, 0),
            ]
    assert result.outcome_consistency_count == result.aggregate_consistency_count == 21
    assert not result.invariant_failures
    assert all(metric.precision == metric.recall == "1.000000"
               for metric in result.category_metrics)


def test_zero_denominator_is_not_applicable():
    negative = next(item for item in LINUX_PROCESS_SCENARIOS if item.id == "linux_normal_tool")
    result = evaluate_linux_process((negative,))
    assert result.passed_scenarios == 1
    assert all(metric.precision == metric.recall == "not_applicable"
               for metric in result.category_metrics)


def test_linux_labels_fail_closed():
    with pytest.raises(LinuxProcessEvaluationError) as duplicate:
        evaluate_linux_process((LINUX_PROCESS_SCENARIOS[0], LINUX_PROCESS_SCENARIOS[0]))
    assert duplicate.value.code == "invalid_label"
    with pytest.raises(LinuxProcessEvaluationError):
        evaluate_linux_process((replace(LINUX_PROCESS_SCENARIOS[0], fixture="../private.log"),))
    with pytest.raises(LinuxProcessEvaluationError):
        evaluate_linux_process((replace(LINUX_PROCESS_SCENARIOS[0], expected_categories=("UNKNOWN",)),))


def test_missing_fixture_has_fixed_error(monkeypatch, tmp_path):
    monkeypatch.setattr("app.evaluation.linux_process._ROOT", tmp_path)
    with pytest.raises(LinuxProcessEvaluationError) as failure:
        evaluate_linux_process((LINUX_PROCESS_SCENARIOS[0],))
    assert str(failure.value) == "fixture_unavailable"


def test_linux_text_json_and_timezone_boundary():
    utc = _cli("--format", "json", tz="UTC")
    kst = _cli("--format", "json", tz="Asia/Seoul")
    text = _cli("--format", "text")
    assert utc.returncode == kst.returncode == text.returncode == 0
    assert utc.stdout == kst.stdout
    body = json.loads(utc.stdout)
    assert body["scenario_count"] == 79
    linux = body["linux_process_execution_evaluation"]
    assert (linux["scenario_count"], linux["passed_scenarios"]) == (21, 21)
    assert "linux_process_execution_evaluation: 21/21" in text.stdout
    for metric in linux["category_metrics"]:
        assert f"linux_category {metric['category_id']}: expected={metric['expected_observation_count']} actual={metric['actual_observation_count']}" in text.stdout
    for marker in ("SYNTHETIC_ARG_CANARY", "SYNTHETIC_TARGET_CANARY", "/usr/bin/curl", "synthetic-network-curl"):
        assert marker not in utc.stdout and marker not in text.stdout
