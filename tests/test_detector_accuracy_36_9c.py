"""Tests for the isolated synthetic detector-accuracy evaluation contract."""

import json
from pathlib import Path

import pytest

from app.evaluation import detector_accuracy as evaluation
from app.evaluation.detector_accuracy_cli import main


def test_confusion_matrix_and_metrics_use_expected_labels():
    confusion = evaluation.Confusion().add(True, True).add(False, True)
    confusion = confusion.add(True, False).add(False, False)
    metric = evaluation._metric("brute_force", confusion, 0, 0)
    assert (metric.tp, metric.fp, metric.fn, metric.tn) == (1, 1, 1, 1)
    assert (metric.precision, metric.recall, metric.f1) == (
        "0.500000", "0.500000", "0.500000",
    )


@pytest.mark.parametrize(
    ("confusion", "precision", "recall", "f1"),
    [
        (evaluation.Confusion(), "not_applicable", "not_applicable", "not_applicable"),
        (evaluation.Confusion(fp=1, tn=2), "0.000000", "not_applicable", "0.000000"),
    ],
)
def test_zero_metric_denominators_are_not_applicable(confusion, precision, recall, f1):
    metric = evaluation._metric("xss_like", confusion, 0, 0)
    assert metric.precision == precision
    assert metric.recall == recall
    assert metric.f1 == f1


def test_corpus_scenarios_are_closed_and_have_independent_label_rationale():
    scenarios = evaluation.load_corpus()
    assert len(scenarios) == 46
    assert len({item["id"] for item in scenarios}) == len(scenarios)
    assert all(item["label_basis"].strip() and item["context_basis"].strip() for item in scenarios)
    assert {item["behavioral_pattern"] for item in scenarios} == set(evaluation.PATTERN_LABELS)
    assert {item["operational_context"] for item in scenarios} == set(evaluation.CONTEXT_LABELS)


def _manifest_with(tmp_path: Path, scenarios):
    (tmp_path / "one.log").write_text(
        "203.0.113.80 - - [30/Oct/2026:00:00:00 +0000] \"GET /safe HTTP/1.1\" 200 10\n",
        encoding="utf-8",
    )
    value = {
        "schema_version": 1,
        "data_scope": "synthetic-only",
        "scenarios": scenarios,
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(value), encoding="utf-8")
    return manifest


def _valid_scenario():
    return {
        "id": "case_001",
        "detector": "path_traversal",
        "source": "access",
        "fixture": "one.log",
        "subject": "203.0.113.80",
        "expected_event_types": ["http_request"],
        "expected_event_subjects": ["203.0.113.80"],
        "required_fields": ["timestamp", "src_ip", "http.method", "http.path", "http.status_code"],
        "behavioral_pattern": "PATTERN_ABSENT",
        "operational_context": "KNOWN_BENIGN",
        "label_basis": "요청에 traversal 구성요소가 없다.",
        "context_basis": "합성 서비스 정상 조회 시나리오로 독립 지정했다.",
    }


def test_duplicate_scenario_id_is_rejected_without_echoing_manifest(tmp_path):
    row = _valid_scenario()
    manifest = _manifest_with(tmp_path, [row, dict(row)])
    with pytest.raises(evaluation.DetectorAccuracyError) as error:
        evaluation.load_corpus(manifest)
    assert str(error.value) == "invalid_manifest"


def test_duplicate_manifest_json_key_is_rejected():
    with pytest.raises(evaluation.DetectorAccuracyError) as error:
        evaluation._decode_manifest(
            b'{"schema_version":1,"schema_version":1,"data_scope":"synthetic-only","scenarios":[]}'
        )
    assert str(error.value) == "invalid_manifest"


def test_manifest_size_is_bounded(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b" " * (evaluation.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(evaluation.DetectorAccuracyError) as error:
        evaluation.load_corpus(manifest)
    assert str(error.value) == "invalid_manifest"


def test_fixture_size_is_bounded(tmp_path):
    manifest = _manifest_with(tmp_path, [_valid_scenario()])
    (tmp_path / "one.log").write_bytes(b"x" * (evaluation.MAX_FIXTURE_BYTES + 1))
    with pytest.raises(evaluation.DetectorAccuracyError) as error:
        evaluation.load_corpus(manifest)
    assert str(error.value) == "fixture_unavailable"


def test_parser_partial_is_distinguished_from_detector_negative(monkeypatch, tmp_path):
    scenario = _valid_scenario()
    fixture = tmp_path / "one.log"
    fixture.write_text("invalid synthetic line\n", encoding="utf-8")
    monkeypatch.setattr(evaluation, "load_normalized_logs", lambda _configs: [])
    assert evaluation._parse_disposition(scenario, fixture) == ("PARSER_PARTIAL", "EVENT_COUNT_MISMATCH")


@pytest.mark.parametrize("mutation", [
    lambda row: row.update(detector="unknown"),
    lambda row: row.update(source="unsupported"),
    lambda row: row.update(fixture="../outside.log"),
    lambda row: row.update(fixture="missing.log"),
    lambda row: row.update(behavioral_pattern="DETECTOR_SAID_TRUE"),
    lambda row: row.update(operational_context=[]),
    lambda row: row.update(required_fields=[[]]),
    lambda row: row.update(expected_event_types=["unmodeled_event"]),
    lambda row: row.update(
        detector="sql_injection_like",
        required_fields=["timestamp", "src_ip", "http.method", "http.path", "http.status_code"],
    ),
])
def test_invalid_labels_sources_detectors_and_paths_are_rejected(tmp_path, mutation):
    row = _valid_scenario()
    mutation(row)
    manifest = _manifest_with(tmp_path, [row])
    with pytest.raises(evaluation.DetectorAccuracyError):
        evaluation.load_corpus(manifest)


def test_metrics_exclude_undetermined_and_parser_contributions_separately():
    summary = evaluation.evaluate()
    metrics = {item["detector"]: item for item in summary["metrics"]}
    brute = metrics["brute_force"]
    assert (brute["tp"], brute["fp"], brute["fn"], brute["tn"]) == (4, 0, 0, 3)
    assert brute["excluded_undetermined"] == 1
    assert brute["excluded_parser"] == 0
    assert summary["parser_contributions"] == []
    assert not any(
        finding["scenario_id"] == "bf_burst_with_late_noise"
        and finding.get("finding") == "DETECTOR_FALSE_NEGATIVE"
        for finding in summary["scenario_results"]
    )


def test_operational_benign_alerts_are_separate_from_pattern_confusion():
    summary = evaluation.evaluate()
    candidates = summary["operational_false_alert_candidates"]
    assert len(candidates) == 7
    assert {item["scenario_id"] for item in candidates} >= {
        "bf_benign_retries", "scan_benign_scanner", "sqli_documented_example",
    }
    assert all("operational_false_alert_candidates" not in item for item in summary["metrics"])


def test_cli_outputs_are_deterministic_and_do_not_echo_fixture_data(capsys):
    assert main(["--format", "json"]) == 0
    first = capsys.readouterr().out
    assert main(["--format", "json"]) == 0
    second = capsys.readouterr().out
    assert first == second
    assert "synthetic_user_a" not in first
    assert "198.51.100.20" not in first
    assert "login_failed" not in first


def test_cli_reports_evaluation_input_error_without_paths_or_fixture_text(monkeypatch, capsys):
    def reject():
        raise evaluation.DetectorAccuracyError("fixture_unavailable")

    monkeypatch.setattr("app.evaluation.detector_accuracy_cli.evaluate", reject)
    assert main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "fixture_unavailable\n"


def test_cli_sanitizes_unexpected_analysis_exception(monkeypatch, capsys):
    def fail():
        raise RuntimeError("synthetic_private_canary")

    monkeypatch.setattr("app.evaluation.detector_accuracy_cli.evaluate", fail)
    assert main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "evaluation_failed\n"
    assert "synthetic_private_canary" not in captured.err


def test_fixed_corpus_has_no_untracked_extra_fixture():
    listed = {row["fixture"] for row in evaluation.load_corpus()}
    actual = {path.name for path in evaluation.CORPUS_ROOT.glob("*.log")}
    assert listed == actual
