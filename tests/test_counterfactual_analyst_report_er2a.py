from dataclasses import replace
import socket
import subprocess
import sys

import pytest

from app.evaluation.counterfactual_comparison import (
    ComparisonState,
    DetectionState,
    ParserState,
)
from app.evaluation.counterfactual_holdout import run_holdout
from app.evaluation.counterfactual_replay import run_corpus
from app.evaluation.counterfactual_analyst_report import (
    AnalystReportError,
    build_report,
    render_markdown,
)


@pytest.fixture(scope="module")
def replay_results():
    return run_corpus(), run_holdout()


def test_report_projects_existing_replay_distributions_and_omits_expected_labels(replay_results):
    development, holdout = replay_results
    report = build_report(development, holdout)
    markdown = render_markdown(report)

    assert report.scenario_count == development.scenario_count + holdout.scenario_count == 30
    assert report.development.comparison_counts == {
        "PRESERVED": 4, "LOST": 6, "GAINED": 2,
        "UNCHANGED_ABSENT": 1, "INCOMPARABLE": 3, "UNDETERMINED": 0,
    }
    assert report.holdout.comparison_counts == {
        "PRESERVED": 3, "LOST": 4, "GAINED": 3,
        "UNCHANGED_ABSENT": 1, "INCOMPARABLE": 3, "UNDETERMINED": 0,
    }
    assert "PATTERN_PRESENT" not in markdown
    assert "PATTERN_ABSENT" not in markdown
    assert "label_basis" not in markdown
    assert "LOST" in markdown and "공격 회피 성공을 뜻하지 않음" in markdown


def test_report_keeps_corpus_denominators_and_label_validation_separate(replay_results):
    report = build_report(*replay_results)
    markdown = render_markdown(report)
    assert "Development Corpus | 16" in markdown
    assert "Holdout Corpus | 14" in markdown
    assert "분모" in markdown
    assert "Human Review | PENDING" in markdown
    assert "Operational Validation | NOT_APPROVED" in markdown
    assert "Baseline" in markdown and "Variant" in markdown
    assert "비교 제외" in markdown


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("baseline_parser_state", "UNKNOWN"),
        ("variant_detection_state", "UNKNOWN"),
        ("comparison_state", "UNKNOWN"),
        ("reason_codes", ("RAW_CANARY",)),
    ],
)
def test_report_rejects_unknown_states_and_reason_codes(replay_results, field, value):
    development, holdout = replay_results
    first = replace(development.results[0], **{field: value})
    broken = replace(development, results=(first, *development.results[1:]))
    with pytest.raises(AnalystReportError):
        build_report(broken, holdout)


def test_report_rejects_inventory_and_count_mismatch(replay_results):
    development, holdout = replay_results
    duplicated = replace(development, results=(development.results[0], *development.results[1:-1], development.results[0]))
    with pytest.raises(AnalystReportError):
        build_report(duplicated, holdout)

    wrong_count = replace(development, scenario_count=development.scenario_count + 1)
    with pytest.raises(AnalystReportError):
        build_report(wrong_count, holdout)

    bad_counts = dict(development.counts)
    bad_counts["comparison"] = dict(bad_counts["comparison"], LOST=bad_counts["comparison"]["LOST"] + 1)
    with pytest.raises(AnalystReportError):
        build_report(replace(development, counts=bad_counts), holdout)


def test_report_rejects_impossible_parser_detection_combination(replay_results):
    development, holdout = replay_results
    first = replace(
        development.results[0],
        baseline_parser_state=ParserState.REJECTED.value,
        baseline_detection_state=DetectionState.DETECTED.value,
    )
    broken = replace(development, results=(first, *development.results[1:]))
    with pytest.raises(AnalystReportError):
        build_report(broken, holdout)


def test_report_preserves_execution_failure_as_not_detected_never_synthesized(replay_results):
    development, holdout = replay_results
    first = replace(
        development.results[0],
        variant_detection_state=DetectionState.EXECUTION_FAILED.value,
        label_validation_variant="NOT_EVALUATED",
        comparison_state=ComparisonState.UNDETERMINED.value,
        reason_codes=("EXECUTION_INCOMPLETE",),
    )
    counts = _recount_development((first, *development.results[1:]))
    injected = replace(development, results=(first, *development.results[1:]), counts=counts)
    report = build_report(injected, holdout)
    rendered = render_markdown(report)
    assert "EXECUTION_FAILED" in rendered
    assert "NOT_DETECTED" in rendered


def _recount_development(results):
    states = {
        "parser_baseline": "baseline_parser_state",
        "parser_variant": "variant_parser_state",
        "detector_baseline": "baseline_detection_state",
        "detector_variant": "variant_detection_state",
        "comparison": "comparison_state",
        "label_baseline": "label_validation_baseline",
        "label_variant": "label_validation_variant",
    }
    allowed = {
        "parser_baseline": [item.value for item in ParserState],
        "parser_variant": [item.value for item in ParserState],
        "detector_baseline": [item.value for item in DetectionState],
        "detector_variant": [item.value for item in DetectionState],
        "comparison": [item.value for item in ComparisonState],
        "label_baseline": ["MATCH", "MISMATCH", "NOT_EVALUATED"],
        "label_variant": ["MATCH", "MISMATCH", "NOT_EVALUATED"],
    }
    counts = {
        name: {state: sum(getattr(row, attr) == state for row in results) for state in values}
        for name, attr in states.items()
        for values in (allowed[name],)
    }
    counts["excluded_comparisons"] = {"count": sum(
        row.comparison_state in ("INCOMPARABLE", "UNDETERMINED") for row in results
    )}
    codes = {code for row in results for code in row.reason_codes}
    counts["reason_codes"] = {code: sum(code in row.reason_codes for row in results) for code in sorted(codes)}
    # Existing report contracts use the complete closed reason-code set.
    from app.evaluation.counterfactual_comparison import _REASON_CODES
    counts["reason_codes"] = {code: sum(code in row.reason_codes for row in results) for code in sorted(_REASON_CODES)}
    return counts


def test_report_markdown_is_deterministic_bounded_and_privacy_safe(replay_results, monkeypatch):
    report = build_report(*replay_results)
    first = render_markdown(report)
    second = render_markdown(report)
    assert first.encode("utf-8") == second.encode("utf-8")
    assert len(first.encode("utf-8")) <= 128 * 1024
    for forbidden in ("192.0.2.", "synthetic_user_", "AnalysisRunOwner", "BruteWindowContext", "/tmp/"):
        assert forbidden not in first

    def denied(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    assert render_markdown(build_report(*replay_results)) == first


def test_report_cli_rejects_arguments_and_outputs_markdown(replay_results):
    invalid = subprocess.run(
        [sys.executable, "-m", "app.evaluation.counterfactual_analyst_report_cli", "--unexpected"],
        check=False, capture_output=True, text=False,
    )
    assert invalid.returncode == 2
    assert invalid.stdout == b""
    assert invalid.stderr == b"INVALID_INTERNAL_CONTRACT\n"

    one = subprocess.run(
        [sys.executable, "-m", "app.evaluation.counterfactual_analyst_report_cli"],
        check=False, capture_output=True, text=False,
    )
    two = subprocess.run(
        [sys.executable, "-m", "app.evaluation.counterfactual_analyst_report_cli"],
        check=False, capture_output=True, text=False,
    )
    assert one.returncode == two.returncode == 0
    assert one.stdout == two.stdout
    assert one.stdout.startswith(b"# ER-2A")
    assert one.stderr == two.stderr == b""
