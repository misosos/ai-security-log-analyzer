"""Run the fixed offline evaluation corpus; no files are written."""

import argparse
from dataclasses import asdict
import json
import sys

from app.evaluation.corpus import SCENARIOS
from app.evaluation.runner import EvaluationError, evaluate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic boundary evaluation")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--scenario")
    args = parser.parse_args(argv)
    if args.scenario is not None and args.scenario not in {item.id for item in SCENARIOS}:
        print("unknown_scenario", file=sys.stderr)
        return 2
    scenarios = tuple(item for item in SCENARIOS if args.scenario in (None, item.id))
    try:
        summary = evaluate(scenarios)
    except EvaluationError as error:
        print(error.code, file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(asdict(summary), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(f"synthetic_boundary_corpus: {summary.passed_scenarios}/{summary.scenario_count} scenarios passed")
        for metric in summary.detection_metrics:
            print(f"detection {metric.detection_type}: TP={metric.tp} FP={metric.fp} FN={metric.fn} TN={metric.tn} precision={metric.precision} recall={metric.recall} F1={metric.f1} support={metric.support}")
        for metric in summary.correlation_metrics:
            print(f"correlation {metric.relation_type}: TP={metric.tp} FP={metric.fp} FN={metric.fn} precision={metric.precision} recall={metric.recall} F1={metric.f1}")
        print(f"parser: {summary.parser_summary.parsed}/{summary.parser_summary.input_lines} parsed; ignored={summary.parser_summary.ignored}; rejected={summary.parser_summary.failed}; unexpected_parse={summary.parser_summary.unexpected_parse_count}; unexpected_rejection={summary.parser_summary.unexpected_rejection_count}")
        print(f"SSH scenarios: {summary.ssh_scenario_count}; ambiguous operational scenarios excluded from confusion matrices: {summary.excluded_ambiguous_scenarios}")
        for reason in summary.excluded_reasons:
            print(f"excluded {reason}")
        print(f"risk: {summary.risk_summary.matched_scenarios}/{summary.risk_summary.applicable_scenarios}; case: {summary.case_summary.matched_scenarios}/{summary.case_summary.applicable_scenarios}")
        linux = summary.linux_process_execution_evaluation
        print(f"linux_process_execution_evaluation: {linux.passed_scenarios}/{linux.scenario_count} scenarios passed")
        for metric in linux.category_metrics:
            print(f"linux_category {metric.category_id}: expected={metric.expected_observation_count} actual={metric.actual_observation_count} false={metric.false_category_assignment} missed={metric.missed_category_assignment} precision={metric.precision} recall={metric.recall}")
        print(f"linux outcome_consistency={linux.outcome_consistency_count}; aggregate_consistency={linux.aggregate_consistency_count}")
        for failure in linux.invariant_failures:
            print(f"FAIL linux {failure}")
        for notice in linux.interpretation_notices:
            print(notice)
        for failure in summary.invariant_failures:
            print(f"FAIL {failure}")
        for notice in summary.interpretation_notices:
            print(notice)
    return 1 if summary.failed_scenarios or summary.linux_process_execution_evaluation.failed_scenarios else 0


if __name__ == "__main__":
    raise SystemExit(main())
