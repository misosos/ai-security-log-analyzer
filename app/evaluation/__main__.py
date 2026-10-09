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
        print(f"parser: {summary.parser_summary.parsed}/{summary.parser_summary.input_lines} parsed; ignored={summary.parser_summary.ignored}; failed={summary.parser_summary.failed}")
        print(f"risk: {summary.risk_summary.matched_scenarios}/{summary.scenario_count}; case: {summary.case_summary.matched_scenarios}/{summary.scenario_count}")
        for failure in summary.invariant_failures:
            print(f"FAIL {failure}")
        for notice in summary.interpretation_notices:
            print(notice)
    return 1 if summary.failed_scenarios else 0


if __name__ == "__main__":
    raise SystemExit(main())
