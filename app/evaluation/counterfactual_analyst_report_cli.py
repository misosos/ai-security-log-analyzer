"""Emit the deterministic ER-2A synthetic analyst report to stdout."""

from __future__ import annotations

import sys

from app.evaluation.counterfactual_analyst_report import AnalystReportError, build_report, render_markdown
from app.evaluation.counterfactual_holdout import HoldoutError, run_holdout
from app.evaluation.counterfactual_replay import CounterfactualReplayError, run_corpus


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print("INVALID_INTERNAL_CONTRACT", file=sys.stderr)
        return 2
    try:
        markdown = render_markdown(build_report(run_corpus(), run_holdout()))
    except (AnalystReportError, CounterfactualReplayError, HoldoutError):
        print("INVALID_INTERNAL_CONTRACT", file=sys.stderr)
        return 1
    sys.stdout.write(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
