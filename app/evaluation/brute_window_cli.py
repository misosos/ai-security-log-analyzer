"""CLI for the isolated synthetic Brute Force window-policy comparison."""

import argparse
import json
import sys

from app.evaluation.brute_window_evaluation import (
    BruteWindowEvaluationError,
    evaluate_corpus,
    render_text,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic Brute Force window evaluation")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        summary = evaluate_corpus()
    except BruteWindowEvaluationError as error:
        print(error.code, file=sys.stderr)
        return 2
    except Exception:
        print("evaluation_failed", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(render_text(summary))
    # Detection differences and low metrics are findings, not CLI errors.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
