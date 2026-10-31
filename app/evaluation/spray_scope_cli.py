"""Command line entry point for the isolated Password Spray scope evaluation."""

import argparse
import json
import sys

from app.evaluation.spray_scope_evaluation import (
    SprayScopeEvaluationError,
    evaluate,
    render_text,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic Password Spray policy comparison")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        summary = evaluate()
    except SprayScopeEvaluationError as error:
        print(error.code, file=sys.stderr)
        return 2
    except Exception:
        print("evaluation_failed", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(render_text(summary))
    # Pattern findings are valid evaluation output, not execution failures.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
