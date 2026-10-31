"""CLI for the synthetic Spray correlation semantic evaluation."""
import argparse
import sys

from app.evaluation.spray_correlation_semantics import (
    SemanticEvaluationError, evaluate, render_json, render_text,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate synthetic Spray correlation semantics")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        result = evaluate()
    except SemanticEvaluationError as error:
        print(f"evaluation_error={error.code}", file=sys.stderr)
        return 2
    print(render_json(result) if args.format == "json" else render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
