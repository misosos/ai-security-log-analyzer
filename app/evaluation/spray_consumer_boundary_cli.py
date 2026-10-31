"""CLI for the bounded synthetic Password Spray consumer-boundary evaluation."""

import argparse
import json

from app.evaluation.spray_consumer_boundary import BoundaryValidationError, evaluate, render_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate synthetic Spray consumer boundaries")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    try:
        result = evaluate()
    except BoundaryValidationError as exc:
        print(f"spray_consumer_boundary_error: {exc.code}")
        return 2
    if args.format == "json":
        print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
