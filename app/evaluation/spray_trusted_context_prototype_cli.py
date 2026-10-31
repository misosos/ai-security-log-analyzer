"""Safe text/JSON entry point for the isolated Spray context prototype."""

from __future__ import annotations

import argparse
import json
import sys

from app.evaluation.spray_trusted_context_prototype import run_prototype_checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run synthetic Spray context prototype checks")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        result = run_prototype_checks()
    except Exception:
        print("evaluation_error", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print("Password Spray trusted-context prototype (synthetic only)")
        for key, value in result.items():
            print(f"{key}: {value}")
    return 0 if all(value != "fail" for value in result.values() if isinstance(value, str)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
