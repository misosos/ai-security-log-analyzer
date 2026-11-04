"""Explicit runner for the fixed ER-1C synthetic holdout corpus."""

from __future__ import annotations

import sys

from app.evaluation.counterfactual_holdout import (
    HoldoutError,
    canonical_holdout_json,
    run_holdout,
)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        sys.stderr.write("INVALID_INTERNAL_CONTRACT\n")
        return 2
    try:
        sys.stdout.buffer.write(canonical_holdout_json(run_holdout()))
    except HoldoutError as error:
        sys.stderr.write(f"{error.code}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
