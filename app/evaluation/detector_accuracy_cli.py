"""CLI for the separate reviewed-label detector accuracy corpus."""

import argparse
import json
import sys

from app.evaluation.detector_accuracy import DetectorAccuracyError, evaluate, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic detector-pattern evaluation")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        summary = evaluate()
    except DetectorAccuracyError as error:
        print(error.code, file=sys.stderr)
        return 2
    except Exception:
        # Keep unexpected parser/analysis diagnostics from echoing fixture data.
        print("evaluation_failed", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print(render_text(summary))
    # Detector FP/FN are measured findings, not an evaluation framework failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
