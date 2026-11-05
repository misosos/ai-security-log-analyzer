"""Emit only a validated synthetic snapshot, without accepting paths."""
import sys

from app.evaluation.counterfactual_safe_projection import ProjectionError, build_snapshot, encode_snapshot


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        print("INVALID_PROJECTION", file=sys.stderr)
        return 2
    try:
        output = encode_snapshot(build_snapshot())
    except Exception:
        print("INVALID_PROJECTION", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
