"""Generate the fixed ER-1C-R packet or compare a bounded stdin submission."""

from __future__ import annotations

import sys

from app.evaluation.counterfactual_review_packet import (
    ReviewPacketError,
    ReviewSubmissionError,
    build_review_packet,
    canonical_review_adjudication_json,
    canonical_review_packet_json,
    compare_review_submission,
)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if not arguments:
            sys.stdout.buffer.write(canonical_review_packet_json(build_review_packet()))
            return 0
        if arguments == ["--compare-submission"]:
            raw = sys.stdin.buffer.read(128 * 1024 + 1)
            report = compare_review_submission(raw)
            sys.stdout.buffer.write(canonical_review_adjudication_json(report))
            return 0
        sys.stderr.write("INVALID_PACKET\n")
        return 2
    except ReviewSubmissionError as error:
        sys.stderr.write(f"{error.code}\n")
        return 2
    except ReviewPacketError as error:
        sys.stderr.write(f"{error.code}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
