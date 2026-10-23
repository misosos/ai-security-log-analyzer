"""Explicit developer command for regenerating the Phase 33.1 corpus manifest."""

import argparse

from app.local_retrieval_33_1 import CORPUS_DIR, generate_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", required=True,
                        help="explicitly write the reviewed corpus manifest")
    args = parser.parse_args()
    del args
    target = CORPUS_DIR / "manifest.json"
    if target.is_symlink():
        raise SystemExit("Manifest target is not a regular file.")
    target.write_bytes(generate_manifest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
