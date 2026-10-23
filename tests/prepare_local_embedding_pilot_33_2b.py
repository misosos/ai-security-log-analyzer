"""Prepare hash-only offline requirements or verify an isolated wheelhouse."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from local_embedding_pilot_33_2b import (
    PilotError,
    load_runtime_wheel_manifest,
    render_runtime_pins,
    verify_runtime_wheelhouse,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("pins", "verify"), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_runtime_wheel_manifest(args.manifest)
        if args.mode == "pins":
            if args.output is None or args.output.exists() or args.output.is_symlink():
                raise PilotError("MANIFEST_INVALID")
            content = render_runtime_pins(manifest)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("xb") as stream:
                stream.write(content)
            args.output.chmod(0o600)
        else:
            if args.output is not None:
                raise PilotError("MANIFEST_INVALID")
            verify_runtime_wheelhouse(args.wheelhouse, manifest)
        print(json.dumps({
            "status": "verified",
            "mode": args.mode,
            "wheel_count": len(manifest.wheels),
            "wheel_bytes": manifest.total_bytes,
            "runtime_lock_sha256": manifest.runtime_lock_sha256,
        }, sort_keys=True))
        return 0
    except PilotError as error:
        print(json.dumps({"status": "refused", "code": error.code}, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps({"status": "failed", "code": "MANIFEST_INVALID"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
