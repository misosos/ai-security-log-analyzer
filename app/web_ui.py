"""Fixed, same-origin synthetic-demo assets; no request-controlled paths."""

import os
from pathlib import Path
import stat

from fastapi import HTTPException
from fastapi.responses import Response


_FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
_MAX_ASSET_BYTES = 128 * 1024
_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; object-src 'none'; script-src 'self'; "
        "script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; "
        "connect-src 'self'; img-src 'none'; font-src 'none'; "
        "media-src 'none'; frame-src 'none'; worker-src 'none'; "
        "manifest-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    ),
    "Cache-Control": "no-store",
}


def _fixed_asset(name: str, media_type: str) -> Response:
    # Callers pass only module-owned literals. lstat and O_NOFOLLOW also prevent
    # a replaced frontend directory or asset from becoming an escape path.
    try:
        parent = _FRONTEND.lstat()
        path = _FRONTEND / name
        entry = path.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or not 0 < entry.st_size <= _MAX_ASSET_BYTES
            or not hasattr(os, "O_NOFOLLOW")
        ):
            raise OSError()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (entry.st_dev, entry.st_ino)
                or not 0 < opened.st_size <= _MAX_ASSET_BYTES
            ):
                raise OSError()
            content = stream.read(_MAX_ASSET_BYTES + 1)
        if len(content) != opened.st_size:
            raise OSError()
    except OSError:
        raise HTTPException(status_code=404, detail="Not Found") from None
    return Response(content=content, media_type=media_type, headers=_HEADERS)


def serve_demo_index() -> Response:
    return _fixed_asset("index.html", "text/html")


def serve_demo_styles() -> Response:
    return _fixed_asset("style.css", "text/css")


def serve_demo_script() -> Response:
    return _fixed_asset("app.js", "text/javascript")


def serve_linux_audit_script() -> Response:
    return _fixed_asset("linux-audit.js", "text/javascript")
