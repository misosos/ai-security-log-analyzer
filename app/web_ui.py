"""Fixed, same-origin synthetic-demo assets; no request-controlled paths."""

import os
from pathlib import Path
import stat

from fastapi import HTTPException
from fastapi.responses import Response


_FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
_MAX_ASSET_BYTES = 160 * 1024
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


def serve_evaluation_index(live_enabled: bool) -> Response:
    response = serve_demo_index()
    html = response.body.decode("utf-8", "strict")
    replacements = (
        ('</head>', '<link rel="stylesheet" href="/assets/evaluation-review-viewer-v1.css"><script type="module" src="/assets/evaluation-review-viewer-v1.js"></script></head>'),
        ('<details class="nav-group" id="nav-group-tools">', '<details class="nav-group" id="nav-group-tools" open>'),
        ('<div class="nav-group-items">\n              <button id="nav-audit"', '<div class="nav-group-items">\n              <button id="nav-evaluation" type="button" aria-controls="evaluation-review-root">합성 평가</button>\n              <button id="nav-audit"'),
        ('</main>', '</main><main id="evaluation-review-root" class="app-content" aria-label="합성 평가" hidden></main>'),
    )
    for needle, replacement in replacements:
        if html.count(needle) != 1:
            raise HTTPException(status_code=404, detail="Not Found")
        html = html.replace(needle, replacement, 1)
    if not live_enabled:
        marker = '<script src="/assets/live-monitoring.js" defer></script>'
        if html.count(marker) != 1:
            raise HTTPException(status_code=404, detail="Not Found")
        html = html.replace(marker, "", 1)
    return Response(content=html, media_type="text/html", headers=_HEADERS)


def serve_demo_styles() -> Response:
    return _fixed_asset("style.css", "text/css")


def serve_demo_script() -> Response:
    return _fixed_asset("app.js", "text/javascript")


def serve_input_quality_ui_script() -> Response:
    return _fixed_asset("input-quality-ui-36-12b.js", "text/javascript")


def serve_review_queue_ui_script_36_13a() -> Response:
    return _fixed_asset("review-queue-ui-36-13a.js", "text/javascript")


def serve_investigation_review_state_script_36_14d() -> Response:
    return _fixed_asset("investigation-review-state-36-14d.js", "text/javascript")


def serve_linux_audit_script() -> Response:
    return _fixed_asset("linux-audit.js", "text/javascript")


def serve_live_monitoring_script(enabled: bool) -> Response:
    if type(enabled) is not bool:
        raise TypeError("invalid live UI setting")
    if not enabled:
        return Response(
            content=b"// Live Monitoring is not configured for this app instance.\n",
            media_type="text/javascript",
            headers=_HEADERS,
        )
    return _fixed_asset("live-monitoring.js", "text/javascript")


def serve_multi_source_live_script() -> Response:
    return _fixed_asset("multi-source-live.js", "text/javascript")
