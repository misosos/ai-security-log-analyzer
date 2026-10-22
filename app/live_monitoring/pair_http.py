"""Explicit internal v3 loopback app; the normal --monitor launcher never calls it."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from app.live_monitoring.http import create_live_events_endpoint, create_live_status_endpoint
from app.live_monitoring.multi_source import open_internal_pair_runtime
from app.live_monitoring.pair_publication import attach_pair_publication
from app.live_monitoring.pair_service import PairMonitoringService, PairRunner
from app.models.live_monitoring import LiveErrorResponse
from app.models.multi_source_live import PairStatusResponse


def create_internal_pair_app(config_path: Path) -> FastAPI:
    """Build the test-only HTTP contract from an explicit private v3 path."""
    runtime = open_internal_pair_runtime(config_path)
    try:
        publication = attach_pair_publication(runtime)
        service = PairMonitoringService(runtime, publication)
        runner = PairRunner(service)
    except Exception:
        runtime.close()
        raise

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(runner.run(), name="internal-pair-runner")
        try:
            yield
        finally:
            try:
                await runner.shutdown()
            finally:
                if not task.done():
                    task.cancel()

    app = FastAPI(lifespan=lifespan)
    app.state.pair_service = service  # Trusted test owner; never returned by a route.
    app.state.pair_runner = runner
    app.add_api_route("/api/health", lambda: {"status": "ok"}, methods=["GET"])
    app.add_api_route(
        "/api/v1/live/status", create_live_status_endpoint(service), methods=["GET"],
        response_model=PairStatusResponse,
        responses={code: {"model": LiveErrorResponse} for code in (400, 403, 404, 503)},
    )
    app.add_api_route(
        "/api/v1/live/events", create_live_events_endpoint(service), methods=["GET"],
        responses={
            200: {"content": {"text/event-stream": {"schema": {"type": "string"}}},
                  "description": "Internal loopback-only bounded v3 SSE"},
            **{code: {"model": LiveErrorResponse} for code in (400, 403, 404, 429, 500, 503)},
        },
    )
    return app
