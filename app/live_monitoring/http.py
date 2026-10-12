"""Optional loopback-only read transport; never opens a log or steps a worker."""

from fastapi import Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from app.local_request_security import classify_local_request
from app.live_monitoring.service import LiveMonitoringService, LiveServiceError
from app.models.live_monitoring import LiveErrorResponse


_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_ERRORS = {
    "LIVE_MONITORING_NOT_ENABLED": (404, "로컬 모니터링이 활성화되지 않았습니다.", "명시적 로컬 설정으로 서버를 실행하십시오.", False),
    "LIVE_LOOPBACK_REQUIRED": (403, "로컬 연결에서만 사용할 수 있습니다.", "loopback 주소로 직접 연결하십시오.", False),
    "LIVE_INVALID_HOST": (403, "허용된 로컬 Host가 아닙니다.", "loopback 주소로 직접 연결하십시오.", False),
    "LIVE_FORWARDED_REQUEST_REJECTED": (403, "전달된 요청은 사용할 수 없습니다.", "프록시 없이 로컬에서 직접 연결하십시오.", False),
    "LIVE_ORIGIN_REJECTED": (403, "다른 Origin에서 사용할 수 없습니다.", "같은 로컬 주소에서 다시 연결하십시오.", False),
    "LIVE_STREAM_LIMIT_REACHED": (429, "동시 연결 상한에 도달했습니다.", "다른 연결을 종료한 뒤 다시 시도하십시오.", True),
    "LIVE_INVALID_LAST_EVENT_ID": (400, "재연결 헤더 형식을 확인할 수 없습니다.", "Last-Event-ID를 한 번만 보내십시오.", False),
    "LIVE_SERVICE_UNAVAILABLE": (503, "로컬 모니터링이 종료됐습니다.", "새 로컬 세션에서 다시 시작하십시오.", False),
    "LIVE_STREAM_FAILED": (500, "스트림을 시작하지 못했습니다.", "새 로컬 세션에서 다시 시도하십시오.", True),
}
_ACCESS_CODES = {
    "LOOPBACK_REQUIRED": "LIVE_LOOPBACK_REQUIRED",
    "INVALID_HOST": "LIVE_INVALID_HOST",
    "FORWARDED_REQUEST_REJECTED": "LIVE_FORWARDED_REQUEST_REJECTED",
    "ORIGIN_REJECTED": "LIVE_ORIGIN_REJECTED",
}


def live_error_response(code: str) -> JSONResponse:
    status, message, action, retryable = _ERRORS[code]
    body = LiveErrorResponse(error_code=code, user_message=message,
                             recovery_action=action, retryable=retryable)
    return JSONResponse(status_code=status, content=body.model_dump(), headers=_HEADERS)


def _rejection(request: Request, service: LiveMonitoringService | None) -> str | None:
    if service is None:
        return "LIVE_MONITORING_NOT_ENABLED"
    code = classify_local_request(request)
    if code is not None:
        return _ACCESS_CODES[code]
    if request.scope.get("query_string"):
        return "LIVE_INVALID_LAST_EVENT_ID"
    return None


def create_live_status_endpoint(service: LiveMonitoringService | None):
    def endpoint(request: Request):
        rejection = _rejection(request, service)
        if rejection is not None:
            return live_error_response(rejection)
        try:
            status = service.status()
            return JSONResponse(content=status.model_dump(mode="json"), headers=_HEADERS)
        except Exception:
            return live_error_response("LIVE_SERVICE_UNAVAILABLE")
    return endpoint


def create_live_events_endpoint(service: LiveMonitoringService | None):
    async def endpoint(request: Request):
        rejection = _rejection(request, service)
        if rejection is not None:
            return live_error_response(rejection)
        headers = request.headers.getlist("last-event-id")
        if len(headers) > 1:
            return live_error_response("LIVE_INVALID_LAST_EVENT_ID")
        try:
            connection = service.open_connection(headers[0] if headers else None)
        except LiveServiceError as error:
            return live_error_response("LIVE_STREAM_LIMIT_REACHED" if error.code == "STREAM_LIMIT"
                                       else "LIVE_SERVICE_UNAVAILABLE")
        except Exception:
            return live_error_response("LIVE_STREAM_FAILED")
        return StreamingResponse(
            connection.stream(), media_type="text/event-stream",
            headers={**_HEADERS, "X-Accel-Buffering": "no"},
            background=BackgroundTask(connection.release),
        )
    return endpoint
