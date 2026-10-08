import asyncio
import os
import tempfile
import uuid

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
    analyze_staged_linux_audit_inputs,
)
from app.api_uploads import (
    LinuxAuditUploadValidationError,
    stage_linux_audit_uploads,
)
from app.main import analyze
from app.analyzer.incident_case_adapter import (
    project_investigation_cases_from_analysis,
)
from app.models.investigation_sample_api import (
    InvestigationErrorResponse,
    InvestigationResponse,
)
from app.sample_investigation_api import create_sample_endpoint
from app.models.linux_audit_api import (
    LinuxAuditAnalysisResponse,
    LinuxAuditApiErrorResponse,
    LinuxAuditResponseProjectionError,
    LinuxAuditUnexpectedServerError,
    build_linux_audit_api_response,
    project_linux_audit_api_error,
)
from app.models.schemas import (
    AnalysisResponse,
    AnalysisResultResponse,
    AnalysisSummary,
    DetectionResponse,
    EvidenceResponse,
)
from app.security.linux_audit_api import (
    LINUX_AUDIT_AUTHENTICATION_ERROR_CODE,
    LinuxAuditAnalysisBusyError,
    LinuxAuditAnalysisLimiter,
    LinuxAuditAnalysisLimiterContractError,
    LinuxAuditApiAccessAuditContractError,
    LinuxAuditApiAccessAuditFailedError,
    LinuxAuditApiAccessAuditRecorder,
    LinuxAuditApiAccessAuditSink,
    LinuxAuditApiAuthenticationError,
    LinuxAuditApiAuthorizationError,
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
    create_linux_audit_authentication_dependency,
    create_linux_audit_authorization_dependency,
    create_linux_audit_access_audit_recorder_factory,
    emit_linux_audit_cancellation_preserving,
    get_linux_audit_access_audit_recorder,
    prepare_linux_audit_api_security,
)


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}


def save_upload_to_temp(file: UploadFile) -> str:
    filename = file.filename or ""
    suffix = os.path.splitext(filename)[1].lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"허용되지 않은 파일 형식입니다: {suffix or '확장자 없음'}",
        )

    content = file.file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="빈 파일은 업로드할 수 없습니다.",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="파일 크기가 너무 큽니다. 최대 10MB까지 업로드할 수 있습니다.",
        )

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix,
    ) as temp_file:
        temp_file.write(content)

    return temp_file.name


def build_detection_response(detection) -> DetectionResponse:
    evidence = [
        EvidenceResponse(
            type=item.type,
            value=item.value,
            source=item.source,
            timestamp=item.timestamp,
            time_range=item.time_range,
        )
        for item in detection.evidence
    ]

    return DetectionResponse(
        is_detected=detection.is_detected,
        detection_type=detection.detection_type,
        evidence=evidence,
    )


def build_analysis_response(
    result: dict,
    total_sources: int,
) -> AnalysisResponse:
    ip_results = result["results"]
    results = []

    for ip, analysis in ip_results.items():
        results.append(
            AnalysisResultResponse(
                ip=ip,
                risk_level=analysis["risk_level"],
                detections={
                    name: build_detection_response(detection)
                    for name, detection in analysis["detections"].items()
                },
                correlation=analysis["correlation"],
                risk_factors=analysis["risk_factors"],
            )
        )

    detected_ips = sum(
        1
        for analysis in ip_results.values()
        if any(
            detection.is_detected
            for detection in analysis["detections"].values()
        )
    )

    high_risk_ips = sum(
        1
        for analysis in ip_results.values()
        if analysis["risk_level"] == "HIGH"
    )

    summary = AnalysisSummary(
        total_sources=total_sources,
        total_ips=len(ip_results),
        detected_ips=detected_ips,
        high_risk_ips=high_risk_ips,
    )

    return AnalysisResponse(
        analysis_id=str(uuid.uuid4()),
        status="completed",
        summary=summary,
        results=results,
        global_correlation=result["global_correlation"],
        ai_summary=None,
    )


def health_check():
    return {
        "status": "ok"
    }


async def analyze_logs(
    application_file: UploadFile = File(...),
    ssh_file: UploadFile = File(...),
    access_file: UploadFile = File(...),
):
    temp_paths = []

    try:
        application_path = save_upload_to_temp(application_file)
        temp_paths.append(application_path)

        ssh_path = save_upload_to_temp(ssh_file)
        temp_paths.append(ssh_path)

        access_path = save_upload_to_temp(access_file)
        temp_paths.append(access_path)

        log_sources = [
            {
                "source": "application",
                "path": application_path,
            },
            {
                "source": "ssh",
                "path": ssh_path,
            },
            {
                "source": "access",
                "path": access_path,
            },
        ]

        result = analyze(log_sources)

        return build_analysis_response(
            result,
            total_sources=len(log_sources),
        )

    finally:
        for path in temp_paths:
            if os.path.exists(path):
                os.remove(path)


def _linux_audit_error_response(error: object) -> JSONResponse:
    projected = project_linux_audit_api_error(error)
    headers = None
    if (
        projected.status_code == 401
        and projected.body.error.code
        == LINUX_AUDIT_AUTHENTICATION_ERROR_CODE
    ):
        headers = {"WWW-Authenticate": "Bearer"}
    return JSONResponse(
        status_code=projected.status_code,
        content=projected.body.model_dump(mode="json"),
        headers=headers,
    )


async def _linux_audit_security_error_handler(
    request: Request,
    error: LinuxAuditApiAuthenticationError
    | LinuxAuditApiAuthorizationError
    | LinuxAuditApiAccessAuditFailedError,
) -> JSONResponse:
    return _linux_audit_error_response(error)


async def _emit_linux_audit_terminal_event(
    recorder: LinuxAuditApiAccessAuditRecorder,
    response: object,
    *,
    result_category: str,
    http_status: int,
    analysis_id=None,
):
    if recorder.terminal_attempted:
        return _linux_audit_error_response(
            LinuxAuditApiAccessAuditFailedError()
        )
    try:
        await recorder.emit(
            result_category=result_category,
            http_status=http_status,
            analysis_id=analysis_id,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        return _linux_audit_error_response(
            LinuxAuditApiAccessAuditFailedError()
        )
    return response


def _create_linux_audit_analysis_endpoint(
    limiter: LinuxAuditAnalysisLimiter,
):
    if type(limiter) is not LinuxAuditAnalysisLimiter:
        raise LinuxAuditApiSecurityConfigurationError()

    async def analyze_linux_audit_logs(
        request: Request,
        linux_audit_files: list[UploadFile] | None = File(default=None),
    ):
        try:
            recorder = get_linux_audit_access_audit_recorder(request)
            uploads = tuple(linux_audit_files or ())
            recorder.set_file_count(len(uploads))
        except LinuxAuditApiAccessAuditContractError:
            return _linux_audit_error_response(
                LinuxAuditApiAccessAuditFailedError()
            )

        try:
            async with limiter.acquire():
                try:
                    async with stage_linux_audit_uploads(
                        uploads
                    ) as staged_inputs:
                        recorder.set_upload_size_bytes(sum(
                            staged.size_bytes
                            for staged in staged_inputs
                        ))
                        analysis = await run_in_threadpool(
                            analyze_staged_linux_audit_inputs,
                            staged_inputs,
                        )
                        analysis_id = uuid.uuid4()
                        response = build_linux_audit_api_response(
                            analysis,
                            analysis_id=analysis_id,
                        )
                        return await _emit_linux_audit_terminal_event(
                            recorder,
                            response,
                            result_category="analysis_completed",
                            http_status=200,
                            analysis_id=analysis_id,
                        )
                except (
                    LinuxAuditUploadValidationError,
                    LinuxAuditAnalysisValidationError,
                    LinuxAuditResponseProjectionError,
                ) as error:
                    response = _linux_audit_error_response(error)
                    result_category = (
                        "validation_failed"
                        if response.status_code < 500
                        else "internal_failed"
                    )
                    return await _emit_linux_audit_terminal_event(
                        recorder,
                        response,
                        result_category=result_category,
                        http_status=response.status_code,
                    )
                except asyncio.CancelledError as cancellation:
                    await emit_linux_audit_cancellation_preserving(
                        recorder,
                        cancellation,
                    )
                    raise
                except Exception:
                    response = _linux_audit_error_response(
                        LinuxAuditUnexpectedServerError()
                    )
                    return await _emit_linux_audit_terminal_event(
                        recorder,
                        response,
                        result_category="internal_failed",
                        http_status=500,
                    )
        except LinuxAuditAnalysisBusyError as error:
            response = _linux_audit_error_response(error)
            return await _emit_linux_audit_terminal_event(
                recorder,
                response,
                result_category="capacity_rejected",
                http_status=429,
            )
        except asyncio.CancelledError as cancellation:
            await emit_linux_audit_cancellation_preserving(
                recorder,
                cancellation,
            )
            raise
        except LinuxAuditAnalysisLimiterContractError:
            response = _linux_audit_error_response(
                LinuxAuditUnexpectedServerError()
            )
            return await _emit_linux_audit_terminal_event(
                recorder,
                response,
                result_category="internal_failed",
                http_status=500,
            )
        except Exception:
            response = _linux_audit_error_response(
                LinuxAuditUnexpectedServerError()
            )
            if recorder.terminal_attempted:
                return response
            return await _emit_linux_audit_terminal_event(
                recorder,
                response,
                result_category="internal_failed",
                http_status=500,
            )

    return analyze_linux_audit_logs


def create_app(
    *,
    enable_linux_audit_api: bool = False,
    linux_audit_api_security: LinuxAuditApiSecurityConfig | None = None,
    linux_audit_api_audit_sink: LinuxAuditApiAccessAuditSink | None = None,
) -> FastAPI:
    if type(enable_linux_audit_api) is not bool:
        raise TypeError("enable_linux_audit_api must be a bool")

    prepared_security = None
    authorization_dependency = None
    analysis_limiter = None
    if enable_linux_audit_api:
        if (
            linux_audit_api_security is None
            or linux_audit_api_audit_sink is None
        ):
            raise LinuxAuditApiSecurityConfigurationError()
        prepared_security = prepare_linux_audit_api_security(
            linux_audit_api_security
        )
        authentication_dependency = (
            create_linux_audit_authentication_dependency(
                prepared_security,
                create_linux_audit_access_audit_recorder_factory(
                    linux_audit_api_audit_sink
                ),
            )
        )
        authorization_dependency = (
            create_linux_audit_authorization_dependency(
                authentication_dependency
            )
        )
        analysis_limiter = LinuxAuditAnalysisLimiter(
            prepared_security.max_concurrent_analyses
        )
    elif (
        linux_audit_api_security is not None
        or linux_audit_api_audit_sink is not None
    ):
        raise LinuxAuditApiSecurityConfigurationError()

    configured_app = FastAPI(
        title="AI Security Log Analyzer",
        description="Security log analysis API",
        version="0.1.0",
    )
    configured_app.add_api_route(
        "/api/health",
        health_check,
        methods=["GET"],
    )
    configured_app.add_api_route(
        "/api/analyze",
        analyze_logs,
        methods=["POST"],
        response_model=AnalysisResponse,
    )
    configured_app.add_api_route(
        "/api/v1/investigations/sample",
        create_sample_endpoint(
            lambda sources: analyze(sources),
            lambda result: project_investigation_cases_from_analysis(result),
        ),
        methods=["POST"],
        response_model=InvestigationResponse,
        responses={
            code: {"model": InvestigationErrorResponse}
            for code in (400, 429, 500, 503)
        },
    )

    if enable_linux_audit_api:
        configured_app.add_exception_handler(
            LinuxAuditApiAuthenticationError,
            _linux_audit_security_error_handler,
        )
        configured_app.add_exception_handler(
            LinuxAuditApiAuthorizationError,
            _linux_audit_security_error_handler,
        )
        configured_app.add_exception_handler(
            LinuxAuditApiAccessAuditFailedError,
            _linux_audit_security_error_handler,
        )
        configured_app.add_api_route(
            "/api/analyze-linux-audit",
            _create_linux_audit_analysis_endpoint(analysis_limiter),
            methods=["POST"],
            response_model=LinuxAuditAnalysisResponse,
            dependencies=[Depends(authorization_dependency)],
            responses={
                status_code: {"model": LinuxAuditApiErrorResponse}
                for status_code in (
                    400,
                    401,
                    403,
                    409,
                    413,
                    415,
                    422,
                    429,
                    500,
                )
            },
        )

    return configured_app


app = create_app()
