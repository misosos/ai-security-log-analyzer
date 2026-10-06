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
    LinuxAuditApiAuthenticationError,
    LinuxAuditApiAuthorizationError,
    LinuxAuditApiSecurityConfig,
    LinuxAuditApiSecurityConfigurationError,
    create_linux_audit_authentication_dependency,
    create_linux_audit_authorization_dependency,
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
    | LinuxAuditApiAuthorizationError,
) -> JSONResponse:
    return _linux_audit_error_response(error)


async def analyze_linux_audit_logs(
    linux_audit_files: list[UploadFile] | None = File(default=None),
):
    try:
        uploads = tuple(linux_audit_files or ())
        async with stage_linux_audit_uploads(uploads) as staged_inputs:
            analysis = await run_in_threadpool(
                analyze_staged_linux_audit_inputs,
                staged_inputs,
            )
            return build_linux_audit_api_response(
                analysis,
                analysis_id=uuid.uuid4(),
            )
    except (
        LinuxAuditUploadValidationError,
        LinuxAuditAnalysisValidationError,
        LinuxAuditResponseProjectionError,
    ) as error:
        return _linux_audit_error_response(error)
    except Exception:
        return _linux_audit_error_response(
            LinuxAuditUnexpectedServerError()
        )


def create_app(
    *,
    enable_linux_audit_api: bool = False,
    linux_audit_api_security: LinuxAuditApiSecurityConfig | None = None,
) -> FastAPI:
    if type(enable_linux_audit_api) is not bool:
        raise TypeError("enable_linux_audit_api must be a bool")

    prepared_security = None
    authorization_dependency = None
    if enable_linux_audit_api:
        if linux_audit_api_security is None:
            raise LinuxAuditApiSecurityConfigurationError()
        prepared_security = prepare_linux_audit_api_security(
            linux_audit_api_security
        )
        authentication_dependency = (
            create_linux_audit_authentication_dependency(
                prepared_security
            )
        )
        authorization_dependency = (
            create_linux_audit_authorization_dependency(
                authentication_dependency
            )
        )
    elif linux_audit_api_security is not None:
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

    if enable_linux_audit_api:
        configured_app.add_exception_handler(
            LinuxAuditApiAuthenticationError,
            _linux_audit_security_error_handler,
        )
        configured_app.add_exception_handler(
            LinuxAuditApiAuthorizationError,
            _linux_audit_security_error_handler,
        )
        configured_app.add_api_route(
            "/api/analyze-linux-audit",
            analyze_linux_audit_logs,
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
                    500,
                )
            },
        )

    return configured_app


app = create_app()
