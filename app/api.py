import os
import tempfile
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.main import analyze
from app.models.schemas import (
    AnalysisResponse,
    AnalysisResultResponse,
    AnalysisSummary,
    DetectionResponse,
    EvidenceResponse,
)


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}


app = FastAPI(
    title="AI Security Log Analyzer",
    description="Security log analysis API",
    version="0.1.0",
)


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


@app.get("/api/health")
def health_check():
    return {
        "status": "ok"
    }


@app.post("/api/upload-test")
async def upload_test(file: UploadFile = File(...)):
    temp_path = save_upload_to_temp(file)

    try:
        return {
            "filename": file.filename,
            "content_type": file.content_type,
            "temp_path": temp_path,
        }
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.post(
    "/api/analyze",
    response_model=AnalysisResponse,
)
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
