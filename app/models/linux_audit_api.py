from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from app.analyzer.linux_audit_api import (
    LinuxAuditAnalysisValidationError,
    LinuxAuditApiAnalysis,
)
from app.api_uploads import LinuxAuditUploadValidationError
from app.security.linux_audit_api import (
    LINUX_AUDIT_AUDIT_FAILED_ERROR_CODE,
    LINUX_AUDIT_AUDIT_FAILED_ERROR_MESSAGE,
    LINUX_AUDIT_AUDIT_FAILED_ERROR_STATUS,
    LINUX_AUDIT_AUTHENTICATION_ERROR_CODE,
    LINUX_AUDIT_AUTHENTICATION_ERROR_MESSAGE,
    LINUX_AUDIT_AUTHENTICATION_ERROR_STATUS,
    LINUX_AUDIT_AUTHORIZATION_ERROR_CODE,
    LINUX_AUDIT_AUTHORIZATION_ERROR_MESSAGE,
    LINUX_AUDIT_AUTHORIZATION_ERROR_STATUS,
    LINUX_AUDIT_BUSY_ERROR_CODE,
    LINUX_AUDIT_BUSY_ERROR_MESSAGE,
    LINUX_AUDIT_BUSY_ERROR_STATUS,
    LinuxAuditAnalysisBusyError,
    LinuxAuditApiAccessAuditFailedError,
    LinuxAuditApiAuthenticationError,
    LinuxAuditApiAuthorizationError,
)


_PROJECTION_ERROR_CODE = "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR"
_PROJECTION_ERROR_STATUS = 500
_PROJECTION_ERROR_MESSAGE = (
    "Linux Audit response could not be created."
)
_INTERNAL_SERVER_ERROR_CODE = "INTERNAL_SERVER_ERROR"
_INTERNAL_SERVER_ERROR_STATUS = 500
_INTERNAL_SERVER_ERROR_MESSAGE = "The request could not be completed."

_ERROR_CONTRACTS = {
    "MISSING_LINUX_AUDIT_FILES": (
        422,
        "At least one Linux Audit file is required.",
    ),
    "LINUX_AUDIT_FILE_COUNT_EXCEEDED": (
        413,
        "Linux Audit file count limit exceeded.",
    ),
    "LINUX_AUDIT_FILE_TOO_LARGE": (
        413,
        "A Linux Audit file exceeds the size limit.",
    ),
    "LINUX_AUDIT_REQUEST_TOO_LARGE": (
        413,
        "Linux Audit upload size limit exceeded.",
    ),
    "EMPTY_LINUX_AUDIT_FILE": (
        400,
        "A Linux Audit file is empty or contains only whitespace.",
    ),
    "INVALID_LINUX_AUDIT_ENCODING": (
        400,
        "Linux Audit input must be valid UTF-8.",
    ),
    "UNSUPPORTED_LINUX_AUDIT_INPUT": (
        415,
        "Linux Audit input format is not supported.",
    ),
    "DUPLICATE_LINUX_AUDIT_FILE": (
        409,
        "Duplicate Linux Audit input is not allowed.",
    ),
    "NO_ELIGIBLE_LINUX_AUDIT_EVENTS": (
        422,
        "No eligible Linux Audit events were found.",
    ),
    "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR": (
        500,
        "Linux Audit analysis could not be completed.",
    ),
    _PROJECTION_ERROR_CODE: (
        _PROJECTION_ERROR_STATUS,
        _PROJECTION_ERROR_MESSAGE,
    ),
    _INTERNAL_SERVER_ERROR_CODE: (
        _INTERNAL_SERVER_ERROR_STATUS,
        _INTERNAL_SERVER_ERROR_MESSAGE,
    ),
    LINUX_AUDIT_AUTHENTICATION_ERROR_CODE: (
        LINUX_AUDIT_AUTHENTICATION_ERROR_STATUS,
        LINUX_AUDIT_AUTHENTICATION_ERROR_MESSAGE,
    ),
    LINUX_AUDIT_AUTHORIZATION_ERROR_CODE: (
        LINUX_AUDIT_AUTHORIZATION_ERROR_STATUS,
        LINUX_AUDIT_AUTHORIZATION_ERROR_MESSAGE,
    ),
    LINUX_AUDIT_BUSY_ERROR_CODE: (
        LINUX_AUDIT_BUSY_ERROR_STATUS,
        LINUX_AUDIT_BUSY_ERROR_MESSAGE,
    ),
    LINUX_AUDIT_AUDIT_FAILED_ERROR_CODE: (
        LINUX_AUDIT_AUDIT_FAILED_ERROR_STATUS,
        LINUX_AUDIT_AUDIT_FAILED_ERROR_MESSAGE,
    ),
}

_UPLOAD_ERROR_CODES = frozenset((
    "MISSING_LINUX_AUDIT_FILES",
    "LINUX_AUDIT_FILE_COUNT_EXCEEDED",
    "LINUX_AUDIT_FILE_TOO_LARGE",
    "LINUX_AUDIT_REQUEST_TOO_LARGE",
    "EMPTY_LINUX_AUDIT_FILE",
    "INVALID_LINUX_AUDIT_ENCODING",
    "UNSUPPORTED_LINUX_AUDIT_INPUT",
    "DUPLICATE_LINUX_AUDIT_FILE",
))
_ANALYSIS_ERROR_CODES = frozenset((
    "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
    "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
))

NonNegativeStrictInt = Annotated[int, Field(strict=True, ge=0)]
LinuxAuditApiErrorCode = Literal[
    "MISSING_LINUX_AUDIT_FILES",
    "LINUX_AUDIT_FILE_COUNT_EXCEEDED",
    "LINUX_AUDIT_FILE_TOO_LARGE",
    "LINUX_AUDIT_REQUEST_TOO_LARGE",
    "EMPTY_LINUX_AUDIT_FILE",
    "INVALID_LINUX_AUDIT_ENCODING",
    "UNSUPPORTED_LINUX_AUDIT_INPUT",
    "DUPLICATE_LINUX_AUDIT_FILE",
    "NO_ELIGIBLE_LINUX_AUDIT_EVENTS",
    "LINUX_AUDIT_ANALYSIS_CONTRACT_ERROR",
    "LINUX_AUDIT_RESPONSE_PROJECTION_ERROR",
    "INTERNAL_SERVER_ERROR",
    "LINUX_AUDIT_AUTHENTICATION_REQUIRED",
    "LINUX_AUDIT_ACCESS_DENIED",
    "LINUX_AUDIT_ANALYSIS_BUSY",
    "LINUX_AUDIT_ACCESS_AUDIT_FAILED",
]


class OutcomeCountsResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    success: NonNegativeStrictInt
    failure: NonNegativeStrictInt
    unknown: NonNegativeStrictInt


class CompletenessCountsResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    complete: NonNegativeStrictInt
    incomplete: NonNegativeStrictInt


class ProcessTelemetryResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    observation_count: NonNegativeStrictInt
    outcome_counts: OutcomeCountsResponse
    argv_completeness_counts: CompletenessCountsResponse
    path_completeness_counts: CompletenessCountsResponse

    @model_validator(mode="after")
    def validate_counts(self):
        if not (
            self.observation_count
            == self.outcome_counts.success
            + self.outcome_counts.failure
            + self.outcome_counts.unknown
            and self.observation_count
            == self.argv_completeness_counts.complete
            + self.argv_completeness_counts.incomplete
            and self.observation_count
            == self.path_completeness_counts.complete
            + self.path_completeness_counts.incomplete
        ):
            raise ValueError("process telemetry counts are inconsistent")
        return self


class SharedMemoryReviewResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    observation_count: NonNegativeStrictInt


class SessionProcessReviewResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    session_co_observation_count: NonNegativeStrictInt
    process_observation_count: NonNegativeStrictInt
    outcome_counts: OutcomeCountsResponse
    shared_memory_observation_count: NonNegativeStrictInt
    sessions_with_shared_memory_observation_count: NonNegativeStrictInt

    @model_validator(mode="after")
    def validate_counts(self):
        if not (
            self.process_observation_count
            == self.outcome_counts.success
            + self.outcome_counts.failure
            + self.outcome_counts.unknown
            and self.shared_memory_observation_count
            <= self.process_observation_count
            and self.sessions_with_shared_memory_observation_count
            <= self.session_co_observation_count
            and (
                self.sessions_with_shared_memory_observation_count == 0
                or self.shared_memory_observation_count > 0
            )
            and (
                self.shared_memory_observation_count > 0
                or self.sessions_with_shared_memory_observation_count == 0
            )
            and (
                self.session_co_observation_count > 0
                or self.process_observation_count
                == self.shared_memory_observation_count
                == self.sessions_with_shared_memory_observation_count
                == 0
            )
        ):
            raise ValueError("session-process counts are inconsistent")
        return self


class LinuxAuditAnalysisResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    analysis_id: UUID
    status: Literal["completed"]
    process_telemetry: ProcessTelemetryResponse
    shared_memory_review: SharedMemoryReviewResponse
    session_process_review: SessionProcessReviewResponse

    @model_validator(mode="after")
    def validate_cross_summary_counts(self):
        process_count = self.process_telemetry.observation_count
        shared_count = self.shared_memory_review.observation_count
        session = self.session_process_review
        if not (
            shared_count <= process_count
            and session.process_observation_count <= process_count
            and session.shared_memory_observation_count
            <= session.process_observation_count
            and session.shared_memory_observation_count <= shared_count
        ):
            raise ValueError("Linux Audit response counts are inconsistent")
        return self


class LinuxAuditApiErrorDetail(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    code: LinuxAuditApiErrorCode
    message: Annotated[str, Field(strict=True, min_length=1)]

    @model_validator(mode="after")
    def validate_known_message(self):
        if not self.message.strip():
            raise ValueError("error message must not be blank")
        if self.message != _ERROR_CONTRACTS[self.code][1]:
            raise ValueError("error message does not match the error code")
        return self


class LinuxAuditApiErrorResponse(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    error: LinuxAuditApiErrorDetail


@dataclass(frozen=True)
class ProjectedLinuxAuditApiError:
    status_code: int
    body: LinuxAuditApiErrorResponse


class LinuxAuditResponseProjectionError(ValueError):

    def __init__(self):
        super().__init__(_PROJECTION_ERROR_MESSAGE)
        self.code = _PROJECTION_ERROR_CODE
        self.status_code = _PROJECTION_ERROR_STATUS
        self.message = _PROJECTION_ERROR_MESSAGE


class LinuxAuditUnexpectedServerError(RuntimeError):

    def __init__(self):
        super().__init__(_INTERNAL_SERVER_ERROR_MESSAGE)
        self.code = _INTERNAL_SERVER_ERROR_CODE
        self.status_code = _INTERNAL_SERVER_ERROR_STATUS
        self.message = _INTERNAL_SERVER_ERROR_MESSAGE


def _projection_error() -> LinuxAuditResponseProjectionError:
    return LinuxAuditResponseProjectionError()


def _is_non_negative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _validate_analysis(analysis: object) -> LinuxAuditApiAnalysis:
    if type(analysis) is not LinuxAuditApiAnalysis:
        raise _projection_error()

    counts = (
        analysis.process_observation_count,
        analysis.process_outcome_success_count,
        analysis.process_outcome_failure_count,
        analysis.process_outcome_unknown_count,
        analysis.argv_complete_count,
        analysis.argv_incomplete_count,
        analysis.path_complete_count,
        analysis.path_incomplete_count,
        analysis.shared_memory_privileged_execution_observation_count,
        analysis.session_co_observation_count,
        analysis.session_process_observation_count,
        analysis.session_process_outcome_success_count,
        analysis.session_process_outcome_failure_count,
        analysis.session_process_outcome_unknown_count,
        analysis.session_linked_shared_memory_observation_count,
        analysis.sessions_with_shared_memory_observation_count,
    )
    if not all(_is_non_negative_integer(count) for count in counts):
        raise _projection_error()

    process_count = analysis.process_observation_count
    shared_count = (
        analysis.shared_memory_privileged_execution_observation_count
    )
    session_count = analysis.session_co_observation_count
    session_process_count = analysis.session_process_observation_count
    linked_count = (
        analysis.session_linked_shared_memory_observation_count
    )
    containing_session_count = (
        analysis.sessions_with_shared_memory_observation_count
    )
    if not (
        process_count
        == analysis.process_outcome_success_count
        + analysis.process_outcome_failure_count
        + analysis.process_outcome_unknown_count
        and process_count
        == analysis.argv_complete_count + analysis.argv_incomplete_count
        and process_count
        == analysis.path_complete_count + analysis.path_incomplete_count
        and shared_count <= process_count
        and session_process_count
        == analysis.session_process_outcome_success_count
        + analysis.session_process_outcome_failure_count
        + analysis.session_process_outcome_unknown_count
        and session_process_count <= process_count
        and linked_count <= session_process_count
        and linked_count <= shared_count
        and containing_session_count <= session_count
        and (containing_session_count == 0 or linked_count > 0)
        and (linked_count > 0 or containing_session_count == 0)
        and (
            session_count > 0
            or session_process_count
            == linked_count
            == containing_session_count
            == 0
        )
    ):
        raise _projection_error()

    return analysis


def build_linux_audit_api_response(
    analysis: LinuxAuditApiAnalysis,
    *,
    analysis_id: UUID,
) -> LinuxAuditAnalysisResponse:
    validated = _validate_analysis(analysis)
    if type(analysis_id) is not UUID:
        raise _projection_error()

    try:
        return LinuxAuditAnalysisResponse(
            analysis_id=analysis_id,
            status="completed",
            process_telemetry=ProcessTelemetryResponse(
                observation_count=validated.process_observation_count,
                outcome_counts=OutcomeCountsResponse(
                    success=validated.process_outcome_success_count,
                    failure=validated.process_outcome_failure_count,
                    unknown=validated.process_outcome_unknown_count,
                ),
                argv_completeness_counts=CompletenessCountsResponse(
                    complete=validated.argv_complete_count,
                    incomplete=validated.argv_incomplete_count,
                ),
                path_completeness_counts=CompletenessCountsResponse(
                    complete=validated.path_complete_count,
                    incomplete=validated.path_incomplete_count,
                ),
            ),
            shared_memory_review=SharedMemoryReviewResponse(
                observation_count=(
                    validated
                    .shared_memory_privileged_execution_observation_count
                ),
            ),
            session_process_review=SessionProcessReviewResponse(
                session_co_observation_count=(
                    validated.session_co_observation_count
                ),
                process_observation_count=(
                    validated.session_process_observation_count
                ),
                outcome_counts=OutcomeCountsResponse(
                    success=(
                        validated
                        .session_process_outcome_success_count
                    ),
                    failure=(
                        validated
                        .session_process_outcome_failure_count
                    ),
                    unknown=(
                        validated
                        .session_process_outcome_unknown_count
                    ),
                ),
                shared_memory_observation_count=(
                    validated
                    .session_linked_shared_memory_observation_count
                ),
                sessions_with_shared_memory_observation_count=(
                    validated
                    .sessions_with_shared_memory_observation_count
                ),
            ),
        )
    except ValidationError:
        raise _projection_error() from None


def _fixed_projection_error() -> ProjectedLinuxAuditApiError:
    return ProjectedLinuxAuditApiError(
        status_code=_PROJECTION_ERROR_STATUS,
        body=LinuxAuditApiErrorResponse(
            error=LinuxAuditApiErrorDetail(
                code=_PROJECTION_ERROR_CODE,
                message=_PROJECTION_ERROR_MESSAGE,
            ),
        ),
    )


def project_linux_audit_api_error(
    error: object,
) -> ProjectedLinuxAuditApiError:
    if type(error) is LinuxAuditUploadValidationError:
        allowed_codes = _UPLOAD_ERROR_CODES
    elif type(error) is LinuxAuditAnalysisValidationError:
        allowed_codes = _ANALYSIS_ERROR_CODES
    elif type(error) is LinuxAuditResponseProjectionError:
        allowed_codes = frozenset((_PROJECTION_ERROR_CODE,))
    elif type(error) is LinuxAuditUnexpectedServerError:
        allowed_codes = frozenset((_INTERNAL_SERVER_ERROR_CODE,))
    elif type(error) is LinuxAuditApiAuthenticationError:
        allowed_codes = frozenset((
            LINUX_AUDIT_AUTHENTICATION_ERROR_CODE,
        ))
    elif type(error) is LinuxAuditApiAuthorizationError:
        allowed_codes = frozenset((
            LINUX_AUDIT_AUTHORIZATION_ERROR_CODE,
        ))
    elif type(error) is LinuxAuditAnalysisBusyError:
        allowed_codes = frozenset((LINUX_AUDIT_BUSY_ERROR_CODE,))
    elif type(error) is LinuxAuditApiAccessAuditFailedError:
        allowed_codes = frozenset((
            LINUX_AUDIT_AUDIT_FAILED_ERROR_CODE,
        ))
    else:
        return _fixed_projection_error()

    code = getattr(error, "code", None)
    if type(code) is not str or code not in allowed_codes:
        return _fixed_projection_error()

    expected_status, expected_message = _ERROR_CONTRACTS[code]
    status_code = getattr(error, "status_code", None)
    message = getattr(error, "message", None)
    if (
        type(status_code) is not int
        or status_code != expected_status
        or type(message) is not str
        or message != expected_message
    ):
        return _fixed_projection_error()

    try:
        body = LinuxAuditApiErrorResponse(
            error=LinuxAuditApiErrorDetail(
                code=code,
                message=expected_message,
            ),
        )
    except ValidationError:
        return _fixed_projection_error()

    return ProjectedLinuxAuditApiError(
        status_code=expected_status,
        body=body,
    )
