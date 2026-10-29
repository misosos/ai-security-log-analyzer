"""Closed request, scope, response and error contracts for local text input."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from app.models.investigation_sample_api import LocalInvestigationResponse


LOCAL_TEXT_INVESTIGATION_OPENAPI_REQUEST = {
    "required": True,
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_version", "source", "log_text"],
                "properties": {
                    "schema_version": {"type": "integer", "const": 1},
                    "source": {
                        "type": "string",
                        "enum": ["application", "ssh", "access"],
                    },
                    "log_text": {
                        "type": "string",
                        "description": "Strict UTF-8 text; validated by the local server.",
                    },
                },
            },
        },
    },
}


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LocalTextInvestigationRequest(_ClosedModel):
    schema_version: Literal[1]
    source: Literal["application", "ssh", "access"]
    log_text: StrictStr = Field(repr=False)


class LocalTextInputScope(_ClosedModel):
    mode: Literal["text"]
    source: Literal["application", "ssh", "access"]
    notice_code: Literal["PARTIAL_SINGLE_SOURCE"]


class LocalTextInvestigationResponse(_ClosedModel):
    schema_version: Literal["1"]
    input_scope: LocalTextInputScope
    result: LocalInvestigationResponse


class LocalTextInvestigationErrorResponse(_ClosedModel):
    error_code: Literal[
        "LOCAL_ONLY", "INVALID_MEDIA_TYPE", "QUERY_NOT_ALLOWED", "INVALID_JSON",
        "INVALID_SCHEMA", "UNKNOWN_SOURCE", "EMPTY_INPUT", "INVALID_UTF8",
        "INVALID_TEXT", "PARSER_INCOMPATIBLE", "TEXT_TOO_LARGE",
        "ENVELOPE_TOO_LARGE", "LINE_TOO_LONG", "LINE_COUNT_EXCEEDED",
        "BODY_TIMEOUT", "ANALYSIS_TIMEOUT", "CONCURRENCY_LIMIT", "RATE_LIMITED",
        "ANALYSIS_FAILED", "CASE_PROJECTION_FAILED", "REPORT_GENERATION_FAILED",
        "RESPONSE_INVALID",
    ]
    user_message: StrictStr
    recovery_action: StrictStr
    retryable: bool
    field: Literal["source", "log_text"] | None = None
