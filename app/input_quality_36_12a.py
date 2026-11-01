"""Closed, deterministic input-recognition summaries for bounded local logs."""

from collections import Counter
from datetime import datetime
import re
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.models.schemas import NormalizedEvent
from app.parser.registry import get_parser, get_timezone


QualitySource = Literal["application", "ssh", "access", "aggregate"]
RecognitionStatus = Literal["complete", "partial", "none", "empty"]
ReasonCode = Literal[
    "unsupported_format", "invalid_timestamp", "invalid_address", "invalid_port",
    "invalid_header", "incomplete_record", "blank_line", "ignored_record",
    "other_rejected",
]
SOURCE_ORDER = ("application", "ssh", "access")
MAX_INPUT_BYTES = 32 * 1024
MAX_LINES = 512
MAX_LINE_BYTES = 2048
_REASON_FIELDS = (
    "unsupported_format", "invalid_timestamp", "invalid_address", "invalid_port",
    "invalid_header", "incomplete_record", "blank_line", "ignored_record",
    "other_rejected",
)
_LIMITATIONS = (
    "INPUT_RECORD_RECOGNITION_ONLY",
    "NOT_COLLECTION_COMPLETENESS_OR_DETECTION_ACCURACY",
)


class _ClosedModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True,
    )


class InputQualityReasonCounts(_ClosedModel):
    unsupported_format: StrictInt = Field(ge=0)
    invalid_timestamp: StrictInt = Field(ge=0)
    invalid_address: StrictInt = Field(ge=0)
    invalid_port: StrictInt = Field(ge=0)
    invalid_header: StrictInt = Field(ge=0)
    incomplete_record: StrictInt = Field(ge=0)
    blank_line: StrictInt = Field(ge=0)
    ignored_record: StrictInt = Field(ge=0)
    other_rejected: StrictInt = Field(ge=0)


class InputQualitySummary(_ClosedModel):
    schema_version: Literal["1"]
    source: QualitySource
    total_lines: StrictInt = Field(ge=0)
    nonempty_lines: StrictInt = Field(ge=0)
    recognized_lines: StrictInt = Field(ge=0)
    unrecognized_lines: StrictInt = Field(ge=0)
    ignored_lines: StrictInt = Field(ge=0)
    recognition_status: RecognitionStatus
    reason_counts: InputQualityReasonCounts
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def validate_counts(self):
        if self.recognized_lines + self.unrecognized_lines + self.ignored_lines != self.total_lines:
            raise ValueError("Invalid input quality counts.")
        if self.nonempty_lines > self.total_lines:
            raise ValueError("Invalid input quality counts.")
        if self.reason_counts.blank_line != self.total_lines - self.nonempty_lines:
            raise ValueError("Invalid input quality counts.")
        expected = (
            "empty" if self.nonempty_lines == 0 else
            "complete" if self.recognized_lines == self.nonempty_lines else
            "partial" if self.recognized_lines > 0 else "none"
        )
        if self.recognition_status != expected:
            raise ValueError("Invalid input quality status.")
        if sum(getattr(self.reason_counts, key) for key in _REASON_FIELDS) != (
            self.unrecognized_lines + self.ignored_lines
        ):
            raise ValueError("Invalid input quality reasons.")
        if self.limitations != _LIMITATIONS:
            raise ValueError("Invalid input quality limitations.")
        return self


class InputQualityProjection(_ClosedModel):
    schema_version: Literal["1"]
    by_source: tuple[InputQualitySummary, ...]
    aggregate: InputQualitySummary

    @model_validator(mode="after")
    def validate_aggregate(self):
        sources = tuple(item.source for item in self.by_source)
        if sources != tuple(source for source in SOURCE_ORDER if source in sources):
            raise ValueError("Invalid input quality source order.")
        if any(source == "aggregate" for source in sources):
            raise ValueError("Invalid input quality source.")
        if self.aggregate.source != "aggregate":
            raise ValueError("Invalid input quality aggregate.")
        for field in (
            "total_lines", "nonempty_lines", "recognized_lines",
            "unrecognized_lines", "ignored_lines",
        ):
            if getattr(self.aggregate, field) != sum(getattr(item, field) for item in self.by_source):
                raise ValueError("Invalid input quality aggregate.")
        for field in _REASON_FIELDS:
            if getattr(self.aggregate.reason_counts, field) != sum(
                getattr(item.reason_counts, field) for item in self.by_source
            ):
                raise ValueError("Invalid input quality aggregate.")
        return self


def _physical_lines(text: str) -> list[str]:
    if not text:
        return []
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    return lines


def _reason_for_exception(source: str, line: str, error: Exception) -> str:
    # Categorize only fixed parser messages. Never copy exception text to a DTO.
    message = str(error)
    if source == "ssh":
        if re.match(r"^<[0-9]{1,3}>1 ", line):
            fields = line.split(" ", 3)
            if len(fields) > 1:
                try:
                    from app.parser.ssh_auth import _parse_rfc5424_timestamp
                    _parse_rfc5424_timestamp(fields[1])
                except ValueError:
                    return "invalid_timestamp"
        else:
            parts = line.split()
            if (len(parts) >= 2
                    and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", parts[0])):
                try:
                    datetime.strptime(parts[0] + " " + parts[1], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return "invalid_timestamp"
        if "source address" in message:
            return "invalid_address"
        if "source port" in message:
            return "invalid_port"
        if "RFC 5424" in message and any(
            part in message for part in ("header", "application", "process identifier")
        ):
            return "invalid_header"
        if "Incomplete" in message or "Malformed" in message:
            return "incomplete_record"
    elif source == "access":
        if "timestamp" in message:
            return "invalid_timestamp"
        if "address" in message:
            return "invalid_address"
        if "Incomplete" in message or "Invalid access request field" in message:
            return "incomplete_record"
        if "trailing" in message or "escaping" in message or "syntax" in message:
            return "unsupported_format"
        if "status" in message or "response size" in message:
            return "other_rejected"
    elif source == "application":
        return "invalid_timestamp"
    if "Incomplete" in message or "Missing" in message:
        return "incomplete_record"
    if "Unsupported" in message:
        return "unsupported_format"
    return "other_rejected"


def assess_record(source: str, line: str) -> tuple[str, str | None, bool]:
    """Return outcome, fixed reason and unchanged API-preflight compatibility."""
    if source == "application":
        parts = line.split()
        if len(parts) < 4:
            return "rejected", "incomplete_record", False
        try:
            datetime.strptime(" ".join(parts[:2]), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            date_shaped = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", parts[0])
            time_shaped = re.fullmatch(r"[0-9]{2}:[0-9]{2}:[0-9]{2}", parts[1])
            reason = "invalid_timestamp" if date_shaped and time_shaped else "unsupported_format"
            return "rejected", reason, False
    parser = get_parser(source)
    try:
        event = parser(line, get_timezone(source))
    except (ValueError, IndexError, TypeError, OverflowError) as error:
        return "rejected", _reason_for_exception(source, line, error), False
    except Exception:
        raise ValueError("Input quality evaluation failed.") from None
    if event is None:
        return "ignored", "ignored_record", False
    if type(event) is not NormalizedEvent or not isinstance(event.timestamp, datetime):
        raise ValueError("Input quality evaluation failed.") from None
    compatible = True
    if source == "application":
        compatible = len(line.split()) >= 4
    elif source == "ssh":
        compatible = event.authentication is not None
    return "parsed", None, compatible


def _make_summary(source: str, counts: Mapping[str, int], reasons: Counter) -> InputQualitySummary:
    total = counts["total"]
    nonempty = counts["nonempty"]
    recognized = counts["parsed"]
    unrecognized = counts["rejected"]
    ignored = counts["ignored"]
    status = (
        "empty" if nonempty == 0 else
        "complete" if recognized == nonempty else
        "partial" if recognized > 0 else "none"
    )
    return InputQualitySummary(
        schema_version="1", source=source, total_lines=total,
        nonempty_lines=nonempty, recognized_lines=recognized,
        unrecognized_lines=unrecognized, ignored_lines=ignored,
        recognition_status=status,
        reason_counts=InputQualityReasonCounts(**{
            key: reasons.get(key, 0) for key in _REASON_FIELDS
        }),
        limitations=_LIMITATIONS,
    )


class InputQualityAccumulator:
    """Bounded counters only; source lines and parser events are never retained."""

    def __init__(self, source: str):
        if source not in SOURCE_ORDER:
            raise ValueError("Unsupported input quality source.") from None
        self.source = source
        self.counts: Counter = Counter()
        self.reasons: Counter = Counter()
        self.parser_compatible = True

    def observe(self, raw_line: str) -> bool:
        if type(raw_line) is not str:
            raise ValueError("Input quality evaluation failed.") from None
        self.counts["total"] += 1
        if not raw_line.strip():
            self.counts["ignored"] += 1
            self.reasons["blank_line"] += 1
            return True
        self.counts["nonempty"] += 1
        outcome, reason, compatible = assess_record(self.source, raw_line)
        self.parser_compatible = self.parser_compatible and compatible
        if outcome == "parsed":
            self.counts["parsed"] += 1
        elif outcome == "ignored":
            self.counts["ignored"] += 1
            self.reasons[reason or "ignored_record"] += 1
        else:
            self.counts["rejected"] += 1
            self.reasons[reason or "other_rejected"] += 1
        return compatible

    def reject_all(self) -> bool:
        """The source was nonempty but its format was not safely evaluable."""
        self.counts["rejected"] += 1
        self.counts["nonempty"] += 1
        self.counts["total"] += 1
        self.reasons["other_rejected"] += 1
        return False

    def summary(self) -> InputQualitySummary:
        return _make_summary(self.source, self.counts, self.reasons)


def evaluate_source_text(source: str, text: str) -> InputQualitySummary:
    if source not in SOURCE_ORDER:
        raise ValueError("Unsupported input quality source.") from None
    if type(text) is not str:
        raise ValueError("Input quality evaluation failed.") from None
    try:
        encoded = text.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise ValueError("Input quality evaluation failed.") from None
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError("Input quality evaluation failed.") from None
    lines = _physical_lines(text)
    if len(lines) > MAX_LINES or any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in lines):
        raise ValueError("Input quality evaluation failed.") from None

    accumulator = InputQualityAccumulator(source)
    for raw_line in lines:
        accumulator.observe(raw_line)
    return accumulator.summary()


def aggregate_input_quality(
    summaries: Mapping[str, InputQualitySummary],
) -> InputQualityProjection:
    if type(summaries) is not dict or not summaries or any(key not in SOURCE_ORDER for key in summaries):
        raise ValueError("Invalid input quality source set.") from None
    for source, item in summaries.items():
        if type(item) is not InputQualitySummary or item.source != source:
            raise ValueError("Invalid input quality source set.") from None
    ordered = tuple(summaries[source] for source in SOURCE_ORDER if source in summaries)
    totals = Counter()
    reasons = Counter()
    for item in ordered:
        for field, count_key in (
            ("total_lines", "total"), ("nonempty_lines", "nonempty"),
            ("recognized_lines", "parsed"), ("unrecognized_lines", "rejected"),
            ("ignored_lines", "ignored"),
        ):
            totals[count_key] += getattr(item, field)
        reasons.update(item.reason_counts.model_dump())
    aggregate = _make_summary("aggregate", totals, reasons)
    return InputQualityProjection(schema_version="1", by_source=ordered, aggregate=aggregate)
