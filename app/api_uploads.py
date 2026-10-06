import codecs
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import tempfile

from starlette.datastructures import UploadFile


LINUX_AUDIT_MAX_FILE_COUNT = 4
LINUX_AUDIT_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES = 20 * 1024 * 1024
LINUX_AUDIT_UPLOAD_CHUNK_SIZE_BYTES = 64 * 1024

_ARCHIVE_PREFIX_SIZE = 262
_LEADING_ARCHIVE_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
)
_VALIDATION_ERRORS = {
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
}


@dataclass(frozen=True)
class StagedLinuxAuditInput:
    path: Path
    source_instance: str
    size_bytes: int


class LinuxAuditUploadValidationError(ValueError):

    def __init__(self, code: str):
        status_code, message = _VALIDATION_ERRORS[code]
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def _validation_error(code: str) -> LinuxAuditUploadValidationError:
    return LinuxAuditUploadValidationError(code)


def _validate_upload_container(files: tuple[UploadFile, ...]) -> None:
    if type(files) is not tuple:
        raise TypeError("Linux Audit uploads must be provided as a tuple.")

    if not files:
        raise _validation_error("MISSING_LINUX_AUDIT_FILES")

    if len(files) > LINUX_AUDIT_MAX_FILE_COUNT:
        raise _validation_error(
            "LINUX_AUDIT_FILE_COUNT_EXCEEDED"
        )

    if not all(isinstance(upload, UploadFile) for upload in files):
        raise TypeError(
            "Linux Audit upload items must be UploadFile instances."
        )


def _has_unsupported_signature(prefix: bytes | bytearray) -> bool:
    if any(
        prefix.startswith(signature)
        for signature in _LEADING_ARCHIVE_SIGNATURES
    ):
        return True

    return (
        len(prefix) >= _ARCHIVE_PREFIX_SIZE
        and prefix[257:262] == b"ustar"
    )


def _decode_utf8(decoder, content: bytes, *, final: bool) -> str:
    try:
        return decoder.decode(content, final=final)
    except UnicodeDecodeError:
        raise _validation_error(
            "INVALID_LINUX_AUDIT_ENCODING"
        ) from None


async def _stage_upload(
    upload: UploadFile,
    *,
    index: int,
    directory: Path,
    request_size_bytes: int,
    seen_content: set[tuple[int, bytes]],
) -> tuple[StagedLinuxAuditInput, int]:
    path = directory / f"input-{index}.audit"
    file_size_bytes = 0
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")(
        errors="strict"
    )
    prefix = bytearray()
    prefix_decoded = False
    has_non_whitespace = False

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(descriptor, "wb") as staged_file:
        while True:
            chunk = await upload.read(
                LINUX_AUDIT_UPLOAD_CHUNK_SIZE_BYTES
            )

            if not isinstance(chunk, bytes):
                raise TypeError(
                    "UploadFile.read(size) must return bytes."
                )

            if not chunk:
                break

            next_file_size = file_size_bytes + len(chunk)
            if next_file_size > LINUX_AUDIT_MAX_FILE_SIZE_BYTES:
                raise _validation_error(
                    "LINUX_AUDIT_FILE_TOO_LARGE"
                )

            next_request_size = request_size_bytes + len(chunk)
            if next_request_size > LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES:
                raise _validation_error(
                    "LINUX_AUDIT_REQUEST_TOO_LARGE"
                )

            if b"\x00" in chunk:
                raise _validation_error(
                    "UNSUPPORTED_LINUX_AUDIT_INPUT"
                )

            staged_file.write(chunk)
            digest.update(chunk)
            file_size_bytes = next_file_size
            request_size_bytes = next_request_size

            if not prefix_decoded:
                prefix_remaining = _ARCHIVE_PREFIX_SIZE - len(prefix)
                prefix.extend(chunk[:prefix_remaining])
                remaining_chunk = chunk[prefix_remaining:]

                if _has_unsupported_signature(prefix):
                    raise _validation_error(
                        "UNSUPPORTED_LINUX_AUDIT_INPUT"
                    )

                if len(prefix) == _ARCHIVE_PREFIX_SIZE:
                    decoded = _decode_utf8(
                        decoder,
                        bytes(prefix),
                        final=False,
                    )
                    has_non_whitespace = (
                        has_non_whitespace
                        or any(not char.isspace() for char in decoded)
                    )
                    prefix_decoded = True

                    if remaining_chunk:
                        decoded = _decode_utf8(
                            decoder,
                            remaining_chunk,
                            final=False,
                        )
                        has_non_whitespace = (
                            has_non_whitespace
                            or any(
                                not char.isspace()
                                for char in decoded
                            )
                        )
                continue

            decoded = _decode_utf8(
                decoder,
                chunk,
                final=False,
            )
            has_non_whitespace = (
                has_non_whitespace
                or any(not char.isspace() for char in decoded)
            )

        if file_size_bytes == 0:
            raise _validation_error("EMPTY_LINUX_AUDIT_FILE")

        if not prefix_decoded:
            if _has_unsupported_signature(prefix):
                raise _validation_error(
                    "UNSUPPORTED_LINUX_AUDIT_INPUT"
                )
            decoded = _decode_utf8(
                decoder,
                bytes(prefix),
                final=True,
            )
        else:
            decoded = _decode_utf8(decoder, b"", final=True)

        has_non_whitespace = (
            has_non_whitespace
            or any(not char.isspace() for char in decoded)
        )

        if not has_non_whitespace:
            raise _validation_error("EMPTY_LINUX_AUDIT_FILE")

    content_identity = (file_size_bytes, digest.digest())
    if content_identity in seen_content:
        raise _validation_error("DUPLICATE_LINUX_AUDIT_FILE")
    seen_content.add(content_identity)

    return (
        StagedLinuxAuditInput(
            path=path,
            source_instance=f"api-linux-audit-{index}",
            size_bytes=file_size_bytes,
        ),
        request_size_bytes,
    )


@asynccontextmanager
async def stage_linux_audit_uploads(
    files: tuple[UploadFile, ...],
) -> AsyncIterator[tuple[StagedLinuxAuditInput, ...]]:
    _validate_upload_container(files)
    temporary_directory = tempfile.TemporaryDirectory(
        prefix="linux-audit-api-"
    )

    try:
        directory = Path(temporary_directory.name)
        staged_inputs = []
        request_size_bytes = 0
        seen_content: set[tuple[int, bytes]] = set()

        for index, upload in enumerate(files, start=1):
            staged_input, request_size_bytes = await _stage_upload(
                upload,
                index=index,
                directory=directory,
                request_size_bytes=request_size_bytes,
                seen_content=seen_content,
            )
            staged_inputs.append(staged_input)

        yield tuple(staged_inputs)
    finally:
        try:
            temporary_directory.cleanup()
        except OSError:
            raise RuntimeError(
                "Linux Audit upload cleanup failed."
            ) from None
