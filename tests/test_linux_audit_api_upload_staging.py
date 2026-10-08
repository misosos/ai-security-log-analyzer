import asyncio
from io import BytesIO
import inspect
from pathlib import Path

import pytest
from starlette.datastructures import Headers, UploadFile

import app.api as api_module
import app.api_uploads as uploads


PRIVACY_CANARY = "SYNTHETIC_LINUX_AUDIT_UPLOAD_SECRET_DO_NOT_EXPOSE"


class TrackingUploadFile(UploadFile):

    def __init__(
        self,
        content: bytes,
        *,
        filename: str = "input.audit",
        content_type: str = "text/plain",
    ):
        super().__init__(
            BytesIO(content),
            filename=filename,
            headers=Headers({"content-type": content_type}),
            size=len(content),
        )
        self.read_sizes = []

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return await super().read(size)


class CancellingUploadFile(TrackingUploadFile):

    async def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        raise asyncio.CancelledError


def make_upload(
    content: bytes,
    *,
    filename: str = "input.audit",
    content_type: str = "text/plain",
) -> TrackingUploadFile:
    return TrackingUploadFile(
        content,
        filename=filename,
        content_type=content_type,
    )


async def snapshot_staged(files):
    async with uploads.stage_linux_audit_uploads(files) as staged:
        snapshot = tuple(
            {
                "path": item.path,
                "source_instance": item.source_instance,
                "size_bytes": item.size_bytes,
                "content": item.path.read_bytes(),
                "mode": item.path.stat().st_mode & 0o777,
            }
            for item in staged
        )
        directories = tuple(item.path.parent for item in staged)
        assert all(item.path.exists() for item in staged)
        return snapshot, directories


def stage_snapshot(files):
    return asyncio.run(snapshot_staged(files))


def assert_validation_error(
    files,
    *,
    code,
    status_code,
    message,
):
    with pytest.raises(
        uploads.LinuxAuditUploadValidationError
    ) as caught:
        stage_snapshot(files)

    error = caught.value
    assert error.code == code
    assert error.status_code == status_code
    assert error.message == message
    assert str(error) == message
    assert set(vars(error)) == {"code", "status_code", "message"}
    return error


def track_request_directories(monkeypatch, tmp_path):
    original = uploads.tempfile.TemporaryDirectory
    directories = []

    def tracked_temporary_directory(*args, **kwargs):
        kwargs["dir"] = tmp_path
        temporary_directory = original(*args, **kwargs)
        directories.append(Path(temporary_directory.name))
        return temporary_directory

    monkeypatch.setattr(
        uploads.tempfile,
        "TemporaryDirectory",
        tracked_temporary_directory,
    )
    return directories


def set_small_limits(
    monkeypatch,
    *,
    file_size=16,
    request_size=32,
    chunk_size=4,
):
    monkeypatch.setattr(
        uploads,
        "LINUX_AUDIT_MAX_FILE_SIZE_BYTES",
        file_size,
    )
    monkeypatch.setattr(
        uploads,
        "LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES",
        request_size,
    )
    monkeypatch.setattr(
        uploads,
        "LINUX_AUDIT_UPLOAD_CHUNK_SIZE_BYTES",
        chunk_size,
    )


def test_v1_limits_are_explicit_operational_constants():
    assert uploads.LINUX_AUDIT_MAX_FILE_COUNT == 4
    assert uploads.LINUX_AUDIT_MAX_FILE_SIZE_BYTES == 10 * 1024 * 1024
    assert uploads.LINUX_AUDIT_MAX_REQUEST_SIZE_BYTES == 20 * 1024 * 1024
    assert uploads.LINUX_AUDIT_UPLOAD_CHUNK_SIZE_BYTES == 64 * 1024


def test_upload_container_contract_and_count_errors_happen_before_read():
    assert_validation_error(
        (),
        code="MISSING_LINUX_AUDIT_FILES",
        status_code=422,
        message="At least one Linux Audit file is required.",
    )

    with pytest.raises(TypeError, match="provided as a tuple"):
        stage_snapshot([])

    with pytest.raises(TypeError, match="UploadFile instances"):
        stage_snapshot((object(),))

    files = tuple(make_upload(f"line-{index}".encode()) for index in range(5))
    assert_validation_error(
        files,
        code="LINUX_AUDIT_FILE_COUNT_EXCEEDED",
        status_code=413,
        message="Linux Audit file count limit exceeded.",
    )
    assert all(upload.read_sizes == [] for upload in files)


def test_one_and_four_valid_uploads_preserve_order_and_source_instances():
    one_snapshot, one_directories = stage_snapshot(
        (make_upload(b"first"),)
    )
    assert one_snapshot[0]["content"] == b"first"
    assert one_snapshot[0]["source_instance"] == "api-linux-audit-1"
    assert one_snapshot[0]["size_bytes"] == 5
    assert one_snapshot[0]["mode"] == 0o600
    assert all(not directory.exists() for directory in one_directories)

    contents = (b"one", b"two", b"three", b"four")
    four_snapshot, four_directories = stage_snapshot(
        tuple(make_upload(content) for content in contents)
    )
    assert tuple(item["content"] for item in four_snapshot) == contents
    assert tuple(
        item["source_instance"] for item in four_snapshot
    ) == tuple(
        f"api-linux-audit-{index}" for index in range(1, 5)
    )
    assert all(not directory.exists() for directory in four_directories)


def test_filename_content_type_and_extension_are_not_trusted_or_mutated():
    filename = f"../../{PRIVACY_CANARY}/악성\x00.zip"
    content_type = f"application/{PRIVACY_CANARY}"
    upload = make_upload(
        b"plain Linux Audit candidate text",
        filename=filename,
        content_type=content_type,
    )
    original_metadata = (
        upload.filename,
        upload.content_type,
        upload.headers,
        upload.size,
    )

    snapshot, directories = stage_snapshot((upload,))

    staged_path = snapshot[0]["path"]
    assert staged_path.name == "input-1.audit"
    assert PRIVACY_CANARY not in str(staged_path)
    assert filename not in str(staged_path)
    assert snapshot[0]["content"] == b"plain Linux Audit candidate text"
    assert (
        upload.filename,
        upload.content_type,
        upload.headers,
        upload.size,
    ) == original_metadata
    assert all(not directory.exists() for directory in directories)


def test_reads_only_with_fixed_chunk_size_and_never_joins_full_content(
    monkeypatch,
):
    set_small_limits(
        monkeypatch,
        file_size=64,
        request_size=64,
        chunk_size=3,
    )
    content = b"0123456789abcdef"
    upload = make_upload(content)

    snapshot, _ = stage_snapshot((upload,))

    assert snapshot[0]["content"] == content
    assert upload.read_sizes
    assert set(upload.read_sizes) == {3}
    assert -1 not in upload.read_sizes
    source = inspect.getsource(uploads._stage_upload)
    assert "b\"\".join" not in source
    assert "BytesIO" not in source


def test_file_size_boundary_and_cleanup(monkeypatch, tmp_path):
    set_small_limits(
        monkeypatch,
        file_size=8,
        request_size=20,
        chunk_size=3,
    )
    directories = track_request_directories(monkeypatch, tmp_path)

    snapshot, _ = stage_snapshot((make_upload(b"12345678"),))
    assert snapshot[0]["size_bytes"] == 8

    error = assert_validation_error(
        (make_upload(b"123456789"),),
        code="LINUX_AUDIT_FILE_TOO_LARGE",
        status_code=413,
        message="A Linux Audit file exceeds the size limit.",
    )
    assert "123456789" not in repr(error)
    assert all(not directory.exists() for directory in directories)


def test_request_size_boundary_and_cleanup(monkeypatch, tmp_path):
    set_small_limits(
        monkeypatch,
        file_size=10,
        request_size=10,
        chunk_size=2,
    )
    directories = track_request_directories(monkeypatch, tmp_path)

    snapshot, _ = stage_snapshot(
        (make_upload(b"12345"), make_upload(b"67890"))
    )
    assert sum(item["size_bytes"] for item in snapshot) == 10

    assert_validation_error(
        (make_upload(b"12345"), make_upload(b"678901")),
        code="LINUX_AUDIT_REQUEST_TOO_LARGE",
        status_code=413,
        message="Linux Audit upload size limit exceeded.",
    )
    assert all(not directory.exists() for directory in directories)


@pytest.mark.parametrize("content", [b"", b" \t\r\n"])
def test_empty_and_whitespace_only_inputs_are_rejected(content):
    assert_validation_error(
        (make_upload(content),),
        code="EMPTY_LINUX_AUDIT_FILE",
        status_code=400,
        message=(
            "A Linux Audit file is empty or contains only whitespace."
        ),
    )


def test_incremental_utf8_accepts_multibyte_boundary(monkeypatch):
    set_small_limits(
        monkeypatch,
        file_size=32,
        request_size=32,
        chunk_size=2,
    )
    content = "가나다\n".encode("utf-8")

    snapshot, _ = stage_snapshot((make_upload(content),))

    assert snapshot[0]["content"] == content


@pytest.mark.parametrize(
    "content",
    [
        b"valid\xfftext",
        b"valid\xe2\x82",
    ],
)
def test_invalid_or_incomplete_utf8_is_rejected_without_details(content):
    error = assert_validation_error(
        (make_upload(content, filename=PRIVACY_CANARY),),
        code="INVALID_LINUX_AUDIT_ENCODING",
        status_code=400,
        message="Linux Audit input must be valid UTF-8.",
    )
    assert PRIVACY_CANARY not in repr(error)
    assert content.hex() not in repr(error)


@pytest.mark.parametrize(
    "content",
    [
        b"plain\x00text",
        b"PK\x03\x04zip",
        b"PK\x05\x06empty-zip",
        b"PK\x07\x08spanned-zip",
        b"\x1f\x8bgzip",
        b"BZh91AY&SYbzip2",
        b"\xfd7zXZ\x00xz",
        b"a" * 257 + b"ustar" + b"tar",
    ],
)
def test_binary_and_common_archive_signatures_are_rejected(
    content,
    monkeypatch,
):
    monkeypatch.setattr(
        uploads,
        "LINUX_AUDIT_UPLOAD_CHUNK_SIZE_BYTES",
        1,
    )
    assert_validation_error(
        (
            make_upload(
                content,
                filename="looks-safe.log",
                content_type="text/plain",
            ),
        ),
        code="UNSUPPORTED_LINUX_AUDIT_INPUT",
        status_code=415,
        message="Linux Audit input format is not supported.",
    )


def test_duplicate_is_content_based_and_cleans_entire_request(
    monkeypatch,
    tmp_path,
):
    directories = track_request_directories(monkeypatch, tmp_path)
    content = PRIVACY_CANARY.encode()

    error = assert_validation_error(
        (
            make_upload(content, filename="first.log"),
            make_upload(content, filename="different-name.txt"),
        ),
        code="DUPLICATE_LINUX_AUDIT_FILE",
        status_code=409,
        message="Duplicate Linux Audit input is not allowed.",
    )

    assert PRIVACY_CANARY not in repr(error)
    assert PRIVACY_CANARY not in str(error)
    assert all(not directory.exists() for directory in directories)


def test_same_filename_with_different_content_is_not_duplicate():
    snapshot, _ = stage_snapshot(
        (
            make_upload(b"first content", filename="same.log"),
            make_upload(b"second content", filename="same.log"),
        )
    )
    assert tuple(item["content"] for item in snapshot) == (
        b"first content",
        b"second content",
    )


def test_caller_exception_and_cancellation_cleanup_owned_directory(
    monkeypatch,
    tmp_path,
):
    tracked_directories = track_request_directories(
        monkeypatch,
        tmp_path,
    )
    caller_directories = []

    async def fail_in_body():
        async with uploads.stage_linux_audit_uploads(
            (make_upload(b"caller failure"),)
        ) as staged:
            caller_directories.append(staged[0].path.parent)
            raise LookupError("synthetic caller failure")

    with pytest.raises(LookupError, match="synthetic caller failure"):
        asyncio.run(fail_in_body())
    assert all(not path.exists() for path in caller_directories)

    cancelled_directories = []

    async def cancel_in_body():
        async with uploads.stage_linux_audit_uploads(
            (make_upload(b"cancelled request"),)
        ) as staged:
            cancelled_directories.append(staged[0].path.parent)
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancel_in_body())
    assert all(not path.exists() for path in cancelled_directories)

    with pytest.raises(asyncio.CancelledError):
        stage_snapshot((CancellingUploadFile(b"partial input"),))
    assert all(
        not directory.exists() for directory in tracked_directories
    )


def test_repeated_and_concurrent_requests_are_deterministic_and_isolated():
    first, _ = stage_snapshot((make_upload(b"repeatable"),))
    second, _ = stage_snapshot((make_upload(b"repeatable"),))
    assert first[0]["source_instance"] == second[0]["source_instance"]
    assert first[0]["size_bytes"] == second[0]["size_bytes"]

    directories = []
    both_staged = asyncio.Event()

    async def worker(content):
        async with uploads.stage_linux_audit_uploads(
            (make_upload(content),)
        ) as staged:
            directory = staged[0].path.parent
            directories.append(directory)
            if len(directories) == 2:
                both_staged.set()
            await both_staged.wait()
            assert directory.exists()

    async def run_concurrently():
        await asyncio.gather(
            worker(b"concurrent one"),
            worker(b"concurrent two"),
        )

    asyncio.run(run_concurrently())
    assert len(set(directories)) == 2
    assert all(not directory.exists() for directory in directories)


def test_all_malformed_text_is_staged_for_later_parser_decision():
    content = b"this is not a Linux Audit record\n"

    snapshot, _ = stage_snapshot((make_upload(content),))

    assert snapshot[0]["content"] == content


def test_staged_contract_has_only_bounded_internal_fields():
    snapshot, _ = stage_snapshot(
        (
            make_upload(
                PRIVACY_CANARY.encode(),
                filename=PRIVACY_CANARY,
                content_type=f"application/{PRIVACY_CANARY}",
            ),
        )
    )
    item = snapshot[0]

    assert set(item) == {
        "path",
        "source_instance",
        "size_bytes",
        "content",
        "mode",
    }
    staged_fields = {
        field.name
        for field in uploads.StagedLinuxAuditInput.__dataclass_fields__.values()
    }
    assert staged_fields == {"path", "source_instance", "size_bytes"}
    assert PRIVACY_CANARY not in repr(
        uploads.StagedLinuxAuditInput(
            path=item["path"],
            source_instance=item["source_instance"],
            size_bytes=item["size_bytes"],
        )
    )


def test_existing_api_routes_and_openapi_are_not_changed():
    route_paths = {
        route.path
        for route in api_module.app.routes
        if route.path.startswith("/api/")
    }
    openapi_paths = {
        path
        for path in api_module.app.openapi()["paths"]
        if path.startswith("/api/")
    }

    assert route_paths == {
        "/api/health", "/api/analyze", "/api/v1/investigations/sample"
    }
    assert openapi_paths == route_paths
    assert callable(api_module.stage_linux_audit_uploads)
    assert not any(
        "LinuxAudit" in name
        for name in api_module.app.openapi()
        .get("components", {})
        .get("schemas", {})
    )
