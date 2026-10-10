import base64
from dataclasses import FrozenInstanceError, fields
import os
from pathlib import Path
import socket
import tempfile

import pytest
from pydantic import SecretStr

import app.api as api_module
import app.bootstrap.linux_audit_api as bootstrap_module
from app.bootstrap.linux_audit_api import (
    LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES,
    LinuxAuditApiSecurityBootstrapConfig,
    LinuxAuditApiSecurityBootstrapError,
    load_linux_audit_api_security_config,
)
from app.security.linux_audit_api import LinuxAuditApiSecurityConfig


TOKEN = base64.urlsafe_b64encode(bytes(range(32))).rstrip(
    b"="
).decode("ascii")
TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
TOKEN_FINAL_INDEX = TOKEN_ALPHABET.index(TOKEN[-1])
NONCANONICAL_TOKEN = TOKEN[:-1] + TOKEN_ALPHABET[TOKEN_FINAL_INDEX ^ 1]
PRINCIPAL = "bootstrap-operator"


def write_secret(
    tmp_path: Path,
    content: bytes = TOKEN.encode("ascii"),
    *,
    mode: int = 0o400,
) -> Path:
    path = tmp_path / "operator-credential"
    path.write_bytes(content)
    path.chmod(mode)
    return path


def bootstrap_config(path: Path, **changes):
    values = {
        "secret_file": path,
        "principal_id": PRINCIPAL,
        "max_concurrent_analyses": 1,
    }
    values.update(changes)
    return LinuxAuditApiSecurityBootstrapConfig(**values)


def load(path: Path, **changes) -> LinuxAuditApiSecurityConfig:
    return load_linux_audit_api_security_config(
        bootstrap_config(path, **changes)
    )


def assert_error(call, expected_code: str):
    with pytest.raises(LinuxAuditApiSecurityBootstrapError) as caught:
        call()
    error = caught.value
    assert error.code == expected_code
    assert error.message == str(error)
    assert error.message.endswith(".")
    return error


def test_bootstrap_config_is_frozen_exact_and_has_bounded_repr(tmp_path):
    path = tmp_path / "private-credential-name"
    config = bootstrap_config(path)

    assert type(config) is LinuxAuditApiSecurityBootstrapConfig
    assert tuple(item.name for item in fields(config)) == (
        "secret_file",
        "principal_id",
        "max_concurrent_analyses",
    )
    representation = repr(config)
    assert representation == "LinuxAuditApiSecurityBootstrapConfig()"
    assert str(path) not in representation
    assert path.name not in representation
    assert PRINCIPAL not in representation
    with pytest.raises(FrozenInstanceError):
        config.principal_id = "changed"


@pytest.mark.parametrize(
    ("mode", "suffix"),
    ((0o400, b""), (0o600, b"\n")),
)
def test_private_regular_secret_returns_existing_security_config(
    tmp_path,
    mode,
    suffix,
):
    path = write_secret(tmp_path, TOKEN.encode("ascii") + suffix, mode=mode)
    result = load(path, max_concurrent_analyses=4)

    assert type(result) is LinuxAuditApiSecurityConfig
    assert type(result.operator_token) is SecretStr
    assert result.operator_token.get_secret_value() == TOKEN
    assert result.principal_id == PRINCIPAL
    assert result.max_concurrent_analyses == 4
    assert TOKEN not in repr(result)
    assert str(path) not in repr(result)


def test_bootstrap_requires_exact_config_and_absolute_path(tmp_path):
    class BootstrapSubclass(LinuxAuditApiSecurityBootstrapConfig):
        pass

    path_type = type(Path())
    path_subclass = type(
        "SyntheticPathSubclass",
        (path_type,),
        {"__slots__": ()},
    )
    for invalid in (
        object(),
        BootstrapSubclass(tmp_path / "secret", PRINCIPAL, 1),
        LinuxAuditApiSecurityBootstrapConfig(
            Path("relative-secret"), PRINCIPAL, 1
        ),
        LinuxAuditApiSecurityBootstrapConfig(
            str(tmp_path / "secret"), PRINCIPAL, 1
        ),
        LinuxAuditApiSecurityBootstrapConfig(
            path_subclass(tmp_path / "secret"), PRINCIPAL, 1
        ),
    ):
        assert_error(
            lambda invalid=invalid: (
                load_linux_audit_api_security_config(invalid)
            ),
            "INVALID_LINUX_AUDIT_SECURITY_BOOTSTRAP_CONFIG",
        )


def test_missing_secret_is_bounded_and_path_free(tmp_path):
    path = tmp_path / "synthetic-private-secret-name"
    error = assert_error(
        lambda: load(path),
        "LINUX_AUDIT_SECURITY_SECRET_UNAVAILABLE",
    )

    for rendered in (str(error), repr(error)):
        assert str(path) not in rendered
        assert path.name not in rendered
        assert PRINCIPAL not in rendered


def test_directory_and_symlink_are_rejected_without_following(tmp_path):
    directory = tmp_path / "credential-directory"
    directory.mkdir(mode=0o700)
    target = write_secret(tmp_path)
    link = tmp_path / "credential-link"
    link.symlink_to(target)

    for path in (directory, link):
        assert_error(
            lambda path=path: load(path),
            "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE",
        )


def test_fifo_and_unix_socket_are_rejected_without_opening(tmp_path):
    fifo = tmp_path / "credential-fifo"
    os.mkfifo(fifo, 0o400)
    with tempfile.TemporaryDirectory(prefix="la-bootstrap-", dir="/tmp") as root:
        socket_path = Path(root) / "s"
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket.bind(str(socket_path))
        try:
            for path in (fifo, socket_path):
                assert_error(
                    lambda path=path: load(path),
                    "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE",
                )
        finally:
            unix_socket.close()


@pytest.mark.parametrize(
    "mode",
    (0o000, 0o100, 0o500, 0o440, 0o404, 0o640, 0o604),
)
def test_non_private_or_executable_modes_are_rejected(tmp_path, mode):
    path = write_secret(tmp_path, mode=mode)
    assert_error(
        lambda: load(path),
        "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE",
    )


@pytest.mark.parametrize(
    "content",
    (
        b"",
        b"   \t",
        b"\x00" + b"A" * 42,
        b" " + TOKEN.encode("ascii"),
        TOKEN.encode("ascii") + b" ",
        b"\t" + TOKEN.encode("ascii"),
        TOKEN.encode("ascii") + b"\t",
        TOKEN.encode("ascii") + b"\r\n",
        TOKEN.encode("ascii") + b"\n\n",
        TOKEN[:20].encode("ascii") + b"\n" + TOKEN[20:].encode("ascii"),
        b"short",
        TOKEN.encode("ascii") + b"=",
        b"!" + TOKEN[1:].encode("ascii"),
        NONCANONICAL_TOKEN.encode("ascii"),
    ),
)
def test_invalid_secret_content_is_rejected_with_fixed_format_error(
    tmp_path,
    content,
):
    path = write_secret(tmp_path, content)
    error = assert_error(
        lambda: load(path),
        "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT",
    )
    assert TOKEN not in str(error)
    assert str(path) not in repr(error)


def test_non_ascii_secret_has_distinct_bounded_encoding_error(tmp_path):
    path = write_secret(tmp_path, b"\xff" + b"A" * 42)
    assert_error(
        lambda: load(path),
        "INVALID_LINUX_AUDIT_SECURITY_SECRET_ENCODING",
    )


def test_oversized_secret_is_rejected_without_unbounded_read(
    tmp_path,
    monkeypatch,
):
    path = write_secret(
        tmp_path,
        b"A" * (LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES + 1),
    )
    read_sizes = []
    original_read = bootstrap_module.os.read

    def recording_read(descriptor, size):
        read_sizes.append(size)
        return original_read(descriptor, size)

    monkeypatch.setattr(bootstrap_module.os, "read", recording_read)
    assert_error(
        lambda: load(path),
        "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT",
    )
    assert read_sizes == []


def test_successful_read_is_explicitly_bounded(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    read_sizes = []
    original_read = bootstrap_module.os.read

    def recording_read(descriptor, size):
        read_sizes.append(size)
        assert 0 < size <= LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES + 1
        return original_read(descriptor, size)

    monkeypatch.setattr(bootstrap_module.os, "read", recording_read)
    load(path)
    assert read_sizes
    assert max(read_sizes) == LINUX_AUDIT_API_SECRET_MAX_FILE_SIZE_BYTES + 1


def test_pre_open_and_opened_identity_must_match_and_descriptor_closes(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    descriptors = []
    original_open = bootstrap_module.os.open

    def recording_open(path_value, flags):
        descriptor = original_open(path_value, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(bootstrap_module.os, "open", recording_open)
    monkeypatch.setattr(
        bootstrap_module,
        "_same_file_identity",
        lambda before, after: False,
    )
    assert_error(
        lambda: load(path),
        "UNSAFE_LINUX_AUDIT_SECURITY_SECRET_FILE",
    )
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_open_uses_nofollow_and_cloexec_when_available(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    observed_flags = []
    original_open = bootstrap_module.os.open

    def recording_open(path_value, flags):
        observed_flags.append(flags)
        return original_open(path_value, flags)

    monkeypatch.setattr(bootstrap_module.os, "open", recording_open)
    load(path)

    assert len(observed_flags) == 1
    assert observed_flags[0] & (os.O_WRONLY | os.O_RDWR) == os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        assert observed_flags[0] & os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        assert observed_flags[0] & os.O_NOFOLLOW


def test_unavailable_optional_flags_have_explicit_fallback(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    expected = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    monkeypatch.delattr(bootstrap_module.os, "O_CLOEXEC", raising=False)
    monkeypatch.delattr(bootstrap_module.os, "O_NOFOLLOW", raising=False)
    assert bootstrap_module._secret_open_flags() == expected
    result = load(path)
    assert result.principal_id == PRINCIPAL


@pytest.mark.parametrize(
    "content",
    (
        TOKEN.encode("ascii"),
        b"\xff" + b"A" * 42,
        b"short",
    ),
)
def test_descriptor_close_is_attempted_after_success_and_content_failure(
    tmp_path,
    monkeypatch,
    content,
):
    path = write_secret(tmp_path, content)
    opened = []
    closed = []
    original_open = bootstrap_module.os.open
    original_close = bootstrap_module.os.close

    def recording_open(path_value, flags):
        descriptor = original_open(path_value, flags)
        opened.append(descriptor)
        return descriptor

    def recording_close(descriptor):
        closed.append(descriptor)
        return original_close(descriptor)

    monkeypatch.setattr(bootstrap_module.os, "open", recording_open)
    monkeypatch.setattr(bootstrap_module.os, "close", recording_close)
    try:
        load(path)
    except LinuxAuditApiSecurityBootstrapError:
        pass
    assert opened == closed
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_read_failure_is_bounded_and_descriptor_closes(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    descriptor_seen = []
    original_open = bootstrap_module.os.open

    def recording_open(path_value, flags):
        descriptor = original_open(path_value, flags)
        descriptor_seen.append(descriptor)
        return descriptor

    def failing_read(descriptor, size):
        raise OSError("synthetic path and credential detail")

    monkeypatch.setattr(bootstrap_module.os, "open", recording_open)
    monkeypatch.setattr(bootstrap_module.os, "read", failing_read)
    error = assert_error(
        lambda: load(path),
        "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED",
    )
    assert "synthetic" not in str(error)
    with pytest.raises(OSError):
        os.fstat(descriptor_seen[0])


def test_close_failure_is_bounded_after_descriptor_is_closed(tmp_path, monkeypatch):
    path = write_secret(tmp_path)
    descriptor_seen = []
    original_close = bootstrap_module.os.close

    def closing_then_failing(descriptor):
        descriptor_seen.append(descriptor)
        original_close(descriptor)
        raise OSError("synthetic secret and path detail")

    monkeypatch.setattr(bootstrap_module.os, "close", closing_then_failing)
    error = assert_error(
        lambda: load(path),
        "LINUX_AUDIT_SECURITY_SECRET_READ_FAILED",
    )
    assert "synthetic" not in str(error)
    assert TOKEN not in repr(error)
    assert str(path) not in repr(error)
    with pytest.raises(OSError):
        os.fstat(descriptor_seen[0])


def test_validation_error_and_logs_do_not_disclose_input(tmp_path, caplog):
    path = write_secret(tmp_path)
    invalid_principal = "private principal value"
    error = assert_error(
        lambda: load(path, principal_id=invalid_principal),
        "INVALID_LINUX_AUDIT_SECURITY_SECRET_FORMAT",
    )
    combined = f"{str(error)} {repr(error)} {caplog.text}"
    assert TOKEN not in combined
    assert str(path) not in combined
    assert path.name not in combined
    assert invalid_principal not in combined
    assert caplog.records == []


def test_input_and_secret_file_are_not_mutated_and_calls_are_deterministic(
    tmp_path,
):
    path = write_secret(tmp_path, TOKEN.encode("ascii") + b"\n", mode=0o600)
    before_bytes = path.read_bytes()
    before_mode = path.stat().st_mode
    config = bootstrap_config(path)

    first = load_linux_audit_api_security_config(config)
    second = load_linux_audit_api_security_config(config)

    assert first == second
    assert config.secret_file is path
    assert path.read_bytes() == before_bytes
    assert path.stat().st_mode == before_mode


def test_explicit_path_ignores_environment_and_integration_stays_disabled(
    tmp_path,
    monkeypatch,
):
    path = write_secret(tmp_path)
    monkeypatch.setenv(
        "CREDENTIALS_DIRECTORY",
        str(tmp_path / "unrelated-environment-location"),
    )
    monkeypatch.setenv("LINUX_AUDIT_API_TOKEN", "unrelated-value")

    result = load(path)
    assert result.operator_token.get_secret_value() == TOKEN
    assert set(api_module.app.openapi()["paths"]) == {
        "/api/health",
        "/api/analyze",
        "/api/v1/investigations/sample",
        "/api/v1/investigations",
        "/api/v1/investigations/linux-audit",
    }
    assert "securitySchemes" not in api_module.app.openapi().get(
        "components", {}
    )
