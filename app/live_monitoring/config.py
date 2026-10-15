"""Closed local configuration and descriptor-based regular-file opening."""

from dataclasses import dataclass, field
import errno
import json
import os
from pathlib import Path
import stat
import sys


CONFIG_MAX_BYTES = 4096
ROLES = frozenset(("application", "ssh", "access"))


_MESSAGES = {
    "INVALID_CONFIG": "모니터링 설정 형식을 확인하십시오.",
    "CONFIG_TOO_LARGE": "모니터링 설정 파일이 너무 큽니다.",
    "DUPLICATE_JSON_KEY": "모니터링 설정에 중복된 항목이 있습니다.",
    "UNSUPPORTED_SCHEMA": "지원하는 설정 버전을 사용하십시오.",
    "SOURCE_DISABLED": "비활성화된 로그 설정은 시작할 수 없습니다.",
    "DEFAULT_CONFIG_MISSING": "기본 설정이 없습니다. 설정 마법사를 실행하십시오.",
    "DEFAULT_CONFIG_UNSAFE_PARENT": "기본 설정 디렉터리 권한을 확인하십시오.",
    "DEFAULT_CONFIG_PERMISSION": "기본 설정의 소유자와 권한을 확인하십시오.",
    "DEFAULT_CONFIG_SYMLINK": "기본 설정은 심볼릭 링크일 수 없습니다.",
    "DEFAULT_CONFIG_TYPE": "기본 설정은 일반 파일이어야 합니다.",
    "DEFAULT_CONFIG_TOO_LARGE": "기본 설정 크기를 확인하십시오.",
    "DEFAULT_CONFIG_MALFORMED": "기본 설정이 손상되었습니다. 수동으로 확인하십시오.",
    "DEFAULT_CONFIG_SCHEMA": "기본 설정은 지원하는 v2 형식이어야 합니다.",
    "DEFAULT_CONFIG_CHANGED": "검사 중 기본 설정이 변경되었습니다. 다시 시도하십시오.",
    "DEFAULT_CONFIG_DELETE_FAILED": "기본 설정을 삭제하지 못했습니다. 권한을 확인하십시오.",
    "DEFAULT_CONFIG_POST_DELETE_FAILED": "삭제 결과를 확인하지 못했습니다. 수동으로 확인하십시오.",
    "UNSUPPORTED_ROLE": "지원하는 로그 역할을 선택하십시오.",
    "UNSUPPORTED_START_POLICY": "FROM_END 시작 정책을 사용하십시오.",
    "NON_ABSOLUTE_PATH": "절대 경로를 지정하십시오.",
    "CONFIG_UNAVAILABLE": "모니터링 설정 파일을 확인하십시오.",
    "SOURCE_UNAVAILABLE": "로그 파일의 접근 가능 여부를 확인하십시오.",
    "SYMLINK_REJECTED": "심볼릭 링크가 아닌 일반 파일을 선택하십시오.",
    "NON_REGULAR_SOURCE": "일반 로그 파일을 선택하십시오.",
    "PERMISSION_DENIED": "파일 읽기 권한을 확인하십시오.",
    "UNSAFE_PLATFORM": "이 플랫폼에서는 안전한 파일 열기를 지원하지 않습니다.",
    "INVALID_UTF8": "UTF-8 텍스트 로그를 사용하십시오.",
    "BINARY_INPUT": "바이너리가 아닌 텍스트 로그를 사용하십시오.",
    "LINE_TOO_LONG": "줄 길이가 짧은 로그를 사용하십시오.",
    "PARTIAL_BUFFER_EXCEEDED": "완성되지 않은 긴 줄을 줄이십시오.",
    "QUEUE_OVERFLOW": "대기 중인 기록을 처리한 뒤 세션을 다시 시작하십시오.",
    "SOURCE_TRUNCATED": "파일이 잘렸습니다. 세션을 다시 시작하십시오.",
    "SOURCE_REPLACED": "파일이 교체되었습니다. 세션을 다시 시작하십시오.",
    "INVALID_STATE_TRANSITION": "세션 상태를 확인하십시오.",
    "POLL_AFTER_CLOSE": "닫힌 세션을 다시 열어 시작하십시오.",
    "INTERNAL_FAILURE": "모니터링을 중단하고 다시 시작하십시오.",
    "COUNTER_LIMIT": "세션을 종료하고 다시 시작하십시오.",
    "INVALID_LEASE_LIMIT": "한 번에 처리할 기록 한도를 확인하십시오.",
    "LEASE_LIMIT_TOO_SMALL": "첫 대기 기록을 담을 수 있는 byte 한도를 지정하십시오.",
    "LEASE_UNAVAILABLE": "처리할 대기 기록이 없습니다.",
    "ACTIVE_LEASE_EXISTS": "현재 처리 중인 기록을 먼저 완료하십시오.",
    "FOREIGN_LEASE": "다른 세션의 처리 권한은 사용할 수 없습니다.",
    "STALE_LEASE": "만료된 처리 권한은 사용할 수 없습니다.",
    "FORGED_LEASE": "처리 권한 식별자를 확인하십시오.",
    "LEASE_INVARIANT_MISMATCH": "처리 권한의 기록 구성을 확인하십시오.",
    "ACK_AFTER_ACK": "이미 완료된 처리 권한입니다.",
    "RELEASE_AFTER_RELEASE": "이미 반환된 처리 권한입니다.",
    "ACK_AFTER_RELEASE": "반환된 처리 권한은 완료할 수 없습니다.",
    "RELEASE_AFTER_ACK": "완료된 처리 권한은 반환할 수 없습니다.",
    "OPERATION_AFTER_CLOSE": "닫힌 세션의 처리 권한은 사용할 수 없습니다.",
    "INTERNAL_OWNERSHIP_FAILURE": "기록 처리를 중단하고 세션을 다시 시작하십시오.",
    "CLOSE_INVALID_OWNERSHIP": "미완료 기록 상태를 확인한 뒤 세션을 다시 시작하십시오.",
}


class LiveMonitorError(ValueError):
    """Fixed-code error without source values, OS paths, or exception text."""

    def __init__(self, code: str):
        if code not in _MESSAGES:
            code = "INTERNAL_FAILURE"
        self.code = code
        super().__init__(f"{code}: {_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"LiveMonitorError(code={self.code!r})"


@dataclass(frozen=True, slots=True)
class LiveMonitorConfig:
    role: str
    path: Path = field(repr=False)
    schema_version: str = "1"
    start_policy: str = "FROM_END"

    def __post_init__(self) -> None:
        if type(self.role) is not str or self.role not in ROLES:
            raise LiveMonitorError("UNSUPPORTED_ROLE")
        if not isinstance(self.path, Path):
            raise LiveMonitorError("NON_ABSOLUTE_PATH")
        _validate_absolute_path(os.fspath(self.path))
        if type(self.schema_version) is not str or self.schema_version != "1":
            raise LiveMonitorError("UNSUPPORTED_SCHEMA")
        if type(self.start_policy) is not str or self.start_policy != "FROM_END":
            raise LiveMonitorError("UNSUPPORTED_START_POLICY")


@dataclass(frozen=True, slots=True)
class LiveMonitorConfigV2:
    """Trusted v2 on-disk contract; source_path never belongs in a public repr."""

    source_path: Path = field(repr=False)
    schema_version: str = "2"
    source_id: str = "SOURCE-000001"
    source_role: str = "application"
    display_alias: str = "애플리케이션 로그 1"
    enabled: bool = True
    start_position: str = "FROM_END"
    parser_timezone: str = "Asia/Seoul"
    checkpoint_policy: str = "DISABLED"
    rotation_policy: str = "FAIL_CLOSED"

    def __post_init__(self) -> None:
        if not isinstance(self.source_path, Path):
            raise LiveMonitorError("NON_ABSOLUTE_PATH")
        _validate_absolute_path(os.fspath(self.source_path))
        if type(self.schema_version) is not str or self.schema_version != "2":
            raise LiveMonitorError("UNSUPPORTED_SCHEMA")
        if (type(self.source_id) is not str or self.source_id != "SOURCE-000001"
            or type(self.source_role) is not str or self.source_role != "application"
            or type(self.display_alias) is not str or self.display_alias != "애플리케이션 로그 1"
            or type(self.enabled) is not bool
            or type(self.start_position) is not str or self.start_position != "FROM_END"
            or type(self.parser_timezone) is not str or self.parser_timezone != "Asia/Seoul"
            or type(self.checkpoint_policy) is not str
            or self.checkpoint_policy not in ("DISABLED", "BOUNDED_REPLAY_V1")
            or type(self.rotation_policy) is not str or self.rotation_policy != "FAIL_CLOSED"):
            raise LiveMonitorError("INVALID_CONFIG")

    def as_document(self) -> dict[str, object]:
        return {
            "schema_version": "2",
            "sources": [{
                "source_id": self.source_id,
                "source_role": self.source_role,
                "source_path": os.fspath(self.source_path),
                "display_alias": self.display_alias,
                "enabled": self.enabled,
                "start_position": self.start_position,
                "parser_timezone": self.parser_timezone,
                "checkpoint_policy": self.checkpoint_policy,
                "rotation_policy": self.rotation_policy,
            }],
        }

    def to_runtime(self) -> LiveMonitorConfig:
        if not self.enabled:
            raise LiveMonitorError("SOURCE_DISABLED")
        return LiveMonitorConfig("application", self.source_path)


def _validate_absolute_path(value: str) -> None:
    if (
        type(value) is not str
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or any(part in ("", ".", "..") for part in value[1:].split("/"))
    ):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")


def resolve_default_monitor_config_path(*, platform: str | None = None,
                                        home: Path | None = None,
                                        xdg_config_home: str | None = None) -> Path:
    """Resolve one conventional local path; never search or expand input text."""
    system = sys.platform if platform is None else platform
    user_home = Path.home() if home is None else home
    if not isinstance(user_home, Path):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    _validate_absolute_path(os.fspath(user_home))
    if system == "darwin":
        base = user_home / "Library/Application Support"
    elif system.startswith("linux"):
        xdg = os.environ.get("XDG_CONFIG_HOME") if xdg_config_home is None else xdg_config_home
        if xdg:
            if type(xdg) is not str:
                raise LiveMonitorError("NON_ABSOLUTE_PATH")
            _validate_absolute_path(xdg)
            base = Path(xdg)
        else:
            base = user_home / ".config"
    else:
        raise LiveMonitorError("UNSAFE_PLATFORM")
    return base / "ai-security-log-analyzer/monitoring.json"


def _open_regular(path: Path, *, config_file: bool = False) -> tuple[int, os.stat_result]:
    """Walk an absolute path without following parent or final symlinks."""
    if not all(hasattr(os, name) for name in (
        "O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC",
    )):
        raise LiveMonitorError("UNSAFE_PLATFORM")
    _validate_absolute_path(os.fspath(path))
    parts = os.fspath(path)[1:].split("/")
    kind = "CONFIG_UNAVAILABLE" if config_file else "SOURCE_UNAVAILABLE"
    root_fd = -1
    file_fd = -1
    try:
        root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in parts[:-1]:
            metadata = os.stat(component, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise LiveMonitorError("SYMLINK_REJECTED")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            os.close(root_fd)
            root_fd = next_fd
        metadata = os.stat(parts[-1], dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise LiveMonitorError("SYMLINK_REJECTED")
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise LiveMonitorError("INVALID_CONFIG" if config_file else "NON_REGULAR_SOURCE")
        if config_file:
            if opened.st_uid != os.geteuid() or opened.st_mode & 0o077:
                raise LiveMonitorError("PERMISSION_DENIED")
        elif opened.st_mode & 0o022:
            raise LiveMonitorError("PERMISSION_DENIED")
        result = file_fd, opened
        file_fd = -1
        return result
    except LiveMonitorError:
        raise
    except PermissionError:
        raise LiveMonitorError("PERMISSION_DENIED") from None
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise LiveMonitorError("SYMLINK_REJECTED") from None
        if error.errno in (errno.EACCES, errno.EPERM):
            raise LiveMonitorError("PERMISSION_DENIED") from None
        raise LiveMonitorError(kind) from None
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LiveMonitorError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise LiveMonitorError("INVALID_CONFIG")


def _read_config_document_from_fd(descriptor: int, metadata: os.stat_result) -> object:
    """Decode an already validated descriptor without reopening its pathname."""
    try:
        if metadata.st_size > CONFIG_MAX_BYTES:
            raise LiveMonitorError("CONFIG_TOO_LARGE")
        data = os.pread(descriptor, CONFIG_MAX_BYTES + 1, 0)
        if len(data) > CONFIG_MAX_BYTES:
            raise LiveMonitorError("CONFIG_TOO_LARGE")
    except OSError:
        raise LiveMonitorError("CONFIG_UNAVAILABLE") from None
    try:
        decoded = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise LiveMonitorError("INVALID_UTF8") from None
    try:
        parsed = json.loads(
            decoded, object_pairs_hook=_unique_keys, parse_constant=_reject_constant,
        )
    except LiveMonitorError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise LiveMonitorError("INVALID_CONFIG") from None
    return parsed


def _read_config_document(path: Path) -> object:
    if not isinstance(path, Path):
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    descriptor, metadata = _open_regular(path, config_file=True)
    try:
        return _read_config_document_from_fd(descriptor, metadata)
    finally:
        os.close(descriptor)


def _parse_v2(parsed: object) -> LiveMonitorConfigV2:
    if type(parsed) is not dict or set(parsed) != {"schema_version", "sources"}:
        raise LiveMonitorError("INVALID_CONFIG")
    if type(parsed["schema_version"]) is not str or parsed["schema_version"] != "2":
        raise LiveMonitorError("UNSUPPORTED_SCHEMA")
    sources = parsed["sources"]
    if type(sources) is not list or len(sources) != 1 or type(sources[0]) is not dict:
        raise LiveMonitorError("INVALID_CONFIG")
    source = sources[0]
    if set(source) != {"source_id", "source_role", "source_path", "display_alias", "enabled",
                       "start_position", "parser_timezone", "checkpoint_policy", "rotation_policy"}:
        raise LiveMonitorError("INVALID_CONFIG")
    if type(source["source_path"]) is not str:
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    return LiveMonitorConfigV2(source_path=Path(source["source_path"]),
                               schema_version=parsed["schema_version"],
                               source_id=source["source_id"], source_role=source["source_role"],
                               display_alias=source["display_alias"], enabled=source["enabled"],
                               start_position=source["start_position"],
                               parser_timezone=source["parser_timezone"],
                               checkpoint_policy=source["checkpoint_policy"],
                               rotation_policy=source["rotation_policy"])


def load_live_monitor_setup_config(path: Path) -> LiveMonitorConfigV2:
    return _parse_v2(_read_config_document(path))


def load_live_monitor_config(path: Path) -> LiveMonitorConfig:
    parsed = _read_config_document(path)
    if type(parsed) is not dict:
        raise LiveMonitorError("INVALID_CONFIG")
    if "schema_version" in parsed and (type(parsed["schema_version"]) is not str
                                        or parsed["schema_version"] not in ("1", "2")):
        raise LiveMonitorError("UNSUPPORTED_SCHEMA")
    if parsed.get("schema_version") == "2":
        if set(parsed) == {"schema_version", "source", "start_policy"}:
            raise LiveMonitorError("UNSUPPORTED_SCHEMA")
        return _parse_v2(parsed).to_runtime()
    if set(parsed) != {"schema_version", "source", "start_policy"}:
        raise LiveMonitorError("INVALID_CONFIG")
    source = parsed["source"]
    if type(source) is not dict or set(source) != {"role", "path"}:
        raise LiveMonitorError("INVALID_CONFIG")
    if type(source["path"]) is not str:
        raise LiveMonitorError("NON_ABSOLUTE_PATH")
    _validate_absolute_path(source["path"])
    return LiveMonitorConfig(
        role=source["role"], path=Path(source["path"]),
        schema_version=parsed["schema_version"], start_policy=parsed["start_policy"],
    )
