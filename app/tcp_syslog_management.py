"""Private CLI management for the synthetic-only loopback TCP Syslog pilot."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
from typing import Callable, Iterator

from app.live_monitoring.config import resolve_default_monitor_config_path
from app.log_collection.runtime import TcpRuntimeConfig, TcpRuntimeError, TcpSyslogRuntime


SCHEMA_VERSION = "tcp-syslog-user-config/v1"
RUNTIME_PROFILE = "bounded-loopback-v1"
MIN_PORT = 49152
MAX_PORT = 65535
CONFIG_NAME = "tcp-syslog.json"
COLLECTOR_LOCK_NAME = ".collector-runtime.lock"
TCP_LOCK_NAME = ".tcp-syslog-runtime.lock"
CONFIG_MAX_BYTES = 4096
SAVE_APPROVAL = "TCP Syslog 설정 저장을 승인합니다"
DELETE_APPROVAL = "TCP Syslog 설정 삭제를 승인합니다"
REVEAL_APPROVAL = "로컬 TCP 연결 정보를 표시합니다"

class TcpManagementError(ValueError):
    """Stable CLI error without caller-provided values or paths."""

    _MESSAGES = {
        "INVALID_INPUT": "입력을 확인하십시오.",
        "UNSAFE_STORAGE": "전용 설정 저장소의 권한을 안전하게 확인할 수 없습니다.",
        "CONFIG_REVIEW": "설정을 안전하게 읽을 수 없습니다. 자동으로 초기화하지 않았습니다.",
        "CONFIG_EXISTS": "TCP 수집 설정이 이미 있습니다. 기존 설정은 변경하지 않았습니다.",
        "CONFIG_MISSING": "TCP 수집 설정이 없습니다.",
        "PORT_UNAVAILABLE": "선택한 포트를 지금 사용할 수 없습니다. 다른 높은 번호를 선택하십시오.",
        "COLLECTOR_BUSY": "다른 로그 수집이 실행 중입니다. 먼저 정상 종료하십시오.",
        "TCP_BUSY": "TCP 수집이 이미 실행 중입니다.",
        "RUNTIME_FAILED": "TCP 수집을 시작하거나 유지하지 못했습니다. 설정과 로컬 상태를 확인하십시오.",
        "DELETE_FAILED": "TCP 수집 설정을 삭제하지 못했습니다.",
        "NOT_RUNNING": "실행 중인 TCP 수집을 확인하지 못했습니다.",
    }

    def __init__(self, code: str):
        self.code = code if code in self._MESSAGES else "RUNTIME_FAILED"
        super().__init__(self._MESSAGES[self.code])

    def __repr__(self) -> str:
        return f"TcpManagementError({self.code})"


@dataclass(frozen=True, slots=True, repr=False)
class TcpUserConfig:
    schema_version: str
    source_role: str
    bind_family: str
    port: int
    runtime_profile: str

    def __post_init__(self) -> None:
        if (self.schema_version != SCHEMA_VERSION
                or self.source_role not in {"application", "ssh"}
                or self.bind_family not in {"ipv4", "ipv6"}
                or type(self.port) is not int or not MIN_PORT <= self.port <= MAX_PORT
                or self.runtime_profile != RUNTIME_PROFILE):
            raise TcpManagementError("CONFIG_REVIEW")

    def __repr__(self) -> str:
        return f"TcpUserConfig(source_role={self.source_role!r}, bind_family={self.bind_family!r})"

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_role": self.source_role,
            "bind_family": self.bind_family,
            "port": self.port,
            "runtime_profile": self.runtime_profile,
        }

    def runtime_config(self) -> TcpRuntimeConfig:
        return TcpRuntimeConfig(
            schema_version="tcp-syslog-runtime/v1", source_role=self.source_role,
            bind_family=self.bind_family, port=self.port, connection_limit=2,
            idle_timeout_seconds=30.0, read_timeout_seconds=5.0,
            parser_timezone="Asia/Seoul", startup_mode="synthetic_pilot",
            test_only_ephemeral_port=False, max_prefix_digits=6, max_frame_bytes=8192,
            max_connection_buffer_bytes=8199, max_queue_events=256,
            max_queue_bytes=1024 * 1024,
        )


@dataclass(slots=True, repr=False)
class _RuntimeLocks:
    descriptors: list[int] = field(default_factory=list, repr=False)
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failed = False
        for descriptor in reversed(self.descriptors):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except Exception:
                failed = True
            try:
                os.close(descriptor)
            except Exception:
                failed = True
        self.descriptors.clear()
        if failed:
            raise TcpManagementError("UNSAFE_STORAGE") from None

    def __enter__(self) -> "_RuntimeLocks":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def tcp_config_path() -> Path:
    return resolve_default_monitor_config_path().with_name(CONFIG_NAME)


def _open_parent(path: Path, *, create: bool) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise TcpManagementError("UNSAFE_STORAGE")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if not all(hasattr(os, item) for item in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
        raise TcpManagementError("UNSAFE_STORAGE")
    fd = -1
    try:
        fd = os.open("/", flags)
        parts = path.parts[1:-1]
        for index, component in enumerate(parts):
            try:
                before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise TcpManagementError("CONFIG_MISSING") from None
                os.mkdir(component, 0o700, dir_fd=fd)
                before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise TcpManagementError("UNSAFE_STORAGE")
            next_fd = os.open(component, flags | os.O_NOFOLLOW, dir_fd=fd)
            after = os.fstat(next_fd)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                os.close(next_fd)
                raise TcpManagementError("UNSAFE_STORAGE")
            os.close(fd)
            fd = next_fd
        current = os.fstat(fd)
        if current.st_uid != os.geteuid() or current.st_mode & 0o777 != 0o700:
            raise TcpManagementError("UNSAFE_STORAGE")
        return fd
    except TcpManagementError:
        if fd >= 0:
            os.close(fd)
        raise
    except Exception:
        if fd >= 0:
            os.close(fd)
        raise TcpManagementError("UNSAFE_STORAGE") from None


def _lock_fd(parent_fd: int, name: str) -> int:
    try:
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o777 != 0o600
                or metadata.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)):
            os.close(descriptor)
            raise TcpManagementError("UNSAFE_STORAGE")
        return descriptor
    except TcpManagementError:
        raise
    except Exception:
        raise TcpManagementError("UNSAFE_STORAGE") from None


def _acquire_names(*names: str, path: Path | None = None) -> _RuntimeLocks:
    target = path or tcp_config_path()
    parent_fd = _open_parent(target, create=True)
    locks = _RuntimeLocks()
    try:
        for name in names:
            descriptor = _lock_fd(parent_fd, name)
            locks.descriptors.append(descriptor)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise TcpManagementError("COLLECTOR_BUSY" if name == COLLECTOR_LOCK_NAME
                                         else "TCP_BUSY") from None
        return locks
    except Exception:
        try:
            locks.close()
        except Exception:
            pass
        raise
    finally:
        os.close(parent_fd)


def acquire_collector_lock(path: Path | None = None) -> _RuntimeLocks:
    """Acquire the shared file/TCP exclusion lock for the process lifetime."""
    return _acquire_names(COLLECTOR_LOCK_NAME, path=path)


def _management_locks(path: Path | None = None) -> _RuntimeLocks:
    return _acquire_names(COLLECTOR_LOCK_NAME, TCP_LOCK_NAME, path=path)


def _config_identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def load_tcp_config(path: Path | None = None) -> TcpUserConfig:
    target = path or tcp_config_path()
    parent_fd = _open_parent(target, create=False)
    descriptor = -1
    try:
        try:
            named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise TcpManagementError("CONFIG_MISSING") from None
        if (stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode)
                or named.st_uid != os.geteuid() or named.st_mode & 0o777 != 0o600
                or named.st_nlink != 1
                or named.st_size > CONFIG_MAX_BYTES):
            raise TcpManagementError("CONFIG_REVIEW")
        descriptor = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if _config_identity(opened) != _config_identity(named):
            raise TcpManagementError("CONFIG_REVIEW")
        raw = bytearray()
        while len(raw) <= CONFIG_MAX_BYTES:
            chunk = os.read(descriptor, min(1024, CONFIG_MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > CONFIG_MAX_BYTES:
            raise TcpManagementError("CONFIG_REVIEW")
        try:
            document = json.loads(bytes(raw).decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                                  parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            if type(document) is not dict or set(document) != {
                "schema_version", "source_role", "bind_family", "port", "runtime_profile"
            }:
                raise ValueError
            config = TcpUserConfig(**document)
        except Exception:
            raise TcpManagementError("CONFIG_REVIEW") from None
        if _config_identity(os.fstat(descriptor)) != _config_identity(opened):
            raise TcpManagementError("CONFIG_REVIEW")
        return config
    except TcpManagementError:
        raise
    except Exception:
        raise TcpManagementError("CONFIG_REVIEW") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _save_config(config: TcpUserConfig, path: Path | None = None) -> None:
    target = path or tcp_config_path()
    try:
        encoded = (json.dumps(config.as_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except Exception:
        raise TcpManagementError("UNSAFE_STORAGE") from None
    parent_fd = _open_parent(target, create=True)
    temporary = ".tcp-config-" + os.urandom(8).hex()
    temporary_exists = True
    descriptor = -1
    linked = False
    cleanup_failed = False
    try:
        try:
            os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TcpManagementError("CONFIG_EXISTS")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                             os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        os.fchmod(descriptor, 0o600)
        if os.fstat(descriptor).st_mode & 0o777 != 0o600:
            raise TcpManagementError("UNSAFE_STORAGE")
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise TcpManagementError("UNSAFE_STORAGE")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                    follow_symlinks=False)
        except FileExistsError:
            raise TcpManagementError("CONFIG_EXISTS") from None
        linked = True
        os.unlink(temporary, dir_fd=parent_fd)
        temporary_exists = False
        published = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(published.st_mode) or published.st_uid != os.geteuid() or published.st_mode & 0o777 != 0o600:
            raise TcpManagementError("UNSAFE_STORAGE")
        os.fsync(parent_fd)
        if load_tcp_config(target) != config:
            raise TcpManagementError("CONFIG_REVIEW")
    except TcpManagementError:
        if linked:
            try:
                os.unlink(target.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    except Exception:
        if linked:
            try:
                os.unlink(target.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise TcpManagementError("UNSAFE_STORAGE") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
                temporary_exists = False
            except FileNotFoundError:
                temporary_exists = False
            except OSError:
                cleanup_failed = True
        if cleanup_failed and linked:
            try:
                os.unlink(target.name, dir_fd=parent_fd)
                linked = False
                os.fsync(parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
        if cleanup_failed:
            raise TcpManagementError("UNSAFE_STORAGE") from None


def _port_is_available(config: TcpUserConfig) -> bool:
    family = socket.AF_INET if config.bind_family == "ipv4" else socket.AF_INET6
    address = "127.0.0.1" if config.bind_family == "ipv4" else "::1"
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((address, config.port))
        return True
    except OSError:
        return False


def _approval(answer: str, expected: str) -> bool:
    return type(answer) is str and answer == expected


def setup_tcp_syslog(*, ask: Callable[[str], str] = input,
                     emit: Callable[[str], None] = print,
                     path: Path | None = None) -> str:
    try:
        with _management_locks(path):
            emit("기능 목적: 같은 컴퓨터의 프로그램이 보내는 합성 로그를 기존 결정적 분석기로 처리합니다.")
            emit("같은 컴퓨터의 프로그램만 연결하도록 loopback 주소에만 엽니다.")
            emit("TCP 연결만으로 송신자 신원은 인증되지 않습니다.")
            emit("TLS·mTLS 암호화는 제공하지 않으며 실제 장비·조직 운영용이 아닌 합성 pilot입니다.")
            emit("중단 중 메시지는 복구되지 않습니다. sender 재전송으로 중복될 수 있으며 무유실을 보장하지 않습니다.")
            emit("원문은 분석 중 제한된 메모리에 있을 수 있지만 공개 화면·오류·상태에는 표시하지 않습니다.")
            emit("외부 AI로 자동 전송하지 않습니다.")
            role_answer = ask("로그 종류 [1 application / 2 SSH]: ")
            role = {"1": "application", "2": "ssh"}.get(role_answer)
            family_answer = ask("loopback 주소 체계 [1 IPv4 / 2 IPv6]: ")
            family = {"1": "ipv4", "2": "ipv6"}.get(family_answer)
            port_text = ask(f"높은 포트 번호 ({MIN_PORT}–{MAX_PORT}): ")
            if (role is None or family is None or type(port_text) is not str
                    or not port_text.isascii() or not port_text.isdecimal() or len(port_text) > 5):
                raise TcpManagementError("INVALID_INPUT")
            port = int(port_text)
            if not MIN_PORT <= port <= MAX_PORT:
                raise TcpManagementError("INVALID_INPUT")
            config = TcpUserConfig(SCHEMA_VERSION, role, family, port, RUNTIME_PROFILE)
            if not _port_is_available(config):
                raise TcpManagementError("PORT_UNAVAILABLE")
            emit("메시지 형식: 메시지 내용 앞에 길이를 붙인 TCP 메시지입니다.")
            emit("예: 5 hello (5는 뒤 메시지의 byte 수). 형식이 맞지 않으면 해당 연결이 거부될 수 있습니다.")
            emit("연결 수, 메시지 크기와 대기열에는 고정 상한이 있습니다.")
            emit("중단 중 메시지는 복구하지 않습니다. sender 재전송은 중복될 수 있습니다.")
            emit("정확히 한 번 처리하거나 무유실을 보장하지 않습니다.")
            emit("TCP 연결은 인증되지 않고 TLS·mTLS 암호화를 제공하지 않습니다.")
            emit("실제 장비·원격 호스트·외부 인터페이스와 조직 운영은 지원하지 않습니다.")
            emit("원문은 분석 중 제한된 메모리에 있을 수 있지만 공개 화면·오류·상태에는 표시하지 않습니다.")
            emit("외부 AI로 자동 전송하지 않습니다.")
            emit(f"선택한 로그 종류: {'애플리케이션 로그' if role == 'application' else 'SSH 인증 로그'}.")
            emit(f"주소 체계: {'IPv4 loopback' if family == 'ipv4' else 'IPv6 loopback'}. 선택한 높은 포트.")
            emit("설정 위치는 비공개입니다. 실제 운영은 승인되지 않았습니다.")
            emit("저장 승인 문구를 정확히 입력하십시오.")
            try:
                answer = ask("승인 문구: ")
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if not _approval(answer, SAVE_APPROVAL):
                emit("설정 저장을 취소했습니다.")
                return "CANCELLED"
            _save_config(config, path)
            emit("TCP 수집 설정을 저장했습니다. 실행: uv run python -m app.monitor_setup --run-tcp-syslog")
            return "CREATED"
    except TcpManagementError:
        raise
    except (EOFError, KeyboardInterrupt):
        emit("설정 저장을 취소했습니다.")
        return "CANCELLED"


def show_tcp_syslog(*, emit: Callable[[str], None] = print,
                    path: Path | None = None) -> str:
    try:
        config = load_tcp_config(path)
    except TcpManagementError as error:
        if error.code == "CONFIG_MISSING":
            emit("TCP 수집 설정: 없음. 다음 행동: --setup-tcp-syslog 로 합성 pilot을 설정하십시오.")
            return "MISSING"
        emit("TCP 수집 설정: 검토 필요. 안전 여부를 확인하지 못해 실행하지 않습니다.")
        return "REVIEW"
    role_name = "애플리케이션 로그" if config.source_role == "application" else "SSH 인증 로그"
    emit(f"TCP 수집 설정: 있음. 로그 종류: {role_name}. loopback 전용.")
    emit(f"주소 체계: {'IPv4' if config.bind_family == 'ipv4' else 'IPv6'}. 설정 권한: 적합.")
    emit("메시지 형식: 길이가 포함된 TCP 메시지. 최대 연결 2개, queue는 크기와 개수가 제한됩니다.")
    emit("재시작하면 이전 메시지를 복구하지 않습니다. 인증·암호화는 제공하지 않습니다.")
    emit("실행 가능 여부: 설정 확인 완료(실행 시 port 경쟁이 있을 수 있음).")
    emit("다음 행동: --run-tcp-syslog 로 시작하거나 --delete-tcp-syslog 로 설정만 삭제하십시오.")
    return "CONFIGURED"


def delete_tcp_syslog(*, ask: Callable[[str], str] = input,
                      emit: Callable[[str], None] = print,
                      path: Path | None = None) -> str:
    target = path or tcp_config_path()
    try:
        with _management_locks(target):
            config = load_tcp_config(target)
            emit("TCP 수집 설정만 삭제합니다. file 설정·checkpoint·원본 sender 자료와 이미 생성된 분석 결과는 보존합니다.")
            emit("실행 중에는 삭제할 수 없습니다. 정확한 승인 문구가 필요합니다.")
            emit("삭제 후 다시 사용하려면 --setup-tcp-syslog로 설정을 새로 만들어야 합니다.")
            try:
                answer = ask("승인 문구: ")
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if not _approval(answer, DELETE_APPROVAL):
                emit("TCP 수집 설정 삭제를 취소했습니다.")
                return "CANCELLED"
            parent_fd = _open_parent(target, create=False)
            try:
                named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(named.st_mode) or named.st_uid != os.geteuid() or named.st_mode & 0o777 != 0o600:
                    raise TcpManagementError("CONFIG_REVIEW")
                if load_tcp_config(target) != config:
                    raise TcpManagementError("CONFIG_REVIEW")
                os.unlink(target.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            emit("TCP 수집 설정을 삭제했습니다. file 설정과 복구 자료는 변경하지 않았습니다.")
            return "DELETED"
    except TcpManagementError:
        raise
    except Exception:
        raise TcpManagementError("DELETE_FAILED") from None


def _tcp_lock_is_held(path: Path | None = None) -> bool:
    target = path or tcp_config_path()
    parent_fd = _open_parent(target, create=False)
    descriptor = -1
    try:
        descriptor = _lock_fd(parent_fd, TCP_LOCK_NAME)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def reveal_tcp_endpoint(*, ask: Callable[[str], str] = input,
                        emit: Callable[[str], None] = print,
                        path: Path | None = None) -> str:
    config = load_tcp_config(path)
    if not _tcp_lock_is_held(path):
        emit("실행 중인 TCP 수집을 확인하지 못했습니다.")
        return "NOT_RUNNING"
    emit("이 값은 로컬 연결 정보이며 공개 공유하지 마십시오. loopback의 다른 프로그램도 메시지를 보낼 수 있습니다.")
    try:
        answer = ask("로컬 연결 정보를 지금 표시하려면 승인 문구를 입력하십시오: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if not _approval(answer, REVEAL_APPROVAL):
        emit("표시를 취소했습니다.")
        return "CANCELLED"
    address = "127.0.0.1" if config.bind_family == "ipv4" else "::1"
    endpoint = f"{address}:{config.port}" if config.bind_family == "ipv4" else f"[{address}]:{config.port}"
    emit(f"로컬 연결 주소: {endpoint}")
    return "REVEALED"


async def _run_async(*, path: Path | None, reveal_endpoint: bool,
                     ask: Callable[[str], str], emit: Callable[[str], None]) -> int:
    target = path or tcp_config_path()
    locks = _management_locks(target)
    config = None
    runtime = None
    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()
    installed: list[signal.Signals] = []
    exit_code = 0
    runtime_started = False
    normal_stop = False
    try:
        config = load_tcp_config(target)
        runtime = TcpSyslogRuntime(config.runtime_config())
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, stopping.set)
                installed.append(signum)
            except (NotImplementedError, RuntimeError):
                pass
        await runtime.start()
        runtime_started = True
        role_name = "애플리케이션 로그" if config.source_role == "application" else "SSH 인증 로그"
        emit(f"{role_name} 수집이 시작되었습니다. loopback 전용입니다.")
        emit("수신 원문은 화면에 표시하지 않습니다. 정상 종료: Ctrl+C.")
        emit(_counter_guidance())
        if reveal_endpoint:
            emit("이 값은 로컬 연결 정보이며 공개 공유하지 마십시오.")
            if _approval(ask("한 번 표시하려면 승인 문구를 입력하십시오: "), REVEAL_APPROVAL):
                address = "127.0.0.1" if config.bind_family == "ipv4" else "::1"
                endpoint = f"{address}:{config.port}" if config.bind_family == "ipv4" else f"[{address}]:{config.port}"
                emit(f"로컬 연결 주소: {endpoint}")
        emit("현재 상태: 수집 중. Ctrl+C로 종료할 수 있습니다.")
        while runtime.snapshot().state.value not in {"FAILED", "STOPPED"}:
            try:
                await asyncio.wait_for(stopping.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass
            if stopping.is_set():
                break
            snapshot = runtime.snapshot()
            if snapshot.state.value in {"FAILED", "DEGRADED"}:
                emit("수집이 중단되었습니다. 설정과 로컬 상태를 확인하십시오.")
                exit_code = 4
                break
            emit(_summary(snapshot))
        if runtime is None:
            return 4
        snapshot = runtime.snapshot()
        if snapshot.state.value in {"FAILED", "DEGRADED"}:
            emit("수집이 중단되었습니다. 설정과 로컬 상태를 확인하십시오.")
            exit_code = 4
        else:
            normal_stop = True
    except TcpRuntimeError:
        emit("TCP 수집을 시작하거나 유지하지 못했습니다. 설정과 로컬 상태를 확인하십시오.")
        exit_code = 4
    except TcpManagementError as error:
        emit(str(error))
        exit_code = 4
    except Exception:
        emit("TCP 수집 중 내부 오류가 발생했습니다.")
        exit_code = 4
    finally:
        if runtime is not None:
            try:
                await runtime.stop()
            except Exception:
                emit("수집 종료 중 일부 자원을 안전하게 정리하지 못했습니다.")
                exit_code = 8
            if normal_stop and runtime_started:
                try:
                    emit(_summary(runtime.snapshot()))
                except Exception:
                    emit("종료 상태를 안전하게 요약하지 못했습니다.")
                    exit_code = 8
        for signum in installed:
            try:
                loop.remove_signal_handler(signum)
            except Exception:
                pass
        try:
            locks.close()
        except Exception:
            emit("수집 잠금 해제를 확인하지 못했습니다.")
            exit_code = 8
        emit("수집을 종료했습니다. 대기열 메시지는 복구되지 않으며 file 설정과 복구 자료는 변경하지 않았습니다.")
    return exit_code


def _summary(snapshot) -> str:
    last_success = snapshot.last_success_at
    if last_success == "unavailable":
        last_success = "없음"
    else:
        last_success = f"{last_success} (UTC)"
    return (f"수신 {snapshot.accepted_frames}, 거부 {snapshot.rejected_frames}, "
            f"내용 인식 {snapshot.parsed_events}, 형식 미인식 {snapshot.parser_rejected_events}, "
            f"분석 완료 {snapshot.analyzed_events}, "
            f"처리 중 폐기 {snapshot.dropped_frames}; 연결 {snapshot.active_connections}/"
            f"{snapshot.connection_limit}, 대기열 {snapshot.queued_events}/{snapshot.queue_event_limit}건 "
            f"({snapshot.queued_bytes}/{snapshot.queue_byte_limit}바이트), "
            f"최근 처리 시각 {last_success}.")


def _counter_guidance() -> str:
    return (
        "수치 안내: 수신은 형식 확인 후 대기열에 들어간 수, 거부는 형식·연결 문제로 거절된 수입니다. "
        "내용 인식과 형식 미인식은 선택한 로그 종류의 내용을 읽었는지 나타냅니다. "
        "분석 완료는 기존 분석 처리가 끝난 수이며 탐지 성공을 뜻하지 않습니다. "
        "처리 중 폐기는 받은 뒤 분석을 마치지 못한 수입니다. "
        "이 수치는 처리 현황이며 침해가 없거나 누락 없는 수집을 보장하지 않습니다."
    )


def run_tcp_syslog(*, path: Path | None = None, reveal_endpoint: bool = False,
                   ask: Callable[[str], str] = input,
                   emit: Callable[[str], None] = print) -> int:
    try:
        return asyncio.run(_run_async(path=path, reveal_endpoint=reveal_endpoint, ask=ask, emit=emit))
    except TcpManagementError as error:
        emit(str(error))
        return 4
    except KeyboardInterrupt:
        emit("수집 시작을 취소했습니다.")
        return 130


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="합성 loopback TCP Syslog 설정 관리")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup-tcp-syslog", action="store_const", const="setup", dest="action")
    group.add_argument("--show-tcp-syslog", action="store_const", const="show", dest="action")
    group.add_argument("--run-tcp-syslog", action="store_const", const="run", dest="action")
    group.add_argument("--delete-tcp-syslog", action="store_const", const="delete", dest="action")
    group.add_argument("--reveal-tcp-syslog-endpoint", action="store_const", const="reveal", dest="action")
    args = parser.parse_args(argv)
    return handle_action(args.action)


def handle_action(action: str, *, ask: Callable[[str], str] = input,
                  emit: Callable[[str], None] = print) -> int:
    try:
        if action == "setup":
            setup_tcp_syslog(ask=ask, emit=emit)
            return 0
        if action == "show":
            return 0 if show_tcp_syslog(emit=emit) != "REVIEW" else 4
        if action == "delete":
            delete_tcp_syslog(ask=ask, emit=emit)
            return 0
        if action == "run":
            return run_tcp_syslog(ask=ask, emit=emit)
        if action == "reveal":
            reveal_tcp_endpoint(ask=ask, emit=emit)
            return 0
        return 2
    except TcpManagementError as error:
        emit(str(error))
        return 4


if __name__ == "__main__":
    raise SystemExit(_main())
