"""Small, loopback-only foreground launcher for the local investigation UI."""

import argparse
import asyncio
import errno
from http.client import HTTPConnection, HTTPException
import json
import socket
import sys
from pathlib import Path
from threading import Thread
import time
import webbrowser

import uvicorn

from app.live_monitoring.config import resolve_default_monitor_config_path


HOST = "127.0.0.1"
DEFAULT_PORT = 8000
MIN_PORT = 1024
MAX_PORT = 65535
READINESS_ATTEMPTS = 40
READINESS_INTERVAL = 0.1
READINESS_DEADLINE = 5.0
SHUTDOWN_DEADLINE = 7.0


def _live_runtime(config_path: Path, *, checkpoint_default: bool = False):
    """Build exactly one trusted internal chain; close the FD on partial failure."""
    from app.live_monitoring import (
        LiveDetectionAccumulator, LiveProcessingWorker,
        load_live_monitor_config, open_live_tail_session,
    )
    from app.live_monitoring.runner import LiveMonitoringRunner
    from app.live_monitoring.service import LiveMonitoringService
    from app.live_monitoring.analysis_accumulator import LiveAnalysisAccumulator
    from app.analyzer.risk import load_account_metadata
    from app.live_monitoring.config import load_live_monitor_setup_config
    from app.live_monitoring.checkpoint import LiveCheckpointManager

    config = load_live_monitor_config(config_path)
    checkpoint = None
    if checkpoint_default:
        v2 = load_live_monitor_setup_config(config_path)
        if v2.checkpoint_policy == "BOUNDED_REPLAY_V1":
            checkpoint = LiveCheckpointManager(config_path, v2)
    try:
        session = open_live_tail_session(config, start_offset=(checkpoint.committed_offset
                                                               if checkpoint else None))
    except Exception:
        if checkpoint is not None:
            checkpoint.close()
        raise

    worker = None
    service = None
    try:
        accumulator = LiveDetectionAccumulator(config.role, 256, 256 * 1024)
        analysis = None
        if config.role in ("application", "ssh"):
            metadata = load_account_metadata()
            analysis = LiveAnalysisAccumulator(
                accumulator, tuple((account, value["privilege"])
                                   for account, value in metadata.items()))
        worker = LiveProcessingWorker(session, accumulator, 16, 4096,
                                      analysis_accumulator=analysis)
        if checkpoint is not None:
            checkpoint.initialize_or_restore(worker)
            worker._checkpoint = checkpoint
        service = LiveMonitoringService(worker)
        runner = LiveMonitoringRunner(service)
        return service, runner
    except Exception:
        if service is not None:
            asyncio.run(service.close())
        elif worker is not None:
            worker.close()
        else:
            session.close()
        if checkpoint is not None:
            checkpoint.close()
        raise


def _pair_runtime(config_path: Path):
    """Build the closed v3 pair runtime before any listener is opened."""
    from app.live_monitoring.multi_source import open_internal_pair_runtime
    from app.live_monitoring.pair_publication import attach_pair_publication
    from app.live_monitoring.pair_service import PairMonitoringService, PairRunner
    runtime = open_internal_pair_runtime(config_path)
    try:
        service = PairMonitoringService(runtime, attach_pair_publication(runtime))
        return service, PairRunner(service)
    except Exception:
        runtime.close()
        raise


def _configured_runtime(config_path: Path, *, checkpoint_default: bool = False):
    from app.live_monitoring.config import _read_config_document
    document = _read_config_document(config_path)
    if type(document) is dict and document.get("schema_version") == "3":
        return _pair_runtime(config_path)
    return _live_runtime(config_path, checkpoint_default=checkpoint_default)


def _private_schema_version(config_path: Path) -> str | None:
    from app.live_monitoring.config import LiveMonitorError
    from app.live_monitoring.default_config import open_default_config
    try:
        with open_default_config(config_path) as guard:
            return guard.config.schema_version
    except LiveMonitorError as error:
        if error.code == "PRIVATE_PAIR_SCHEMA":
            return "3"
        raise


class _ArgumentFailure(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        code = "INVALID_PORT" if "INVALID_PORT" in message else "INVALID_ARGUMENT"
        raise _ArgumentFailure(code) from None


class _SinglePort(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error("duplicate port")
        setattr(namespace, self.dest, values)


class _SingleConfig(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error("duplicate monitor config")
        setattr(namespace, self.dest, values)


def _port_text(value: str) -> int:
    if len(value) > 5 or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("INVALID_PORT")
    port = int(value)
    if not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError("INVALID_PORT")
    return port


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = _Parser(description="로컬 보안 로그 분석기 실행",
                     epilog="예: uv run python -m app.local_web --monitor --no-browser")
    parser.add_argument("--port", type=_port_text, action=_SinglePort,
                        default=None, metavar="PORT", help="로컬 포트 (1024–65535, 기본 8000)")
    parser.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않음")
    parser.add_argument("--monitor-config", action=_SingleConfig, default=None,
                        metavar="/absolute/path/to/live-monitor.json",
                        help="명시적으로 승인한 단일 로그의 로컬 모니터링 설정")
    parser.add_argument("--monitor", action="store_true",
                        help="기본 private v2 설정으로 로컬 모니터링 시작 (예: --monitor --no-browser)")
    result = parser.parse_args(argv)
    if result.monitor and result.monitor_config is not None:
        parser.error("monitor options conflict")
    if result.port is None:
        result.port = DEFAULT_PORT
    return result


def _listener(port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((HOST, port))
        listener.listen(128)
    except OSError:
        listener.close()
        raise
    return listener


def _healthy(port: int) -> bool:
    connection = HTTPConnection(HOST, port, timeout=0.25)
    try:
        connection.request("GET", "/api/health", headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Type", "").split(";")[0] != "application/json":
            return False
        return json.loads(response.read(64)) == {"status": "ok"}
    except (OSError, HTTPException, ValueError):
        return False
    finally:
        connection.close()


def _server(app, port: int) -> uvicorn.Server:
    config = uvicorn.Config(
        app, host=HOST, port=port, reload=False, workers=1,
        access_log=False, proxy_headers=False, log_level="critical",
        timeout_graceful_shutdown=5,
    )
    return uvicorn.Server(config)


def _run_local_web_unlocked(
    port: int = DEFAULT_PORT,
    *,
    open_browser: bool = True,
    monitor_config: Path | None = None,
    monitor_default: bool = False,
    listener_factory=_listener,
    server_factory=_server,
    readiness=_healthy,
    browser_open=webbrowser.open,
    monotonic=time.monotonic,
    sleep=time.sleep,
    runtime_factory=_live_runtime,
    default_config_resolver=resolve_default_monitor_config_path,
) -> int:
    """Run until interrupted; injectable boundaries keep lifecycle tests bounded."""
    if type(port) is not int or not MIN_PORT <= port <= MAX_PORT:
        print("LOCAL_WEB_INVALID_PORT: 포트는 1024~65535의 정수여야 합니다.", file=sys.stderr)
        return 2
    if type(open_browser) is not bool:
        print("LOCAL_WEB_INVALID_ARGUMENT: 실행 옵션을 확인하십시오.", file=sys.stderr)
        return 2
    if monitor_config is not None and not isinstance(monitor_config, Path):
        print("LIVE_CONFIG_INVALID: 설정은 절대 경로의 로컬 파일이어야 합니다. 설정 파일을 확인하십시오.", file=sys.stderr)
        return 2
    if type(monitor_default) is not bool or (monitor_default and monitor_config is not None):
        print("LOCAL_WEB_INVALID_ARGUMENT: 모니터링 옵션을 확인하십시오.", file=sys.stderr)
        return 2
    try:
        from app.api import app
    except Exception:
        print("LOCAL_WEB_IMPORT_FAILED: 앱을 시작할 수 없습니다.", file=sys.stderr)
        return 4
    service = None
    if monitor_config is not None or monitor_default:
        from app.api import create_app
        from app.live_monitoring.config import LiveMonitorError
        from app.live_monitoring.default_config import open_default_config
        try:
            if monitor_default:
                config_path = default_config_resolver()
                if runtime_factory is _live_runtime:
                    if _private_schema_version(config_path) == "3":
                        service, runner = _pair_runtime(config_path)
                    else:
                        with open_default_config(config_path) as guard:
                            service, runner = _configured_runtime(config_path, checkpoint_default=True)
                            guard.check()
                else:
                    with open_default_config(config_path) as guard:
                        service, runner = runtime_factory(config_path)
                        guard.check()
            else:
                service, runner = (_configured_runtime(monitor_config)
                                   if runtime_factory is _live_runtime else runtime_factory(monitor_config))
            app = create_app(live_monitoring_service=service, live_monitoring_runner=runner)
        except LiveMonitorError as error:
            if service is not None:
                asyncio.run(service.close())
            if monitor_default:
                print(f"{error.code}: 기본 설정으로 모니터링을 준비하지 못했습니다. "
                      "uv run python -m app.monitor_setup 으로 설정을 확인하십시오.", file=sys.stderr)
                return 4
            code = "LIVE_SOURCE_UNAVAILABLE" if error.code in (
                "SOURCE_UNAVAILABLE", "NON_REGULAR_SOURCE", "SYMLINK_REJECTED", "PERMISSION_DENIED",
            ) else "LIVE_CONFIG_INVALID"
            print(f"{code}: 로컬 로그 모니터링을 준비하지 못했습니다. 설정과 파일 권한을 확인하십시오.", file=sys.stderr)
            return 4
        except Exception as error:
            from app.live_monitoring.checkpoint import LiveCheckpointError
            if isinstance(error, LiveCheckpointError):
                if service is not None:
                    asyncio.run(service.close())
                print(f"{error.code}: 자동 복구를 중단했습니다. 기본 설정과 같은 파일의 상태를 수동으로 확인하십시오.",
                      file=sys.stderr)
                return 4
            if service is not None:
                asyncio.run(service.close())
            print("LIVE_RUNTIME_START_FAILED: 로컬 모니터링을 시작하지 못했습니다. 설정을 확인한 뒤 다시 시도하십시오.", file=sys.stderr)
            return 4
    try:
        listener = listener_factory(port)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            if service is not None:
                asyncio.run(service.close())
            print("LOCAL_WEB_PORT_IN_USE: 포트가 이미 사용 중입니다. 실행 중인 서버를 종료하거나 다른 허용 포트를 지정하세요.", file=sys.stderr)
            return 3
        if service is not None:
            asyncio.run(service.close())
        print("LOCAL_WEB_START_FAILED: 로컬 포트를 사용할 수 없습니다.", file=sys.stderr)
        return 5
    try:
        try:
            server = server_factory(app, port)
        except Exception:
            print("LOCAL_WEB_START_FAILED: 서버를 시작할 수 없습니다.", file=sys.stderr)
            return 5
        failed = False

        def serve() -> None:
            nonlocal failed
            try:
                server.run(sockets=[listener])
            except Exception:
                failed = True

        try:
            worker = Thread(target=serve, name="local-web-server")
            worker.start()
        except Exception:
            print("LOCAL_WEB_START_FAILED: 서버를 시작할 수 없습니다.", file=sys.stderr)
            return 5
        deadline = monotonic() + READINESS_DEADLINE
        ready = False
        exit_code = 0
        try:
            for _ in range(READINESS_ATTEMPTS):
                if not worker.is_alive():
                    exit_code = 5
                    print("LOCAL_WEB_START_FAILED: 서버를 시작할 수 없습니다.", file=sys.stderr)
                    break
                try:
                    healthy = readiness(port)
                except Exception:
                    healthy = False
                if healthy and worker.is_alive():
                    ready = True
                    break
                if monotonic() >= deadline:
                    break
                sleep(READINESS_INTERVAL)
            if not ready and exit_code == 0:
                exit_code = 6
                print("LOCAL_WEB_READINESS_TIMEOUT: 서버 준비를 확인하지 못했습니다. 다시 실행하거나 다른 허용 포트를 확인하세요.", file=sys.stderr)
            if ready:
                url = f"http://{HOST}:{port}/"
                print("로컬 보안 로그 분석기를 시작했습니다.", flush=True)
                if service is not None:
                    print("실시간 로그 모니터링이 활성화되었습니다.", flush=True)
                print(f"웹 주소: {url}", flush=True)
                print("이 서버는 현재 컴퓨터에서만 접근할 수 있습니다.", flush=True)
                print("종료하려면 Ctrl+C를 누르세요.", flush=True)
                if open_browser:
                    try:
                        if not browser_open(url):
                            raise OSError("browser unavailable")
                    except Exception:
                        print(f"LOCAL_WEB_BROWSER_FAILED: 브라우저를 열지 못했습니다. 직접 {url} 을 여세요.", file=sys.stderr)
                while worker.is_alive():
                    sleep(0.1)
                if failed:
                    exit_code = 7
                    print("LOCAL_WEB_UNEXPECTED_EXIT: 서버가 예상하지 못하게 종료되었습니다.", file=sys.stderr)
                elif exit_code == 0:
                    exit_code = 7
                    print("LOCAL_WEB_UNEXPECTED_EXIT: 서버가 예상하지 못하게 종료되었습니다.", file=sys.stderr)
        except KeyboardInterrupt:
            print("로컬 서버를 종료합니다.", flush=True)
        finally:
            server.should_exit = True
            worker.join(SHUTDOWN_DEADLINE)
            if worker.is_alive():
                server.force_exit = True
                worker.join(1.0)
                print("LOCAL_WEB_SHUTDOWN_FAILED: 서버 종료를 확인하지 못했습니다.", file=sys.stderr)
                return 8
        return exit_code
    finally:
        listener.close()
        if service is not None:
            try:
                asyncio.run(service.close())
            except Exception:
                print("LIVE_SHUTDOWN_TIMEOUT: 모니터링 종료를 확인하십시오.", file=sys.stderr)


def run_local_web(
    port: int = DEFAULT_PORT,
    *,
    open_browser: bool = True,
    monitor_config: Path | None = None,
    monitor_default: bool = False,
    listener_factory=_listener,
    server_factory=_server,
    readiness=_healthy,
    browser_open=webbrowser.open,
    monotonic=time.monotonic,
    sleep=time.sleep,
    runtime_factory=_live_runtime,
    default_config_resolver=resolve_default_monitor_config_path,
) -> int:
    """Use one shared process lock when file monitoring is enabled."""
    if (not monitor_default and monitor_config is None) or (
        monitor_config is not None and (not isinstance(monitor_config, Path) or not monitor_config.is_absolute())
    ):
        return _run_local_web_unlocked(
            port, open_browser=open_browser, monitor_config=monitor_config,
            monitor_default=monitor_default, listener_factory=listener_factory,
            server_factory=server_factory, readiness=readiness, browser_open=browser_open,
            monotonic=monotonic, sleep=sleep, runtime_factory=runtime_factory,
            default_config_resolver=default_config_resolver,
        )
    if monitor_default and monitor_config is not None:
        return _run_local_web_unlocked(
            port, open_browser=open_browser, monitor_config=monitor_config,
            monitor_default=monitor_default, listener_factory=listener_factory,
            server_factory=server_factory, readiness=readiness, browser_open=browser_open,
            monotonic=monotonic, sleep=sleep, runtime_factory=runtime_factory,
            default_config_resolver=default_config_resolver,
        )
    try:
        from app.tcp_syslog_management import acquire_collector_lock
        lock_path = default_config_resolver()
        lock = acquire_collector_lock(lock_path)
    except Exception:
        print("LOCAL_COLLECTION_BUSY: 다른 로그 수집이 실행 중입니다. 먼저 정상 종료하십시오.",
              file=sys.stderr)
        return 4
    result = 4
    try:
        result = _run_local_web_unlocked(
            port, open_browser=open_browser, monitor_config=monitor_config,
            monitor_default=monitor_default, listener_factory=listener_factory,
            server_factory=server_factory, readiness=readiness, browser_open=browser_open,
            monotonic=monotonic, sleep=sleep, runtime_factory=runtime_factory,
            default_config_resolver=default_config_resolver,
        )
    finally:
        try:
            lock.close()
        except Exception:
            print("LOCAL_COLLECTION_LOCK_RELEASE_FAILED: 수집 잠금 해제를 확인하지 못했습니다.",
                  file=sys.stderr)
            if result == 0:
                result = 8
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(argv)
    except _ArgumentFailure as error:
        if str(error) == "INVALID_PORT":
            print("LOCAL_WEB_INVALID_PORT: 포트는 1024~65535의 정수여야 합니다.", file=sys.stderr)
        else:
            print("LOCAL_WEB_INVALID_ARGUMENT: 옵션을 확인하십시오. --monitor와 --monitor-config는 함께 사용할 수 없습니다.", file=sys.stderr)
        return 2
    try:
        return run_local_web(arguments.port, open_browser=not arguments.no_browser,
                             monitor_default=arguments.monitor,
                             monitor_config=(Path(arguments.monitor_config)
                                             if arguments.monitor_config is not None else None))
    except KeyboardInterrupt:
        print("로컬 서버 시작을 중단했습니다.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
