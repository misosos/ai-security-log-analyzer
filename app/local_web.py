"""Small, loopback-only foreground launcher for the local investigation UI."""

import argparse
import errno
from http.client import HTTPConnection, HTTPException
import json
import socket
import sys
from threading import Thread
import time
import webbrowser

import uvicorn


HOST = "127.0.0.1"
DEFAULT_PORT = 8000
MIN_PORT = 1024
MAX_PORT = 65535
READINESS_ATTEMPTS = 40
READINESS_INTERVAL = 0.1
READINESS_DEADLINE = 5.0
SHUTDOWN_DEADLINE = 7.0


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


def _port_text(value: str) -> int:
    if len(value) > 5 or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("INVALID_PORT")
    port = int(value)
    if not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError("INVALID_PORT")
    return port


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = _Parser(description="로컬 보안 로그 분석기 실행")
    parser.add_argument("--port", type=_port_text, action=_SinglePort,
                        default=None, metavar="PORT", help="로컬 포트 (1024–65535, 기본 8000)")
    parser.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않음")
    result = parser.parse_args(argv)
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


def run_local_web(
    port: int = DEFAULT_PORT,
    *,
    open_browser: bool = True,
    listener_factory=_listener,
    server_factory=_server,
    readiness=_healthy,
    browser_open=webbrowser.open,
    monotonic=time.monotonic,
    sleep=time.sleep,
) -> int:
    """Run until interrupted; injectable boundaries keep lifecycle tests bounded."""
    if type(port) is not int or not MIN_PORT <= port <= MAX_PORT:
        print("LOCAL_WEB_INVALID_PORT: 포트는 1024~65535의 정수여야 합니다.", file=sys.stderr)
        return 2
    if type(open_browser) is not bool:
        print("LOCAL_WEB_INVALID_ARGUMENT: 실행 옵션을 확인하십시오.", file=sys.stderr)
        return 2
    try:
        from app.api import app
    except Exception:
        print("LOCAL_WEB_IMPORT_FAILED: 앱을 시작할 수 없습니다.", file=sys.stderr)
        return 4
    try:
        listener = listener_factory(port)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            print("LOCAL_WEB_PORT_IN_USE: 포트가 이미 사용 중입니다. 실행 중인 서버를 종료하거나 다른 허용 포트를 지정하세요.", file=sys.stderr)
            return 3
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


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _arguments(argv)
    except _ArgumentFailure as error:
        if str(error) == "INVALID_PORT":
            print("LOCAL_WEB_INVALID_PORT: 포트는 1024~65535의 정수여야 합니다.", file=sys.stderr)
        else:
            print("LOCAL_WEB_INVALID_ARGUMENT: --port는 한 번만 허용하며 --host는 지원하지 않습니다.", file=sys.stderr)
        return 2
    try:
        return run_local_web(arguments.port, open_browser=not arguments.no_browser)
    except KeyboardInterrupt:
        print("로컬 서버 시작을 중단했습니다.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
