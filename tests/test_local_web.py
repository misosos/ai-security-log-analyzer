"""Bounded launcher lifecycle and first-user command contract."""

import errno
import importlib
from threading import Event

import pytest

import app.api as api
from app import local_web


class _Listener:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _Server:
    def __init__(self):
        self.should_exit = False
        self.force_exit = False
        self.started = Event()
        self.stopped = Event()
        self.sockets = None

    def run(self, *, sockets):
        self.sockets = sockets
        self.started.set()
        while not self.should_exit:
            self.stopped.wait(0.001)
        self.stopped.set()


def _run_fake(*, no_browser=False, ready=True, browser_success=True):
    listener = _Listener()
    server = _Server()
    opened = []
    checks = []

    def probe(port):
        assert server.started.wait(1)
        checks.append(port)
        return ready

    def open_url(url):
        opened.append(url)
        return browser_success

    ticks = [0]

    def clock():
        ticks[0] += 1
        return ticks[0]

    def pause(_seconds):
        if ready:
            raise KeyboardInterrupt

    result = local_web.run_local_web(
        open_browser=not no_browser,
        listener_factory=lambda port: listener,
        server_factory=lambda app, port: server,
        readiness=probe,
        browser_open=open_url,
        monotonic=clock,
        sleep=pause,
    )
    assert listener.closed and server.stopped.is_set()
    assert server.sockets == [listener]
    return result, opened, checks


def test_import_has_no_startup_side_effect(monkeypatch):
    monkeypatch.setattr(local_web, "_listener", lambda port: pytest.fail("import bound a socket"))
    monkeypatch.setattr(local_web.webbrowser, "open", lambda url: pytest.fail("import opened browser"))
    importlib.reload(local_web)
    assert local_web.HOST == "127.0.0.1"
    assert local_web.DEFAULT_PORT == 8000


def test_fixed_loopback_configuration_and_port_validation(capsys):
    for args in ([], ["--no-browser"], ["--port", "8080"]):
        parsed = local_web._arguments(args)
        assert parsed.port == (8080 if "8080" in args else 8000)
    for args in (["--port", "0"], ["--port", "65536"], ["--port", "9" * 10000], ["--port", "true"],
                 ["--port", "8000", "--port", "8001"], ["--host", "0.0.0.0"]):
        with pytest.raises(local_web._ArgumentFailure):
            local_web._arguments(args)
    assert local_web.run_local_web(True) == 2
    assert local_web.run_local_web(80) == 2
    assert local_web.run_local_web(8000, open_browser=1) == 2
    assert local_web.main(["--port", "0"]) == 2
    assert "LOCAL_WEB_INVALID_PORT" in capsys.readouterr().err
    assert local_web.main(["--port", "8000", "--port", "8001"]) == 2
    assert "LOCAL_WEB_INVALID_ARGUMENT" in capsys.readouterr().err


def test_monitor_flag_is_explicit_and_exclusive(capsys, tmp_path):
    assert local_web._arguments([]).monitor is False
    assert local_web._arguments(["--monitor", "--no-browser", "--port", "8123"]).monitor is True
    with pytest.raises(local_web._ArgumentFailure):
        local_web._arguments(["--monitor", "--monitor-config", str(tmp_path / "x.json")])
    assert local_web.main(["--monitor", "--monitor-config", str(tmp_path / "x.json")]) == 2
    assert "LOCAL_WEB_INVALID_ARGUMENT" in capsys.readouterr().err
    assert local_web.run_local_web(monitor_default=True, monitor_config=tmp_path / "x.json") == 2


def test_monitor_missing_default_is_fixed_error_before_socket(capsys, tmp_path):
    def no_listener(_port):
        pytest.fail("missing config must never bind a socket")

    result = local_web.run_local_web(monitor_default=True,
                                     default_config_resolver=lambda: tmp_path / "missing" / "config.json",
                                     listener_factory=no_listener)
    assert result == 4
    text = capsys.readouterr().err
    assert "DEFAULT_CONFIG_MISSING" in text and str(tmp_path) not in text


@pytest.mark.parametrize("mutation,expected", [
    ("mode", "DEFAULT_CONFIG_PERMISSION"),
    ("v1", "DEFAULT_CONFIG_SCHEMA"),
    ("malformed", "DEFAULT_CONFIG_MALFORMED"),
    ("source_missing", "SOURCE_UNAVAILABLE"),
])
def test_monitor_default_refuses_invalid_config_before_bind(capsys, tmp_path, mutation, expected):
    import json
    from app.monitor_setup import create_monitor_config

    source = tmp_path / "source.log"
    source.write_text("2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1\n")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_config(source, config)
    if mutation == "mode":
        config.chmod(0o644)
    elif mutation == "v1":
        config.write_text(json.dumps({"schema_version": "1", "source": {
            "role": "application", "path": str(source)}, "start_policy": "FROM_END"}))
    elif mutation == "malformed":
        config.write_text("{invalid")
    else:
        source.unlink()
    def no_listener(_port):
        pytest.fail("unsafe default config must never bind")
    assert local_web.run_local_web(monitor_default=True, default_config_resolver=lambda: config,
                                   listener_factory=no_listener) == 4
    error = capsys.readouterr().err
    assert expected in error and str(config) not in error and str(source) not in error


def test_monitor_config_replacement_during_runtime_build_closes_service(capsys, tmp_path):
    import os
    from app.monitor_setup import create_monitor_config

    source = tmp_path / "source.log"
    source.write_text("2026-01-02 03:04:05 INFO login_failed user=synthetic ip=192.0.2.1\n")
    config = tmp_path / "private" / "monitoring.json"
    create_monitor_config(source, config)
    closed = []
    class Service:
        async def close(self):
            closed.append(True)
    def replace_and_return(_path):
        replacement = config.parent / "replacement"
        replacement.write_bytes(config.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, config)
        return Service(), object()
    def no_listener(_port):
        pytest.fail("changed config must never bind")
    assert local_web.run_local_web(monitor_default=True, default_config_resolver=lambda: config,
                                   runtime_factory=replace_and_return, listener_factory=no_listener) == 4
    assert closed == [True]
    assert "DEFAULT_CONFIG_CHANGED" in capsys.readouterr().err


def test_readiness_precedes_one_browser_open_and_ctrl_c_shutdown(capsys):
    result, opened, checks = _run_fake()
    assert result == 0
    assert checks == [8000]
    assert opened == ["http://127.0.0.1:8000/"]
    output = capsys.readouterr()
    assert "로컬 보안 로그 분석기를 시작했습니다." in output.out
    assert "웹 주소: http://127.0.0.1:8000/" in output.out
    assert "Ctrl+C" in output.out
    assert output.err == ""


def test_no_browser_and_browser_failure_do_not_stop_server(capsys):
    result, opened, _ = _run_fake(no_browser=True)
    assert result == 0 and opened == []
    result, opened, _ = _run_fake(browser_success=False)
    assert result == 0 and len(opened) == 1
    assert "LOCAL_WEB_BROWSER_FAILED" in capsys.readouterr().err


def test_startup_port_conflict_and_readiness_timeout_are_bounded(capsys):
    def occupied(_port):
        raise OSError(errno.EADDRINUSE, "private path or credential")

    assert local_web.run_local_web(listener_factory=occupied) == 3
    error = capsys.readouterr().err
    assert "private path" not in error
    assert "포트가 이미 사용 중" in error
    result, opened, checks = _run_fake(ready=False)
    assert result == 6 and opened == []
    assert 1 <= len(checks) <= local_web.READINESS_ATTEMPTS
    assert "LOCAL_WEB_READINESS_TIMEOUT" in capsys.readouterr().err


def test_app_import_failure_is_bounded_before_socket_or_browser(monkeypatch, capsys):
    monkeypatch.delattr(api, "app")
    result = local_web.run_local_web(
        listener_factory=lambda port: pytest.fail("socket created"),
        browser_open=lambda url: pytest.fail("browser opened"),
    )
    assert result == 4
    error = capsys.readouterr().err
    assert "LOCAL_WEB_IMPORT_FAILED" in error
    assert "Traceback" not in error


def test_thread_start_failure_closes_reserved_port_without_browser(monkeypatch, capsys):
    listener = _Listener()
    opened = []

    class _BrokenThread:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise OSError("private-startup-detail")

    monkeypatch.setattr(local_web, "Thread", _BrokenThread)
    result = local_web.run_local_web(
        listener_factory=lambda port: listener,
        server_factory=lambda app, port: _Server(),
        browser_open=lambda url: opened.append(url),
    )
    assert result == 5
    assert listener.closed and opened == []
    assert "private-startup-detail" not in capsys.readouterr().err


def test_server_configuration_disables_reload_proxy_and_access_log(monkeypatch):
    captured = {}

    def config(app, **options):
        captured.update(options)
        return object()

    monkeypatch.setattr(local_web.uvicorn, "Config", config)
    monkeypatch.setattr(local_web.uvicorn, "Server", lambda value: value)
    local_web._server(object(), 8000)
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8000
    assert captured["reload"] is False
    assert captured["access_log"] is False
    assert captured["proxy_headers"] is False
