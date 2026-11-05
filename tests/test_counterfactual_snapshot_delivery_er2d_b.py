import pytest
from fastapi.testclient import TestClient
from app.api import create_app

PATH = "/assets/evaluation-snapshot-v1.json"


def client(enabled=True, **kwargs):
    app = create_app(enable_evidence_review_viewer=enabled, evidence_review_port=8000 if enabled else None, **kwargs)
    return TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 43210))


def test_off_route_absent_and_on_returns_fixed_asset():
    off = TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 1234))
    assert off.get(PATH).status_code == 404
    assert PATH not in off.app.openapi()["paths"]
    response = client().get(PATH)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["evaluation_scope"] == "SYNTHETIC_ONLY"


@pytest.mark.parametrize("headers", [
    {"host": "attacker.invalid:8000"}, {"host": "127.0.0.1:9999"},
    {"origin": "https://attacker.invalid"}, {"origin": "null"},
    {"sec-fetch-site": "cross-site"}, {"x-forwarded-host": "127.0.0.1"},
])
def test_local_admission_denies_untrusted_headers(headers):
    assert client().get(PATH, headers=headers).status_code != 200


def test_query_and_body_rejected():
    c = client()
    assert c.get(PATH + "?x=1").status_code != 200
    assert c.request("GET", PATH, content=b"CANARY").status_code != 200


@pytest.mark.parametrize("value", ["true", 1, None, [], {}])
def test_flag_requires_bool(value):
    with pytest.raises(TypeError):
        create_app(enable_evidence_review_viewer=value)


@pytest.mark.parametrize("port", [None, True, "8000", 80, 65536])
def test_on_requires_explicit_valid_port(port):
    with pytest.raises(TypeError):
        create_app(enable_evidence_review_viewer=True, evidence_review_port=port)


def test_restricted_mode_conflict_rejected():
    with pytest.raises(TypeError):
        create_app(enable_linux_audit_api=True, enable_evidence_review_viewer=True, evidence_review_port=8000)


@pytest.mark.parametrize("method", ["HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def test_unsupported_methods_have_no_snapshot(method):
    response = client().request(method, PATH)
    assert response.status_code != 200
    assert b'SYNTHETIC_ONLY' not in response.content


def test_headers_and_request_body_and_peer():
    c = client()
    r = c.get(PATH, headers={"Origin": "http://127.0.0.1:8000", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "access-control-allow-origin" not in r.headers
    assert c.get(PATH, headers=[("Host", "127.0.0.1:8000"), ("Host", "127.0.0.1:8000")]).status_code != 200
    assert c.get(PATH, headers={"Sec-Fetch-Site": "same-site"}).status_code != 200
    assert c.get(PATH + "/extra").status_code == 404
    foreign = TestClient(c.app, base_url="http://127.0.0.1:8000", client=("192.0.2.2", 1234))
    assert foreign.get(PATH).status_code != 200
    response = c.request("GET", PATH, content=b"BODY_CANARY")
    assert b"BODY_CANARY" not in response.content


def test_fixed_snapshot_and_zero_replay(monkeypatch):
    import hashlib
    from pathlib import Path
    from app.evaluation import counterfactual_safe_projection as projection
    from app.evaluation import counterfactual_replay as replay
    from app.evaluation import counterfactual_holdout as holdout
    from app.evaluation import counterfactual_analyst_report as report
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected replay")
    for module, names in [(projection, ("build_snapshot", "decode_snapshot", "run_corpus", "run_holdout", "build_report")), (replay, ("run_corpus",)), (holdout, ("run_holdout",)), (report, ("build_report",))]:
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    expected = Path("frontend/evaluation-snapshot-v1.json").read_bytes()
    assert hashlib.sha256(expected).hexdigest() == "9f39bb5c814acf8627151681525c7d169e880feb8bd24dc106b5d87075559195"
    c = client()
    assert c.get(PATH).content == expected
    assert c.get(PATH).content == expected
    assert all(value not in expected for value in (b"PATTERN_PRESENT", b"label_basis", b"192.0.2.", b"AnalysisRunOwner", b"BruteWindowContext", b"/Users/"))
    assert set(c.get(PATH).json()["scenarios"][0]) == {"corpus_id", "scenario_id", "detector_id", "mutation_type", "baseline_parser_state", "variant_parser_state", "baseline_detection_state", "variant_detection_state", "comparison_state", "reason_codes"}


@pytest.fixture
def isolated_root(tmp_path, monkeypatch):
    import shutil
    from app import evaluation_snapshot_delivery as delivery
    for directory, name, _ in (*delivery._MANIFEST_PINS, *delivery._FIXTURE_PINS, *delivery._SOURCE_VERSION_PINS):
        target = tmp_path.joinpath(*directory, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(delivery._ROOT.joinpath(*directory, name), target)
    target = tmp_path / "frontend" / "evaluation-snapshot-v1.json"
    target.parent.mkdir()
    shutil.copyfile(delivery._ROOT / "frontend" / target.name, target)
    monkeypatch.setattr(delivery, "_ROOT", tmp_path)
    return tmp_path


@pytest.mark.parametrize("condition", ["missing", "empty", "changed", "oversized", "directory", "symlink", "manifest", "fixture", "source"])
def test_asset_corruption_fails_closed(isolated_root, condition):
    path = isolated_root / "frontend" / "evaluation-snapshot-v1.json"
    if condition == "missing":
        path.unlink()
    elif condition == "empty":
        path.write_bytes(b"")
    elif condition == "changed":
        path.write_bytes(path.read_bytes().replace(b'SYNTHETIC_ONLY', b'SYNTHETIC_FAIL'))
    elif condition == "oversized":
        path.write_bytes(b"x" * (128 * 1024 + 1))
    elif condition == "directory":
        path.unlink()
        path.mkdir()
    elif condition == "symlink":
        path.unlink()
        path.symlink_to(isolated_root / "sample_logs" / "counterfactual" / "manifest.json")
    elif condition == "manifest":
        (isolated_root / "sample_logs" / "counterfactual" / "manifest.json").write_bytes(b"changed")
    elif condition == "fixture":
        from app import evaluation_snapshot_delivery as delivery
        directories, name, _ = delivery._FIXTURE_PINS[0]
        isolated_root.joinpath(*directories, name).write_bytes(b"changed")
    else:
        from app import evaluation_snapshot_delivery as delivery
        directories, name, _ = delivery._SOURCE_VERSION_PINS[0]
        isolated_root.joinpath(*directories, name).write_bytes(b"changed")
    response = client().get(PATH)
    assert response.status_code == 404
    assert b"CANARY" not in response.content
    assert str(isolated_root).encode() not in response.content


def test_replacement_during_read_fails_closed(isolated_root, monkeypatch):
    import os
    from app import evaluation_snapshot_delivery as delivery
    path = isolated_root / "frontend" / "evaluation-snapshot-v1.json"
    replacement = path.with_name("replacement.json")
    replacement.write_bytes(path.read_bytes())
    real_read = os.read
    swapped = False
    def swapping_read(fd, count):
        nonlocal swapped
        data = real_read(fd, count)
        if not swapped and data.startswith(b'{"corpora"'):
            os.replace(replacement, path)
            swapped = True
        return data
    monkeypatch.setattr(delivery.os, "read", swapping_read)
    response = client().get(PATH)
    assert swapped
    assert response.status_code == 404


def test_checked_in_asset_matches_validated_offline_producer():
    from pathlib import Path
    from app.evaluation.counterfactual_safe_projection import build_snapshot, decode_snapshot, encode_snapshot
    raw = Path("frontend/evaluation-snapshot-v1.json").read_bytes()
    assert raw == encode_snapshot(build_snapshot())
    assert raw == encode_snapshot(decode_snapshot(raw))
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")


def test_partial_read_fails_closed(isolated_root, monkeypatch):
    import os
    from app import evaluation_snapshot_delivery as delivery
    real_read = os.read
    truncated = set()
    def partial(fd, count):
        data = real_read(fd, count)
        if data.startswith(b'{"corpora"'):
            truncated.add(fd)
            return data[:10]
        if fd in truncated:
            return b""
        return data
    monkeypatch.setattr(delivery.os, "read", partial)
    assert client().get(PATH).status_code == 404


def test_concurrent_requests_do_not_invoke_replay(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from app.evaluation import counterfactual_safe_projection as projection
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected evaluation")
    for name in ("build_snapshot", "decode_snapshot", "run_corpus", "run_holdout", "build_report"):
        monkeypatch.setattr(projection, name, forbidden)
    c = client()
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: c.get(PATH), range(8)))
    assert all(response.status_code == 200 for response in responses)
    assert len({response.content for response in responses}) == 1


def test_unknown_asset_and_default_ui_do_not_expose_snapshot():
    c = TestClient(create_app(), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 1234))
    assert c.get("/assets/../evaluation-snapshot-v1.json").status_code == 404
    assert c.get("/assets/evaluation-snapshot-v2.json").status_code == 404
    assert b"evaluation-snapshot" not in c.get("/").content
    assert b"evaluation-snapshot" not in c.get("/assets/app.js").content


def test_request_attempts_no_network_or_llm(monkeypatch):
    import socket
    def blocked(*args, **kwargs):
        pytest.fail("unexpected outbound network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    assert client().get(PATH).status_code == 200


def test_real_loopback_server_admission():
    import http.client
    import socket
    import threading
    import time
    import uvicorn
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    port = listener.getsockname()[1]
    app = create_app(enable_evidence_review_viewer=True, evidence_review_port=port)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, workers=1, proxy_headers=False, log_level="critical", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.started
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", PATH)
        response = connection.getresponse()
        assert response.status == 200
        assert b'SYNTHETIC_ONLY' in response.read()
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("GET", PATH, headers={"Host": "untrusted.invalid"})
        response = connection.getresponse()
        assert response.status == 404
        assert b'SYNTHETIC_ONLY' not in response.read()
        connection.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
    assert not thread.is_alive()


def test_self_hash_recomputed_tamper_still_rejected(isolated_root):
    import hashlib
    import json
    path = isolated_root / "frontend" / "evaluation-snapshot-v1.json"
    data = json.loads(path.read_bytes())
    data["summary"]["scenario_count"] = 0
    body = {key: value for key, value in data.items() if key != "snapshot_sha256"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    data["snapshot_sha256"] = hashlib.sha256(canonical).hexdigest()
    path.write_bytes(json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
    assert client().get(PATH).status_code == 404


def test_private_exception_is_not_reflected(monkeypatch):
    from app import evaluation_snapshot_delivery as delivery
    original = delivery._read_pinned
    def fail(*args, **kwargs):
        if args[1] == "evaluation-snapshot-v1.json":
            raise OSError("EXCEPTION_CANARY")
        return original(*args, **kwargs)
    monkeypatch.setattr(delivery, "_read_pinned", fail)
    result = client().get(PATH)
    assert result.status_code == 404
    assert b"EXCEPTION_CANARY" not in result.content


def test_asset_change_after_first_success_has_no_cached_fallback(isolated_root):
    c = client()
    assert c.get(PATH).status_code == 200
    path = isolated_root / "frontend" / "evaluation-snapshot-v1.json"
    path.write_bytes(path.read_bytes() + b" ")
    assert c.get(PATH).status_code == 404


def test_code_pin_mismatch_is_rejected(monkeypatch):
    from app import evaluation_snapshot_delivery as delivery
    monkeypatch.setattr(delivery, "_ASSET_PIN", "0" * 64)
    assert client().get(PATH).status_code == 404
