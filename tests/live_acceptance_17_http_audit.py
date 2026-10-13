"""Opt-in read-only audit of the running synthetic Phase 17 loopback server."""

import json
from urllib.request import Request, urlopen

from tests.smoke_live_analysis_16_3 import _frame


BASE = "http://127.0.0.1:8000"
PRIVATE = (
    b"SYNTHETIC_ACCOUNT_CANARY_P17", b"192.0.2.123",
    b"SYNTHETIC_SOURCE_FILENAME_CANARY_P17",
    b"SYNTHETIC_CONFIG_FILENAME_CANARY_P17", b"RAW_LINE_CANARY_P17",
    b"HTTP_PATH_CANARY_P17", b"HTTP_QUERY_CANARY_P17",
)


def _get(path: str) -> bytes:
    with urlopen(BASE + path, timeout=5) as response:
        assert response.status == 200
        return response.read()


def main() -> None:
    status = _get("/api/v1/live/status")
    body = json.loads(status)
    assert body["schema_version"] == "2"
    assert body["source_role"] == "application"
    assert body["latest_detection_revision"] == body["analysis_revision"]
    assert body["active_relation_count"] >= 2
    assert body["active_risk_count"] >= 1
    assert body["active_case_count"] >= 1
    with urlopen(BASE + "/api/v1/live/events", timeout=5) as stream:
        snapshot = _frame(stream)
        assert b"event: snapshot" in snapshot
        frames = tuple(_frame(stream) for _ in range(body["available_event_count"]))
    names = tuple(frame.split(b"event: ", 1)[1].split(b"\n", 1)[0] for frame in frames)
    assert b"observation_changes" in names and b"analysis_changes" in names
    ids = tuple(frame.split(b"id: ", 1)[1].split(b"\n", 1)[0] for frame in frames)
    assert len(ids) == len(set(ids))
    assert ids == tuple(sorted(ids))
    with urlopen(Request(BASE + "/api/v1/live/events",
                         headers={"Last-Event-ID": ids[0].decode()}), timeout=5) as stream:
        assert b"event: snapshot" in _frame(stream)
        assert _frame(stream) == frames[1]
    with urlopen(Request(BASE + "/api/v1/live/events",
                         headers={"Last-Event-ID": "invalid"}), timeout=5) as stream:
        gap = _frame(stream)
        assert b"event: replay_gap" in gap
        assert b"event: snapshot" in _frame(stream)
    openapi = _get("/openapi.json")
    assert b"LiveAnalysisAccumulator" not in openapi
    for value in PRIVATE:
        assert value not in status + snapshot + b"".join(frames) + gap + openapi
    print("HTTP_AUDIT_PASS: schema 2, ordered mixed replay, gap, safe projection")


if __name__ == "__main__":
    main()
