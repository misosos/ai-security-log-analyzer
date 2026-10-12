"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync("frontend/live-monitoring.js", "utf8");
const id = "LIVE-SESSION-000001";
const eventId = (n) => `LIVE-EVENT-000001-${String(n).padStart(6, "0")}`;
const ids = ["live-monitoring", "live-service-state", "live-connection-state", "live-processing-state", "live-source-role", "live-summary", "live-show-pending", "live-pause", "live-reconnect", "live-pending-status", "live-error", "live-empty", "live-observations", "live-stale"];

class Node {
  constructor(tag = "p") { this.tagName = tag; this.children = []; this._text = ""; this.hidden = false; this.listeners = {}; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this._text = ""; this.children = nodes; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  click() { this.listeners.click(); }
}

function status() { return {
  schema_version: "1", service_state: "RUNNING", session_id: id, source_role: "application",
  worker_state: "READY", publication_state: "OPEN", latest_detection_revision: 0,
  available_event_count: 0, earliest_event_id: null, latest_event_id: null,
  active_observation_count: 0, published_total: 0, evicted_total: 0, replay_gap_total: 0,
  max_event_items: 32, max_event_bytes: 16384, max_connections: 2, active_connections: 0,
  fixed_error_code: null, recovery_action: null,
  interpretation_notices: [
    "규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.",
    "지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다."
  ],
  capabilities: ["READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM"]
}; }

function snapshot(revision = 0) { return {
  schema_version: "1", state: "OPEN", session_id: id, item_count: 0, byte_count: 0,
  max_items: 32, max_bytes: 16384, earliest_available_event_id: null,
  latest_available_event_id: null, latest_committed_detection_revision: revision,
  published_total: 0, evicted_total: 0, rejected_oversized_total: 0,
  replay_gap_total: 0, active_observation_count: 0, last_created_count: 0,
  last_updated_count: 0, last_no_longer_matches_count: 0
}; }

function event(n, changeType = "CREATED", revision = n) { return {
  event_id: eventId(n), session_id: id, revision, event_type: "DETECTION_CHANGE",
  created_count: Number(changeType === "CREATED"), updated_count: Number(changeType === "UPDATED"),
  no_longer_matches_count: Number(changeType === "NO_LONGER_MATCHES"), active_observation_count: 1,
  published_observation_count: 1, observations: [{
    observation_id: "LIVE-OBS-000001", observation_revision: n, change_type: changeType,
    state: changeType === "NO_LONGER_MATCHES" ? "NO_LONGER_MATCHES_CURRENT_RESULT" : "ACTIVE",
    detection_type: "brute_force", accumulator_revision: revision
  }]
}; }

async function app(responseStatus = 200, body = status()) {
  const nodes = Object.fromEntries(ids.map((key) => [key, new Node()]));
  for (const key of ["live-monitoring", "live-show-pending", "live-reconnect", "live-error", "live-stale"])
    nodes[key].hidden = true;
  const streams = [];
  const calls = [];
  let resultStatus = responseStatus;
  let resultBody = body;
  class EventSourceStub {
    constructor(url) { this.url = url; this.handlers = {}; this.closed = false; streams.push(this); }
    addEventListener(type, handler) { this.handlers[type] = handler; }
    close() { this.closed = true; }
    send(type, body, lastEventId = "") {
      if (!this.closed) this.handlers[type]({data: JSON.stringify(body), lastEventId});
    }
  }
  const document = {getElementById: (key) => nodes[key], createElement: (tag) => new Node(tag)};
  const window = {addEventListener: () => {}};
  const fetch = async (url, options) => {
    calls.push({url, options});
    return {status: resultStatus, ok: resultStatus < 400, json: async () => resultBody};
  };
  vm.runInNewContext(script, {document, window, fetch, EventSource: EventSourceStub, TextEncoder, Number, Map, Set, JSON});
  await new Promise((resolve) => setImmediate(resolve));
  return {nodes, streams, calls, setResponse: (code, value) => { resultStatus = code; resultBody = value; },
    flush: async () => new Promise((resolve) => setImmediate(resolve))};
}

async function main() {
  const disabled = await app(404, {error_code: "LIVE_MONITORING_NOT_ENABLED",
    user_message: "로컬 모니터링이 활성화되지 않았습니다.",
    recovery_action: "명시적 로컬 설정으로 서버를 실행하십시오.", retryable: false});
  assert.equal(disabled.calls.length, 1);
  assert.equal(disabled.streams.length, 0);
  assert.equal(disabled.nodes["live-monitoring"].hidden, true);
  const malformed = status(); malformed.max_event_items = true;
  const bad = await app(200, malformed);
  assert.equal(bad.streams.length, 0);
  assert.equal(bad.nodes["live-error"].hidden, false);
  const unknown = status(); unknown.private_path = "private-path-canary";
  const unknownApp = await app(200, unknown);
  assert.equal(unknownApp.streams.length, 0);
  assert.equal(unknownApp.nodes["live-error"].textContent.includes("private-path-canary"), false);

  const current = await app();
  assert.deepEqual(current.calls.map((call) => call.url), ["/api/v1/live/status"]);
  assert.equal(current.streams.length, 1);
  assert.match(current.nodes["live-processing-state"].textContent, /다음 로그 줄 대기/);
  assert.equal(current.streams[0].url, "/api/v1/live/events");
  const stream = current.streams[0];
  stream.onopen();
  assert.equal(current.nodes["live-connection-state"].textContent, "연결됨");
  stream.send("snapshot", snapshot());
  stream.send("observation_changes", event(1), eventId(1));
  assert.equal(current.nodes["live-observations"].children.length, 0, "staged, no automatic insertion");
  assert.equal(current.nodes["live-show-pending"].textContent, "새 결과 1건 보기");
  current.nodes["live-show-pending"].click();
  assert.equal(current.nodes["live-observations"].children.length, 1);
  assert.match(current.nodes["live-observations"].textContent, /반복 인증 실패 관찰/);
  current.nodes["live-pause"].click();
  stream.send("observation_changes", event(2, "UPDATED"), eventId(2));
  assert.equal(current.nodes["live-observations"].children.length, 1);
  assert.equal(current.nodes["live-show-pending"].hidden, true);
  current.nodes["live-pause"].click();
  current.nodes["live-show-pending"].click();
  assert.equal(current.nodes["live-observations"].children.length, 1, "update is bounded in place");
  stream.send("observation_changes", event(3, "NO_LONGER_MATCHES"), eventId(3));
  current.nodes["live-show-pending"].click();
  assert.match(current.nodes["live-observations"].textContent, /현재 탐지 결과에는 더 이상 일치하지 않음/);
  stream.send("heartbeat", {status: "CONNECTED"});
  assert.equal(current.nodes["live-pending-status"].textContent, "현재 표시할 관찰 변경 없음");
  stream.send("observation_changes", event(3, "NO_LONGER_MATCHES"), eventId(3));
  assert.equal(stream.closed, false, "same event ID is ignored once");
  stream.send("observation_changes", event(2, "UPDATED"), eventId(2));
  assert.equal(stream.closed, true, "decreasing event ID fails closed");

  const gapApp = await app();
  const gapStream = gapApp.streams[0];
  gapStream.send("replay_gap", {code: "EVICTED_EVENT_ID", snapshot: snapshot(), earliest_event_id: null,
    latest_event_id: null, recovery_action: "최신 snapshot부터 다시 시작하십시오."});
  assert.equal(gapStream.closed, true);
  assert.equal(gapApp.nodes["live-stale"].hidden, false);
  assert.equal(gapApp.nodes["live-reconnect"].hidden, false);
  assert.match(gapApp.nodes["live-error"].textContent, /이어받지 못했습니다/);
  gapApp.nodes["live-reconnect"].click(); await gapApp.flush();
  assert.equal(gapApp.streams.length, 2);
  assert.equal(gapApp.streams[1].url.includes("?"), false);

  const errors = await app();
  errors.streams[0].onerror(); errors.streams[0].onerror();
  assert.equal(errors.streams[0].closed, false);
  errors.streams[0].onerror();
  assert.equal(errors.streams[0].closed, true);
  assert.equal(errors.nodes["live-reconnect"].hidden, false);

  const terminal = await app();
  terminal.streams[0].send("service_status", {state: "FAILED", code: "LIVE_RUNNER_FAILED",
    recovery_action: "프로세스를 종료하고 로그와 설정을 확인한 뒤 다시 시작하십시오."});
  assert.match(terminal.nodes["live-service-state"].textContent, /모니터링 중단/);
  assert.equal(terminal.streams[0].closed, true);

  const ended = await app();
  ended.streams[0].send("stream_end", {code: "LIVE_STREAM_ENDED"});
  assert.equal(ended.streams[0].closed, true);
  assert.equal(ended.nodes["live-connection-state"].textContent, "연결 종료");
  assert.equal(ended.nodes["live-reconnect"].hidden, false, "ended stream offers manual recovery");
  assert.match(ended.nodes["live-error"].textContent, /서버 상태를 확인/);
  assert.equal(ended.streams.length, 1, "ended stream does not automatically reconnect");

  const malformedEvent = await app();
  const badPayload = event(1);
  badPayload.observations[0].detection_type = "unapproved-canary";
  malformedEvent.streams[0].send("observation_changes", badPayload, eventId(1));
  assert.equal(malformedEvent.streams[0].closed, true);
  assert.equal(malformedEvent.nodes["live-monitoring"].textContent.includes("unapproved-canary"), false);

  const overflow = await app();
  for (let n = 1; n <= 33 && !overflow.streams[0].closed; n += 1)
    overflow.streams[0].send("observation_changes", event(n), eventId(n));
  assert.equal(overflow.streams[0].closed, true);
  assert.equal(overflow.nodes["live-stale"].hidden, false);
  assert.match(overflow.nodes["live-error"].textContent, /반영하지 못한 변경/);
  await overflow.flush();
  assert.equal(overflow.calls.length, 2, "overflow refreshes safe status");
  assert.equal(overflow.streams.length, 1, "overflow never reconnects automatically");

  const byteOverflow = await app();
  for (let n = 1; n <= 5 && !byteOverflow.streams[0].closed; n += 1) {
    const wide = event(n);
    wide.observations = Array.from({length: 32}, (_, i) => ({
      observation_id: `LIVE-OBS-${String(i + 1).padStart(6, "0")}`,
      observation_revision: n, change_type: "CREATED", state: "ACTIVE",
      detection_type: "brute_force", accumulator_revision: n
    }));
    wide.created_count = 32;
    wide.published_observation_count = 32;
    byteOverflow.streams[0].send("observation_changes", wide, eventId(n));
  }
  assert.equal(byteOverflow.streams[0].closed, true, "byte overflow closes stream");
  assert.match(byteOverflow.nodes["live-error"].textContent, /반영하지 못한 변경/);
  assert.equal(byteOverflow.streams.length, 1);

  const degraded = await app();
  degraded.streams[0].send("service_status", {state: "DEGRADED", code: "LIVE_RUNNER_DEGRADED",
    recovery_action: "프로세스를 종료하고 다시 시작하십시오."});
  assert.match(degraded.nodes["live-service-state"].textContent, /확인 필요/);
  assert.equal(degraded.streams[0].closed, true);
  assert.equal(degraded.nodes["live-reconnect"].hidden, true);

  const stopping = await app();
  stopping.streams[0].send("service_status", {state: "STOPPED"});
  assert.equal(stopping.nodes["live-service-state"].textContent, "모니터링 종료");
  stopping.streams[0].send("stream_end", {code: "LIVE_STREAM_ENDED"});
  assert.equal(stopping.nodes["live-reconnect"].hidden, false);

  const statusFailure = await app(500, {unsafe: "private-path-canary"});
  assert.match(statusFailure.nodes["live-error"].textContent, /실시간 상태를 확인하지 못했습니다/);
  assert.equal(statusFailure.nodes["live-error"].textContent.includes("private-path-canary"), false);

  const noData = await app();
  noData.streams[0].send("snapshot", snapshot(1));
  assert.match(noData.nodes["live-empty"].textContent, /새 로그 줄은 처리됐지만/);
}

main().catch((error) => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; });
