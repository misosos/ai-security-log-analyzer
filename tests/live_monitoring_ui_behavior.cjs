"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync("frontend/live-monitoring.js", "utf8");
const id = "LIVE-SESSION-000001";
const eventId = (n) => `LIVE-EVENT-000001-${String(n).padStart(6, "0")}`;
const ids = ["live-monitoring", "live-service-state", "live-connection-state", "live-processing-state", "live-source-role", "live-summary", "live-show-pending", "live-pause", "live-reconnect", "live-pending-status", "live-error", "live-result-details", "live-empty", "live-observations", "live-relations", "live-risks", "live-cases", "live-relations-empty", "live-risks-empty", "live-cases-empty", "live-stale"];

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
  schema_version: "2", service_state: "RUNNING", session_id: id, source_role: "application",
  worker_state: "READY", publication_state: "OPEN", latest_detection_revision: 0,
  available_event_count: 0, earliest_event_id: null, latest_event_id: null,
  active_observation_count: 0, published_total: 0, evicted_total: 0, replay_gap_total: 0,
  max_event_items: 32, max_event_bytes: 16384, max_connections: 2, active_connections: 0,
  fixed_error_code: null, recovery_action: null,
  analysis_available: true, analysis_revision: 0, active_relation_count: 0,
  active_risk_count: 0, active_case_count: 0, analysis_state: "AVAILABLE",
  interpretation_notices: [
    "규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.",
    "지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다."
  ],
  capabilities: ["READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM"]
}; }

function snapshot(revision = 0) { return {
  schema_version: "2", state: "OPEN", session_id: id, item_count: 0, byte_count: 0,
  max_items: 32, max_bytes: 16384, earliest_available_event_id: null,
  latest_available_event_id: null, latest_committed_detection_revision: revision,
  published_total: 0, evicted_total: 0, rejected_oversized_total: 0,
  replay_gap_total: 0, active_observation_count: 0, last_created_count: 0,
  last_updated_count: 0, last_no_longer_matches_count: 0,
  analysis: {schema_version: "1", analysis_available: true, revision,
    relation_count: 0, risk_count: 0, case_count: 0, independent_observation_count: 0,
    relations: [], risks: [], cases: [], bounded_warnings: []}
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

function analysisEvent(n, revision) { return {
  event_id: eventId(n), session_id: id, revision, event_type: "ANALYSIS_CHANGE",
  source_role: "application", relation_changes: [{relation_id: "LIVE-REL-000001",
    revision: 1, relation_type: "failed_to_successful_login", state: "ACTIVE",
    delta_seconds: 2, change_type: "RELATION_CREATED"}],
  risk_changes: [{risk_id: "LIVE-RISK-000001", revision: 1, state: "CURRENT",
    risk_level: "HIGH", confidence: "HIGH", change_type: "RISK_CREATED"}],
  case_changes: [{case_id: "LIVE-CASE-000001", revision: 1, state: "CURRENT",
    rule_id: "CASE-AUTH-TRANSITION-01", included_highest_risk: "HIGH",
    included_highest_confidence: "HIGH", relation_count: 1, observation_count: 1,
    supporting_relation_count: 0, account_reference_status: "ACCOUNT_REFERENCE_UNAVAILABLE",
    change_type: "CASE_CREATED"}],
  summary: {relation_count: 1, risk_count: 1, case_count: 1}, bounded_warnings: []
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

  const browserSafe = status();
  browserSafe.session_id = "LIVE-SESSION-9007199254740991";
  const largeSession = await app(200, browserSafe);
  assert.equal(largeSession.streams.length, 1, "browser-safe process session ID is accepted");
  const largeSnapshot = snapshot();
  largeSnapshot.session_id = browserSafe.session_id;
  largeSession.streams[0].send("snapshot", largeSnapshot);
  assert.equal(largeSession.streams[0].closed, false);

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
  assert.equal(current.nodes["live-result-details"].open, true, "user applies and reveals details");
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
  assert.equal(current.nodes["live-pending-status"].textContent, "새로 확인할 결과 없음");
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
  assert.match(terminal.nodes["live-service-state"].textContent, /모니터링 종료됨/);
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

  const analysisApp = await app();
  const analysisStream = analysisApp.streams[0];
  analysisStream.send("snapshot", snapshot());
  analysisStream.send("observation_changes", event(1), eventId(1));
  analysisStream.send("analysis_changes", analysisEvent(2, 1), eventId(2));
  assert.equal(analysisApp.nodes["live-relations"].children.length, 0, "analysis remains staged");
  assert.equal(analysisApp.nodes["live-show-pending"].textContent, "새 결과 2건 보기");
  analysisApp.nodes["live-show-pending"].click();
  assert.match(analysisApp.nodes["live-relations"].textContent, /인증 실패 후 로그인 성공 관계/);
  assert.match(analysisApp.nodes["live-risks"].textContent, /HIGH/);
  assert.match(analysisApp.nodes["live-cases"].textContent, /계정 별칭을 표시할 수 없음/);
  const noLonger = analysisEvent(3, 2);
  noLonger.relation_changes[0].revision = 2;
  noLonger.relation_changes[0].state = "NO_LONGER_MATCHES_CURRENT_RESULT";
  noLonger.relation_changes[0].change_type = "RELATION_NO_LONGER_MATCHES";
  noLonger.risk_changes[0].revision = 2;
  noLonger.risk_changes[0].state = "NO_LONGER_PRESENT";
  noLonger.risk_changes[0].change_type = "RISK_NO_LONGER_PRESENT";
  noLonger.case_changes[0].revision = 2;
  noLonger.case_changes[0].state = "NO_LONGER_MATCHES_CURRENT_RESULT";
  noLonger.case_changes[0].change_type = "CASE_NO_LONGER_MATCHES";
  noLonger.summary = {relation_count: 0, risk_count: 0, case_count: 0};
  analysisStream.send("analysis_changes", noLonger, eventId(3));
  assert.equal(analysisApp.nodes["live-show-pending"].textContent, "새 결과 1건 보기");
  analysisApp.nodes["live-show-pending"].click();
  assert.match(analysisApp.nodes["live-relations"].textContent, /더 이상 일치하지 않음/);
  assert.match(analysisApp.nodes["live-risks"].textContent, /더 이상 포함되지 않음/);
  assert.match(analysisApp.nodes["live-cases"].textContent, /더 이상 일치하지 않음/);
  const malformedAnalysis = await app();
  const privatePayload = analysisEvent(1, 1);
  privatePayload.case_changes[0].subject_ip = "PRIVATE_IP_CANARY";
  malformedAnalysis.streams[0].send("analysis_changes", privatePayload, eventId(1));
  assert.equal(malformedAnalysis.streams[0].closed, true);
  assert.equal(malformedAnalysis.nodes["live-cases"].children.length, 0);
  assert.equal(malformedAnalysis.nodes["live-monitoring"].textContent.includes("PRIVATE_IP_CANARY"), false);

  const sshStatus = status();
  sshStatus.source_role = "ssh";
  const sshApp = await app(200, sshStatus);
  sshApp.streams[0].send("snapshot", snapshot());
  const sshAnalysis = analysisEvent(1, 1);
  sshAnalysis.source_role = "ssh";
  sshApp.streams[0].send("analysis_changes", sshAnalysis, eventId(1));
  assert.equal(sshApp.nodes["live-relations"].children.length, 0);
  assert.equal(sshApp.nodes["live-risks"].children.length, 0);
  assert.equal(sshApp.nodes["live-cases"].children.length, 0);
  sshApp.nodes["live-show-pending"].click();
  assert.equal(sshApp.nodes["live-relations"].children.length, 1);
  assert.equal(sshApp.nodes["live-risks"].children.length, 1);
  assert.equal(sshApp.nodes["live-cases"].children.length, 1);
  sshApp.streams[0].send("analysis_changes", sshAnalysis, eventId(1));
  assert.equal(sshApp.nodes["live-relations"].children.length, 1, "SSH duplicate event ID is ignored");
  const wrongSource = await app(200, sshStatus);
  wrongSource.streams[0].send("analysis_changes", analysisEvent(1, 1), eventId(1));
  assert.equal(wrongSource.streams[0].closed, true);
  const sshFileAccess = await app(200, sshStatus);
  const invalidRelation = analysisEvent(1, 1);
  invalidRelation.source_role = "ssh";
  invalidRelation.relation_changes[0].relation_type = "successful_login_to_file_access";
  sshFileAccess.streams[0].send("analysis_changes", invalidRelation, eventId(1));
  assert.equal(sshFileAccess.streams[0].closed, true);

  const accessStatus = status();
  accessStatus.source_role = "access";
  accessStatus.analysis_available = false;
  accessStatus.analysis_revision = null;
  accessStatus.analysis_state = "UNAVAILABLE";
  const accessApp = await app(200, accessStatus);
  const accessSnapshot = snapshot();
  accessSnapshot.analysis.analysis_available = false;
  accessSnapshot.analysis.revision = null;
  accessApp.streams[0].send("snapshot", accessSnapshot);
  assert.match(accessApp.nodes["live-relations-empty"].textContent, /지원하지 않습니다/);

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
  assert.match(degraded.nodes["live-service-state"].textContent, /연결에 문제가 있음/);
  assert.equal(degraded.streams[0].closed, true);
  assert.equal(degraded.nodes["live-reconnect"].hidden, true);

  const stopping = await app();
  stopping.streams[0].send("service_status", {state: "STOPPED"});
  assert.equal(stopping.nodes["live-service-state"].textContent, "모니터링 종료됨");
  stopping.streams[0].send("stream_end", {code: "LIVE_STREAM_ENDED"});
  assert.equal(stopping.nodes["live-reconnect"].hidden, false);

  const statusFailure = await app(500, {unsafe: "private-path-canary"});
  assert.match(statusFailure.nodes["live-error"].textContent, /실시간 상태를 확인하지 못했습니다/);
  assert.equal(statusFailure.nodes["live-error"].textContent.includes("private-path-canary"), false);

  const noData = await app();
  noData.streams[0].send("snapshot", snapshot(1));
  assert.match(noData.nodes["live-empty"].textContent, /새 로그 줄은 처리됐지만/);

  if (process.env.LIVE_UI_BENCHMARK === "1") {
    const timings = [];
    for (let sample = 0; sample < 12; sample += 1) {
      const measured = await app();
      const source = measured.streams[0];
      source.send("snapshot", snapshot());
      for (let n = 1; n <= 32; n += 1)
        source.send("observation_changes", event(n), eventId(n));
      assert.equal(source.closed, false);
      const start = process.hrtime.bigint();
      measured.nodes["live-show-pending"].click();
      timings.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    timings.sort((a, b) => a - b);
    process.stdout.write(JSON.stringify({samples: timings.length,
      median_ms: (timings[5] + timings[6]) / 2,
      p95_ms: timings[11], max_ms: timings[11]}) + "\n");
  }
}

main().catch((error) => { process.stderr.write(`${error.stack}\n`); process.exitCode = 1; });
