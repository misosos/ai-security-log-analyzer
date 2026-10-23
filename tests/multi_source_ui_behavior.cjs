"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const script = fs.readFileSync("frontend/multi-source-live.js", "utf8");

class Node {
  constructor(id = "") { this.id = id; this.dataset = {}; this.children = []; this.hidden = false; this.attributes = {}; this.listeners = {}; this._text = ""; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((item) => item.textContent).join(""); }
  setAttribute(key, value) { this.attributes[key] = value; }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  replaceChildren(...items) { this._text = ""; this.children = items; }
  appendChild(item) { this.children.push(item); }
  click() { this.listeners.click(); }
}
const ids = ["live-pair", "live-result-details", "pair-overall", "pair-role-heading", "pair-role-state", "pair-role-counts", "pair-recovery", "pair-app-badge", "pair-ssh-badge", "pair-apply", "pair-pause", "pair-pending", "pair-observations", "pair-relations", "pair-risks", "pair-cases"];
const nodes = Object.fromEntries(ids.map((id) => [id, new Node(id)]));
const buttons = ["application", "ssh"].map((role) => { const button = new Node(); button.dataset.pairRole = role; return button; });
const streams = [];
class Stream {
  constructor(url) { this.url = url; this.handlers = {}; this.closed = false; streams.push(this); }
  addEventListener(type, fn) { this.handlers[type] = fn; }
  close() { this.closed = true; }
  send(type, value, id = "") { this.handlers[type]({data: JSON.stringify(value), lastEventId: id}); }
}
const document = {getElementById: (id) => nodes[id], querySelectorAll: () => buttons,
  createElement: (tag) => new Node(tag)};
const window = {};
vm.runInNewContext(script, {document, window, EventSource: Stream, TextEncoder, Number, Set, JSON});

const role = (name) => ({role: name, service_state: "RUNNING", detection_revision: 0, analysis_revision: 0,
  active_observation_count: 0, active_relation_count: 0, active_risk_count: 0, active_case_count: 0,
  checkpoint_available: true, last_step_code: "NO_DATA"});
const status = {schema_version: "3", service_state: "RUNNING", session_id: "LIVE-SESSION-000001",
  roles: [role("application"), role("ssh")], available_event_count: 0, event_byte_count: 0,
  earliest_event_id: null, latest_event_id: null, published_total: 0, evicted_total: 0,
  replay_gap_total: 0, max_event_items: 32, max_event_bytes: 16384, max_connections: 2,
  active_connections: 0, fixed_error_code: null, interpretation_notices: ["safe", "safe"],
  capabilities: ["READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM"]};
(async () => {
assert.equal(await window.MultiSourceLive.start({...status, roles: [{...role("application"), source_path: "PRIVATE_CANARY"}, role("ssh")]}), false);
assert.equal(await window.MultiSourceLive.start(status), true);
assert.equal(streams.length, 1);
assert.match(nodes["pair-overall"].textContent, /함께 확인/);

const event = {schema_version: "3", event_id: "LIVE-EVENT-000001-000001", session_id: status.session_id,
  revision: 1, event_type: "observation_changes", source_role: "application", detection_revision: 1,
  analysis_revision: 1, created_count: 1, updated_count: 0, no_longer_matches_count: 0,
  active_observation_count: 1, published_observation_count: 1, observations: [{
    observation_id: "LIVE-OBS-000001", observation_revision: 1, change_type: "CREATED", state: "ACTIVE",
    detection_type: "brute_force", accumulator_revision: 1
  }]};
streams[0].send("observation_changes", event, event.event_id);
assert.equal(nodes["pair-apply"].hidden, false);
assert.match(nodes["pair-pending"].textContent, /1건/);
nodes["pair-apply"].click();
assert.match(nodes["pair-observations"].textContent, /로그인 실패가 반복된 관찰/);
assert.doesNotMatch(nodes["pair-observations"].textContent, /brute_force|revision|schema/);
streams[0].send("observation_changes", event, event.event_id);
assert.equal(streams[0].closed, true);
assert.equal(nodes["pair-recovery"].hidden, false);
buttons[1].click();
assert.equal(nodes["pair-role-heading"].textContent, "SSH 인증 로그");
assert.equal(nodes["pair-observations"].textContent, "");
assert.equal(buttons[1].attributes["aria-pressed"], "true");
assert.equal(await window.MultiSourceLive.start(status), true);
streams[1].send("service_status", {schema_version: "3", state: "FAILED", code: "PAIR_RUNNER_FAILED"});
assert.match(nodes["pair-overall"].textContent, /확인/);
assert.doesNotMatch(nodes["pair-overall"].textContent, /함께 확인/);
assert.equal(nodes["pair-recovery"].hidden, false);
assert.doesNotMatch(nodes["pair-recovery"].textContent, /PAIR_RUNNER_FAILED/);
console.log("multi-source UI staged role behavior: PASS");
})().catch((error) => { console.error(error); process.exitCode = 1; });
