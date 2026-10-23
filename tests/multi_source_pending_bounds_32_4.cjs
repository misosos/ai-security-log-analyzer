"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const source = fs.readFileSync("frontend/multi-source-live.js", "utf8");

function harness() {
  class Node {
    constructor(id = "") { this.id = id; this.dataset = {}; this.children = []; this.hidden = false; this.attributes = {}; this.listeners = {}; this._text = ""; }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
    setAttribute(key, value) { this.attributes[key] = value; }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    replaceChildren(...items) { this._text = ""; this.children = items; }
    appendChild(item) { this.children.push(item); }
    click() { this.listeners.click(); }
  }
  const ids = ["live-pair", "live-result-details", "pair-overall", "pair-role-heading", "pair-role-state",
    "pair-role-counts", "pair-recovery", "pair-app-badge", "pair-ssh-badge", "pair-apply", "pair-pause",
    "pair-pending", "pair-observations", "pair-relations", "pair-risks", "pair-cases"];
  const nodes = Object.fromEntries(ids.map((id) => [id, new Node(id)]));
  const buttons = ["application", "ssh"].map((role) => {
    const item = new Node(); item.dataset.pairRole = role; return item;
  });
  const streams = [];
  class EventSource {
    constructor() { this.handlers = {}; this.closed = false; streams.push(this); }
    addEventListener(type, fn) { this.handlers[type] = fn; }
    close() { this.closed = true; }
    send(type, value, id) { this.handlers[type]({data: JSON.stringify(value), lastEventId: id}); }
  }
  const document = {getElementById: (id) => nodes[id], querySelectorAll: () => buttons,
    createElement: (name) => new Node(name)};
  const window = {};
  vm.runInNewContext(source, {document, window, EventSource, TextEncoder, Number, Set, JSON, BigInt});
  const role = (name) => ({role: name, service_state: "RUNNING", detection_revision: 0, analysis_revision: 0,
    active_observation_count: 0, active_relation_count: 0, active_risk_count: 0, active_case_count: 0,
    checkpoint_available: false, last_step_code: "NO_DATA"});
  const status = {schema_version: "3", service_state: "RUNNING", session_id: "LIVE-SESSION-000001",
    roles: [role("application"), role("ssh")], available_event_count: 0, event_byte_count: 0,
    earliest_event_id: null, latest_event_id: null, published_total: 0, evicted_total: 0,
    replay_gap_total: 0, max_event_items: 32, max_event_bytes: 16384, max_connections: 2,
    active_connections: 0, fixed_error_code: null, interpretation_notices: ["safe", "safe"],
    capabilities: ["READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_LLM"]};
  window.MultiSourceLive.start(status);
  return {nodes, streams, buttons, status};
}

function observation(number, observations = undefined) {
  const eventId = `LIVE-EVENT-000001-${String(number).padStart(6, "0")}`;
  return {event_id: eventId, session_id: "LIVE-SESSION-000001", revision: number,
    event_type: "observation_changes", source_role: number % 2 ? "application" : "ssh",
    schema_version: "3", detection_revision: number, analysis_revision: 0,
    created_count: 1, updated_count: 0, no_longer_matches_count: 0,
    active_observation_count: 1, published_observation_count: 1,
    observations: observations || [{observation_id: `LIVE-OBS-${String(number).padStart(6, "0")}`,
      observation_revision: number, change_type: "CREATED", state: "ACTIVE",
      detection_type: "brute_force", accumulator_revision: number}]};
}

{
  const {nodes, streams} = harness();
  nodes["pair-pause"].click();
  streams[0].send("observation_changes", observation(1), observation(1).event_id);
  assert.equal(nodes["pair-apply"].hidden, true);
  assert.match(nodes["pair-pending"].textContent, /일시 정지/);
  nodes["pair-pause"].click();
  assert.equal(nodes["pair-apply"].hidden, false);
  nodes["pair-apply"].click();
  for (let n = 2; n <= 33; n++) {
    const value = observation(n);
    streams[0].send("observation_changes", value, value.event_id);
  }
  assert.equal(nodes["pair-apply"].hidden, false);
  const overflow = observation(34);
  streams[0].send("observation_changes", overflow, overflow.event_id);
  assert.equal(streams[0].closed, true);
  assert.equal(nodes["pair-recovery"].hidden, false);
}

{
  const {nodes, streams} = harness();
  const many = Array.from({length: 160}, (_, index) => ({
    observation_id: `LIVE-OBS-${String(index + 1).padStart(6, "0")}`,
    observation_revision: 1, change_type: "CREATED", state: "ACTIVE",
    detection_type: "brute_force", accumulator_revision: 1,
  }));
  const value = observation(1, many);
  assert.ok(Buffer.byteLength(JSON.stringify(value)) > 16384);
  streams[0].send("observation_changes", value, value.event_id);
  assert.equal(streams[0].closed, true);
  assert.equal(nodes["pair-recovery"].hidden, false);
}

console.log("schema 3 pause, 32-item pending bound, and 16 KiB bound: PASS");
