"use strict";

// A tiny source-contract DOM stub: checks renderer logic, not browser layout or AT.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync("frontend/app.js", "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));

class Node {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.attributes = {};
    this._text = "";
    this.hidden = false;
    this.open = false;
    this.disabled = false;
    this.focused = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ""; }
  setAttribute(name, value) { this.attributes[name] = value; }
  focus() { this.focused = true; }
  addEventListener(name, listener) { this.listener = listener; }
}

const ids = [
  "sample-button", "sample-status", "error-summary", "error-message",
  "error-recovery", "results", "result-jump", "summary-cards",
  "case-list", "independent-list", "capability-message"
];

function nodesOf(root, tag) {
  return (root.tagName === tag ? [root] : []).concat(
    root.children.flatMap((child) => nodesOf(child, tag))
  );
}

function sectionNamed(root, name) {
  return nodesOf(root, "section").find((section) =>
    nodesOf(section, "h5").some((heading) => heading.textContent === name)
  );
}

function makeApp(initial) {
  const nodes = Object.fromEntries(ids.map((id) => [id, new Node("div")]));
  let response = initial;
  const document = {
    getElementById: (id) => nodes[id],
    createElement: (tag) => new Node(tag)
  };
  const fetch = async () => {
    const bytes = new TextEncoder().encode(JSON.stringify(response));
    let used = false;
    return {
      ok: true,
      headers: {get: (name) => name === "content-type" ? "application/json" : String(bytes.length)},
      body: {getReader: () => ({
        read: async () => {
          if (used) return {done: true};
          used = true;
          return {done: false, value: bytes};
        },
        releaseLock: () => {},
        cancel: async () => {}
      })}
    };
  };
  vm.runInNewContext(script, {document, fetch, TextDecoder, Uint8Array, Date});
  return {nodes, click: () => nodes["sample-button"].listener(), setResponse: (value) => { response = value; }};
}

function copy() { return JSON.parse(JSON.stringify(input)); }

async function main() {
  const app = makeApp(copy());
  await app.click();
  const nodes = app.nodes;
  assert.equal(nodes.results.hidden, false);
  assert.equal(nodes["error-summary"].hidden, true);
  assert.equal(nodes["case-list"].children.length, 2);
  assert.equal(nodes["independent-list"].children.length, 3);
  const [high, low] = nodes["case-list"].children;
  assert.equal(high.tagName, "details");
  assert.equal(high.open, true);
  assert.equal(low.open, false);
  assert.equal(nodesOf(high, "summary").length, 1);
  assert.equal(nodesOf(high, "time").length > 0, true);
  assert.equal(nodesOf(high, "time")[0].attributes.datetime.endsWith("Z"), true);
  assert.equal(nodesOf(high, "time")[0].textContent.includes("KST"), true);
  const caseRange = sectionNamed(high, "시간 범위");
  assert.ok(caseRange);
  const caseRangeList = nodesOf(caseRange, "dl")[0];
  assert.deepEqual(nodesOf(caseRangeList, "dt").map((item) => item.textContent), ["시작", "종료"]);
  assert.equal(caseRangeList.children.length, 2);
  for (const row of caseRangeList.children) {
    assert.deepEqual(nodesOf(row, "span").filter((item) => item.className === "time-zone-label")
      .map((item) => item.textContent), ["KST", "UTC"]);
    assert.equal(nodesOf(row, "time").length, 1);
  }
  const timeline = sectionNamed(high, "시간순 조사 흐름");
  const timelineList = nodesOf(timeline, "ol")[0];
  assert.equal(timelineList.children.length, input.cases[0].timeline.length);
  assert.equal(nodesOf(timelineList.children[0], "dl").length, 1, "Timeline range uses start/end blocks");
  assert.equal(nodesOf(timelineList.children[1], "dl").length, 0, "Timeline point uses two visible lines");
  assert.deepEqual(nodesOf(timelineList.children[1], "span").filter((item) => item.className === "time-zone-label")
    .map((item) => item.textContent), ["KST", "UTC"]);
  assert.equal(timelineList.textContent.includes("endpoint"), false);
  assert.equal(timelineList.textContent.includes("기존 상관분석에서 관계가 확인된 인증 관찰입니다."), true);
  assert.equal(nodesOf(high, "dl").some((list) => nodesOf(list, "dt").some((item) => item.textContent === "실패 횟수")), true);
  const detections = sectionNamed(high, "탐지 관찰");
  const relations = sectionNamed(high, "지원되는 관계");
  assert.equal(nodesOf(detections, "time").length, 0);
  assert.equal(nodesOf(relations, "time").length, 0);
  assert.equal(nodesOf(detections, "dt").some((item) => item.textContent === "실패 횟수"), true);
  assert.equal(nodesOf(detections, "dt").some((item) => item.textContent === "대상 계정 수"), true);
  assert.equal(nodesOf(detections, "dt").some((item) => item.textContent === "시간 범위"), true);
  assert.equal(nodesOf(relations, "dt").some((item) => item.textContent === "시간 차이"), true);
  assert.equal(high.textContent.includes("확인되지 않은 사항"), true);
  assert.equal(high.textContent.includes("다음 조사 단계"), true);
  assert.equal(high.textContent.includes("계정 별칭을 표시할 수 없음"), true);
  assert.equal(high.textContent.includes("ACCOUNT_REFERENCE_UNAVAILABLE"), false);
  assert.equal(nodes["independent-list"].textContent.includes("Password Spraying-like"), true);
  assert.equal(nodes["independent-list"].textContent.includes("Path Traversal"), true);
  assert.equal(nodesOf(nodes["independent-list"], "dt").some((item) => item.textContent === "실패 횟수"), true);

  const medium = copy();
  medium.cases[1].included_highest_risk = "MEDIUM";
  medium.case_summary.medium_case_count = 1;
  medium.case_summary.low_case_count = 0;
  app.setResponse(medium);
  await app.click();
  assert.equal(nodes["case-list"].children[1].open, true, "MEDIUM disclosure");

  const microseconds = copy();
  const firstTime = microseconds.cases[0].timeline[0].start_time;
  firstTime.display_utc = firstTime.display_utc.replace("Z", ".123456Z");
  firstTime.display_kst = firstTime.display_kst.replace(" KST", ".123456 KST");
  app.setResponse(microseconds);
  await app.click();
  assert.equal(nodes.results.hidden, false, "microsecond response accepted");
  assert.equal(nodesOf(nodes["case-list"], "time").some((node) => node.attributes.datetime.includes(".123456Z")), true, "microseconds retained");
  assert.equal(nodesOf(nodes["case-list"], "time").some((node) => node.textContent.includes(".123456 KST")), true, "microseconds visible");

  const noTime = copy();
  const finalEntry = noTime.cases[0].timeline.at(-1);
  finalEntry.start_time = null;
  finalEntry.end_time = null;
  finalEntry.timestamp_state = "NO_TIME";
  finalEntry.timestamp_state_label = "시간 정보 없음";
  app.setResponse(noTime);
  await app.click();
  assert.equal(nodes.results.hidden, false, "no-time response accepted");
  assert.equal(nodes["case-list"].textContent.includes("시간 정보 없음"), true, "no-time visible");

  const mutations = [
    (value) => { value.cases[1].review_order = 1; },
    (value) => { value.cases[0].timeline[0].sequence = 2; },
    (value) => { value.cases[0].timeline[0].start_time.display_utc = "not-a-time"; },
    (value) => { value.cases[0].included_highest_risk = "UNKNOWN"; },
    (value) => { value.cases[0].timeline[0].category = "INVENTED"; },
    (value) => { value.cases[0].timeline[0].evidence[0].label = "raw evidence"; },
    (value) => { value.cases[0].next_steps.push(value.cases[0].next_steps[0]); },
    (value) => { value.cases[0].next_steps[0].text = "IP를 차단하십시오."; },
    (value) => { value.cases[0].included_highest_confidence = "UNKNOWN"; },
    (value) => { value.cases[0].account_alias_state = "ACCOUNT_REFERENCE_UNAVAILABLE"; }
  ];
  for (const mutate of mutations) {
    const malformed = copy();
    mutate(malformed);
    app.setResponse(malformed);
    await app.click();
    assert.equal(nodes.results.hidden, true);
    assert.equal(nodes["case-list"].children.length, 0);
    assert.equal(nodes["error-summary"].hidden, false);
    assert.equal(nodes["error-summary"].focused, true);
    assert.equal(nodes["error-message"].textContent, "결과 형식을 확인할 수 없습니다.");
    assert.equal(nodes["error-message"].textContent.includes("raw evidence"), false);
    assert.equal(nodes["sample-button"].disabled, false);
  }

  const empty = copy();
  empty.cases = [];
  empty.independent_observations = [];
  empty.case_summary = {
    case_count: 0, independent_observation_count: 0, high_case_count: 0,
    medium_case_count: 0, low_case_count: 0, relation_case_count: 0,
    no_time_observation_count: 0
  };
  app.setResponse(empty);
  await app.click();
  assert.equal(nodes.results.hidden, false);
  assert.equal(nodes["case-list"].textContent.includes("보안 문제가 없다는 의미가 아닙니다"), true);
  assert.equal(nodes["independent-list"].textContent, "별도로 표시할 독립 관찰이 없습니다.");
  process.stdout.write("renderer logic verified\n");
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
