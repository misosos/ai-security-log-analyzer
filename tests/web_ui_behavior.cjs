"use strict";

// A tiny source-contract DOM stub: checks renderer logic, not browser layout or AT.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync("frontend/app.js", "utf8");
const supplied = JSON.parse(fs.readFileSync(0, "utf8"));
const input = supplied.sample || supplied;

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
    this.files = [];
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  append(...children) { children.forEach((child) => { child.parent = this; }); this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ""; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.focused = true; }
  addEventListener(name, listener) { this.listener = listener; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this);
  }
}

const ids = [
  "sample-button", "sample-status", "error-summary", "error-message",
  "error-recovery", "error-retry", "results", "result-jump", "summary-cards",
  "case-list", "independent-list", "capability-message", "report-download", "report-button",
  "local-form", "local-upload", "local-button", "local-status", "results-heading", "result-context",
  "application-file", "ssh-file", "access-file",
  "application-error", "ssh-error", "access-error"
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

function makeApp(initial, hostname = "127.0.0.1") {
  const nodes = Object.fromEntries(ids.map((id) => [id, new Node("div")]));
  let response = initial;
  let httpStatus = 200;
  let fetchCount = 0;
  let pendingFetch = null;
  let failFetch = false;
  const fetchCalls = [];
  const downloads = [];
  const revoked = [];
  const body = new Node("body");
  const objectUrl = {
    createObjectURL: (file) => {
      downloads.push({file, clicked: false, filename: null});
      return "test-object-url";
    },
    revokeObjectURL: (value) => revoked.push(value)
  };
  const document = {
    getElementById: (id) => nodes[id],
    body,
    createElement: (tag) => {
      const node = new Node(tag);
      if (tag === "a") node.click = () => {
        downloads.at(-1).clicked = true;
        downloads.at(-1).filename = node.download;
      };
      return node;
    }
  };
  class FormDataStub {
    constructor() { this.entries = []; }
    append(field, file) { this.entries.push([field, file]); }
  }
  const fetch = async (url, options) => {
    fetchCount += 1;
    fetchCalls.push({url, options});
    if (pendingFetch) await pendingFetch;
    if (failFetch) throw new Error("private-network-detail");
    const bytes = new TextEncoder().encode(JSON.stringify(response));
    let used = false;
    return {
      ok: httpStatus < 400,
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
  vm.runInNewContext(script, {document, fetch, FormData: FormDataStub,
    window: {location: {hostname}},
    TextDecoder, TextEncoder, Uint8Array, Date, Blob, URL: objectUrl});
  return {
    nodes, downloads, revoked, body,
    click: () => nodes["sample-button"].listener(),
    submit: () => nodes["local-form"].listener({preventDefault: () => {}}),
    download: () => nodes["report-button"].listener(),
    fetchCount: () => fetchCount,
    fetchCalls,
    setHttpStatus: (value) => { httpStatus = value; },
    setResponse: (value) => { response = value; },
    holdFetch: () => {
      let release;
      pendingFetch = new Promise((resolve) => { release = resolve; });
      return () => { pendingFetch = null; release(); };
    },
    setNetworkFailure: (value) => { failFetch = value; }
  };
}

function copy() { return JSON.parse(JSON.stringify(input)); }

async function main() {
  const remote = makeApp(copy(), "public.example");
  assert.equal(remote.nodes["local-upload"].hidden, true);
  await remote.submit();
  assert.equal(remote.fetchCount(), 0, "remote landing cannot submit local files");
  const app = makeApp(copy());
  await app.click();
  const nodes = app.nodes;
  assert.equal(nodes.results.hidden, false);
  assert.equal(nodes["error-summary"].hidden, true);
  assert.equal(nodes["case-list"].children.length, 2);
  assert.equal(nodes["independent-list"].children.length, 3);
  assert.equal(nodes["report-download"].hidden, false);
  assert.equal(app.downloads.length, 0, "no automatic download");
  const callsBeforeDownload = app.fetchCount();
  app.download();
  assert.equal(app.fetchCount(), callsBeforeDownload, "download does not refetch");
  assert.equal(app.downloads.length, 1);
  assert.equal(app.downloads[0].clicked, true);
  assert.equal(app.downloads[0].filename, "investigation-report.html");
  assert.equal(app.downloads[0].file.type, "text/html;charset=utf-8");
  assert.equal(app.downloads[0].file.size, input.report_export.byte_count);
  assert.equal(input.report_export.html.includes("교육용 합성 샘플 결과입니다"), true);
  assert.deepEqual(app.revoked, ["test-object-url"]);
  assert.equal(app.body.children.length, 0, "temporary anchor removed");
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
    (value) => { value.cases[0].account_alias_state = "ACCOUNT_REFERENCE_UNAVAILABLE"; },
    (value) => { value.report_export.byte_count += 1; },
    (value) => { value.report_export.html = "x".repeat(32769); },
    (value) => { value.report_export.html = "<script>bad</script>"; },
    (value) => { value.report_export.html = value.report_export.html.replace("교육용 합성 샘플 결과입니다.", ""); }
  ];
  for (const mutate of mutations) {
    const malformed = copy();
    mutate(malformed);
    app.setResponse(malformed);
    await app.click();
    assert.equal(nodes.results.hidden, true);
    assert.equal(nodes["case-list"].children.length, 0);
    assert.equal(nodes["report-download"].hidden, true);
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
  if (supplied.local) {
    const local = makeApp(supplied.local);
    const selected = {name: "browser-only-name.log"};
    ["application-file", "ssh-file", "access-file"].forEach((id) => {
      local.nodes[id].files = [selected];
    });
    await local.submit();
    assert.equal(local.nodes.results.hidden, false);
    assert.equal(local.nodes["results-heading"].textContent, "로컬 실제 로그 분석 결과");
    assert.equal(local.nodes["result-context"].textContent.includes("합성 샘플"), false);
    assert.equal(local.nodes["case-list"].children.length, 2);
    assert.equal(local.nodes["independent-list"].children.length, 3);
    assert.equal(local.fetchCalls.length, 1);
    assert.equal(local.fetchCalls[0].url, "/api/v1/investigations");
    assert.equal(local.fetchCalls[0].options.method, "POST");
    assert.equal(local.fetchCalls[0].options.headers["Content-Type"], undefined);
    assert.deepEqual(local.fetchCalls[0].options.body.entries.map(([field]) => field),
      ["application_file", "ssh_file", "access_file"]);
    assert.equal(local.nodes["case-list"].textContent.includes(selected.name), false);
    const before = local.fetchCount();
    local.download();
    assert.equal(local.fetchCount(), before);
    assert.equal(local.downloads.at(-1).filename, "investigation-report.html");
    assert.equal(local.revoked.at(-1), "test-object-url");
    local.setResponse({
      error_code: "INVALID_UTF8", user_message: "UTF-8 로그로 읽을 수 없습니다.",
      recovery_action: "UTF-8 텍스트 파일을 선택하십시오.", retryable: false,
      field: "ssh_file"
    });
    local.setHttpStatus(400);
    await local.submit();
    assert.equal(local.nodes.results.hidden, true, "failure discards prior local result");
    assert.equal(local.nodes["report-download"].hidden, true);
    assert.equal(local.nodes["error-summary"].focused, true);
    assert.equal(local.nodes["ssh-error"].hidden, false);
    assert.equal(local.nodes["ssh-file"].attributes["aria-invalid"], "true");
    assert.equal(local.nodes["error-message"].textContent, "UTF-8 로그로 읽을 수 없습니다.");
    assert.equal(local.nodes["error-retry"].textContent.includes("그대로 재시도하지 마세요"), true);
    assert.equal(local.nodes["local-button"].disabled, false);
    local.setResponse({
      error_code: "PARSER_INCOMPATIBLE", user_message: "지원하는 로그 형식이 아닙니다.",
      recovery_action: "파일 종류와 입력칸을 확인한 뒤 다시 선택하십시오.",
      retryable: false, field: "application_file"
    });
    await local.submit();
    assert.equal(local.nodes["application-error"].hidden, false);
    assert.equal(local.nodes["error-recovery"].textContent.includes("입력칸"), true);
    local.setResponse({
      error_code: "RATE_LIMITED", user_message: "로컬 분석 요청 횟수 한도에 도달했습니다.",
      recovery_action: "잠시 후 다시 시도하십시오.", retryable: true, field: null
    });
    local.setHttpStatus(429);
    await local.submit();
    assert.equal(local.nodes["error-retry"].textContent.includes("재시도 가능"), true);
    assert.equal(local.nodes["error-summary"].focused, true);
    const mismatched = {
      error_code: "INVALID_UTF8", user_message: "UTF-8 로그로 읽을 수 없습니다.",
      recovery_action: "잠시 후 다시 시도하십시오.", retryable: true, field: "ssh_file"
    };
    local.setResponse(mismatched);
    await local.submit();
    assert.equal(local.nodes["error-message"].textContent, "결과 형식을 확인할 수 없습니다.");
    assert.equal(local.nodes["ssh-error"].hidden, true);
    local.setResponse({
      error_code: "INVALID_UTF8", user_message: "raw-private-canary",
      recovery_action: "UTF-8 텍스트 파일을 선택하십시오.", retryable: false,
      field: "ssh_file"
    });
    await local.submit();
    assert.equal(local.nodes["error-message"].textContent.includes("raw-private-canary"), false);
    local.setResponse(supplied.local);
    local.setHttpStatus(200);
    local.nodes["ssh-file"].files = [];
    await local.submit();
    assert.equal(local.nodes["error-summary"].focused, true);
    assert.equal(local.nodes["ssh-error"].hidden, false);
    assert.equal(local.nodes["ssh-file"].attributes["aria-invalid"], "true");
    assert.equal(local.nodes.results.hidden, true);
    local.nodes["ssh-file"].files = [selected];
    await local.submit();
    assert.equal(local.nodes.results.hidden, false, "missing-file recovery succeeds");
    const release = local.holdFetch();
    const beforeConcurrent = local.fetchCount();
    const firstRequest = local.submit();
    await local.submit();
    assert.equal(local.fetchCount(), beforeConcurrent + 1, "duplicate submit is ignored");
    assert.equal(local.nodes["local-button"].disabled, true);
    release();
    await firstRequest;
    assert.equal(local.nodes["local-button"].disabled, false);
    local.setNetworkFailure(true);
    await local.submit();
    assert.equal(local.nodes.results.hidden, true);
    assert.equal(local.nodes["report-download"].hidden, true);
    assert.equal(local.nodes["error-message"].textContent.includes("private-network-detail"), false);
    local.setNetworkFailure(false);
    local.setResponse(copy());
    await local.click();
    assert.equal(local.nodes["ssh-error"].hidden, true, "sample restart clears local field errors");
    assert.equal(local.nodes.results.hidden, false);
  }
  process.stdout.write("renderer logic verified\n");
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n`);
  process.exitCode = 1;
});
