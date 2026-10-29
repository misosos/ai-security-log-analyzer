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
    this.dataset = {};
    this._text = "";
    this.classList = {add: (...names) => { this.className = [...new Set(`${this.className || ""} ${names.join(" ")}`.trim().split(/\s+/))].join(" "); }};
    this.hidden = false;
    this.open = false;
    this.disabled = false;
    this.focused = false;
    this.files = [];
    this.value = "";
    this.checked = false;
    this.required = false;
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  append(...children) { children.forEach((child) => { child.parent = this; }); this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ""; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.focused = true; }
  scrollIntoView() { this.scrolled = true; }
  addEventListener(name, listener) { this.listeners ||= {}; this.listeners[name] = listener; this.listener = listener; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this);
  }
}

const ids = [
  "sample-button", "sample-status", "error-summary", "error-message",
  "error-recovery", "error-retry", "results", "results-dashboard", "case-detail-view",
  "case-detail-content", "review-detail-context", "review-back-link", "review-route-expired",
  "review-expired-return", "result-jump", "summary-cards",
  "case-list", "case-section", "independent-list", "independent-details", "result-empty",
  "capability-message", "report-download", "report-button",
  "local-form", "local-upload", "local-choice-button", "local-choice-details", "local-button", "local-status", "results-heading", "result-context",
  "application-file", "ssh-file", "access-file",
  "application-error", "ssh-error", "access-error", "input-mode-file", "input-mode-text",
  "file-input-panel", "text-input-panel", "text-source", "log-text", "text-help", "text-error",
  "text-byte-count", "text-line-count", "text-clear", "text-input-scope-notice", "text-input-source-label",
  "nav-start", "nav-audit", "nav-live", "nav-results"
  ,"local-action-card", "audit-action-card", "audit-choice-button", "linux-audit-file",
  "workspace-current-title", "workspace-current-description"
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
  nodes["input-mode-file"].tagName = "input";
  nodes["input-mode-text"].tagName = "input";
  nodes["input-mode-file"].checked = true;
  nodes["file-input-panel"].tagName = "fieldset";
  nodes["text-input-panel"].tagName = "section";
  nodes["text-input-panel"].hidden = true;
  nodes["text-source"].tagName = "select";
  nodes["text-source"].value = "application";
  nodes["log-text"].tagName = "textarea";
  nodes["text-input-scope-notice"].hidden = true;
  nodes["text-error"].hidden = true;
  let response = initial;
  let httpStatus = 200;
  let fetchCount = 0;
  let pendingFetch = null;
  let failFetch = false;
  let confirmResult = true;
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
  const location = {hostname, hash: "", pathname: "/", search: ""};
  const history = {state: null, replaceState(state, _title, url) { this.state = state; location.hash = url.includes("#") ? url.slice(url.indexOf("#")) : ""; },
    pushState(state, _title, url) { this.state = state; location.hash = url.includes("#") ? url.slice(url.indexOf("#")) : ""; }, back() {}};
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
    },
    createElementNS: (_namespace, tag) => new Node(tag),
    createTextNode: (value) => { const node = new Node("#text"); node.textContent = value; return node; }
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
      status: httpStatus,
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
  vm.runInNewContext(script, {document, fetch, FormData: FormDataStub, history, location,
    window: {location, history, addEventListener() {}, scrollTo() {}, confirm: () => confirmResult},
    TextDecoder, TextEncoder, Uint8Array, Date, Blob, URL: objectUrl});
  return {
    nodes, downloads, revoked, body,
    click: () => nodes["sample-button"].listener(),
    submit: () => nodes["local-form"].listeners.submit({preventDefault: () => {}}),
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
    setNetworkFailure: (value) => { failFetch = value; },
    setConfirmResult: (value) => { confirmResult = value; }
  };
}

function copy() { return JSON.parse(JSON.stringify(input)); }

async function main() {
  const remote = makeApp(copy(), "public.example");
  assert.equal(remote.nodes["local-upload"].hidden, true);
  await remote.submit();
  assert.equal(remote.fetchCount(), 0, "remote landing cannot submit local files");
  const app = makeApp(copy());
  app.nodes["local-choice-button"].listener();
  assert.equal(app.nodes["local-choice-details"].open, true);
  assert.equal(app.nodes["application-file"].focused, true);
  assert.equal(app.nodes["local-upload"].scrolled, undefined, "workspace choice does not jump down the page");
  await app.click();
  const nodes = app.nodes;
  assert.equal(nodes.results.hidden, false, `sample render failure: ${nodes["error-message"].textContent}`);
  assert.equal(nodes["error-summary"].hidden, true);
  assert.equal(nodes["case-list"].children.length, 2);
  assert.equal(nodes["summary-cards"].children.length, 4);
  assert.equal(nodes["summary-cards"].textContent.includes("독립 관찰"), true);
  assert.equal(nodes["summary-cards"].textContent.includes("추가 확인 필요"), false);
  assert.equal(nodes["independent-list"].children.length, 4);
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
  const [high] = nodes["case-list"].children;
  assert.equal(nodesOf(high, "a").some((link) => link.textContent === "상세 분석 보기"), true);
  assert.equal(high.textContent.includes("검토 건 #1"), true);
  assert.equal(high.textContent.includes("위험도 높음"), true);
  assert.equal(high.textContent.includes("확인 순서 미정"), true);
  assert.equal(high.textContent.includes("역할 미확인"), true);
  assert.equal(high.textContent.includes("목록 위치"), false);
  assert.equal(nodesOf(high, "p").some((item) => item.className === "review-card-facts" &&
    item.textContent.includes("활동 3개") && item.textContent.includes("연결 2개")), true);
  assert.equal(nodesOf(nodes["case-list"], "details").length, 0, "dashboard omits detail disclosures");
  assert.equal(nodesOf(nodes["case-list"], "ol").length, 0, "dashboard omits timeline and checklist");
  assert.equal(nodes["case-list"].textContent.includes("CORRELATION_IS_NOT_CAUSATION"), false);
  assert.equal(app.fetchCalls.filter((call) => call.url.includes("/guidance")).length, 0,
    "guidance is never fetched before an explicit click");
  assert.equal(app.fetchCalls.filter((call) => call.url.includes("/checklist")).length, 0,
    "checklist is never fetched before an explicit click");
  assert.equal(nodesOf(high, "button").length, 0, "checklist action belongs to the selected detail view");
  assert.equal(nodesOf(high, "time").length > 0, true);
  assert.equal(nodesOf(high, "time")[0].attributes.datetime.endsWith("Z"), true);
  assert.equal(nodes["case-list"].textContent.includes("KST"), true);
  assert.equal(nodes["case-list"].textContent.includes("UTC"), false);
  assert.equal(nodes["case-list"].textContent.includes("review_soon"), false);
  assert.equal(nodes["case-list"].textContent.includes("조사 사례"), false);
  assert.equal(nodes["independent-list"].textContent.includes("여러 계정 대상 인증 실패"), true);
  assert.equal(nodes["independent-list"].textContent.includes("웹 경로 탐색 요청"), true);
  assert.equal(nodes["independent-list"].textContent.includes("SQL 관련 요청 패턴"), true);
  assert.equal(nodes["independent-list"].textContent.includes("SQL 결합 조회 구문"), true);
  assert.equal(nodes["independent-list"].textContent.includes("UNION SELECT"), false);
  assert.equal(nodes["independent-list"].textContent.includes("V1"), false);
  assert.equal(nodesOf(nodes["independent-list"], "dt").some((item) => item.textContent === "실패 횟수"), true);

  const medium = copy();
  medium.cases[1].included_highest_risk = "MEDIUM";
  medium.case_summary.medium_case_count = 1;
  medium.case_summary.low_case_count = 0;
  app.setResponse(medium);
  await app.click();
  assert.equal(nodes["case-list"].children.length, 2, "result list remains compact across risk bands");
  assert.equal(nodesOf(nodes["case-list"], "details").length, 0);

  const microseconds = copy();
  const firstTime = microseconds.cases[0].timeline[0].start_time;
  firstTime.display_utc = firstTime.display_utc.replace("Z", ".123456Z");
  firstTime.display_kst = firstTime.display_kst.replace(" KST", ".123456 KST");
  microseconds.cases[0].start_time = JSON.parse(JSON.stringify(firstTime));
  app.setResponse(microseconds);
  await app.click();
  assert.equal(nodes.results.hidden, false, "microsecond response accepted");
  assert.equal(nodesOf(nodes["case-list"], "time").some((node) => node.attributes.datetime.includes(".123456Z")), true, "microseconds retained");
  assert.equal(nodes["case-list"].textContent.includes("UTC"), false, "UTC remains out of the compact list");

  const noTime = copy();
  const finalEntry = noTime.cases[0].timeline.at(-1);
  finalEntry.start_time = null;
  finalEntry.end_time = null;
  finalEntry.timestamp_state = "NO_TIME";
  finalEntry.timestamp_state_label = "시간 정보 없음";
  noTime.cases[0].start_time = null;
  noTime.cases[0].end_time = null;
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
    (value) => { value.cases[0].timeline[0].fact = "RAW-LOG-CANARY-192.0.2.77"; },
    (value) => { value.cases[0].timeline[0].evidence[0].label = "raw evidence"; },
    (value) => { value.cases[0].next_steps.push(value.cases[0].next_steps[0]); },
    (value) => { value.cases[0].next_steps[0].text = "IP를 차단하십시오."; },
    (value) => { value.cases[0].included_highest_confidence = "UNKNOWN"; },
    (value) => { value.cases[0].account_alias_state = "ACCOUNT_REFERENCE_UNAVAILABLE"; },
    (value) => { value.independent_observations.at(-1).evidence[0].value = "PRIVATE-CANARY-raw-target"; },
    (value) => { value.independent_observations.at(-1).next_step = "파일을 삭제하십시오."; },
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
    assert.equal(nodes["error-message"].textContent.includes("RAW-LOG-CANARY"), false);
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
  assert.equal(nodes["case-section"].hidden, true);
  assert.equal(nodes["independent-details"].hidden, true);
  assert.equal(nodes["result-empty"].hidden, false, "one empty state carries the safety limit");
  if (supplied.local) {
    const local = makeApp(supplied.local);
    assert.equal(local.nodes["input-mode-file"].checked, true, "file upload remains the default mode");
    assert.equal(local.nodes["text-input-panel"].hidden, true);
    assert.equal(local.nodes["text-source"].tagName, "select");
    assert.equal(local.nodes["log-text"].tagName, "textarea");
    assert.equal(local.fetchCount(), 0, "opening the input screen never submits text");
    const selected = {name: "browser-only-name.log"};
    ["application-file", "ssh-file", "access-file"].forEach((id) => {
      local.nodes[id].files = [selected];
    });
    await local.submit();
    assert.equal(local.nodes.results.hidden, false);
    assert.equal(local.nodes["results-heading"].textContent, "분석 결과");
    assert.equal(local.nodes["result-context"].textContent.includes("합성 샘플"), false);
    assert.equal(local.nodes["case-list"].children.length, 2);
    assert.equal(local.nodes["independent-list"].children.length, 4);
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

    const text = makeApp(supplied.local);
    text.nodes["input-mode-text"].checked = true;
    text.nodes["input-mode-text"].listeners.change();
    assert.equal(text.nodes["text-input-panel"].hidden, false);
    assert.equal(text.fetchCount(), 0, "choosing text mode never submits automatically");
    text.nodes["text-source"].value = "ssh";
    text.nodes["log-text"].value = "synthetic ssh line";
    const textResult = JSON.parse(JSON.stringify(supplied.local));
    const notice = "입력한 로그 범위에서만 분석한 결과입니다. 다른 로그나 누락된 시간대에 발생한 활동은 포함되지 않을 수 있습니다.";
    textResult.report_export.html = textResult.report_export.html.replace("</body>", `<p>${notice}</p></body>`);
    textResult.report_export.byte_count = new TextEncoder().encode(textResult.report_export.html).byteLength;
    text.setResponse({schema_version: "1", input_scope: {
      mode: "text", source: "ssh", notice_code: "PARTIAL_SINGLE_SOURCE"
    }, result: textResult});
    await text.submit();
    assert.equal(text.fetchCalls.length, 1);
    assert.equal(text.fetchCalls[0].url, "/api/v1/investigations/text");
    assert.equal(text.fetchCalls[0].options.credentials, "omit");
    assert.equal(text.fetchCalls[0].options.headers["Content-Type"], "application/json");
    assert.deepEqual(Object.keys(JSON.parse(text.fetchCalls[0].options.body)).sort(),
      ["log_text", "schema_version", "source"]);
    assert.equal(JSON.parse(text.fetchCalls[0].options.body).source, "ssh");
    assert.equal(text.nodes.results.hidden, false, `closed text envelope renders validated result: ${text.nodes["error-message"].textContent}`);
    assert.equal(text.nodes["text-input-scope-notice"].hidden, false);
    assert.equal(text.nodes["text-input-source-label"].textContent, "SSH 인증 로그");
    assert.equal(text.nodes["log-text"].value, "", "successful submission clears sensitive input");
    text.download();
    assert.equal(text.downloads.length, 1, "text report uses existing safe download path");
    text.nodes["log-text"].value = "unsent text cleared on navigation";
    text.nodes["nav-start"].listener();
    assert.equal(text.nodes["log-text"].value, "", "leaving the input screen clears unsent text");
    text.nodes["log-text"].value = "synthetic unsent draft";
    text.setConfirmResult(false);
    text.nodes["input-mode-file"].checked = true;
    text.nodes["input-mode-file"].listeners.change();
    assert.equal(text.nodes["input-mode-text"].checked, true, "cancelled switch preserves selected mode");
    assert.equal(text.nodes["log-text"].value, "synthetic unsent draft", "cancelled switch preserves text");
    text.setConfirmResult(true);
    text.nodes["input-mode-file"].checked = true;
    text.nodes["input-mode-file"].listeners.change();
    assert.equal(text.nodes["log-text"].value, "", "approved switch clears previous text");
    assert.equal(text.nodes["text-input-panel"].hidden, true);

    const invalidEnvelope = {schema_version: "1", input_scope: {
      mode: "text", source: "application", notice_code: "PARTIAL_SINGLE_SOURCE"
    }, result: supplied.local};
    text.nodes["input-mode-text"].checked = true;
    text.nodes["input-mode-text"].listeners.change();
    text.nodes["text-source"].value = "ssh";
    text.nodes["log-text"].value = "synthetic input";
    text.setResponse(invalidEnvelope);
    await text.submit();
    assert.equal(text.nodes.results.hidden, true, "mismatched response scope is rejected without partial rendering");
    assert.equal(text.nodes["text-input-scope-notice"].hidden, true);
    assert.equal(text.nodes["error-message"].textContent, "결과 형식을 확인할 수 없습니다.");

    text.setResponse({error_code: "EMPTY_INPUT", user_message: "로그가 비었거나 공백만 있습니다.",
      recovery_action: "내용이 있는 로그를 입력하십시오.", retryable: false, field: "log_text"});
    text.setHttpStatus(400);
    text.nodes["log-text"].value = "synthetic input";
    await text.submit();
    assert.equal(text.nodes["log-text"].attributes["aria-invalid"], "true");
    assert.equal(text.nodes["text-error"].hidden, false);
    assert.equal(text.nodes["error-message"].textContent, "로그가 비었거나 공백만 있습니다.");
    assert.equal(text.nodes["error-message"].textContent.includes("synthetic input"), false);
  }
  process.stdout.write("renderer logic verified\n");
}

main().catch((error) => {
  process.stderr.write(`${error.name}: ${error.message}\n${error.stack || ""}`);
  process.exitCode = 1;
});
