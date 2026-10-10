"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../frontend/linux-audit.js"), "utf8");
class Element {
  constructor() {
    this.hidden = false;
    this.textContent = "";
    this.children = [];
    this.handlers = {};
    this.files = [];
    this.attributes = {};
    this.focused = false;
  }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  append(...children) { this.children.push(...children); }
  replaceChildren() { this.children = []; }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; }
  focus() { this.focused = true; }
}

const ids = ["linux-audit-upload", "linux-audit-form", "linux-audit-file",
  "linux-audit-field-error", "linux-audit-button", "linux-audit-status",
  "linux-audit-error", "linux-audit-error-message", "linux-audit-error-recovery",
  "linux-audit-results", "linux-audit-summary", "linux-audit-categories",
  "linux-audit-outcomes", "linux-audit-warnings", "results", "report-download",
  "sample-button", "local-form"];
const elements = Object.fromEntries(ids.map((id) => [id, new Element()]));
elements["linux-audit-file"].files = [{name: "PRIVATE_FILENAME_CANARY"}];
class FormData {
  constructor() { this.entries = []; }
  append(name, value) { this.entries.push([name, value]); }
}
const labels = ["셸 인터프리터 실행 관찰", "네트워크 전송 도구 실행 관찰",
  "권한·소유권 변경 도구 실행 관찰", "임시 디렉터리 실행 관찰"];
const names = ["LINUX_SHELL_INTERPRETER_EXECUTION", "LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION",
  "LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION", "LINUX_TEMP_DIRECTORY_EXECUTION"];
const limits = [
  "셸 실행만으로 명령 내용, 사용자 의도 또는 악성 여부를 판단할 수 없습니다.",
  "전송 도구 실행만으로 파일이 다운로드·업로드되었거나 외부 통신이 성공했다고 판단할 수 없습니다.",
  "도구 실행만으로 대상 파일의 권한·소유권이 실제로 변경되었거나 권한 상승이 발생했다고 판단할 수 없습니다.",
  "임시 디렉터리의 실행 관찰만으로 파일의 출처, 내용, 악성 여부 또는 실행 목적을 판단할 수 없습니다."
];
const steps = [
  "승인된 관리·자동화 작업인지 확인하고 필요한 경우 부모 프로세스와 실행 맥락을 검토하십시오.",
  "승인된 관리·자동화 작업인지 확인하고, 필요한 경우 네트워크·프록시·파일 생성 기록을 함께 검토하십시오.",
  "승인된 배포·관리 작업인지 확인하고, 필요한 경우 파일 metadata와 변경 감사 기록을 검토하십시오.",
  "파일 생성·해시·서명·소유자·부모 프로세스·네트워크 기록과 승인된 작업 여부를 확인하십시오."
];
const payload = {
  schema_version: "1",
  source_context: {kind: "LOCAL_PRIVATE_UPLOAD", label: "로컬 Linux Audit 분석 결과",
    storage_notice: "로그와 결과를 서버에 영구 저장하지 않습니다. 비정상 종료 후 임시 파일이 남을 수 있습니다."},
  summary: {eligible_execution_count: 1, classified_execution_count: 1,
    unclassified_execution_count: 0, category_observation_count: 2,
    outcome_counts: {success: 1, failure: 0, unknown: 0},
    low_priority_observation_count: 1, medium_priority_observation_count: 1,
    incomplete_context_count: 0},
  observations: names.map((category_id, index) => ({category_id,
    display_name: labels[index], observation_count: [0, 1, 0, 1][index],
    review_priority: index === 3 ? "MEDIUM" : "LOW",
    confidence: [null, "HIGH", null, "HIGH"][index],
    outcome_counts: {success: [0, 1, 0, 1][index], failure: 0, unknown: 0},
    limitation: limits[index], next_step: steps[index]})),
  interpretation_notices: [
    "이 결과는 Linux Audit 로그에서 검토할 프로세스 실행 관찰을 분류한 것입니다.",
    "악성 행위나 침해 성공을 확정하지 않으며, 실행 목적과 승인 여부는 별도로 확인해야 합니다.",
    "성공은 실행 syscall의 기록된 결과를 뜻합니다. 파일 전송, 권한 변경 또는 공격 목적이 성공했다는 의미가 아닙니다.",
    "인증·웹 조사 사례와 자동으로 결합하지 않습니다."
  ],
  bounded_warnings: [],
  capabilities: {html_report_available: false, llm_summary_available: false,
    auth_web_case_linking_available: false}
};
let response = payload;
let calls = [];
const context = {
  document: {getElementById: (id) => elements[id], createElement: () => new Element()},
  window: {location: {hostname: "127.0.0.1"}},
  FormData,
  TextDecoder,
  Uint8Array,
  fetch: async (url, options) => {
    calls.push({url, options});
    const bytes = new TextEncoder().encode(JSON.stringify(response));
    let read = false;
    return {ok: true, headers: {get: (key) => key === "content-type" ? "application/json" : null},
      body: {getReader: () => ({read: async () => {
        if (read) return {done: true};
        read = true;
        return {done: false, value: bytes};
      }})}};
  }
};
vm.runInNewContext(source, context, {filename: "linux-audit.js"});
function textTree(item) {
  return item.textContent + item.children.map(textTree).join(" ");
}
(async () => {
  assert.equal(elements["linux-audit-upload"].hidden, false);
  assert.equal(calls.length, 0, "no automatic upload");
  await elements["linux-audit-form"].handlers.submit({preventDefault() {}});
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/v1/investigations/linux-audit");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.body.entries.length, 1);
  assert.equal(calls[0].options.body.entries[0][0], "audit_file");
  assert.equal(calls[0].options.headers["Content-Type"], undefined);
  assert.equal(elements["linux-audit-results"].hidden, false);
  assert.equal(elements["linux-audit-categories"].children.length, 4);
  assert.equal(elements["results"].hidden, true, "auth/web results remain separate");
  assert.equal(textTree(elements["linux-audit-categories"]).includes("PRIVATE_FILENAME_CANARY"), false);
  response = {...payload, summary: {...payload.summary, eligible_execution_count: 9}};
  await elements["linux-audit-form"].handlers.submit({preventDefault() {}});
  assert.equal(elements["linux-audit-results"].hidden, true, "malformed response clears prior result");
  assert.equal(elements["linux-audit-error"].focused, true);
  elements["linux-audit-file"].files = [];
  await elements["linux-audit-form"].handlers.submit({preventDefault() {}});
  assert.equal(calls.length, 2, "missing file never fetches");
  assert.equal(elements["linux-audit-file"].attributes["aria-invalid"], "true");
  console.log("linux audit UI behavior passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
