"use strict";

(() => {
  const endpoint = "/api/v1/investigations/linux-audit";
  const maxResponseBytes = 16 * 1024;
  const names = [
    "LINUX_SHELL_INTERPRETER_EXECUTION",
    "LINUX_NETWORK_TRANSFER_UTILITY_EXECUTION",
    "LINUX_PERMISSION_CHANGE_UTILITY_EXECUTION",
    "LINUX_TEMP_DIRECTORY_EXECUTION"
  ];
  const labels = [
    "셸 인터프리터 실행 관찰", "네트워크 전송 도구 실행 관찰",
    "권한·소유권 변경 도구 실행 관찰", "임시 디렉터리 실행 관찰"
  ];
  const priorities = ["LOW", "LOW", "LOW", "MEDIUM"];
  const limitations = [
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
  const notices = [
    "이 결과는 Linux Audit 로그에서 검토할 프로세스 실행 관찰을 분류한 것입니다.",
    "악성 행위나 침해 성공을 확정하지 않으며, 실행 목적과 승인 여부는 별도로 확인해야 합니다.",
    "성공은 실행 syscall의 기록된 결과를 뜻합니다. 파일 전송, 권한 변경 또는 공격 목적이 성공했다는 의미가 아닙니다.",
    "인증·웹 조사 사례와 자동으로 결합하지 않습니다."
  ];
  const warning = "실행 파일 식별 정보가 불명확하거나 일치하지 않아 일부 관찰을 분류하지 않았습니다.";
  const errors = Object.freeze({
    LOCAL_ONLY: ["이 기능은 로컬 서버에서만 사용할 수 있습니다.", "127.0.0.1에 직접 연결하십시오.", false],
    QUERY_NOT_ALLOWED: ["조회 조건을 받을 수 없습니다.", "조회 조건 없이 다시 시도하십시오.", false],
    INVALID_MEDIA_TYPE: ["Linux Audit 파일의 multipart 요청이 필요합니다.", "파일을 다시 선택하십시오.", false],
    MALFORMED_MULTIPART: ["업로드 형식을 확인할 수 없습니다.", "파일을 다시 선택하십시오.", false],
    MISSING_FIELD: ["Linux Audit 파일이 누락되었습니다.", "파일을 선택하십시오.", false],
    REPEATED_FIELD: ["파일 입력이 여러 번 전송되었습니다.", "한 파일만 선택하십시오.", false],
    UNKNOWN_FIELD: ["지원하지 않는 업로드 항목이 있습니다.", "Linux Audit 파일만 선택하십시오.", false],
    FILE_COUNT_EXCEEDED: ["파일 수 한도를 넘었습니다.", "한 파일만 선택하십시오.", false],
    FILE_TOO_LARGE: ["파일 크기 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", false],
    ENVELOPE_TOO_LARGE: ["요청 크기 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", false],
    LINE_TOO_LONG: ["로그 한 줄이 길이 한도를 넘었습니다.", "입력 형식을 확인하십시오.", false],
    LINE_COUNT_EXCEEDED: ["로그 줄 수 한도를 넘었습니다.", "더 작은 로그를 선택하십시오.", false],
    EMPTY_INPUT: ["로그가 비었거나 공백만 있습니다.", "내용이 있는 로그를 선택하십시오.", false],
    INVALID_UTF8: ["UTF-8 로그로 읽을 수 없습니다.", "UTF-8 텍스트 파일을 선택하십시오.", false],
    BINARY_INPUT: ["텍스트 로그 형식을 확인할 수 없습니다.", "UTF-8 텍스트 로그를 선택하십시오.", false],
    ARCHIVE_UNSUPPORTED: ["압축·보관 파일은 지원하지 않습니다.", "압축을 풀고 텍스트 로그를 선택하십시오.", false],
    PARSER_INCOMPATIBLE: ["지원되는 Linux Audit 구조를 확인할 수 없습니다.", "Audit 텍스트 형식과 수집 범위를 확인하십시오.", false],
    UPLOAD_TIMEOUT: ["업로드 처리 시간이 초과되었습니다.", "잠시 후 다시 시도하십시오.", true],
    ANALYSIS_TIMEOUT: ["분류 시간이 초과되었습니다.", "더 작은 로그로 다시 시도하십시오.", true],
    CONCURRENCY_LIMIT: ["다른 Linux Audit 분석이 진행 중입니다.", "완료 후 다시 시도하십시오.", true],
    RATE_LIMITED: ["Linux Audit 요청 횟수 한도에 도달했습니다.", "잠시 후 다시 시도하십시오.", true],
    ANALYSIS_FAILED: ["Linux Audit 로그를 분류하지 못했습니다.", "입력 형식을 확인하고 다시 시도하십시오.", true],
    RESPONSE_INVALID: ["결과를 준비하지 못했습니다.", "잠시 후 다시 시도하십시오.", true]
  });
  const section = document.getElementById("linux-audit-upload");
  const form = document.getElementById("linux-audit-form");
  const input = document.getElementById("linux-audit-file");
  const fieldError = document.getElementById("linux-audit-field-error");
  const button = document.getElementById("linux-audit-button");
  const status = document.getElementById("linux-audit-status");
  const error = document.getElementById("linux-audit-error");
  const errorMessage = document.getElementById("linux-audit-error-message");
  const errorRecovery = document.getElementById("linux-audit-error-recovery");
  const results = document.getElementById("linux-audit-results");
  const summary = document.getElementById("linux-audit-summary");
  const categories = document.getElementById("linux-audit-categories");
  const outcomes = document.getElementById("linux-audit-outcomes");
  const warnings = document.getElementById("linux-audit-warnings");
  const loopback = ["127.0.0.1", "::1", "[::1]"].includes(window.location.hostname);
  section.hidden = !loopback;
  let pending = false;

  function invalid() { throw new Error("invalid_linux_response"); }
  function record(value, keys) {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).sort().join("|") !== [...keys].sort().join("|")) invalid();
  }
  function number(value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 2147483647) invalid();
    return value;
  }
  function counts(value) {
    record(value, ["success", "failure", "unknown"]);
    return number(value.success) + number(value.failure) + number(value.unknown);
  }
  function validate(value) {
    record(value, ["schema_version", "source_context", "summary", "observations",
      "interpretation_notices", "bounded_warnings", "capabilities"]);
    if (value.schema_version !== "1") invalid();
    record(value.source_context, ["kind", "label", "storage_notice"]);
    if (value.source_context.kind !== "LOCAL_PRIVATE_UPLOAD" ||
        value.source_context.label !== "로컬 Linux Audit 분석 결과" ||
        value.source_context.storage_notice !== "로그와 결과를 서버에 영구 저장하지 않습니다. 비정상 종료 후 임시 파일이 남을 수 있습니다.") invalid();
    record(value.summary, ["eligible_execution_count", "classified_execution_count",
      "unclassified_execution_count", "category_observation_count", "outcome_counts",
      "low_priority_observation_count", "medium_priority_observation_count", "incomplete_context_count"]);
    const s = value.summary;
    for (const name of ["eligible_execution_count", "classified_execution_count", "unclassified_execution_count",
      "category_observation_count", "low_priority_observation_count", "medium_priority_observation_count",
      "incomplete_context_count"]) number(s[name]);
    if (s.eligible_execution_count !== s.classified_execution_count + s.unclassified_execution_count ||
        s.eligible_execution_count !== counts(s.outcome_counts) ||
        s.category_observation_count !== s.low_priority_observation_count + s.medium_priority_observation_count ||
        s.incomplete_context_count > s.eligible_execution_count) invalid();
    if (!Array.isArray(value.observations) || value.observations.length !== 4) invalid();
    let total = 0;
    let low = 0;
    let medium = 0;
    value.observations.forEach((item, index) => {
      record(item, ["category_id", "display_name", "observation_count", "review_priority",
        "confidence", "outcome_counts", "limitation", "next_step"]);
      if (item.category_id !== names[index] || item.display_name !== labels[index] ||
          item.review_priority !== priorities[index] || item.limitation !== limitations[index] ||
          item.next_step !== steps[index] ||
          !(["HIGH", "MEDIUM", "LOW"].includes(item.confidence) ||
            (item.confidence === null && item.observation_count === 0)) ||
          (item.observation_count > 0 && item.confidence === null)) invalid();
      number(item.observation_count);
      if (counts(item.outcome_counts) !== item.observation_count) invalid();
      total += item.observation_count;
      if (item.review_priority === "LOW") low += item.observation_count;
      else medium += item.observation_count;
    });
    if (total !== s.category_observation_count || low !== s.low_priority_observation_count ||
        medium !== s.medium_priority_observation_count) invalid();
    if (!Array.isArray(value.interpretation_notices) ||
        value.interpretation_notices.length !== notices.length ||
        value.interpretation_notices.some((item, index) => item !== notices[index])) invalid();
    if (!Array.isArray(value.bounded_warnings) || value.bounded_warnings.length > 1 ||
        value.bounded_warnings.some((item) => item !== warning)) invalid();
    record(value.capabilities, ["html_report_available", "llm_summary_available", "auth_web_case_linking_available"]);
    if (value.capabilities.html_report_available !== false ||
        value.capabilities.llm_summary_available !== false ||
        value.capabilities.auth_web_case_linking_available !== false) invalid();
    return value;
  }

  async function boundedJson(response) {
    const type = response.headers.get("content-type") || "";
    if (!type.toLowerCase().startsWith("application/json")) invalid();
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxResponseBytes)) invalid();
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maxResponseBytes) { await reader.cancel(); invalid(); }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of chunks) { bytes.set(part, offset); offset += part.byteLength; }
    return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
  }

  function node(tag, value, className) {
    const item = document.createElement(tag);
    item.textContent = value;
    if (className) item.className = className;
    return item;
  }
  function clear() {
    results.hidden = true;
    status.textContent = "Linux Audit 파일을 선택해 확인할 수 있습니다.";
    summary.replaceChildren();
    categories.replaceChildren();
    outcomes.textContent = "";
    warnings.replaceChildren();
    error.hidden = true;
    fieldError.hidden = true;
    fieldError.textContent = "";
    input.removeAttribute("aria-invalid");
  }
  function showError(message, recovery, isField) {
    clear();
    errorMessage.textContent = message;
    errorRecovery.textContent = recovery;
    if (isField) {
      fieldError.textContent = message;
      fieldError.hidden = false;
      input.setAttribute("aria-invalid", "true");
    }
    status.textContent = "Linux Audit 로그를 확인하지 못했습니다.";
    error.hidden = false;
    error.focus();
  }
  function render(data) {
    const s = data.summary;
    for (const [label, value] of [
      ["전체 실행 관찰", s.eligible_execution_count], ["분류된 실행", s.classified_execution_count],
      ["미분류 실행", s.unclassified_execution_count], ["범주 관찰 합계", s.category_observation_count],
      ["LOW 우선순위 관찰", s.low_priority_observation_count],
      ["MEDIUM 우선순위 관찰", s.medium_priority_observation_count]
    ]) {
      const card = node("div", "", "summary-card");
      card.append(node("p", label), node("p", `${value}건`, "summary-value"));
      summary.append(card);
    }
    if (s.category_observation_count === 0) {
      categories.append(node("p", "분류된 실행 관찰이 없습니다. 이는 시스템이 안전하거나 악성 행위가 없다는 의미가 아닙니다. 입력 형식과 수집 범위가 지원 조건에 맞는지 확인하세요."));
    }
    data.observations.forEach((item) => {
      const card = node("article", "", "independent-card");
      card.append(node("h4", item.display_name),
        node("p", `관찰 ${item.observation_count}건 · 검토 우선순위 ${item.review_priority} · 신뢰도 ${item.confidence === null ? "해당 없음" : item.confidence}`),
        node("p", `성공 ${item.outcome_counts.success} / 실패 ${item.outcome_counts.failure} / 미상 ${item.outcome_counts.unknown}`),
        node("p", `해석 한계: ${item.limitation}`), node("p", `다음 확인 단계: ${item.next_step}`));
      categories.append(card);
    });
    outcomes.textContent = `성공 ${s.outcome_counts.success}건 / 실패 ${s.outcome_counts.failure}건 / 미상 ${s.outcome_counts.unknown}건. 다중 범주 때문에 범주 관찰 합계는 분류된 실행 수보다 클 수 있습니다.`;
    data.bounded_warnings.forEach((item) => warnings.append(node("p", item)));
    results.hidden = false;
    status.textContent = "Linux Audit 실행 관찰 분류가 완료되었습니다.";
  }
  async function submit(event) {
    event.preventDefault();
    if (pending || !loopback) return;
    clear();
    if (input.files.length !== 1) {
      showError("Linux Audit 파일이 누락되었습니다.", "파일을 선택하십시오.", true);
      return;
    }
    pending = true;
    button.disabled = true;
    button.textContent = "Linux Audit 로그 확인 중";
    status.textContent = "Linux Audit 로그를 전송하고 결과를 준비하고 있습니다.";
    document.getElementById("results").hidden = true;
    document.getElementById("report-download").hidden = true;
    const body = new FormData();
    body.append("audit_file", input.files[0]);
    try {
      const response = await fetch(endpoint, {
        method: "POST", headers: {Accept: "application/json"}, body, credentials: "omit"
      });
      const payload = await boundedJson(response);
      if (!response.ok) {
        record(payload, ["error_code", "user_message", "recovery_action", "retryable", "field"]);
        const known = Object.hasOwn(errors, payload.error_code) ? errors[payload.error_code] : null;
        if (known && payload.user_message === known[0] && payload.recovery_action === known[1] &&
            payload.retryable === known[2] && [null, "audit_file"].includes(payload.field)) {
          showError(known[0], known[1], payload.field === "audit_file");
        } else {
          showError("Linux Audit 결과를 가져오지 못했습니다.", "연결 또는 입력 상태를 확인한 뒤 다시 시도하십시오.", false);
        }
        return;
      }
      render(validate(payload));
    } catch (_failure) {
      showError("Linux Audit 결과를 가져오지 못했습니다.", "연결 또는 응답 상태를 확인한 뒤 다시 시도하십시오.", false);
    } finally {
      pending = false;
      button.disabled = false;
      button.textContent = "Linux Audit 로그 확인";
    }
  }
  form.addEventListener("submit", submit);
  document.getElementById("sample-button").addEventListener("click", clear);
  document.getElementById("local-form").addEventListener("submit", clear);
})();
