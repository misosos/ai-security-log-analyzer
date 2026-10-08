"use strict";

(() => {
  const ENDPOINT = "/api/v1/investigations/sample";
  const MAX_RESPONSE_BYTES = 512 * 1024;
  const MAX_TEXT = 1000;
  const MAX_ITEMS = 256;
  const RISK_CLASSES = Object.freeze({HIGH: "risk-high", MEDIUM: "risk-medium", LOW: "risk-low"});
  const TIMELINE_CATEGORIES = new Set(["OBSERVED_FACT", "DETECTION_OBSERVATION", "SUPPORTED_RELATION"]);
  const ERROR_CODES = new Set([
    "NON_EMPTY_BODY", "QUERY_NOT_ALLOWED", "RATE_LIMITED", "CONCURRENCY_LIMIT",
    "ANALYSIS_TIMEOUT", "FIXTURE_UNAVAILABLE", "ANALYSIS_FAILED",
    "CASE_PROJECTION_FAILED", "RESPONSE_INVALID"
  ]);
  const TOP_LEVEL = [
    "schema_version", "sample_context", "analysis_summary", "case_summary", "cases",
    "independent_observations", "interpretation_notices", "capabilities",
    "bounded_warnings", "report_export"
  ];
  const ACCOUNT_MESSAGE = "계정 별칭을 표시할 수 없음. 원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다.";

  const button = document.getElementById("sample-button");
  const status = document.getElementById("sample-status");
  const errorSummary = document.getElementById("error-summary");
  const errorMessage = document.getElementById("error-message");
  const errorRecovery = document.getElementById("error-recovery");
  const results = document.getElementById("results");
  const resultJump = document.getElementById("result-jump");
  const summaryCards = document.getElementById("summary-cards");
  const caseList = document.getElementById("case-list");
  const independentList = document.getElementById("independent-list");
  const capabilityMessage = document.getElementById("capability-message");
  let pending = false;

  class PublicFailure extends Error {
    constructor(message, recovery) {
      super("Sample request failed");
      this.publicMessage = message;
      this.recovery = recovery;
    }
  }

  function failContract() {
    throw new PublicFailure("결과 형식을 확인할 수 없습니다.", "잠시 후 다시 시도하십시오.");
  }

  function closedRecord(value, names) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) failContract();
    const keys = Object.keys(value);
    if (keys.length !== names.length || !names.every((name) => Object.hasOwn(value, name))) failContract();
    return value;
  }

  function boundedText(value) {
    if (typeof value !== "string" || value.length > MAX_TEXT) failContract();
    return value;
  }

  function count(value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_ITEMS) failContract();
    return value;
  }

  function items(value, maximum = MAX_ITEMS) {
    if (!Array.isArray(value) || value.length > maximum) failContract();
    return value;
  }

  function texts(value) {
    return items(value).map(boundedText);
  }

  function risk(value) {
    if (!Object.hasOwn(RISK_CLASSES, value)) failContract();
    return value;
  }

  function timestamp(value) {
    if (value === null) return;
    closedRecord(value, ["display_kst", "display_utc"]);
    boundedText(value.display_kst);
    boundedText(value.display_utc);
  }

  function evidence(value) {
    items(value).forEach((item) => {
      closedRecord(item, ["label", "value", "unit"]);
      boundedText(item.label);
      if (typeof item.value !== "number" || !Number.isFinite(item.value)) failContract();
      if (item.unit !== null) boundedText(item.unit);
    });
  }

  function textItems(value) {
    items(value).forEach((item) => {
      closedRecord(item, ["label", "text"]);
      boundedText(item.label);
      boundedText(item.text);
    });
  }

  function account(value) {
    if (value.account_alias_state !== "unavailable" || value.account_alias_message !== ACCOUNT_MESSAGE) failContract();
  }

  function timeline(value) {
    items(value).forEach((entry, index) => {
      closedRecord(entry, [
        "sequence", "category", "category_label", "timestamp_state", "timestamp_state_label",
        "start_time", "end_time", "title", "fact", "subject",
        "detection_display_name", "relation_display_name", "evidence"
      ]);
      if (entry.sequence !== index + 1 || !TIMELINE_CATEGORIES.has(entry.category)) failContract();
      if (entry.timestamp_state !== "TIMESTAMPED" && entry.timestamp_state !== "NO_TIME") failContract();
      ["category_label", "timestamp_state_label", "title", "fact", "subject"].forEach((key) => boundedText(entry[key]));
      if (entry.detection_display_name !== null) boundedText(entry.detection_display_name);
      if (entry.relation_display_name !== null) boundedText(entry.relation_display_name);
      timestamp(entry.start_time);
      timestamp(entry.end_time);
      evidence(entry.evidence);
    });
  }

  function validateCase(item, index) {
    closedRecord(item, [
      "review_order", "case_label", "subject", "included_highest_risk",
      "included_highest_confidence", "start_time", "end_time", "observation_count",
      "supporting_relation_count", "grouping_explanation", "supported_detections",
      "supported_relations", "timeline_label", "timeline", "limitations", "unverified_items",
      "next_steps", "account_alias_state", "account_alias_message"
    ]);
    if (item.review_order !== index + 1 || item.case_label !== `조사 사례 ${index + 1}`) failContract();
    boundedText(item.subject);
    risk(item.included_highest_risk);
    risk(item.included_highest_confidence);
    timestamp(item.start_time);
    timestamp(item.end_time);
    count(item.observation_count);
    count(item.supporting_relation_count);
    boundedText(item.grouping_explanation);
    texts(item.supported_detections);
    texts(item.supported_relations);
    if (item.timeline_label !== "시간순 조사 흐름") failContract();
    timeline(item.timeline);
    textItems(item.limitations);
    textItems(item.unverified_items);
    textItems(item.next_steps);
    account(item);
  }

  function validateIndependent(item, index) {
    closedRecord(item, [
      "review_order", "label", "category_label", "display_type", "subject",
      "existing_risk_level", "existing_confidence", "start_time", "end_time",
      "timestamp_state", "evidence", "reason", "account_alias_state", "account_alias_message"
    ]);
    if (item.review_order !== index + 1 || item.label !== "독립 관찰") failContract();
    ["category_label", "display_type", "subject", "reason"].forEach((key) => boundedText(item[key]));
    risk(item.existing_risk_level);
    risk(item.existing_confidence);
    timestamp(item.start_time);
    timestamp(item.end_time);
    if (item.timestamp_state !== "TIMESTAMPED" && item.timestamp_state !== "NO_TIME") failContract();
    evidence(item.evidence);
    account(item);
  }

  function validateInvestigationResponse(value) {
    closedRecord(value, TOP_LEVEL);
    if (value.schema_version !== "1") failContract();
    closedRecord(value.sample_context, ["label", "environment_notice", "certificate_notice"]);
    if (value.sample_context.label !== "합성 샘플 결과" ||
        value.sample_context.environment_notice !== "실제 조직 환경의 보안 상태가 아닙니다." ||
        value.sample_context.certificate_notice !== "보안 점검 인증서가 아닙니다.") failContract();
    closedRecord(value.analysis_summary, ["analyzed_subject_count", "supported_detection_count", "supported_relation_count"]);
    Object.values(value.analysis_summary).forEach(count);
    closedRecord(value.case_summary, [
      "case_count", "independent_observation_count", "high_case_count", "medium_case_count",
      "low_case_count", "relation_case_count", "no_time_observation_count"
    ]);
    Object.values(value.case_summary).forEach(count);
    const summary = value.case_summary;
    if (summary.case_count !== summary.high_case_count + summary.medium_case_count + summary.low_case_count ||
        summary.case_count !== items(value.cases).length ||
        summary.independent_observation_count !== items(value.independent_observations).length ||
        summary.relation_case_count > summary.case_count) failContract();
    value.cases.forEach(validateCase);
    value.independent_observations.forEach(validateIndependent);
    texts(value.interpretation_notices);
    texts(value.bounded_warnings);
    closedRecord(value.capabilities, [
      "html_report_available", "llm_summary_available", "linux_audit_aggregate_available", "actual_log_upload_available"
    ]);
    if (Object.values(value.capabilities).some((flag) => flag !== false)) failContract();
    closedRecord(value.report_export, ["available", "message"]);
    if (value.report_export.available !== false ||
        value.report_export.message !== "HTML 보고서 다운로드는 이 단계에서 제공되지 않습니다.") failContract();
    return value;
  }

  async function boundedJson(response) {
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.toLowerCase().startsWith("application/json")) failContract();
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) failContract();
    if (!response.body) failContract();
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        total += next.value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          failContract();
        }
        chunks.push(next.value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    chunks.forEach((chunk) => { bytes.set(chunk, offset); offset += chunk.byteLength; });
    try {
      return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
    } catch (error) {
      failContract();
    }
  }

  function validateApiError(value) {
    closedRecord(value, ["error_code", "user_message", "recovery_action", "retryable"]);
    if (!ERROR_CODES.has(value.error_code) || typeof value.retryable !== "boolean") failContract();
    boundedText(value.user_message);
    boundedText(value.recovery_action);
    return value;
  }

  function element(tag, text, className) {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function detail(list, label, value) {
    const pair = document.createElement("div");
    pair.append(element("dt", label), element("dd", value));
    list.append(pair);
  }

  function riskBadge(value) {
    return element("span", value, `risk ${RISK_CLASSES[value]}`);
  }

  function timeRange(start, end) {
    if (!start || !end) return "시간 정보 없음";
    return `${start.display_kst} ~ ${end.display_kst}`;
  }

  function renderSummary(data) {
    const cards = [
      ["분석 대상 수", data.analysis_summary.analyzed_subject_count],
      ["지원 탐지 관찰 수", data.analysis_summary.supported_detection_count],
      ["지원 관계 관찰 수", data.analysis_summary.supported_relation_count],
      ["조사 사례 수", data.case_summary.case_count],
      ["독립 관찰 수", data.case_summary.independent_observation_count],
      ["HIGH", data.case_summary.high_case_count],
      ["MEDIUM", data.case_summary.medium_case_count],
      ["LOW", data.case_summary.low_case_count]
    ];
    cards.forEach(([label, value]) => {
      const card = document.createElement("div");
      card.className = "summary-card";
      card.append(element("p", label), element("p", String(value), "summary-value"));
      summaryCards.append(card);
    });
  }

  function renderCaseOverview(cases) {
    if (cases.length === 0) {
      caseList.append(element("p", "지원되는 규칙으로 구성된 조사 사례가 없습니다. 이 결과는 보안 문제가 없다는 의미가 아닙니다."));
    }
    cases.forEach((item) => {
      const card = document.createElement("article");
      card.className = "case-card";
      card.append(element("h4", item.case_label));
      const meta = document.createElement("dl");
      meta.className = "card-meta";
      detail(meta, "조사 순서", String(item.review_order));
      detail(meta, "분석 대상", item.subject);
      const riskPair = document.createElement("div");
      riskPair.append(element("dt", "포함된 최고 위험도"));
      const riskValue = document.createElement("dd");
      riskValue.append(riskBadge(item.included_highest_risk));
      riskPair.append(riskValue);
      meta.append(riskPair);
      detail(meta, "시간 범위 (KST)", timeRange(item.start_time, item.end_time));
      detail(meta, "관찰 수", String(item.observation_count));
      detail(meta, "주요 탐지 관찰", item.supported_detections.join(", ") || "탐지 관찰 없음");
      detail(meta, "지원되는 관계", item.supported_relations.join(", ") || "지원되는 관계 없음");
      card.append(meta, element("p", item.grouping_explanation), element("p", item.account_alias_message, "account-note"));
      caseList.append(card);
    });
  }

  function renderIndependentObservations(observations) {
    if (observations.length === 0) {
      independentList.append(element("p", "독립 관찰이 없습니다. 이는 안전하다는 의미가 아닙니다."));
    }
    observations.forEach((item) => {
      const card = document.createElement("article");
      card.className = "independent-card";
      card.append(element("h4", `${item.label} ${item.review_order}: ${item.display_type}`));
      const meta = document.createElement("dl");
      meta.className = "card-meta";
      detail(meta, "분석 대상", item.subject);
      const riskPair = document.createElement("div");
      riskPair.append(element("dt", "기존 위험도"));
      const riskValue = document.createElement("dd");
      riskValue.append(riskBadge(item.existing_risk_level));
      riskPair.append(riskValue);
      meta.append(riskPair);
      detail(meta, "기존 신뢰도", item.existing_confidence);
      detail(meta, "시간 범위 (KST)", timeRange(item.start_time, item.end_time));
      card.append(meta, element("p", item.reason));
      independentList.append(card);
    });
  }

  function clearPreviousResult() {
    results.hidden = true;
    resultJump.hidden = true;
    errorSummary.hidden = true;
    summaryCards.replaceChildren();
    caseList.replaceChildren();
    independentList.replaceChildren();
    capabilityMessage.textContent = "";
  }

  function renderError(failure) {
    const publicFailure = failure instanceof PublicFailure ? failure :
      new PublicFailure("샘플 분석 결과를 가져오지 못했습니다.", "연결 상태를 확인한 뒤 다시 시도하십시오.");
    status.textContent = "샘플 분석에 실패했습니다.";
    errorMessage.textContent = publicFailure.publicMessage;
    errorRecovery.textContent = publicFailure.recovery;
    errorSummary.hidden = false;
    errorSummary.focus();
  }

  async function requestSampleInvestigation() {
    if (pending) return;
    pending = true;
    button.disabled = true;
    button.textContent = "분석 요청 중";
    clearPreviousResult();
    status.textContent = "합성 샘플 분석을 요청하고 있습니다. 조사 결과를 준비하고 있습니다.";
    try {
      const response = await fetch(ENDPOINT, {
        method: "POST", headers: {Accept: "application/json"}, credentials: "omit"
      });
      const payload = await boundedJson(response);
      if (!response.ok) {
        const error = validateApiError(payload);
        throw new PublicFailure(error.user_message, error.recovery_action);
      }
      const data = validateInvestigationResponse(payload);
      renderSummary(data);
      renderCaseOverview(data.cases);
      renderIndependentObservations(data.independent_observations);
      capabilityMessage.textContent = "실제 로그 웹 업로드, HTML 보고서 다운로드, LLM 설명과 Linux Audit 집계는 이 체험에서 제공되지 않습니다.";
      results.hidden = false;
      resultJump.hidden = false;
      status.textContent = "합성 샘플 분석이 완료되었습니다.";
    } catch (failure) {
      clearPreviousResult();
      renderError(failure);
    } finally {
      pending = false;
      button.disabled = false;
      button.textContent = "샘플로 체험하기";
    }
  }

  button.addEventListener("click", requestSampleInvestigation);
})();
