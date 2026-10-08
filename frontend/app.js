"use strict";

(() => {
  const ENDPOINT = "/api/v1/investigations/sample";
  const MAX_RESPONSE_BYTES = 64 * 1024;
  const MAX_REPORT_BYTES = 32 * 1024;
  const MAX_TEXT = 1000;
  const MAX_ITEMS = 256;
  const MAX_CASES = 64;
  const MAX_INDEPENDENT = 128;
  const MAX_EVIDENCE_VALUE = 1000000000;
  const RISK_CLASSES = Object.freeze({HIGH: "risk-high", MEDIUM: "risk-medium", LOW: "risk-low"});
  const TIMELINE_CATEGORIES = new Set(["OBSERVED_FACT", "DETECTION_OBSERVATION", "SUPPORTED_RELATION"]);
  const CATEGORY_LABELS = Object.freeze({
    OBSERVED_FACT: "관찰된 사실", DETECTION_OBSERVATION: "탐지 관찰",
    SUPPORTED_RELATION: "지원되는 관계"
  });
  const DETECTION_NAMES = new Set(["Brute Force", "Password Spraying-like"]);
  const RELATION_NAMES = new Set(["Brute Force → Successful Login", "Failed Login → Successful Login"]);
  const INDEPENDENT_NAMES = new Set([
    "Brute Force", "Password Spraying-like", "Path Traversal", "인증 실패 관찰",
    "인증 성공 관찰", "지원되지 않는 탐지 관찰", "지원되지 않는 관계 관찰",
    "Brute Force 계약 미검증 관찰", "Brute Force 시간 미검증 관찰",
    "Password Spraying-like 계약 미검증 관찰", "Password Spraying-like 시간 미검증 관찰",
    "Failed Login → Successful Login", "Brute Force → Successful Login",
    "Password Spraying-like → Successful Login", "Successful Login → File Access",
    "Failed Login → Successful Login 시간 미검증 관찰",
    "Brute Force → Successful Login 시간 미검증 관찰"
  ]);
  const DETECTION_EVIDENCE = Object.freeze([
    ["실패 횟수", "회", true], ["대상 계정 수", "개", true], ["시간 범위", "초", false]
  ]);
  const RELATION_EVIDENCE = Object.freeze([["시간 차이", "초", false]]);
  const NEXT_STEP_SEQUENCES = Object.freeze([
    [
      "인증 실패의 출발지와 시간 범위를 확인하십시오.",
      "상관된 로그인의 IdP, MFA, 장치 및 세션 기록을 확인하십시오.",
      "후속 세션 활동을 확인하십시오."
    ],
    [
      "인증 실패와 성공의 출발지 및 시간대를 비교하십시오.",
      "성공 로그인의 MFA, 장치 및 세션 기록을 확인하십시오.",
      "승인된 사용자 또는 자동화 활동인지 확인하십시오."
    ]
  ]);
  const LIMITATION_TEXTS = new Set([
    "동일 계정의 후속 로그인 관계만으로 계정 탈취를 판단할 수 없습니다.",
    "실패 후 성공 관계만으로 이전 실패의 주체와 성공 주체가 동일하다고 판단할 수 없습니다."
  ]);
  const UNVERIFIED_TEXTS = new Set([
    "로그인 주체의 정당성은 확인되지 않았습니다.", "MFA 승인 주체는 확인되지 않았습니다.",
    "사용 장치의 신뢰 여부는 확인되지 않았습니다.", "세션의 후속 활동은 확인되지 않았습니다.",
    "계정 침해 여부는 확인되지 않았습니다.", "NAT, proxy 또는 공유 시스템의 영향은 확인되지 않았습니다.",
    "승인된 자동화 또는 관리 작업 여부는 확인되지 않았습니다."
  ]);
  const INDEPENDENT_REASONS = new Set([
    "V1에서 지원되는 관계가 없어 독립 관찰로 유지되었습니다.",
    "검증된 시간 정보가 부족하여 자동 시간 결합에서 제외되었습니다.",
    "인증 사례와 안전하게 결합할 관계를 입증하지 못했습니다.",
    "V1 조사 사례 지원 범위 밖의 관찰이라 독립적으로 유지되었습니다.",
    "Password Spraying-like 관찰은 유지되었지만 성공 로그인 계정이 탐지 대상에 포함됨을 형식이 보장된 내부 계약으로 입증하지 못해 자동 사례 결합을 수행하지 않았습니다.",
    "Path Traversal은 V1 인증 사례와 자동 결합하지 않습니다.",
    "모호한 관계라 자동 사례 결합을 수행하지 않았습니다."
  ]);
  const ERROR_CODES = new Set([
    "NON_EMPTY_BODY", "QUERY_NOT_ALLOWED", "RATE_LIMITED", "CONCURRENCY_LIMIT",
    "ANALYSIS_TIMEOUT", "FIXTURE_UNAVAILABLE", "ANALYSIS_FAILED",
    "CASE_PROJECTION_FAILED", "RESPONSE_INVALID", "REPORT_GENERATION_FAILED"
  ]);
  const TOP_LEVEL = [
    "schema_version", "sample_context", "analysis_summary", "case_summary", "cases",
    "independent_observations", "interpretation_notices", "capabilities",
    "bounded_warnings", "report_export"
  ];
  const ACCOUNT_MESSAGE = "계정 별칭을 표시할 수 없음. 원래 계정 정보는 개인정보 보호를 위해 결과에 포함되지 않습니다.";
  const GROUPING_EXPLANATIONS = new Set([
    "Brute Force 탐지 관찰과 이후 동일 계정의 로그인 성공 관계가 기존 상관분석에서 확인되어 함께 검토합니다.",
    "동일 계정의 로그인 실패 후 성공 관계가 기존 상관분석에서 확인되어 함께 검토합니다."
  ]);

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
  const reportDownload = document.getElementById("report-download");
  const reportButton = document.getElementById("report-button");
  let pending = false;
  let currentReport = null;

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
    if (value === null) return null;
    closedRecord(value, ["display_kst", "display_utc"]);
    const utc = boundedText(value.display_utc);
    const kst = boundedText(value.display_kst);
    const utcMatch = /^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(\.\d{6})?Z$/.exec(utc);
    const kstMatch = /^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(\.\d{6})? KST \(UTC\+09:00\)$/.exec(kst);
    if (!utcMatch || !kstMatch || (utcMatch[3] || "") !== (kstMatch[3] || "")) failContract();
    const base = `${utcMatch[1]}T${utcMatch[2]}`;
    const milliseconds = Date.parse(`${base}Z`);
    if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 19) !== base) failContract();
    const kstBase = new Date(milliseconds + 9 * 60 * 60 * 1000).toISOString().slice(0, 19);
    if (`${kstMatch[1]}T${kstMatch[2]}` !== kstBase) failContract();
    return `${base}${utcMatch[3] || ".000000"}`;
  }

  function evidence(value, expected) {
    if (items(value).length !== expected.length) failContract();
    value.forEach((item, index) => {
      closedRecord(item, ["label", "value", "unit"]);
      const [label, unit, integer] = expected[index];
      if (item.label !== label || item.unit !== unit ||
          typeof item.value !== "number" || !Number.isFinite(item.value) ||
          item.value < 0 || item.value > MAX_EVIDENCE_VALUE ||
          (integer && !Number.isSafeInteger(item.value))) failContract();
    });
  }

  function textItems(value, label, approvedTexts) {
    items(value).forEach((item) => {
      closedRecord(item, ["label", "text"]);
      if (item.label !== label || !approvedTexts.has(boundedText(item.text))) failContract();
    });
  }

  function account(value) {
    if (value.account_alias_state !== "unavailable" || value.account_alias_message !== ACCOUNT_MESSAGE) failContract();
  }

  function timeline(value) {
    let previousStart = null;
    let seenNoTime = false;
    items(value).forEach((entry, index) => {
      closedRecord(entry, [
        "sequence", "category", "category_label", "timestamp_state", "timestamp_state_label",
        "start_time", "end_time", "title", "fact", "subject",
        "detection_display_name", "relation_display_name", "evidence"
      ]);
      if (entry.sequence !== index + 1 || !TIMELINE_CATEGORIES.has(entry.category) ||
          entry.category_label !== CATEGORY_LABELS[entry.category]) failContract();
      if (entry.timestamp_state !== "TIMESTAMPED" && entry.timestamp_state !== "NO_TIME") failContract();
      ["title", "fact", "subject"].forEach((key) => boundedText(entry[key]));
      if (entry.timestamp_state_label !== (entry.timestamp_state === "TIMESTAMPED" ? "시각 정보 있음" : "시간 정보 없음")) failContract();
      if (entry.detection_display_name !== null) boundedText(entry.detection_display_name);
      if (entry.relation_display_name !== null) boundedText(entry.relation_display_name);
      const startKey = timestamp(entry.start_time);
      const endKey = timestamp(entry.end_time);
      if (entry.timestamp_state === "NO_TIME" ?
          entry.start_time !== null || entry.end_time !== null : entry.start_time === null) failContract();
      if (startKey === null) {
        seenNoTime = true;
      } else {
        if (seenNoTime || (previousStart !== null && startKey < previousStart) ||
            (endKey !== null && endKey < startKey)) failContract();
        previousStart = startKey;
      }
      if (entry.category === "OBSERVED_FACT") {
        if (!["인증 실패 관찰", "인증 성공 관찰"].includes(entry.title) ||
            entry.detection_display_name !== null || entry.relation_display_name !== null) failContract();
        evidence(entry.evidence, []);
      } else if (entry.category === "DETECTION_OBSERVATION") {
        if (!DETECTION_NAMES.has(entry.detection_display_name) || entry.relation_display_name !== null ||
            entry.title !== `${entry.detection_display_name} 탐지 관찰`) failContract();
        evidence(entry.evidence, DETECTION_EVIDENCE);
      } else {
        if (!RELATION_NAMES.has(entry.relation_display_name) || entry.detection_display_name !== null ||
            entry.title !== entry.relation_display_name) failContract();
        evidence(entry.evidence, RELATION_EVIDENCE);
      }
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
    const startKey = timestamp(item.start_time);
    const endKey = timestamp(item.end_time);
    if (startKey !== null && endKey !== null && endKey < startKey) failContract();
    count(item.observation_count);
    count(item.supporting_relation_count);
    if (!GROUPING_EXPLANATIONS.has(boundedText(item.grouping_explanation))) failContract();
    if (!texts(item.supported_detections).every((name) => DETECTION_NAMES.has(name)) ||
        !texts(item.supported_relations).every((name) => RELATION_NAMES.has(name))) failContract();
    if (item.timeline_label !== "시간순 조사 흐름") failContract();
    timeline(item.timeline);
    const detections = [...new Set(item.timeline.map((entry) => entry.detection_display_name).filter((name) => name !== null))];
    const relations = [...new Set(item.timeline.map((entry) => entry.relation_display_name).filter((name) => name !== null))];
    if (item.supported_detections.join("|") !== detections.join("|") ||
        item.supported_relations.join("|") !== relations.join("|") ||
        item.supporting_relation_count !== relations.length ||
        item.observation_count + item.supporting_relation_count !== item.timeline.length) failContract();
    textItems(item.limitations, "해석 시 유의사항", LIMITATION_TEXTS);
    textItems(item.unverified_items, "확인되지 않은 사항", UNVERIFIED_TEXTS);
    if (items(item.next_steps, 3).length !== 0) {
      textItems(item.next_steps, "다음 조사 단계", new Set(NEXT_STEP_SEQUENCES.flat()));
      const expected = item.supported_relations.includes("Brute Force → Successful Login") ?
        NEXT_STEP_SEQUENCES[0] : NEXT_STEP_SEQUENCES[1];
      if (item.next_steps.map((step) => step.text).join("|") !== expected.join("|")) failContract();
    }
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
    if (!["관찰된 사실", "탐지 관찰", "지원되는 관계"].includes(item.category_label) ||
        !INDEPENDENT_NAMES.has(item.display_type) || !INDEPENDENT_REASONS.has(item.reason)) failContract();
    risk(item.existing_risk_level);
    risk(item.existing_confidence);
    const startKey = timestamp(item.start_time);
    const endKey = timestamp(item.end_time);
    if (startKey !== null && endKey !== null && endKey < startKey) failContract();
    if (item.timestamp_state !== "TIMESTAMPED" && item.timestamp_state !== "NO_TIME") failContract();
    if (item.timestamp_state === "NO_TIME" ?
        item.start_time !== null || item.end_time !== null : item.start_time === null) failContract();
    evidence(item.evidence, DETECTION_NAMES.has(item.display_type) ? DETECTION_EVIDENCE : []);
    account(item);
  }

  function validateReportExport(value) {
    closedRecord(value, [
      "available", "format", "filename", "media_type", "html", "byte_count",
      "format_notice", "handling_warning"
    ]);
    if (value.available !== true || value.format !== "standalone_html" ||
        value.filename !== "investigation-report.html" ||
        value.media_type !== "text/html;charset=utf-8" ||
        value.format_notice !== "현재 형식: 대상별 결정적 조사 보고서. 조사 사례 Timeline은 포함하지 않습니다." ||
        value.handling_warning !== "다운로드 파일은 민감한 조사 자료입니다. 저장·공유·삭제에 주의하십시오." ||
        !Number.isSafeInteger(value.byte_count) || value.byte_count < 1 ||
        value.byte_count > MAX_REPORT_BYTES || typeof value.html !== "string" ||
        value.html.length > MAX_REPORT_BYTES) failContract();
    const bytes = new TextEncoder().encode(value.html);
    if (bytes.byteLength !== value.byte_count ||
        !value.html.startsWith("<!doctype html>\n<html lang=\"ko\">") ||
        !value.html.endsWith("</html>\n") ||
        !value.html.includes('http-equiv="Content-Security-Policy"') ||
        !value.html.includes("교육용 합성 샘플 결과입니다.") ||
        !value.html.includes("script-src 'none'") ||
        !value.html.includes("connect-src 'none'") ||
        !value.html.includes("style-src 'sha256-") ||
        /<(?:script|iframe|object|embed|link|img)\b|\b(?:src|href|onload|onclick)\s*=|https?:\/\/|@import|url\s*\(/i.test(value.html)) failContract();
    return value;
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
        summary.case_count !== items(value.cases, MAX_CASES).length ||
        summary.independent_observation_count !== items(value.independent_observations, MAX_INDEPENDENT).length ||
        summary.relation_case_count > summary.case_count) failContract();
    value.cases.forEach(validateCase);
    value.independent_observations.forEach(validateIndependent);
    const risks = {HIGH: 0, MEDIUM: 0, LOW: 0};
    value.cases.forEach((item) => { risks[item.included_highest_risk] += 1; });
    if (risks.HIGH !== summary.high_case_count || risks.MEDIUM !== summary.medium_case_count ||
        risks.LOW !== summary.low_case_count ||
        value.cases.filter((item) => item.supporting_relation_count > 0).length !== summary.relation_case_count) failContract();
    texts(value.interpretation_notices);
    texts(value.bounded_warnings);
    closedRecord(value.capabilities, [
      "html_report_available", "llm_summary_available", "linux_audit_aggregate_available", "actual_log_upload_available"
    ]);
    if (value.capabilities.html_report_available !== true ||
        value.capabilities.llm_summary_available !== false ||
        value.capabilities.linux_audit_aggregate_available !== false ||
        value.capabilities.actual_log_upload_available !== false) failContract();
    validateReportExport(value.report_export);
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

  function timeNode(value) {
    const node = element("time", value.display_kst);
    node.setAttribute("datetime", value.display_utc);
    return node;
  }

  function timeBlock(value) {
    const block = document.createElement("div");
    block.className = "time-block";
    const kst = document.createElement("div");
    kst.className = "time-line time-kst";
    kst.append(element("span", "KST", "time-zone-label"), timeNode(value));
    const utc = document.createElement("div");
    utc.className = "time-line time-utc";
    utc.append(element("span", "UTC", "time-zone-label"),
      element("span", value.display_utc, "time-utc-value"));
    block.append(kst, utc);
    return block;
  }

  function appendTime(parent, start, end) {
    if (!start) {
      parent.append(element("span", "시간 정보 없음"));
      return;
    }
    if (!end || end.display_utc === start.display_utc) {
      parent.append(timeBlock(start));
      return;
    }
    const range = document.createElement("dl");
    range.className = "time-range";
    const startRow = document.createElement("div");
    startRow.className = "time-row";
    const startValue = document.createElement("dd");
    startValue.append(timeBlock(start));
    startRow.append(element("dt", "시작"), startValue);
    const endRow = document.createElement("div");
    endRow.className = "time-row";
    const endValue = document.createElement("dd");
    endValue.append(timeBlock(end));
    endRow.append(element("dt", "종료"), endValue);
    range.append(startRow, endRow);
    parent.append(range);
  }

  function detailSection(title) {
    const section = document.createElement("section");
    section.className = "case-section";
    section.append(element("h5", title));
    return section;
  }

  function textList(section, values, ordered, emptyMessage) {
    if (values.length === 0) {
      section.append(element("p", emptyMessage));
      return;
    }
    const list = document.createElement(ordered ? "ol" : "ul");
    values.forEach((value) => list.append(element("li", value)));
    section.append(list);
  }

  function evidenceList(values) {
    const list = document.createElement("dl");
    list.className = "evidence-list";
    values.forEach((item) => detail(list, item.label, `${item.value} ${item.unit}`));
    return list;
  }

  function renderTimeline(caseItem) {
    const section = detailSection("시간순 조사 흐름");
    if (caseItem.timeline.length === 0) {
      section.append(element("p", "표시할 시간순 조사 항목이 없습니다."));
      return section;
    }
    const list = document.createElement("ol");
    list.className = "timeline";
    caseItem.timeline.forEach((entry) => {
      const row = document.createElement("li");
      row.className = `timeline-item ${{
        OBSERVED_FACT: "timeline-fact", DETECTION_OBSERVATION: "timeline-detection",
        SUPPORTED_RELATION: "timeline-relation"
      }[entry.category]}`;
      row.append(element("span", entry.category_label, "category-label"),
        element("strong", entry.title));
      const time = document.createElement("div");
      time.className = "timeline-time";
      appendTime(time, entry.start_time, entry.end_time);
      row.append(time, element("p", entry.fact));
      list.append(row);
    });
    section.append(list);
    return section;
  }

  function renderObservedSection(caseItem, category, title, emptyMessage) {
    const section = detailSection(title);
    const entries = caseItem.timeline.filter((entry) => entry.category === category);
    if (entries.length === 0) {
      section.append(element("p", emptyMessage));
      return section;
    }
    const list = document.createElement("ul");
    list.className = "observation-list";
    entries.forEach((entry) => {
      const item = document.createElement("li");
      item.append(element("strong", category === "DETECTION_OBSERVATION" ?
        entry.detection_display_name : entry.relation_display_name));
      item.append(evidenceList(entry.evidence));
      list.append(item);
    });
    section.append(list);
    if (category === "SUPPORTED_RELATION") {
      section.append(element("p", caseItem.account_alias_message, "account-note"));
    }
    return section;
  }

  function renderCaseDetail(caseItem) {
    const body = document.createElement("div");
    body.className = "case-detail";
    body.append(element("p", caseItem.grouping_explanation, "grouping-explanation"));
    const meta = document.createElement("dl");
    meta.className = "card-meta";
    detail(meta, "관찰 수", String(caseItem.observation_count));
    body.append(meta);
    const range = detailSection("시간 범위");
    const time = document.createElement("div");
    appendTime(time, caseItem.start_time, caseItem.end_time);
    range.append(time);
    body.append(range, renderTimeline(caseItem),
      renderObservedSection(caseItem, "DETECTION_OBSERVATION", "탐지 관찰", "표시할 지원 탐지 관찰이 없습니다."),
      renderObservedSection(caseItem, "SUPPORTED_RELATION", "지원되는 관계", "표시할 지원되는 관계가 없습니다."));
    const assessment = detailSection("위험도 평가");
    const assessmentValues = document.createElement("dl");
    assessmentValues.className = "card-meta";
    detail(assessmentValues, "포함된 최고 위험도", caseItem.included_highest_risk);
    detail(assessmentValues, "포함된 최고 신뢰도", caseItem.included_highest_confidence);
    assessment.append(assessmentValues, element("p",
      "이 위험도는 사례 안에 포함된 기존 분석 결과 중 가장 높은 값입니다. 새로운 사건 점수나 침해 확률이 아닙니다."));
    body.append(assessment);
    const limitations = detailSection("해석 시 유의사항");
    textList(limitations, caseItem.limitations.map((item) => item.text), false,
      "추가로 표시할 사례별 해석 한계가 없습니다. 공통 해석 주의사항도 확인하십시오.");
    const unverified = detailSection("확인되지 않은 사항");
    textList(unverified, caseItem.unverified_items.map((item) => item.text), false,
      "추가로 표시할 미확인 사항이 없습니다.");
    const nextSteps = detailSection("다음 조사 단계");
    textList(nextSteps, caseItem.next_steps.map((item) => item.text), true,
      "표시할 고정 조사 단계가 없습니다.");
    body.append(limitations, unverified, nextSteps);
    return body;
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
      const card = document.createElement("details");
      card.className = "case-card";
      card.open = item.included_highest_risk === "HIGH" || item.included_highest_risk === "MEDIUM";
      const summary = document.createElement("summary");
      summary.className = "case-summary";
      summary.append(element("h4", item.case_label),
        element("span", `조사 순서 ${item.review_order} · 분석 대상 ${item.subject}`, "summary-subject"));
      summary.append(riskBadge(item.included_highest_risk),
        element("span", `신뢰도 ${item.included_highest_confidence}`, "summary-confidence"),
        element("span", `주요 탐지: ${item.supported_detections.join(", ") || "표시할 지원 탐지 관찰이 없습니다."}`, "summary-line"),
        element("span", `지원 관계: ${item.supported_relations.join(", ") || "표시할 지원되는 관계가 없습니다."}`, "summary-line"),
        element("span", "기존 지원 관계에 따라 함께 검토합니다.", "summary-line"));
      card.append(summary, renderCaseDetail(item));
      caseList.append(card);
    });
  }

  function renderIndependentObservations(observations) {
    if (observations.length === 0) {
      independentList.append(element("p", "별도로 표시할 독립 관찰이 없습니다."));
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
      card.append(meta);
      const time = document.createElement("div");
      time.className = "independent-time";
      appendTime(time, item.start_time, item.end_time);
      card.append(time, element("p", item.reason));
      if (item.evidence.length > 0) {
        const evidenceSection = document.createElement("section");
        evidenceSection.className = "independent-evidence";
        evidenceSection.append(element("h5", "관찰 근거"), evidenceList(item.evidence));
        card.append(evidenceSection);
      } else {
        card.append(element("p", "이 응답에서 승인된 상세 관찰 근거를 표시할 수 없습니다."));
      }
      independentList.append(card);
    });
  }

  function clearPreviousResult() {
    currentReport = null;
    reportDownload.hidden = true;
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

  function downloadReport() {
    if (pending || currentReport === null) return;
    try {
      const report = validateReportExport(currentReport);
      const bytes = new TextEncoder().encode(report.html);
      const file = new Blob([bytes], {type: "text/html;charset=utf-8"});
      const objectUrl = URL.createObjectURL(file);
      const link = document.createElement("a");
      try {
        link.href = objectUrl;
        link.download = "investigation-report.html";
        document.body.append(link);
        link.click();
      } finally {
        link.remove();
        URL.revokeObjectURL(objectUrl);
      }
    } catch (failure) {
      clearPreviousResult();
      renderError(failure);
    }
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
      capabilityMessage.textContent = "실제 로그 웹 업로드, LLM 설명과 Linux Audit 집계는 이 체험에서 제공되지 않습니다.";
      currentReport = data.report_export;
      reportDownload.hidden = false;
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
  reportButton.addEventListener("click", downloadReport);
})();
