"use strict";

(() => {
  const ROLE_NAMES = Object.freeze({application: "애플리케이션 로그인 로그", ssh: "SSH 인증 로그"});
  const DETECTION_NAMES = Object.freeze({
    brute_force: "로그인 실패가 반복된 관찰", password_spraying_like: "여러 계정의 로그인 실패 관찰",
    path_traversal: "경로 조작 시도 관찰", sql_injection_like: "SQL 입력 패턴 관찰",
    xss_like: "스크립트 입력 패턴 관찰", sensitive_resource_probing_like: "민감 경로 접근 관찰",
    web_scanning_like: "웹 경로 탐색 관찰",
  });
  const RELATION_NAMES = Object.freeze({
    failed_to_successful_login: "로그인 실패 뒤 성공 기록",
    brute_force_to_successful_login: "반복 실패 뒤 성공 기록",
    password_spray_to_successful_login: "여러 계정 실패 뒤 성공 기록",
    successful_login_to_file_access: "로그인 뒤 파일 접근 기록",
  });
  const LEVEL_NAMES = Object.freeze({LOW: "낮음", MEDIUM: "보통", HIGH: "높음"});
  const STATES = new Set(["READY", "RUNNING", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]);
  const ID = /^LIVE-EVENT-([0-9]{6,19})-([0-9]{6,19})$/;
  const STATUS_KEYS = ["schema_version", "service_state", "session_id", "roles", "available_event_count", "event_byte_count", "earliest_event_id", "latest_event_id", "published_total", "evicted_total", "replay_gap_total", "max_event_items", "max_event_bytes", "max_connections", "active_connections", "fixed_error_code", "interpretation_notices", "capabilities"];
  const ROLE_KEYS = ["role", "service_state", "detection_revision", "analysis_revision", "active_observation_count", "active_relation_count", "active_risk_count", "active_case_count", "checkpoint_available", "last_step_code"];
  const OBS_KEYS = ["event_id", "session_id", "revision", "event_type", "created_count", "updated_count", "no_longer_matches_count", "active_observation_count", "published_observation_count", "observations", "schema_version", "source_role", "detection_revision", "analysis_revision"];
  const ANALYSIS_KEYS = ["event_id", "session_id", "revision", "event_type", "source_role", "relation_changes", "risk_changes", "case_changes", "summary", "bounded_warnings", "schema_version", "detection_revision", "analysis_revision"];
  const dom = (id) => document.getElementById(id);
  let source = null;
  let statusValue = null;
  let selectedRole = "application";
  let paused = false;
  let stale = false;
  let lastNumber = 0n;
  let pending = {application: [], ssh: []};
  let committed = {application: null, ssh: null};
  const displayed = {application: [], ssh: []};

  function exact(value, keys) {
    return value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).sort().join("|") === [...keys].sort().join("|");
  }
  function integer(value) { return Number.isSafeInteger(value) && value >= 0; }
  function validateStatus(value) {
    if (!exact(value, STATUS_KEYS) || value.schema_version !== "3" || !STATES.has(value.service_state) ||
        !/^LIVE-SESSION-[0-9]{6,19}$/.test(value.session_id) || !Array.isArray(value.roles) || value.roles.length !== 2) throw new Error("invalid");
    if (value.roles.map((item) => item.role).join("|") !== "application|ssh") throw new Error("invalid");
    for (const role of value.roles) {
      if (!exact(role, ROLE_KEYS) || !STATES.has(role.service_state) || typeof role.checkpoint_available !== "boolean" ||
          ![role.detection_revision, role.analysis_revision, role.active_observation_count, role.active_relation_count,
            role.active_risk_count, role.active_case_count].every(integer) || role.analysis_revision > role.detection_revision ||
          ![null, "NO_DATA", "PROCESSED", "DEGRADED", "FAILED"].includes(role.last_step_code)) throw new Error("invalid");
    }
    for (const key of ["available_event_count", "event_byte_count", "published_total", "evicted_total", "replay_gap_total", "max_event_items", "max_event_bytes", "max_connections", "active_connections"]) if (!integer(value[key])) throw new Error("invalid");
    if (value.available_event_count > 32 || value.event_byte_count > 16384 || value.available_event_count > value.max_event_items ||
        value.event_byte_count > value.max_event_bytes || value.active_connections > value.max_connections) throw new Error("invalid");
    return value;
  }
  function showStatus(value) {
    statusValue = value;
    dom("live-pair").hidden = false;
    dom("live-result-details").hidden = true;
    const failed = value.service_state === "DEGRADED" || value.service_state === "FAILED" || value.service_state === "STOPPED";
    dom("pair-overall").textContent = failed ? "전체 모니터링에 확인이 필요합니다." : "두 로그를 함께 확인하고 있습니다.";
    const item = value.roles.find((row) => row.role === selectedRole);
    dom("pair-role-heading").textContent = ROLE_NAMES[selectedRole];
    const stateText = ({READY: "새 기록 대기 중", RUNNING: "기록 확인 중", DEGRADED: "처리 확인 필요", FAILED: "처리 중단", STOPPING: "종료 중", STOPPED: "종료됨"})[item.service_state];
    dom("pair-role-state").textContent = `${stateText} · ${item.checkpoint_available ? "이전 상태를 이어갈 복구 자료가 있습니다" : "첫 실행 상태입니다"}`;
    dom("pair-role-counts").textContent = `관찰 ${item.active_observation_count}건 · 관계 ${item.active_relation_count}건 · 위험도 ${item.active_risk_count}건 · 조사 사례 ${item.active_case_count}건`;
    for (const button of document.querySelectorAll("[data-pair-role]")) button.setAttribute("aria-pressed", String(button.dataset.pairRole === selectedRole));
    dom("pair-recovery").hidden = !stale;
    updatePending();
  }
  function updatePending() {
    const count = pending[selectedRole].length;
    dom("pair-app-badge").textContent = pending.application.length ? `새 결과 ${pending.application.length}` : "";
    dom("pair-ssh-badge").textContent = pending.ssh.length ? `새 결과 ${pending.ssh.length}` : "";
    dom("pair-apply").hidden = count === 0 || paused || stale;
    dom("pair-pending").textContent = paused ? "화면 반영을 일시 정지했습니다. 서버 수집은 계속될 수 있습니다." :
      count ? `${ROLE_NAMES[selectedRole]}에 새 결과 ${count}건이 준비되어 있습니다. 버튼을 선택하면 현재 요약에 반영합니다.` : "현재 새 결과가 없습니다.";
  }
  function addList(id, label, items, limit = 12) {
    const list = dom(id); list.replaceChildren();
    for (const text of items.slice(-limit)) { const row = document.createElement("li"); row.textContent = text; list.appendChild(row); }
  }
  function renderRole() {
    const events = displayed[selectedRole];
    const observations = [], relations = [], risks = [], cases = [];
    for (const value of events) {
      if (value.event_type === "observation_changes") {
        for (const item of value.observations) observations.push(`${DETECTION_NAMES[item.detection_type]} · ${item.change_type === "CREATED" ? "새 관찰" : item.change_type === "UPDATED" ? "관찰 변경" : "현재 결과에서 제외"}`);
      } else {
        for (const item of value.relation_changes) relations.push(`${RELATION_NAMES[item.relation_type]} · ${item.change_type === "RELATION_CREATED" ? "관계 기록 추가" : item.change_type === "RELATION_UPDATED" ? "관계 기록 변경" : "현재 결과에서 제외"}`);
        for (const item of value.risk_changes) risks.push(`위험도 ${LEVEL_NAMES[item.risk_level]} · 근거 수준 ${LEVEL_NAMES[item.confidence]} · ${item.change_type === "RISK_CREATED" ? "새 평가" : item.change_type === "RISK_UPDATED" ? "평가 변경" : "현재 결과에 없음"}`);
        for (const item of value.case_changes) cases.push(`조사 사례 · ${item.change_type === "CASE_CREATED" ? "추가" : item.change_type === "CASE_UPDATED" ? "변경" : "현재 결과에서 제외"}`);
      }
    }
    addList("pair-observations", "관찰", observations);
    addList("pair-relations", "관계", relations);
    addList("pair-risks", "위험도", risks);
    addList("pair-cases", "사례", cases);
  }
  function close(terminal) {
    if (source) { source.close(); source = null; }
    if (terminal) { stale = true; dom("pair-recovery").hidden = false; }
  }
  function event(type, message) {
    let value;
    try { value = JSON.parse(message.data); } catch (_) { close(true); return; }
    if (type === "snapshot") {
      try { showStatus(validateStatus(value)); } catch (_) { close(true); }
      return;
    }
    if (type === "replay_gap") {
      if (!exact(value, ["schema_version", "code", "affected_roles", "stale", "recovery_action"]) || value.schema_version !== "3" ||
          value.stale !== true || !Array.isArray(value.affected_roles) || value.affected_roles.some((role) => !ROLE_NAMES[role])) { close(true); return; }
      stale = true; dom("pair-recovery").hidden = false; close(true); return;
    }
    if (type === "service_status" || type === "stream_end") { close(true); return; }
    if (type === "heartbeat") return;
    if (type !== "observation_changes" && type !== "analysis_changes") { close(true); return; }
    try {
      if (!exact(value, type === "observation_changes" ? OBS_KEYS : ANALYSIS_KEYS) || value.schema_version !== "3" || value.event_type !== type || !ROLE_NAMES[value.source_role] ||
          value.session_id !== statusValue.session_id || !integer(value.revision) || !integer(value.detection_revision) ||
          !integer(value.analysis_revision) || value.analysis_revision > value.detection_revision ||
          (type === "observation_changes" && (!Array.isArray(value.observations) || value.observations.some((item) =>
            !exact(item, ["observation_id", "observation_revision", "change_type", "state", "detection_type", "accumulator_revision"]) ||
            !/^LIVE-OBS-[0-9]{6,19}$/.test(item.observation_id) || !integer(item.observation_revision) || !integer(item.accumulator_revision) ||
            !["CREATED", "UPDATED", "NO_LONGER_MATCHES"].includes(item.change_type) ||
            !["ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT"].includes(item.state) ||
            !["brute_force", "password_spraying_like", "path_traversal", "sql_injection_like", "xss_like", "sensitive_resource_probing_like", "web_scanning_like"].includes(item.detection_type)))) ||
          (type === "analysis_changes" && (!Array.isArray(value.relation_changes) || !Array.isArray(value.risk_changes) ||
            !Array.isArray(value.case_changes) || !exact(value.summary, ["relation_count", "risk_count", "case_count"]) ||
            !Array.isArray(value.bounded_warnings) || value.bounded_warnings.length !== 0 ||
            ![value.summary.relation_count, value.summary.risk_count, value.summary.case_count].every(integer) ||
            value.relation_changes.some((item) =>
              !exact(item, ["relation_id", "revision", "relation_type", "state", "delta_seconds", "change_type"]) ||
              !/^LIVE-REL-[0-9]{6,19}$/.test(item.relation_id) || !integer(item.revision) ||
              typeof item.delta_seconds !== "number" || !Number.isFinite(item.delta_seconds) || item.delta_seconds <= 0 || item.delta_seconds > 60 ||
              !["ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT"].includes(item.state) ||
              !["RELATION_CREATED", "RELATION_UPDATED", "RELATION_NO_LONGER_MATCHES"].includes(item.change_type) ||
              !["failed_to_successful_login", "brute_force_to_successful_login", "password_spray_to_successful_login", "successful_login_to_file_access"].includes(item.relation_type)) ||
            value.risk_changes.some((item) => !exact(item, ["risk_id", "revision", "state", "risk_level", "confidence", "change_type"]) ||
              !/^LIVE-RISK-[0-9]{6,19}$/.test(item.risk_id) || !integer(item.revision) ||
              !["CURRENT", "NO_LONGER_PRESENT"].includes(item.state) ||
              !["RISK_CREATED", "RISK_UPDATED", "RISK_NO_LONGER_PRESENT"].includes(item.change_type) || !["LOW", "MEDIUM", "HIGH"].includes(item.risk_level) || !["LOW", "MEDIUM", "HIGH"].includes(item.confidence)) ||
            value.case_changes.some((item) => !exact(item, ["case_id", "revision", "state", "rule_id", "included_highest_risk", "included_highest_confidence", "relation_count", "observation_count", "supporting_relation_count", "account_reference_status", "change_type"]) ||
              !/^LIVE-CASE-[0-9]{6,19}$/.test(item.case_id) || !integer(item.revision) ||
              !["CURRENT", "NO_LONGER_MATCHES_CURRENT_RESULT"].includes(item.state) ||
              !["CASE_CREATED", "CASE_UPDATED", "CASE_NO_LONGER_MATCHES"].includes(item.change_type) ||
              !["CASE-AUTH-TRANSITION-01", "CASE-BRUTE-SUCCESS-01"].includes(item.rule_id) ||
              ![item.relation_count, item.observation_count, item.supporting_relation_count].every(integer) ||
              !["LOW", "MEDIUM", "HIGH"].includes(item.included_highest_risk) ||
              !["LOW", "MEDIUM", "HIGH"].includes(item.included_highest_confidence) ||
              item.account_reference_status !== "ACCOUNT_REFERENCE_UNAVAILABLE"))) || typeof message.lastEventId !== "string") throw new Error("invalid");
      const match = ID.exec(message.lastEventId);
      if (!match || value.event_id !== message.lastEventId || BigInt(match[1]) !== BigInt(statusValue.session_id.slice(13))) throw new Error("invalid");
      const number = BigInt(match[2]);
      if (number <= lastNumber || pending.application.length + pending.ssh.length >= 32) throw new Error("overflow");
      const encodedBytes = new TextEncoder().encode(message.data).length;
      const byteTotal = [...pending.application, ...pending.ssh].reduce((n, item) => n + item.bytes, 0);
      if (byteTotal + encodedBytes > 16384) throw new Error("overflow");
      lastNumber = number;
      pending[value.source_role].push({bytes: encodedBytes, value});
      if (!paused) updatePending();
    } catch (_) { stale = true; pending = {application: [], ssh: []}; dom("pair-recovery").hidden = false; close(true); }
  }
  function start(value) {
    try { showStatus(validateStatus(value)); } catch (_) { return false; }
    if (source) return true;
    source = new EventSource("/api/v1/live/events");
    ["snapshot", "observation_changes", "analysis_changes", "replay_gap", "service_status", "stream_end", "heartbeat"].forEach((type) => source.addEventListener(type, (message) => { if (source) event(type, message); }));
    source.onerror = () => close(true);
    return true;
  }
  document.querySelectorAll("[data-pair-role]").forEach((button) => button.addEventListener("click", () => {
    selectedRole = button.dataset.pairRole; if (statusValue) { showStatus(statusValue); renderRole(); }
  }));
  dom("pair-apply").addEventListener("click", () => {
    const batch = pending[selectedRole]; if (!batch.length) return;
    const latest = batch[batch.length - 1];
    committed[selectedRole] = latest.value;
    displayed[selectedRole].push(...batch.map((entry) => entry.value));
    pending[selectedRole] = [];
    renderRole();
    updatePending();
  });
  dom("pair-pause").addEventListener("click", () => {
    paused = !paused; dom("pair-pause").textContent = paused ? "화면 업데이트 다시 시작" : "화면 업데이트 일시 정지";
    updatePending();
  });
  window.MultiSourceLive = Object.freeze({start});
})();
