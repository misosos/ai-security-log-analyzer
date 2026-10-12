"use strict";

(() => {
  const STATUS_URL = "/api/v1/live/status";
  const EVENTS_URL = "/api/v1/live/events";
  const MAX_PENDING_ITEMS = 32;
  const MAX_PENDING_BYTES = 16384;
  const MAX_VISIBLE = 32;
  const MAX_ERRORS = 3;
  const MAX_SAFE = Number.MAX_SAFE_INTEGER;
  const SESSION_ID = /^LIVE-SESSION-([0-9]{6,19})$/;
  const EVENT_ID = /^LIVE-EVENT-([0-9]{6,19})-([0-9]{6,19})$/;
  const OBSERVATION_ID = /^LIVE-OBS-([0-9]{6,19})$/;
  const TYPES = Object.freeze({
    brute_force: "반복 인증 실패 관찰",
    password_spraying_like: "다계정 인증 시도 관찰",
    path_traversal: "경로 탐색 요청 관찰",
    sql_injection_like: "SQL Injection 유사 요청 관찰",
    xss_like: "XSS 유사 요청 관찰",
    sensitive_resource_probing_like: "민감 리소스 탐색 관찰",
    web_scanning_like: "다중 웹 대상 탐색 관찰"
  });
  const ROLES = Object.freeze({application: "애플리케이션 인증 로그", ssh: "SSH 인증 로그", access: "웹 접근 로그"});
  const SERVICE_STATES = new Set(["READY", "RUNNING", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]);
  const WORKER_STATES = new Set(["READY", "RUNNING_STEP", "DEGRADED", "FAILED", "STOPPING", "STOPPED"]);
  const CHANGE_TYPES = new Set(["CREATED", "UPDATED", "NO_LONGER_MATCHES"]);
  const OBSERVATION_STATES = new Set(["ACTIVE", "NO_LONGER_MATCHES_CURRENT_RESULT"]);
  const GAP_CODES = new Set(["BUFFER_CLOSED", "MALFORMED_EVENT_ID", "FOREIGN_SESSION", "FUTURE_EVENT_ID", "EVICTED_EVENT_ID", "UNKNOWN_EVENT_ID"]);
  const NOTICES = new Set([
    "규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.",
    "지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다."
  ]);
  const CAPABILITIES = new Set(["READ_ONLY_STATUS", "BOUNDED_SSE_REPLAY", "AUTOMATIC_POLLING", "NO_AUTOMATIC_POLLING", "NO_LLM"]);
  const STATUS_KEYS = ["schema_version", "service_state", "session_id", "source_role", "worker_state", "publication_state", "latest_detection_revision", "available_event_count", "earliest_event_id", "latest_event_id", "active_observation_count", "published_total", "evicted_total", "replay_gap_total", "max_event_items", "max_event_bytes", "max_connections", "active_connections", "fixed_error_code", "recovery_action", "interpretation_notices", "capabilities"];
  const SNAPSHOT_KEYS = ["schema_version", "state", "session_id", "item_count", "byte_count", "max_items", "max_bytes", "earliest_available_event_id", "latest_available_event_id", "latest_committed_detection_revision", "published_total", "evicted_total", "rejected_oversized_total", "replay_gap_total", "active_observation_count", "last_created_count", "last_updated_count", "last_no_longer_matches_count"];
  const EVENT_KEYS = ["event_id", "session_id", "revision", "event_type", "created_count", "updated_count", "no_longer_matches_count", "active_observation_count", "published_observation_count", "observations"];
  const CHANGE_KEYS = ["observation_id", "observation_revision", "change_type", "state", "detection_type", "accumulator_revision"];
  const ids = ["live-monitoring", "live-service-state", "live-connection-state", "live-processing-state", "live-source-role", "live-summary", "live-show-pending", "live-pause", "live-reconnect", "live-pending-status", "live-error", "live-empty", "live-observations", "live-stale"];
  const dom = Object.fromEntries(ids.map((id) => [id, document.getElementById(id)]));
  if (ids.some((id) => !dom[id])) return;

  let sessionId = null;
  let source = null;
  let pending = [];
  let pendingBytes = 0;
  let visible = new Map();
  let paused = false;
  let stale = false;
  let eventSource = null;
  let errors = 0;
  let lastEventNumber = 0;
  let lastEventRevision = 0;
  let latestSnapshotRevision = 0;

  function fail() { throw new Error("LIVE_UI_CONTRACT_INVALID"); }
  function object(value, keys) {
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).length !== keys.length ||
        !keys.every((key) => Object.hasOwn(value, key))) fail();
    return value;
  }
  function count(value, max = MAX_SAFE) {
    if (!Number.isSafeInteger(value) || value < 0 || value > max) fail();
    return value;
  }
  function positive(value, max = MAX_SAFE) {
    if (count(value, max) < 1) fail();
    return value;
  }
  function id(value, pattern) {
    if (typeof value !== "string" || !pattern.test(value)) fail();
    const numbers = pattern.exec(value).slice(1).map(Number);
    const prefix = pattern === SESSION_ID ? "LIVE-SESSION-" : pattern === EVENT_ID ? "LIVE-EVENT-" : "LIVE-OBS-";
    if (numbers.some((number) => !Number.isSafeInteger(number) || number < 1) ||
        value !== prefix + numbers.map((number) => String(number).padStart(6, "0")).join("-")) fail();
    return numbers;
  }
  function optionalId(value, pattern) { if (value !== null) id(value, pattern); }
  function pairedIds(first, last, session, itemCount) {
    if ((first === null) !== (last === null) || (itemCount === 0) !== (first === null)) fail();
    if (first !== null) {
      const a = id(first, EVENT_ID), b = id(last, EVENT_ID), s = id(session, SESSION_ID)[0];
      if (a[0] !== s || b[0] !== s || a[1] > b[1] || b[1] - a[1] + 1 !== itemCount) fail();
    }
  }
  function validateStatus(value) {
    object(value, STATUS_KEYS);
    if (value.schema_version !== "1" || !SERVICE_STATES.has(value.service_state) ||
        !WORKER_STATES.has(value.worker_state) || !Object.hasOwn(ROLES, value.source_role) ||
        !["OPEN", "CLOSED"].includes(value.publication_state)) fail();
    id(value.session_id, SESSION_ID);
    ["latest_detection_revision", "available_event_count", "active_observation_count", "published_total", "evicted_total", "replay_gap_total", "active_connections"].forEach((key) => count(value[key]));
    ["max_event_items", "max_event_bytes", "max_connections"].forEach((key) => positive(value[key]));
    if (value.available_event_count > value.max_event_items || value.active_connections > value.max_connections ||
        value.published_total < value.evicted_total + value.available_event_count) fail();
    pairedIds(value.earliest_event_id, value.latest_event_id, value.session_id, value.available_event_count);
    if (value.fixed_error_code === null ? value.recovery_action !== null :
        (!["LIVE_RUNNER_DEGRADED", "LIVE_RUNNER_FAILED", "LIVE_SHUTDOWN_TIMEOUT"].includes(value.fixed_error_code) ||
         typeof value.recovery_action !== "string" || value.recovery_action.length > 160)) fail();
    if (!Array.isArray(value.interpretation_notices) || value.interpretation_notices.length !== 2 ||
        new Set(value.interpretation_notices).size !== 2 || !value.interpretation_notices.every((item) => NOTICES.has(item)) ||
        !Array.isArray(value.capabilities) || value.capabilities.length !== 4 ||
        new Set(value.capabilities).size !== 4 || !value.capabilities.every((item) => CAPABILITIES.has(item)) ||
        !value.capabilities.includes("NO_LLM") || !value.capabilities.includes("READ_ONLY_STATUS") ||
        !value.capabilities.includes("BOUNDED_SSE_REPLAY") ||
        value.capabilities.includes("AUTOMATIC_POLLING") === value.capabilities.includes("NO_AUTOMATIC_POLLING")) fail();
    return value;
  }
  function validateSnapshot(value) {
    object(value, SNAPSHOT_KEYS);
    if (value.schema_version !== "1" || !["OPEN", "CLOSED"].includes(value.state)) fail();
    id(value.session_id, SESSION_ID);
    ["item_count", "byte_count", "latest_committed_detection_revision", "published_total", "evicted_total", "rejected_oversized_total", "replay_gap_total", "active_observation_count", "last_created_count", "last_updated_count", "last_no_longer_matches_count"].forEach((key) => count(value[key]));
    positive(value.max_items); positive(value.max_bytes);
    if (value.item_count > value.max_items || value.byte_count > value.max_bytes ||
        value.published_total < value.evicted_total + value.item_count ||
        (value.state === "CLOSED" && value.item_count !== 0)) fail();
    pairedIds(value.earliest_available_event_id, value.latest_available_event_id, value.session_id, value.item_count);
    return value;
  }
  function validateEvent(value, wireId) {
    object(value, EVENT_KEYS);
    if (value.event_type !== "DETECTION_CHANGE" || value.session_id !== sessionId ||
        wireId !== value.event_id) fail();
    const numbers = id(value.event_id, EVENT_ID);
    if (numbers[0] !== id(sessionId, SESSION_ID)[0] || numbers[1] < lastEventNumber) fail();
    positive(value.revision);
    if (numbers[1] === lastEventNumber ? value.revision !== lastEventRevision : value.revision <= lastEventRevision) fail();
    ["created_count", "updated_count", "no_longer_matches_count", "active_observation_count", "published_observation_count"].forEach((key) => count(value[key]));
    if (!Array.isArray(value.observations) || value.observations.length < 1 ||
        value.observations.length > MAX_PENDING_ITEMS || value.published_observation_count !== value.observations.length ||
        value.created_count + value.updated_count + value.no_longer_matches_count !== value.observations.length) fail();
    const counts = {CREATED: 0, UPDATED: 0, NO_LONGER_MATCHES: 0};
    const seen = new Set();
    value.observations.forEach((change) => {
      object(change, CHANGE_KEYS);
      id(change.observation_id, OBSERVATION_ID);
      positive(change.observation_revision);
      if (seen.has(change.observation_id) || !CHANGE_TYPES.has(change.change_type) ||
          !OBSERVATION_STATES.has(change.state) || !Object.hasOwn(TYPES, change.detection_type) ||
          change.accumulator_revision !== value.revision ||
          (change.change_type === "NO_LONGER_MATCHES") !== (change.state === "NO_LONGER_MATCHES_CURRENT_RESULT")) fail();
      seen.add(change.observation_id);
      counts[change.change_type] += 1;
    });
    if (counts.CREATED !== value.created_count || counts.UPDATED !== value.updated_count ||
        counts.NO_LONGER_MATCHES !== value.no_longer_matches_count) fail();
    return {number: numbers[1], duplicate: numbers[1] === lastEventNumber, event: value};
  }
  function data(message, keys) {
    if (typeof message.data !== "string" || new TextEncoder().encode(message.data).length > MAX_PENDING_BYTES) fail();
    const parsed = JSON.parse(message.data);
    object(parsed, keys);
    return parsed;
  }
  function closeSource() { if (eventSource) { eventSource.close(); eventSource = null; } }
  function connection(text) { if (dom["live-connection-state"].textContent !== text) dom["live-connection-state"].textContent = text; }
  function error(text, recovery) {
    dom["live-error"].hidden = false;
    dom["live-error"].textContent = `${text} ${recovery}`;
  }
  function clearError() { dom["live-error"].hidden = true; dom["live-error"].textContent = ""; }
  function terminal(text, recovery) {
    closeSource(); connection("복구가 필요한 오류"); error(text, recovery);
    dom["live-reconnect"].hidden = false;
  }
  function state(value) {
    const messages = {
      READY: "시작 준비", RUNNING: "모니터링 중 — 새로 추가되는 로그 줄을 확인하고 있습니다.",
      DEGRADED: "모니터링 확인 필요 — 자동 처리가 멈췄습니다. 터미널 안내를 확인하고 서버를 다시 시작해 주세요.",
      FAILED: "모니터링 중단 — 서버를 종료한 뒤 설정과 로그 파일을 확인해 주세요.",
      STOPPING: "모니터링 종료 중", STOPPED: "모니터링 종료"
    };
    dom["live-service-state"].textContent = messages[value];
    if (value === "DEGRADED" || value === "FAILED") {
      closeSource(); connection("중단됨");
      error("실시간 처리를 계속할 수 없습니다.", "터미널 안내를 확인하고 서버를 다시 시작해 주세요.");
      dom["live-reconnect"].hidden = true;
    }
  }
  function summary(value) {
    latestSnapshotRevision = value.latest_committed_detection_revision;
    dom["live-summary"].textContent = `현재 활성 관찰 ${value.active_observation_count}건 · 게시 기록 ${value.published_total}건 · 재연결 기록 누락 ${value.evicted_total}건`;
    if (value.latest_committed_detection_revision > 0 && value.active_observation_count === 0 && visible.size === 0 && !stale)
      dom["live-empty"].textContent = "새 로그 줄은 처리됐지만 현재 탐지 관찰은 없습니다. 안전을 뜻하지 않습니다.";
  }
  function pendingStatus() {
    dom["live-show-pending"].hidden = stale || paused || pending.length === 0;
    dom["live-show-pending"].textContent = `새 결과 ${pending.length}건 보기`;
    dom["live-pending-status"].textContent = stale ? "일부 기록을 이어받지 못해 최신 요약만 표시 중" :
      pending.length ? `새 관찰 변경 ${pending.length}건${paused ? " — 화면 표시 일시 정지 중" : ""}` :
      "현재 표시할 관찰 변경 없음";
  }
  function gap(snapshot) {
    closeSource(); pending = []; pendingBytes = 0; stale = true;
    visible.clear(); dom["live-observations"].replaceChildren();
    dom["live-stale"].hidden = false;
    dom["live-empty"].textContent = "일부 기록을 이어받지 못해 최신 요약만 표시 중";
    summary(snapshot); pendingStatus(); connection("연결 종료");
    error("일부 실시간 변경 기록을 이어받지 못했습니다.", "현재 요약을 기준으로 다시 확인해 주세요.");
    dom["live-reconnect"].textContent = "최신 상태로 다시 연결";
    dom["live-reconnect"].hidden = false;
  }
  function render() {
    const rows = [...visible.values()].sort((a, b) =>
      b.observation_revision - a.observation_revision ||
      id(a.observation_id, OBSERVATION_ID)[0] - id(b.observation_id, OBSERVATION_ID)[0]);
    const nodes = rows.map((item) => {
      const row = document.createElement("li");
      const heading = document.createElement("strong");
      heading.textContent = `${TYPES[item.detection_type]} — ${item.observation_id}`;
      const detail = document.createElement("p");
      detail.textContent = `${item.change_type === "CREATED" ? "새 관찰" : item.change_type === "UPDATED" ? "관찰 변경" : "현재 탐지 결과에는 더 이상 일치하지 않음"} · revision ${item.observation_revision}`;
      row.append(heading, detail);
      return row;
    });
    dom["live-observations"].replaceChildren(...nodes);
    dom["live-empty"].textContent = rows.length ? "" : "현재 표시할 관찰 변경 없음. 관찰이 없다는 것은 안전하다는 뜻이 아닙니다.";
  }
  function applyPending() {
    if (paused || stale) return;
    const candidate = new Map(visible);
    pending.forEach(({event}) => event.observations.forEach((change) => candidate.set(change.observation_id, change)));
    if (candidate.size > MAX_VISIBLE) {
      closeSource(); pending = []; pendingBytes = 0; stale = true;
      dom["live-stale"].hidden = false;
      dom["live-empty"].textContent = "일부 기록을 이어받지 못해 최신 요약만 표시 중";
      pendingStatus();
      error("화면 표시 상한에 도달했습니다.", "최신 상태를 다시 조회한 뒤 확인해 주세요.");
      dom["live-reconnect"].textContent = "최신 상태로 다시 연결";
      dom["live-reconnect"].hidden = false;
      refreshStatus(false);
      return;
    }
    visible = candidate; pending = []; pendingBytes = 0; render(); pendingStatus();
  }
  function onEvent(message) {
    try {
      if (message.type === "heartbeat") {
        const payload = data(message, ["status"]);
        if (payload.status !== "CONNECTED" || message.lastEventId) fail();
        return;
      }
      if (message.type === "snapshot") {
        const snapshot = validateSnapshot(data(message, SNAPSHOT_KEYS));
        if (snapshot.session_id !== sessionId || snapshot.latest_committed_detection_revision < latestSnapshotRevision) fail();
        summary(snapshot); return;
      }
      if (message.type === "observation_changes") {
        const payload = data(message, EVENT_KEYS);
        const checked = validateEvent(payload, message.lastEventId);
        if (checked.duplicate) return;
        const size = new TextEncoder().encode(message.data).length;
        lastEventNumber = checked.number; lastEventRevision = checked.event.revision;
        if (pending.length >= MAX_PENDING_ITEMS || pendingBytes + size > MAX_PENDING_BYTES) {
          closeSource(); stale = true; pending = []; pendingBytes = 0;
          dom["live-stale"].hidden = false; pendingStatus();
          error("화면에 반영하지 못한 변경이 있습니다.", "최신 상태를 다시 조회한 뒤 확인해 주세요.");
          dom["live-reconnect"].textContent = "최신 상태로 다시 연결";
          dom["live-reconnect"].hidden = false;
          refreshStatus(false); return;
        }
        pending.push(checked); pendingBytes += size; pendingStatus(); return;
      }
      if (message.type === "replay_gap") {
        const value = data(message, ["code", "snapshot", "earliest_event_id", "latest_event_id", "recovery_action"]);
        const snapshot = validateSnapshot(value.snapshot);
        if (!GAP_CODES.has(value.code) || snapshot.session_id !== sessionId ||
            value.earliest_event_id !== snapshot.earliest_available_event_id ||
            value.latest_event_id !== snapshot.latest_available_event_id ||
            typeof value.recovery_action !== "string" || value.recovery_action.length > 160) fail();
        gap(snapshot); return;
      }
      if (message.type === "service_status") {
        if (typeof message.data !== "string" || new TextEncoder().encode(message.data).length > MAX_PENDING_BYTES) fail();
        const value = JSON.parse(message.data);
        if (Object.keys(value).length === 1) {
          object(value, ["state"]);
          if (!["READY", "DEGRADED", "FAILED", "STOPPED"].includes(value.state)) fail();
        } else {
          object(value, ["state", "code", "recovery_action"]);
          if (!["DEGRADED", "FAILED"].includes(value.state) ||
              !["LIVE_RUNNER_DEGRADED", "LIVE_RUNNER_FAILED", "LIVE_SHUTDOWN_TIMEOUT"].includes(value.code) ||
              typeof value.recovery_action !== "string" || value.recovery_action.length > 160) fail();
        }
        state(value.state); return;
      }
      if (message.type === "stream_end") {
        const value = data(message, ["code"]);
        if (!["LIVE_STREAM_ENDED", "LIVE_STREAM_FAILED"].includes(value.code)) fail();
        closeSource(); connection("연결 종료");
        if (value.code === "LIVE_STREAM_FAILED") terminal("실시간 연결 오류가 발생했습니다.", "최신 상태로 다시 연결해 주세요.");
        else {
          error("실시간 연결이 종료되었습니다.", "서버 상태를 확인하고 필요하면 최신 상태로 다시 연결해 주세요.");
          dom["live-reconnect"].textContent = "최신 상태로 다시 연결";
          dom["live-reconnect"].hidden = false;
        }
        return;
      }
      fail();
    } catch (_) {
      terminal("실시간 데이터 형식을 확인할 수 없습니다.", "서버를 확인한 뒤 최신 상태로 다시 연결해 주세요.");
    }
  }
  function connect() {
    if (eventSource) return;
    errors = 0; lastEventNumber = 0; lastEventRevision = 0;
    connection("재연결 중");
    const stream = new EventSource(EVENTS_URL);
    eventSource = stream;
    ["snapshot", "observation_changes", "replay_gap", "service_status", "heartbeat", "stream_end"].forEach((type) =>
      stream.addEventListener(type, (message) => { if (eventSource === stream) onEvent({data: message.data, lastEventId: message.lastEventId, type}); }));
    stream.onmessage = () => { if (eventSource === stream) terminal("알 수 없는 실시간 메시지입니다.", "서버를 확인한 뒤 다시 연결해 주세요."); };
    stream.onopen = () => { if (eventSource === stream) { errors = 0; connection("연결됨"); } };
    stream.onerror = () => {
      if (eventSource !== stream) return;
      errors += 1;
      if (errors >= MAX_ERRORS) terminal("실시간 연결을 유지하지 못했습니다.", "최신 상태로 다시 연결해 주세요.");
      else connection("재연결 중");
    };
  }
  async function refreshStatus(allowConnect = true) {
    try {
      const response = await fetch(STATUS_URL, {method: "GET", credentials: "omit", cache: "no-store"});
      if (response.status === 404) {
        const errorBody = await response.json();
        object(errorBody, ["error_code", "user_message", "recovery_action", "retryable"]);
        if (errorBody.error_code === "LIVE_MONITORING_NOT_ENABLED" &&
            typeof errorBody.user_message === "string" && errorBody.user_message.length <= 160 &&
            typeof errorBody.recovery_action === "string" && errorBody.recovery_action.length <= 160 &&
            errorBody.retryable === false) return;
        fail();
      }
      if (!response.ok) fail();
      const value = validateStatus(await response.json());
      if (sessionId !== null && value.session_id !== sessionId) { stale = true; visible.clear(); dom["live-observations"].replaceChildren(); }
      sessionId = value.session_id;
      dom["live-monitoring"].hidden = false;
      dom["live-source-role"].textContent = `로그 유형: ${ROLES[value.source_role]}`;
      dom["live-processing-state"].textContent = `처리 상태: ${{
        READY: "다음 로그 줄 대기", RUNNING_STEP: "로그 처리 중", DEGRADED: "처리 확인 필요",
        FAILED: "처리 중단", STOPPING: "종료 중", STOPPED: "종료됨"
      }[value.worker_state]}`;
      state(value.service_state);
      summary({latest_committed_detection_revision: value.latest_detection_revision, active_observation_count: value.active_observation_count, published_total: value.published_total, evicted_total: value.evicted_total});
      if (allowConnect && (value.service_state === "READY" || value.service_state === "RUNNING")) connect();
    } catch (_) {
      dom["live-monitoring"].hidden = false;
      terminal("실시간 상태를 확인하지 못했습니다.", "서버를 확인한 뒤 다시 연결해 주세요.");
    }
  }
  dom["live-show-pending"].addEventListener("click", applyPending);
  dom["live-pause"].addEventListener("click", () => {
    paused = !paused;
    dom["live-pause"].textContent = paused ? "화면 업데이트 다시 시작" : "화면 업데이트 일시 정지";
    pendingStatus();
  });
  dom["live-reconnect"].addEventListener("click", () => {
    closeSource(); pending = []; pendingBytes = 0; visible.clear();
    dom["live-observations"].replaceChildren();
    stale = false; dom["live-stale"].hidden = true;
    dom["live-reconnect"].hidden = true; clearError(); pendingStatus();
    refreshStatus();
  });
  window.addEventListener("pagehide", closeSource);
  refreshStatus();
})();
