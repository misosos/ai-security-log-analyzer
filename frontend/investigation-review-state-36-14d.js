(() => {
  "use strict";

  const SCHEMA_VERSION = 1;
  const MAX_CASES_PER_ANALYSIS = 128;
  const MAX_REVISION = Number.MAX_SAFE_INTEGER;
  const ANALYSIS_REF = /^a_[0-9a-f]{32}$/;
  const CASE_REF = /^c_[0-9a-f]{24}$/;
  const STATES = Object.freeze(["unreviewed", "in_review", "reviewed", "deferred"]);
  const STATE_SET = new Set(STATES);
  const STATE_LABELS = Object.freeze({
    unreviewed: "검토 전", in_review: "검토 중", reviewed: "검토함", deferred: "나중에 확인"
  });
  const TRANSITIONS = Object.freeze({
    unreviewed: Object.freeze(["in_review", "reviewed", "deferred"]),
    in_review: Object.freeze(["reviewed", "deferred"]),
    reviewed: Object.freeze(["in_review", "deferred"]),
    deferred: Object.freeze(["in_review", "reviewed"])
  });

  function failure(code) {
    return Object.freeze({ok: false, code});
  }

  function validateIdentity(identity) {
    if (identity === null || typeof identity !== "object" || Array.isArray(identity) ||
        Object.keys(identity).sort().join(",") !== "analysis_ref,case_ref,schema_version" ||
        !Number.isSafeInteger(identity.schema_version) || identity.schema_version !== SCHEMA_VERSION ||
        typeof identity.analysis_ref !== "string" || !ANALYSIS_REF.test(identity.analysis_ref) ||
        typeof identity.case_ref !== "string" || !CASE_REF.test(identity.case_ref)) {
      return "INVALID_IDENTIFIER";
    }
    return null;
  }

  function createStore(cryptoProvider = globalThis.crypto) {
    let analysisRef = null;
    let states = new Map();

    function clear() {
      states.clear();
      states = new Map();
      analysisRef = null;
    }

    function beginGeneration(caseRefs) {
      clear();
      if (!Array.isArray(caseRefs)) return failure("INVALID_INPUT");
      if (caseRefs.length > MAX_CASES_PER_ANALYSIS) return failure("CAPACITY_EXCEEDED");
      if (caseRefs.some((ref) => typeof ref !== "string" || !CASE_REF.test(ref)) ||
          new Set(caseRefs).size !== caseRefs.length) return failure("INVALID_IDENTIFIER");
      if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== "function") {
        return failure("STORE_UNAVAILABLE");
      }
      let bytes;
      try {
        bytes = new Uint8Array(16);
        cryptoProvider.getRandomValues(bytes);
      } catch {
        return failure("STORE_UNAVAILABLE");
      }
      const generated = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
      analysisRef = `a_${generated}`;
      const nextStates = new Map();
      for (const caseRef of caseRefs) {
        nextStates.set(caseRef, Object.freeze({
          schema_version: SCHEMA_VERSION,
          analysis_ref: analysisRef,
          case_ref: caseRef,
          review_state: "unreviewed",
          revision: 0
        }));
      }
      states = nextStates;
      return Object.freeze({ok: true, analysis_ref: analysisRef, snapshots: list()});
    }

    function lookup(identity) {
      const invalid = validateIdentity(identity);
      if (invalid) return {error: invalid};
      if (analysisRef === null || identity.analysis_ref !== analysisRef) return {error: "UNKNOWN_ANALYSIS"};
      const snapshot = states.get(identity.case_ref);
      return snapshot ? {snapshot} : {error: "UNKNOWN_CASE"};
    }

    function snapshot(identity) {
      const result = lookup(identity);
      if (result.error) return failure(result.error);
      return Object.freeze({ok: true, snapshot: Object.freeze({...result.snapshot})});
    }

    function list() {
      return Object.freeze(Array.from(states.values(), (entry) => Object.freeze({...entry})));
    }

    function transition(identity, reviewState, expectedRevision) {
      const result = lookup(identity);
      if (result.error) return failure(result.error);
      if (typeof reviewState !== "string" || !STATE_SET.has(reviewState) ||
          !Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || expectedRevision > MAX_REVISION) {
        return failure("INVALID_INPUT");
      }
      const current = result.snapshot;
      if (current.revision !== expectedRevision) return failure("STALE_REVISION");
      if (!TRANSITIONS[current.review_state].includes(reviewState)) return failure("INVALID_TRANSITION");
      if (current.revision >= MAX_REVISION) return failure("REVISION_LIMIT_REACHED");
      const updated = Object.freeze({...current, review_state: reviewState, revision: current.revision + 1});
      states.set(identity.case_ref, updated);
      return Object.freeze({ok: true, snapshot: Object.freeze({...updated})});
    }

    function reset(identity, expectedRevision) {
      const result = lookup(identity);
      if (result.error) return failure(result.error);
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || expectedRevision > MAX_REVISION) {
        return failure("INVALID_INPUT");
      }
      const current = result.snapshot;
      if (current.revision !== expectedRevision) return failure("STALE_REVISION");
      if (current.review_state === "unreviewed") return failure("INVALID_TRANSITION");
      if (current.revision >= MAX_REVISION) return failure("REVISION_LIMIT_REACHED");
      const updated = Object.freeze({...current, review_state: "unreviewed", revision: current.revision + 1});
      states.set(identity.case_ref, updated);
      return Object.freeze({ok: true, snapshot: Object.freeze({...updated})});
    }

    return Object.freeze({beginGeneration, snapshot, list, transition, reset, clear});
  }

  function createUi(queue) {
    let store = null;
    let analysisRef = null;
    let available = false;
    const controls = new Map();
    const revisions = new WeakMap();
    const summary = document.getElementById("review-workflow-summary-36-14d");
    const note = document.getElementById("review-workflow-note-36-14d");
    const countsNode = document.getElementById("review-workflow-counts-36-14d");
    const feedback = document.getElementById("review-workflow-feedback-36-14d");
    const stateFilterLabel = document.getElementById("review-queue-state-filter-label-36-14d");
    const stateFilter = document.getElementById("review-queue-state-36-14d");

    function showUnavailable() {
      note.hidden = false;
      note.textContent = "검토 상태를 사용할 수 없습니다. 분석 결과는 계속 표시됩니다.";
      feedback.hidden = false;
      feedback.textContent = "검토 상태 저장소를 사용할 수 없습니다.";
    }

    function clear() {
      if (store) store.clear();
      store = null;
      analysisRef = null;
      available = false;
      controls.clear();
      summary.hidden = true;
      note.hidden = true;
      note.textContent = "검토 상태는 작업 진행 표시이며 안전·해결 판정이 아닙니다.";
      countsNode.textContent = "";
      feedback.hidden = true;
      feedback.textContent = "";
      stateFilterLabel.hidden = true;
      stateFilter.value = "all";
    }

    function begin(caseRefs) {
      clear();
      try {
        store = createStore();
        const result = store.beginGeneration(caseRefs);
        if (!result.ok) {
          clear();
          showUnavailable();
          return false;
        }
        analysisRef = result.analysis_ref;
        available = true;
        summary.hidden = false;
        note.hidden = false;
        stateFilterLabel.hidden = false;
        updateCounts();
        return true;
      } catch {
        clear();
        showUnavailable();
        return false;
      }
    }

    function identity(caseRef) {
      return available ? {schema_version: SCHEMA_VERSION, analysis_ref: analysisRef, case_ref: caseRef} : null;
    }

    function snapshot(caseRef) {
      const key = identity(caseRef);
      if (!key) return null;
      const result = store.snapshot(key);
      return result.ok ? result.snapshot : null;
    }

    function updateCounts() {
      if (!available || !store) return;
      const values = Object.fromEntries(STATES.map((state) => [state, 0]));
      store.list().forEach((entry) => { values[entry.review_state] += 1; });
      countsNode.textContent = `${STATE_LABELS.unreviewed} ${values.unreviewed} · ` +
        `${STATE_LABELS.in_review} ${values.in_review} · ${STATE_LABELS.reviewed} ${values.reviewed} · ` +
        `${STATE_LABELS.deferred} ${values.deferred}`;
    }

    function fillOptions(select, state, revision) {
      select.replaceChildren();
      [state, ...TRANSITIONS[state]].forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = STATE_LABELS[value];
        select.append(option);
      });
      if (state !== "unreviewed") {
        const resetOption = document.createElement("option");
        resetOption.value = "__reset__";
        resetOption.textContent = "상태 초기화 — 검토 전으로";
        select.append(resetOption);
      }
      select.value = state;
      revisions.set(select, revision);
    }

    function feedbackFor(code) {
      const messages = {
        SUCCESS: "검토 상태를 변경했습니다.",
        INVALID_TRANSITION: "이 검토 상태 변경은 허용되지 않습니다.",
        STALE_REVISION: "검토 상태가 최신이 아닙니다. 현재 표시를 다시 확인하세요.",
        UNKNOWN_CASE: "현재 검토 건의 상태를 사용할 수 없습니다.",
        UNKNOWN_ANALYSIS: "현재 분석의 검토 상태를 사용할 수 없습니다.",
        STORE_UNAVAILABLE: "검토 상태를 사용할 수 없습니다. 분석 결과는 계속 표시됩니다.",
        INVALID_INPUT: "검토 상태를 변경하지 못했습니다. 현재 표시를 다시 확인하세요."
      };
      feedback.textContent = messages[code] || messages.INVALID_INPUT;
      feedback.hidden = false;
    }

    function synchronize(caseRef, current, sourceControl = null) {
      const group = controls.get(caseRef);
      if (group) {
        for (const select of group) {
          if (!select.isConnected) { group.delete(select); continue; }
          fillOptions(select, current.review_state, current.revision);
        }
        if (!group.size) controls.delete(caseRef);
      }
      queue.refreshWorkflowState(caseRef, sourceControl);
      updateCounts();
    }

    function createControl(caseRef, context, order) {
      if (!available) return null;
      const initial = snapshot(caseRef);
      if (!initial) return null;
      const group = document.createElement("div");
      group.className = `review-workflow-control-36-14d review-workflow-control-${context}-36-14d`;
      const label = document.createElement("label");
      const select = document.createElement("select");
      select.id = `review-workflow-${context}-${order}-36-14d`;
      select.setAttribute("aria-describedby", "review-workflow-note-36-14d review-workflow-feedback-36-14d");
      label.htmlFor = select.id;
      label.textContent = "검토 상태";
      fillOptions(select, initial.review_state, initial.revision);
      if (!controls.has(caseRef)) controls.set(caseRef, new Set());
      const registered = controls.get(caseRef);
      for (const existing of registered) if (!existing.isConnected) registered.delete(existing);
      registered.add(select);
      select.addEventListener("change", () => {
        const key = identity(caseRef);
        const previous = snapshot(caseRef);
        const target = select.value;
        const result = target === "__reset__" ? store.reset(key, revisions.get(select)) :
          store.transition(key, target, revisions.get(select));
        if (!result.ok) {
          const latest = snapshot(caseRef);
          if (latest) synchronize(caseRef, latest, select);
          else if (previous) fillOptions(select, previous.review_state, previous.revision);
          else select.disabled = true;
          feedbackFor(result.code);
          return;
        }
        synchronize(caseRef, result.snapshot, select);
        feedbackFor("SUCCESS");
      });
      group.append(label, select);
      return group;
    }

    queue.setWorkflowStateProvider((caseRef) => snapshot(caseRef)?.review_state ?? null);
    return Object.freeze({begin, clear, snapshot, createControl});
  }

  globalThis.investigationReviewState36_14d = Object.freeze({
    SCHEMA_VERSION, MAX_CASES_PER_ANALYSIS, MAX_REVISION, STATES, STATE_LABELS,
    TRANSITIONS, createStore, createUi
  });
})();
