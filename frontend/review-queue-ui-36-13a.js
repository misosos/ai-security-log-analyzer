(() => {
  "use strict";

  const RISK_ORDER = Object.freeze({HIGH: 0, MEDIUM: 1, LOW: 2});
  const ROLE_LABELS = Object.freeze({
    application: "애플리케이션 로그", ssh: "SSH 인증 로그", access: "접근 로그", unknown: "역할 미확인"
  });
  const PRIORITY_LABELS = Object.freeze({
    review_now: "먼저 확인", review_soon: "우선 확인", review_later: "일반 확인", undetermined: "확인 순서 미정"
  });
  const SORTS = new Set(["default", "risk", "newest", "oldest", "title"]);
  const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

  function normalizeSearch(value) {
    const bound = (text) => {
      let result = "";
      for (const character of text) {
        if (result.length + character.length > 100) break;
        result += character;
      }
      return result;
    };
    return bound(bound(value.replace(CONTROL_CHARS, "")).normalize("NFKC").trim().toLowerCase());
  }

  function create() {
    const controls = document.getElementById("review-queue-controls-36-13a");
    const searchInput = document.getElementById("review-queue-search-36-13a");
    const filterToggle = document.getElementById("review-queue-filter-toggle-36-13a");
    const filterPanel = document.getElementById("review-queue-filter-panel-36-13a");
    const filterClose = document.getElementById("review-queue-filter-close-36-13a");
    const filterCount = document.getElementById("review-queue-filter-count-36-13a");
    const chips = document.getElementById("review-queue-filter-chips-36-13a");
    const chipList = document.getElementById("review-queue-active-chip-list-36-13a");
    const totalText = document.getElementById("review-queue-total-36-13a");
    const countAnnouncement = document.getElementById("review-queue-count-announcement-36-13a");
    const riskSelect = document.getElementById("review-queue-risk-36-13a");
    const roleSelect = document.getElementById("review-queue-role-36-13a");
    const prioritySelect = document.getElementById("review-queue-priority-36-13a");
    const sortSelect = document.getElementById("review-queue-sort-36-13a");
    const countText = document.getElementById("review-queue-count-36-13a");
    const emptyState = document.getElementById("review-queue-empty-36-13a");
    const resetButton = document.getElementById("review-queue-reset-36-13a");
    const list = document.getElementById("case-list");
    const records = [];
    let total = 0;
    let announcementTimer = 0;
    const riskLabels = Object.freeze({HIGH: "높음", MEDIUM: "보통", LOW: "낮음"});

    function corpus(projection, role) {
      const category = projection.category === "authentication" ? "인증 활동" : "기타 관찰";
      return normalizeSearch([projection.display_title, category, ROLE_LABELS[role], projection.summary].join(" "));
    }

    function resetValues() {
      searchInput.value = "";
      riskSelect.value = "all";
      roleSelect.value = "all";
      prioritySelect.value = "all";
      sortSelect.value = "default";
      emptyState.hidden = true;
      setFilterOpen(false);
    }

    function setFilterOpen(open, restoreFocus = false) {
      filterPanel.hidden = !open;
      filterToggle.setAttribute("aria-expanded", String(open));
      if (restoreFocus) filterToggle.focus();
    }

    function renderChips(query, risk, role, priority, sort) {
      const activeFilterCount = [risk, role, priority].filter((value) => value !== "all").length;
      filterCount.textContent = `${activeFilterCount}개`;
      filterToggle.removeAttribute("aria-label");
      chipList.replaceChildren();
      const items = [];
      if (query !== "") items.push({key: "search", text: "검색 조건 적용 중", clear: () => {
        searchInput.value = "";
        apply();
        searchInput.focus();
      }});
      if (risk !== "all") items.push({key: "risk", text: `위험도: ${riskLabels[risk] ?? "미정"}`, clear: () => {
        riskSelect.value = "all";
        apply();
        (filterPanel.hidden ? filterToggle : riskSelect).focus();
      }});
      if (role !== "all") items.push({key: "role", text: `역할: ${ROLE_LABELS[role] ?? "역할 미확인"}`, clear: () => {
        roleSelect.value = "all";
        apply();
        (filterPanel.hidden ? filterToggle : roleSelect).focus();
      }});
      if (priority !== "all") items.push({key: "priority", text: `확인 순서: ${PRIORITY_LABELS[priority] ?? "확인 순서 미정"}`, clear: () => {
        prioritySelect.value = "all";
        apply();
        (filterPanel.hidden ? filterToggle : prioritySelect).focus();
      }});
      const sortLabels = {risk: "위험도 높은 순", newest: "최근 관찰 순", oldest: "오래된 관찰 순", title: "제목 순"};
      if (sort !== "default") items.push({key: "sort", text: `정렬: ${sortLabels[sort]}`, clear: () => {
        sortSelect.value = "default";
        apply();
        sortSelect.focus();
      }});
      items.forEach(({key, text, clear}) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "review-queue-chip-36-13a";
        chip.dataset.reviewQueueChip = key;
        chip.textContent = `${text} ×`;
        chip.setAttribute("aria-label", `${text} 조건 제거`);
        chip.addEventListener("click", clear);
        chipList.append(chip);
      });
      chips.hidden = items.length === 0;
      resetButton.hidden = items.length === 0;
    }

    function compare(left, right, sort) {
      if (sort === "risk") {
        const rank = (value) => RISK_ORDER[value] ?? 3;
        return rank(left.risk) - rank(right.risk) || left.index - right.index;
      }
      if (sort === "newest" || sort === "oldest") {
        if (left.time === null || right.time === null) {
          if (left.time === right.time) return left.index - right.index;
          return left.time === null ? 1 : -1;
        }
        const delta = sort === "newest" ? right.time - left.time : left.time - right.time;
        return delta || left.index - right.index;
      }
      if (sort === "title") {
        const a = normalizeSearch(left.projection.display_title);
        const b = normalizeSearch(right.projection.display_title);
        return (a < b ? -1 : a > b ? 1 : 0) || left.index - right.index;
      }
      return left.index - right.index;
    }

    function apply() {
      if (records.length === 0) return;
      const query = normalizeSearch(searchInput.value);
      const risk = riskSelect.value;
      const role = roleSelect.value;
      const priority = prioritySelect.value;
      const sort = SORTS.has(sortSelect.value) ? sortSelect.value : "default";
      renderChips(query, risk, role, priority, sort);
      const visible = records.filter((record) =>
        (query === "" || record.searchText.includes(query)) &&
        (risk === "all" || record.risk === risk) &&
        (role === "all" || record.role === role) &&
        (priority === "all" || record.priority === priority)
      );
      visible.sort((left, right) => compare(left, right, sort));
      list.replaceChildren(...visible.map((record) => record.card));
      const narrowed = query !== "" || risk !== "all" || role !== "all" || priority !== "all";
      countText.textContent = narrowed ? `전체 ${total}건 중 ${visible.length}건` : `${total}건`;
      totalText.textContent = `${total}건`;
      window.clearTimeout(announcementTimer);
      announcementTimer = window.setTimeout(() => {
        countAnnouncement.textContent = countText.textContent;
      }, 350);
      emptyState.hidden = visible.length !== 0;
    }

    function reset() {
      resetValues();
      apply();
      searchInput.focus();
    }

    [searchInput, riskSelect, roleSelect, prioritySelect, sortSelect].forEach((control) => {
      control.addEventListener(control === searchInput ? "input" : "change", apply);
    });
    resetButton.addEventListener("click", reset);
    emptyState.querySelector("[data-review-queue-reset]").addEventListener("click", reset);
    filterToggle.addEventListener("click", () => setFilterOpen(filterPanel.hidden));
    filterClose.addEventListener("click", () => setFilterOpen(false, true));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !filterPanel.hidden) {
        event.preventDefault();
        setFilterOpen(false, true);
      }
    });

    return Object.freeze({
      begin(showControls) {
        records.length = 0;
        total = 0;
        resetValues();
        controls.hidden = !showControls;
        window.clearTimeout(announcementTimer);
        countAnnouncement.textContent = "";
        countText.textContent = "";
        totalText.textContent = `${total}건`;
        renderChips("", "all", "all", "all", "default");
      },
      add(projection, card, index, priorityBadge, roleBadge) {
        records.push({projection, card, index, priorityBadge, roleBadge,
          risk: projection.risk_band, role: projection.source_role, priority: projection.review_priority,
          searchText: corpus(projection, projection.source_role),
          time: projection.end_time_utc === null ? null : Date.parse(projection.end_time_utc)});
        total = records.length;
      },
      addUnavailable(card, index) {
        const projection = Object.freeze({display_title: "검토 건 상세 정보를 사용할 수 없음",
          category: "unknown", summary: "검토 건 상세 정보를 사용할 수 없음", risk_band: null,
          source_role: "unknown", review_priority: "undetermined", start_time_utc: null, case_ref: null});
        records.push({projection, card, index, risk: null, role: "unknown", priority: "undetermined",
          searchText: normalizeSearch(`${projection.display_title} ${ROLE_LABELS.unknown}`), time: null});
        total = records.length;
      },
      render: apply,
      updateVerifiedLabels(caseRef, role, priority) {
        const record = records.find((candidate) => candidate.projection.case_ref === caseRef);
        if (!record || !Object.hasOwn(ROLE_LABELS, role) || !Object.hasOwn(PRIORITY_LABELS, priority)) return;
        record.role = role;
        record.priority = priority;
        record.roleBadge.textContent = ROLE_LABELS[role];
        record.priorityBadge.textContent = PRIORITY_LABELS[priority];
        record.searchText = corpus(record.projection, role);
        apply();
      },
      clear() {
        records.length = 0;
        total = 0;
        resetValues();
        controls.hidden = true;
        window.clearTimeout(announcementTimer);
        countAnnouncement.textContent = "";
        countText.textContent = "";
        totalText.textContent = "";
        chipList.replaceChildren();
        chips.hidden = true;
        resetButton.hidden = true;
        filterCount.textContent = "0";
      }
    });
  }

  window.reviewQueueUi36_13a = Object.freeze({create});
})();
