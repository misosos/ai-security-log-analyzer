"use strict";

(() => {
  const STATUS = Object.freeze({
    complete: ["모두 인식", "비어 있지 않은 입력 형식을 모두 인식했습니다. 안전하거나 위협이 없다는 뜻은 아닙니다."],
    partial: ["일부 인식", "일부 줄을 해석하지 못해 분석 범위가 제한될 수 있습니다. 인식한 줄의 분석 결과는 유지됩니다."],
    none: ["인식하지 못함", "비어 있지 않은 입력이 있었지만 지원 형식으로 해석하지 못했습니다. 탐지 없음이나 안전 판정이 아닙니다."],
    empty: ["분석할 내용 없음", "분석할 비어 있지 않은 줄이 없습니다. 정상 또는 안전을 뜻하지 않습니다."]
  });
  const SOURCES = Object.freeze({application: "애플리케이션 로그", ssh: "SSH 인증 로그", access: "웹 접근 로그"});
  const REASONS = Object.freeze({
    unsupported_format: "지원하지 않는 형식", invalid_timestamp: "올바르지 않은 시각",
    invalid_address: "올바르지 않은 주소", invalid_port: "올바르지 않은 포트",
    invalid_header: "올바르지 않은 헤더", incomplete_record: "완성되지 않은 레코드",
    blank_line: "빈 줄", ignored_record: "무시된 기록", other_rejected: "기타 거부"
  });
  const NOTICE = "로그 인식 상태는 입력 형식의 처리 범위이며, 탐지 결과·위험도·안전 여부를 뜻하지 않습니다.";

  function text(tag, value, className) {
    const node = document.createElement(tag);
    node.textContent = value;
    if (className) node.className = className;
    return node;
  }

  function render(container, projection, selectedSource = null) {
    container.replaceChildren();
    container.hidden = true;
    if (!projection) return;
    const aggregate = projection.aggregate;
    const state = STATUS[aggregate.recognition_status];
    if (!state) return;
    const heading = text("h3", "로그 인식 상태");
    heading.id = container.id === "error-input-quality-36-12b" ?
      "error-input-quality-heading-36-12b" : "input-quality-heading-36-12b";
    const status = document.createElement("p");
    status.id = "input-quality-status-36-12b";
    status.className = "input-quality-state-36-12b";
    status.append(text("strong", state[0]));
    status.append(document.createTextNode(` — ${state[1]}`));
    const counts = document.createElement("dl");
    counts.className = "input-quality-counts-36-12b";
    [["전체 입력 줄", aggregate.total_lines], ["인식", aggregate.recognized_lines],
      ["인식하지 못함", aggregate.unrecognized_lines], ["무시됨", aggregate.ignored_lines]]
      .forEach(([label, value]) => {
        const item = document.createElement("div");
        item.append(text("dt", label), text("dd", String(value)));
        counts.append(item);
      });
    const rows = selectedSource ? projection.by_source.filter((row) => row.source === selectedSource) :
      projection.by_source;
    const sources = document.createElement("div");
    sources.className = "input-quality-sources-36-12b";
    if (rows.length > 0) {
      sources.append(text("h4", selectedSource ? "선택한 로그 종류" : "로그 종류별 상태"));
      const list = document.createElement("div");
      list.className = "input-quality-source-list-36-12b";
      rows.forEach((row) => {
        const item = document.createElement("div");
        const metrics = document.createElement("dl");
        const entry = document.createElement("div");
        entry.append(text("dt", SOURCES[row.source]));
        entry.append(text("dd", `${STATUS[row.recognition_status][0]} · ${row.recognized_lines}/${row.nonempty_lines}줄 인식`));
        metrics.append(entry);
        item.append(metrics);
        const reasons = document.createElement("details");
        reasons.className = "input-quality-reasons-36-12b";
        const reasonList = document.createElement("dl");
        reasonList.className = "input-quality-reason-list-36-12b";
        Object.entries(REASONS).forEach(([code, label]) => {
          const amount = row.reason_counts[code];
          if (amount === 0) return;
          const reason = document.createElement("div");
          reason.append(text("dt", label), text("dd", String(amount)));
          reasonList.append(reason);
        });
        if (reasonList.childElementCount > 0) {
          reasons.append(text("summary", "처리 사유 보기"), reasonList);
          item.append(reasons);
        }
        list.append(item);
      });
      sources.append(list);
    }
    container.append(heading, status, counts, sources,
      text("p", NOTICE, "input-quality-limit-36-12b"));
    container.hidden = false;
  }

  window.inputQualityUi36_12b = Object.freeze({render});
})();
