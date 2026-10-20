// Standalone synthetic comparison. No API, SSE, storage, network, or user files.
(() => {
  'use strict';
  const DATA = Object.freeze({
    source: 'SSH 인증 로그', revision: '42',
    counts: [3, 2, 1, 1],
    case: {id: 'CASE-01', title: '인증 실패 이후 성공 기록', detail: '시간상 지원 관계 2건. 성공 기록만으로 계정 탈취를 판단할 수 없습니다.'},
    observations: [
      ['OBS-01', 'Brute Force 관찰', '인증 실패 집계가 규칙 조건에 맞음'],
      ['OBS-02', 'Password Spraying-like 관찰', '여러 대상에 대한 실패 패턴'],
      ['OBS-03', '성공 기록', '침해나 공격 성공의 확정이 아님'],
    ],
    relations: [
      ['REL-01', '실패 관찰 → 성공 기록', '지원 관계 · 인과관계 아님'],
      ['REL-02', 'Spray-like 관찰 → 성공 기록', '지원 관계 · 동일 행위자 확정 아님'],
    ],
  });
  const $ = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) {
      if (name === 'className') node.className = value;
      else if (name === 'text') node.textContent = value;
      else node.setAttribute(name, value);
    }
    for (const child of children) if (child !== null) node.append(child);
    return node;
  };
  const text = (tag, value, className) => $(tag, className ? {text: value, className} : {text: value});
  const root = document.querySelector('#prototype-root');
  const variant = document.body.dataset.variant;
  const isDense = variant === 'dense';
  const labels = {
    running: ['RUNNING', '수집 중', '서버가 새 줄을 수집하고 있습니다. 화면 결과는 버튼을 눌러 적용합니다.'],
    pending: ['RUNNING', '새 결과 대기', '새 결과 2건이 대기 중입니다. 화면의 현재 결과는 아직 바뀌지 않았습니다.'],
    applied: ['RUNNING', '결과 적용됨', '합성 결과가 현재 화면에 적용됐습니다. 관찰은 침해 확정이 아닙니다.'],
    paused: ['RUNNING', '화면 표시 일시 정지', '화면만 일시 정지했습니다. 서버 수집은 계속됩니다.'],
    degraded: ['DEGRADED', '모니터링 확인 필요', '현재 결과가 오래됐을 수 있습니다. 터미널 상태를 확인하십시오.'],
    failed: ['FAILED', '모니터링 중단', '새 분석 결과를 받지 못합니다. 터미널 원인을 확인하고 서버를 다시 시작하십시오.'],
    gap: ['DEGRADED', '재생 간격 발생', '이전 결과는 오래됐습니다. 최신 상태를 다시 연결해 확인하십시오.'],
    empty: ['RUNNING', '현재 결과 없음', '새 줄이 아직 처리되지 않았습니다. 결과 없음은 안전을 뜻하지 않습니다.'],
  };
  let mode = 'running';
  let resumeMode = 'running';
  let applied = false;
  let pending = false;
  const shell = $('div', {className: 'shell'});
  root.append(shell);
  const header = $('header', {className: 'masthead'});
  header.append(
    $('div', {className: 'brand'}, text('span', 'A', 'brand-mark'), $('div', {},
      text('div', 'AI Security Log Analyzer'), text('div', isDense ? 'Dense Analyst Console · 비교용 합성 화면' : 'Calm Light Operations · 비교용 합성 화면', 'eyebrow'))),
    text('span', '● 로컬에서만 실행 · 합성 prototype', 'local-note'));
  shell.append(header);
  const main = $('main', {id: 'main'});
  shell.append(main);
  const hero = $('section', {className: 'hero', 'aria-labelledby': 'page-title'});
  const heroMain = $('div', {className: 'panel hero-main'});
  const title = text('h1', isDense ? '현재 상태와 조사 우선순위' : '지금 무엇을 확인해야 하나요?', '');
  title.id = 'page-title';
  const stateMark = $('span', {className: 'state-mark', 'aria-hidden': 'true'}, text('span', '●'));
  const stateLabel = text('span', '', 'state-label');
  const stateDescription = text('p', '', 'subtle');
  const announcement = text('p', '', 'subtle');
  announcement.id = 'state-announcement';
  announcement.setAttribute('role', 'status');
  announcement.setAttribute('aria-live', 'polite');
  const pendingButton = $('button', {className: 'primary', type: 'button', id: 'apply-results', text: '새 결과 2건 보기'});
  const pauseButton = $('button', {type: 'button', id: 'pause-display', text: '화면 표시 일시 정지'});
  const reconnectButton = $('button', {type: 'button', id: 'reconnect', text: '수동 재연결'});
  const actionRow = $('div', {className: 'hero-actions'}, pendingButton, pauseButton, reconnectButton);
  heroMain.append(text('p', 'LOCAL INVESTIGATION / SSH', 'eyebrow'), title,
    $('div', {className: 'status-line'}, stateMark, stateLabel, text('strong', '·'), text('span', DATA.source)),
    stateDescription, announcement, actionRow);
  const meta = $('div', {className: 'panel hero-side'});
  const metaList = $('dl', {}, text('dt', '현재 source role'), text('dd', DATA.source),
    text('dt', '마지막 처리 revision'), text('dd', DATA.revision),
    text('dt', '시작 위치'), text('dd', 'FROM_END'),
    text('dt', '결과 적용'), text('dd', '사용자 선택'));
  meta.append(text('h2', '수집 범위'), text('p', '시작 전 기존 줄은 분석하지 않습니다. 같은 파일의 bounded checkpoint만 재시작에 사용합니다.', 'subtle'), metaList);
  hero.append(heroMain, meta);
  main.append(hero);
  const controls = $('section', {className: 'panel state-controls', 'aria-labelledby': 'scenario-title'});
  const controlList = $('div', {className: 'controls'});
  const scenarios = [
    ['running', 'RUNNING'], ['pending', '새 결과 대기'], ['applied', '결과 적용'],
    ['paused', '일시 정지'], ['degraded', 'DEGRADED'], ['failed', 'FAILED'],
    ['gap', 'replay gap'], ['empty', '결과 없음'],
  ];
  for (const [key, label] of scenarios) {
    const button = $('button', {type: 'button', 'data-scenario': key, text: label});
    button.addEventListener('click', () => setMode(key));
    controlList.append(button);
  }
  controls.append(text('h2', '합성 상태 비교', ''), text('p', '아래 버튼은 같은 합성 데이터를 여러 상태로 보여줍니다. 실제 모니터링과 연결되지 않습니다.', 'subtle'), controlList);
  controls.querySelector('h2').id = 'scenario-title';
  main.append(controls);
  const metricSection = $('section', {'aria-labelledby': 'metric-title'});
  const metricHead = $('div', {className: 'section-head'}, text('h2', '현재 분석 요약'), text('p', '개수는 조사 대상의 규모이지 침해 건수가 아닙니다.', 'subtle'));
  metricHead.querySelector('h2').id = 'metric-title';
  const metricGrid = $('div', {className: 'metrics'});
  const countEls = [];
  for (const [i, label] of ['탐지 관찰', '지원 관계', '위험도 평가', '조사 사례'].entries()) {
    const number = text('strong', '0');
    countEls.push(number);
    metricGrid.append($('article', {className: 'panel metric'}, text('h3', label), number,
      text('small', ['규칙과 일치한 관찰', '시간·조건상 연결', '근거 기반 우선순위', '검토할 근거 묶음'][i])));
  }
  metricSection.append(metricHead, metricGrid);
  main.append(metricSection);
  const detail = $('section', {className: 'content-grid', 'aria-label': '조사 상세'});
  const caseCard = $('article', {className: 'panel'});
  const caseBody = $('div');
  caseCard.append(text('p', 'PRIORITY / CASE', 'eyebrow'), text('h2', '중요 조사 사례'), caseBody);
  const obsCard = $('article', {className: 'panel'});
  const obsList = $('ul', {className: 'list'});
  obsCard.append(text('h2', '최근 관찰'), obsList);
  const relationCard = $('article', {className: 'panel'});
  const relList = $('ul', {className: 'list'});
  relationCard.append(text('h2', '지원 관계·위험도'), relList);
  detail.append(caseCard, obsCard, relationCard);
  main.append(detail);
  const recovery = $('section', {className: 'notice', id: 'recovery', 'aria-labelledby': 'recovery-title'});
  const recoveryTitle = text('h2', '복구 안내');
  recoveryTitle.id = 'recovery-title';
  const recoveryText = text('p', '');
  recovery.append(recoveryTitle, recoveryText);
  main.append(recovery);
  const boundary = $('section', {className: 'panel state-controls', 'aria-labelledby': 'boundary-title'});
  const boundaryTitle = text('h2', '판정과 개인정보 경계');
  boundaryTitle.id = 'boundary-title';
  boundary.append(boundaryTitle,
    text('p', '로그만으로 침해, 계정 탈취, 공격 성공 또는 안전을 확정할 수 없습니다. 관계는 인과관계를 뜻하지 않습니다.'),
    $('details', {}, text('summary', 'checkpoint·설치 경계 자세히 보기'),
      text('p', '명시적 reset은 checkpoint와 과거 분석·SSE 연속성을 버립니다. 원본 로그 삭제가 아닙니다. 다음 실행은 파일 끝부터 새 epoch로 시작합니다.'),
      text('p', 'Source checkout 실행만 지원합니다. rotation·copytruncate 자동 복구, exactly-once, 무유실은 지원하지 않습니다.')));
  main.append(boundary);
  shell.append($('footer', {}, text('p', '독립 합성 디자인 비교안 · 실제 로그·설정·checkpoint를 읽지 않음 · production 앱에 연결되지 않음')));

  function row([id, title, description]) {
    return $('li', {}, $('div', {className: 'item-top'}, text('strong', title), text('span', id, 'tag')),
      text('p', description, 'subtle'));
  }
  function render() {
    const [service, label, description] = labels[mode];
    stateMark.dataset.state = service;
    stateMark.className = `state-mark state-${service.toLowerCase()}`;
    stateMark.firstChild.textContent = service === 'RUNNING' ? '●' : service === 'DEGRADED' ? '!' : '×';
    stateLabel.className = `state-label state-${service.toLowerCase()}`;
    stateLabel.textContent = `${service} · ${label}`;
    stateDescription.textContent = description;
    announcement.textContent = pending ? '새 결과 2건이 대기 중입니다. 버튼 선택 전 목록은 그대로입니다.' :
      applied ? '사용자가 선택한 합성 결과가 화면에 적용됐습니다.' : '현재 표시된 결과의 상태를 확인하십시오.';
    pendingButton.hidden = !pending || mode === 'paused';
    pauseButton.textContent = mode === 'paused' ? '화면 표시 재개' : '화면 표시 일시 정지';
    reconnectButton.hidden = mode !== 'degraded' && mode !== 'failed' && mode !== 'gap';
    for (const button of controlList.querySelectorAll('button'))
      button.setAttribute('aria-pressed', String(button.dataset.scenario === mode));
    const shown = applied && mode !== 'empty';
    for (const [i, number] of countEls.entries()) number.textContent = shown ? String(DATA.counts[i]) : '0';
    caseBody.replaceChildren(shown ? $('div', {}, text('h3', `${DATA.case.id} · ${DATA.case.title}`),
      text('p', DATA.case.detail, 'subtle'), text('p', '위험도 HIGH · 신뢰도 HIGH · 조사 우선순위', 'tag')) :
      text('p', mode === 'empty' ? '관찰 없음은 안전을 뜻하지 않습니다.' : '새 결과를 적용하면 사례 근거가 표시됩니다.', 'subtle'));
    obsList.replaceChildren(...(shown ? DATA.observations.map(row) : [row(['—', '표시할 관찰 없음', '새 결과 적용 전이거나 현재 결과가 없습니다.'])]));
    relList.replaceChildren(...(shown ? [...DATA.relations.map(row), row(['RISK-01', '위험도 HIGH', '현재 근거의 조사 우선순위이며 해결·침해 확정이 아님'])] :
      [row(['—', '표시할 관계·위험도 없음', '결과 없음은 안전의 증거가 아닙니다.'])]));
    recovery.dataset.kind = mode === 'failed' ? 'error' : 'warning';
    if (mode === 'failed' || mode === 'degraded' || mode === 'gap') recovery.setAttribute('role', 'alert');
    else recovery.removeAttribute('role');
    recoveryTitle.textContent = mode === 'failed' ? 'FAILED · 서버 재시작 필요' :
      mode === 'gap' ? 'Replay gap · 이전 결과 stale' : mode === 'degraded' ? 'DEGRADED · 확인 필요' : '복구와 연속성 안내';
    recoveryText.textContent = mode === 'failed' ? '정상 0건이 아닙니다. 터미널 오류를 확인한 뒤 서버를 다시 시작하십시오. 자동 reset은 수행하지 않습니다.' :
      mode === 'gap' ? '이전 결과가 오래됐습니다. 수동 재연결로 최신 상태를 확인하십시오. 누락 구간은 복구를 보장하지 않습니다.' :
      mode === 'degraded' ? '정상 0건이 아닙니다. 터미널 상태를 확인하고 수동 재연결하십시오.' :
      '동일 파일 bounded checkpoint만 복구합니다. reset은 로그 삭제가 아닌 분석 연속성 초기화입니다.';
  }
  function setMode(next) {
    mode = next;
    if (next === 'pending') { pending = true; applied = false; }
    else if (next === 'applied') { pending = false; applied = true; }
    else if (next === 'empty' || next === 'running') { pending = false; applied = false; }
    render();
  }
  pendingButton.addEventListener('click', () => setMode('applied'));
  pauseButton.addEventListener('click', () => {
    if (mode === 'paused') { mode = resumeMode; render(); }
    else { resumeMode = mode; setMode('paused'); }
  });
  reconnectButton.addEventListener('click', () => setMode('running'));
  render();
})();
