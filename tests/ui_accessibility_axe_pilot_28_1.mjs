// Development-only browser checks. Print rule IDs/counts, never axe nodes or DOM text.
import AxeBuilder from '@axe-core/playwright';
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {performance} from 'node:perf_hooks';

const ROOT = resolve(import.meta.dirname, '..');
const UI1_SCREENSHOTS = process.env.UI1_SCREENSHOTS;
const UI1_BASELINE_CSS = process.env.UI1_BASELINE_CSS ?
  await readFile(process.env.UI1_BASELINE_CSS, 'utf8') : null;
const SESSION = 'LIVE-SESSION-000001';
const eventId = (n) => `LIVE-EVENT-000001-${String(n).padStart(6, '0')}`;
const CANARY = ['synthetic', 'private', 'account', '28', '1'].join('-');
const STATES = [
  'base', 'live-empty', 'pending', 'applied', 'paused', 'no-longer-matches',
  'private-event-rejected', 'degraded', 'failed', 'replay-gap', 'checkpoint-reset-explanation', 'text-input',
  'three-file-error', 'linux-audit-error',
];
const CHECKLIST_STATES = [
  'CHECKLIST_LOADING', 'CHECKLIST_AVAILABLE', 'CHECKLIST_REFUSED', 'CHECKLIST_STALE',
  'CHECKLIST_TIMEOUT', 'CHECKLIST_RATE', 'CHECKLIST_UNAVAILABLE', 'CHECKLIST_NETWORK', 'CHECKLIST_RETRY',
  'CHECKLIST_REAL',
];
let currentScenario = 'startup';

function checklistPayload(state) {
  if (state === 'CHECKLIST_AVAILABLE' || state === 'CHECKLIST_RENDER_EXCEPTION') return {
    schema: 'investigation-checklist/v2', status: 'available', source_role: 'application', source_role_label: '애플리케이션 로그', review_priority: 'review_soon',
    priority_meaning: 'analyst_review_order_only_not_security_risk', category: 'authentication',
    steps: [{text: '합성 자료의 coverage를 확인하세요.', purpose_code: 'manual_coverage',
      citation_ids: ['next-checks:review-records'], limitation_codes: ['INCOMPLETE_EVIDENCE']}],
    explanation: {text: '검토 순서에 관한 참고 제안입니다.', citation_ids: ['next-checks:review-records']}, uncertainty_codes: [], limitation_codes: [],
    citations: [{citation_id: 'next-checks:review-records', title: '조사 범위 확인',
      summary: '승인된 일반 조사 참고 자료입니다. 사례 발생의 증거가 아닙니다.'}],
    citation_meaning: 'general_reference_not_case_evidence', generated_by: 'deterministic_lexical_template'
  };
  return {
    schema: 'investigation-checklist/v2', status: 'refused', source_role: 'unknown', source_role_label: '역할 정보 미확인', review_priority: 'undetermined',
    priority_meaning: 'analyst_review_order_only_not_security_risk', category: 'unknown', steps: [],
    explanation: {text: '현재 승인된 근거로는 이 범주의 점검표를 만들 수 없습니다. 이는 안전 또는 비위험 판정이 아닙니다. 기존 결정적 분석 결과를 확인하고, 원본 자료는 승인된 내부 분석 경로에서 별도로 확인하세요. 승인 근거가 검토되기 전에는 추측하지 않습니다.', citation_ids: []},
    uncertainty_codes: ['insufficient_context'], limitation_codes: ['INCOMPLETE_EVIDENCE'], citations: [],
    citation_meaning: 'general_reference_not_case_evidence', generated_by: 'deterministic_lexical_template'
  };
}

function requireSafe(condition, code) {
  if (!condition) throw new Error(code);
}

function targetGapPx(first, second) {
  const horizontalGap = Math.max(0, first.left - second.right, second.left - first.right);
  const verticalGap = Math.max(0, first.top - second.bottom, second.top - first.bottom);
  return Math.hypot(horizontalGap, verticalGap);
}

async function assertWorkspaceReflow(page, label) {
  const viewports = [
    {width: 1920, height: 1080}, {width: 1440, height: 900}, {width: 1280, height: 800},
    {width: 1024, height: 768}, {width: 768, height: 1024},
    {width: 390, height: 844}, {width: 320, height: 568},
  ];
  const measurements = [];
  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    const measurement = await page.evaluate(() => {
      const visible = (node) => {
        if (!node || node.closest('[hidden]')) return false;
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
      };
      const selectors = [
        '.app-shell', '#main', '.app-content', '#workspace-results', '#results-dashboard',
        '#summary-cards', '#case-list', '.review-case-card', '.review-status-badges',
        '#case-detail-view', '.workspace-detail-shell-36-6b', '.workspace-detail-header-36-6c',
        '.workspace-overview-36-6c', '.workspace-overview-metrics-36-6c', '.workspace-detail-tabs-36-6d',
        '#workspace-timeline-panel-36-6d', '.workspace-timeline-36-6d', '.workspace-timeline-item-36-6d',
        '#workspace-tasks-panel-36-6e', '.workspace-task-master-detail-36-6e',
        '.workspace-task-list-36-6e', '.workspace-task-choice-36-6e', '.workspace-task-detail-36-6e',
        '#workspace-evidence-panel-36-6e', '.workspace-evidence-disclosure-36-6e',
        '.workspace-evidence-citation-36-6e', '.workspace-checklist-status-36-6e',
        '.workspace-checklist-output-36-6e', '.guidance-citation',
      ];
      const panel_overflow = [];
      for (const selector of selectors) {
        for (const node of document.querySelectorAll(selector)) {
          if (!visible(node)) continue;
          if (node.scrollWidth > node.clientWidth + 1) panel_overflow.push({selector,
            scrollWidth: node.scrollWidth, clientWidth: node.clientWidth,
            descendants: [...node.querySelectorAll('*')].filter((child) => visible(child) &&
              child.scrollWidth > child.clientWidth + 1).slice(0, 6).map((child) => ({
              tag: child.tagName.toLowerCase(), id: child.id, className: String(child.className).slice(0, 80),
              scrollWidth: child.scrollWidth, clientWidth: child.clientWidth,
              text: child.textContent.trim().slice(0, 70),
            }))});
        }
      }
      const clippedNodes = [...document.querySelectorAll('body *')].filter((node) => {
        if (!visible(node) || node.matches('.review-card-summary, .icon-sprite')) return false;
        const style = getComputedStyle(node);
        const clipsX = ['hidden', 'clip'].includes(style.overflowX) && node.scrollWidth > node.clientWidth + 1;
        const clipsY = ['hidden', 'clip'].includes(style.overflowY) && node.scrollHeight > node.clientHeight + 1;
        return clipsX || clipsY;
      });
      const clipped = clippedNodes.length;
      const targetSelectors = '#workspace-nav-toggle, .workspace-nav-list button, #case-list .review-detail-link, ' +
        '#review-back-link, .workspace-detail-tabs-36-6d button, .workspace-checklist-request-36-6e, ' +
        '.workspace-task-choice-36-6e, .workspace-task-detail-36-6e summary, ' +
        '.workspace-evidence-panel-36-6e summary, .workspace-evidence-panel-36-6e select, ' +
        '.workspace-evidence-panel-36-6e .guidance-request, .input-mode-choice label, ' +
        '#text-source, #log-text, #text-clear, #local-button';
      const targets = [...document.querySelectorAll(targetSelectors)].filter(visible).map((node) => {
        const rect = node.getBoundingClientRect();
        return {selector: node.matches('#workspace-nav-toggle') ? '#workspace-nav-toggle' :
          node.matches('.workspace-nav-list button') ? '.workspace-nav-list button' :
          node.matches('#case-list .review-detail-link') ? '#case-list .review-detail-link' :
          node.matches('#review-back-link') ? '#review-back-link' :
          node.matches('.workspace-detail-tabs-36-6d button') ? '.workspace-detail-tabs-36-6d button' :
          node.matches('.workspace-checklist-request-36-6e') ? '.workspace-checklist-request-36-6e' :
          node.matches('.workspace-task-choice-36-6e') ? '.workspace-task-choice-36-6e' :
          node.matches('.workspace-task-detail-36-6e summary') ? '.workspace-task-detail-36-6e summary' :
          node.matches('.workspace-evidence-panel-36-6e summary') ? '.workspace-evidence-panel-36-6e summary' :
          node.matches('.workspace-evidence-panel-36-6e select') ? '.workspace-evidence-panel-36-6e select' :
          node.matches('.workspace-evidence-panel-36-6e .guidance-request') ? '.workspace-evidence-panel-36-6e .guidance-request' :
          node.matches('.input-mode-choice label') ? '.input-mode-choice label' :
          node.matches('#text-source') ? '#text-source' : node.matches('#log-text') ? '#log-text' :
          node.matches('#text-clear') ? '#text-clear' : '#local-button',
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
        width: rect.width, height: rect.height};
      });
      const target_gap_failures = [];
      for (let first = 0; first < targets.length; first += 1) {
        for (let second = first + 1; second < targets.length; second += 1) {
          const a = targets[first]; const b = targets[second];
          const dx = Math.max(0, a.left - b.right, b.left - a.right);
          const dy = Math.max(0, a.top - b.bottom, b.top - a.bottom);
          const gap = Math.hypot(dx, dy);
          if (gap < 8) target_gap_failures.push({first: a.selector, second: b.selector, gap,
            first_rect: {left: a.left, top: a.top, right: a.right, bottom: a.bottom},
            second_rect: {left: b.left, top: b.top, right: b.right, bottom: b.bottom}});
        }
      }
      return {
        viewport: {width: innerWidth, height: innerHeight},
        document: {scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth},
        body: {scrollWidth: document.body.scrollWidth, clientWidth: document.body.clientWidth},
        panel_overflow, clipped, target_count: targets.length,
        target_size_failures: targets.filter((target) => target.width < 44 || target.height < 44)
          .map(({selector, width, height}) => ({selector, width, height})),
        target_gap_failures,
      };
    });
    measurements.push(measurement);
    const readability = await page.evaluate(() => {
      const read = (selector) => {
        const node = document.querySelector(selector);
        if (!node) return null;
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return {font: Number.parseFloat(style.fontSize), height: rect.height,
          minHeight: Number.parseFloat(style.minHeight),
          width: rect.width, paddingLeft: Number.parseFloat(style.paddingLeft),
          paddingRight: Number.parseFloat(style.paddingRight)};
      };
      return {
        viewport: innerWidth,
        sidebar: read('.workspace-nav'),
        nav: read('.workspace-nav-list button'),
        title: read('#page-title'),
        body: read('.app-content'),
        lead: read('.lead'),
        card: read('.action-card'),
        cardTitle: read('.action-card h3'),
        helper: read('.action-card p'),
        button: read('#sample-button'),
        entryPage: Boolean(document.querySelector('.action-card')),
        overflow: document.documentElement.scrollWidth > innerWidth,
      };
    });
    if (label === 'WORKSPACE_START') {
      const expectedSidebar = viewport.width >= 1200 ? 320 : viewport.width >= 901 ? 276 :
        viewport.width >= 768 ? 248 : viewport.width;
      requireSafe(Math.abs(readability.sidebar.width - expectedSidebar) < 1 &&
        readability.nav.font >= (viewport.width < 768 ? 16 : 17.5) && readability.title.font >= 32 &&
        readability.lead.font >= 18 && readability.cardTitle.font >= 21 && readability.helper.font >= 16.5 &&
        readability.button.font >= 16.5 && readability.button.minHeight >= 48 &&
        readability.card.paddingLeft >= 22 && readability.card.paddingRight >= 22 &&
        readability.body.paddingLeft >= 10 && readability.body.paddingRight >= 10 && !readability.overflow,
      `${label}_READABILITY_SCALE_FAILED`);
      console.log(`WORKSPACE_READABILITY_METRICS ${JSON.stringify(readability)}`);
    }
    if (measurement.document.scrollWidth > measurement.document.clientWidth ||
        measurement.body.scrollWidth > measurement.body.clientWidth || measurement.panel_overflow.length ||
        measurement.clipped || measurement.target_size_failures.length || measurement.target_gap_failures.length) {
      console.log(`${label}_REFLOW_DIAGNOSTIC ${JSON.stringify(measurement)}`);
    }
    requireSafe(measurement.document.scrollWidth <= measurement.document.clientWidth &&
      measurement.body.scrollWidth <= measurement.body.clientWidth &&
      measurement.panel_overflow.length === 0 && measurement.clipped === 0 &&
      measurement.target_size_failures.length === 0 && measurement.target_gap_failures.length === 0,
    `${label}_REFLOW_FAILED`);
  }
  await page.setViewportSize({width: 320, height: 568});
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  const equivalent200 = await page.evaluate(() => {
    const selectors = ['.app-shell', '#main', '.app-content', '#workspace-results', '#results-dashboard',
      '#case-list', '.review-case-card', '#case-detail-view', '.workspace-detail-shell-36-6b',
      '.workspace-detail-tabs-36-6d', '.workspace-timeline-panel-36-6d', '#workspace-tasks-panel-36-6e',
      '.workspace-task-master-detail-36-6e', '#workspace-evidence-panel-36-6e', '.workspace-evidence-disclosure-36-6e'];
    const shown = (node) => {
      if (!node || node.closest('[hidden]')) return false;
      for (let ancestor = node; ancestor; ancestor = ancestor.parentElement) {
        const style = getComputedStyle(ancestor);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
      }
      const rect = node.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    };
    const panel_overflow = selectors.flatMap((selector) => [...document.querySelectorAll(selector)]
      .filter(shown).filter((node) => node.scrollWidth > node.clientWidth + 1).map((node) => ({selector,
        scrollWidth: node.scrollWidth, clientWidth: node.clientWidth,
        descendants: [...node.querySelectorAll('*')].filter((child) => shown(child) &&
          child.scrollWidth > child.clientWidth + 1).slice(0, 8).map((child) => ({
          tag: child.tagName.toLowerCase(), id: child.id, className: String(child.className).slice(0, 100),
          scrollWidth: child.scrollWidth, clientWidth: child.clientWidth,
          width: Math.round(child.getBoundingClientRect().width * 100) / 100,
        }))})));
    const targetSelectors = '#workspace-nav-toggle, .workspace-nav-list button, #case-list .review-detail-link, ' +
      '#review-back-link, .workspace-detail-tabs-36-6d button, .workspace-checklist-request-36-6e, ' +
      '.workspace-task-choice-36-6e, .workspace-task-detail-36-6e summary, ' +
      '.workspace-evidence-panel-36-6e summary, .workspace-evidence-panel-36-6e select, ' +
      '.workspace-evidence-panel-36-6e .guidance-request, .input-mode-choice label, ' +
      '#text-source, #log-text, #text-clear, #local-button';
    const targets = [...document.querySelectorAll(targetSelectors)].filter(shown).map((node) => {
      const rect = node.getBoundingClientRect();
      return {selector: node.matches('#workspace-nav-toggle') ? '#workspace-nav-toggle' :
        node.matches('.workspace-nav-list button') ? `.workspace-nav-list button#${node.id}` :
        node.matches('#case-list .review-detail-link') ? '#case-list .review-detail-link' :
        node.matches('#review-back-link') ? '#review-back-link' :
        node.matches('.workspace-detail-tabs-36-6d button') ? '.workspace-detail-tabs-36-6d button' :
        node.matches('.workspace-checklist-request-36-6e') ? '.workspace-checklist-request-36-6e' :
        node.matches('.workspace-task-choice-36-6e') ? '.workspace-task-choice-36-6e' :
        node.matches('.workspace-task-detail-36-6e summary') ? '.workspace-task-detail-36-6e summary' :
        node.matches('.workspace-evidence-panel-36-6e summary') ? '.workspace-evidence-panel-36-6e summary' :
        node.matches('.workspace-evidence-panel-36-6e select') ? '.workspace-evidence-panel-36-6e select' :
        node.matches('.workspace-evidence-panel-36-6e .guidance-request') ? '.workspace-evidence-panel-36-6e .guidance-request' :
        node.matches('.input-mode-choice label') ? '.input-mode-choice label' :
        node.matches('#text-source') ? '#text-source' : node.matches('#log-text') ? '#log-text' :
        node.matches('#text-clear') ? '#text-clear' : '#local-button',
        left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
        width: rect.width, height: rect.height};
    });
    const target_gap_failures = [];
    for (let first = 0; first < targets.length; first += 1) for (let second = first + 1; second < targets.length; second += 1) {
      const a = targets[first]; const b = targets[second];
      const dx = Math.max(0, a.left - b.right, b.left - a.right);
      const dy = Math.max(0, a.top - b.bottom, b.top - a.bottom);
      if (Math.hypot(dx, dy) < 8) target_gap_failures.push({first: a.selector, second: b.selector,
        gap: Math.round(Math.hypot(dx, dy) * 100) / 100,
        first_rect: {left: a.left, top: a.top, right: a.right, bottom: a.bottom},
        second_rect: {left: b.left, top: b.top, right: b.right, bottom: b.bottom}});
    }
    const clippedNodes = [...document.querySelectorAll('body *')].filter((node) => {
      if (!shown(node) || node.matches('.review-card-summary, .icon-sprite')) return false;
      const style = getComputedStyle(node);
      return (['hidden', 'clip'].includes(style.overflowX) && node.scrollWidth > node.clientWidth + 1) ||
        (['hidden', 'clip'].includes(style.overflowY) && node.scrollHeight > node.clientHeight + 1);
    });
    const clipped = clippedNodes.length;
    const layout_boxes = ['.app-shell', '#workspace-nav', '#workspace-nav details', '.workspace-nav-list',
      '.app-area', '.app-content', '#review-back-link'].flatMap((selector) => {
      const node = document.querySelector(selector);
      if (!node) return [];
      const rect = node.getBoundingClientRect(); const style = getComputedStyle(node);
      return [{selector, top: rect.top, bottom: rect.bottom, height: rect.height,
        minHeight: style.minHeight, heightStyle: style.height, display: style.display,
        flexShrink: style.flexShrink, rowGap: style.rowGap, position: style.position,
        overflow: style.overflow, open: node instanceof HTMLDetailsElement ? node.open : undefined,
        childRects: selector === '#workspace-nav details' ? [...node.children].map((child) => {
          const childRect = child.getBoundingClientRect(); const childStyle = getComputedStyle(child);
          return {tag: child.tagName, top: childRect.top, bottom: childRect.bottom, height: childRect.height,
            display: childStyle.display, position: childStyle.position};
        }) : undefined}];
    });
    return {viewport: {width: innerWidth, height: innerHeight}, root_font_size: getComputedStyle(document.documentElement).fontSize,
      document: {scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth},
      body: {scrollWidth: document.body.scrollWidth, clientWidth: document.body.clientWidth}, panel_overflow,
      clipped, clipped_nodes: clippedNodes.slice(0, 8).map((node) => ({tag: node.tagName.toLowerCase(), id: node.id, className: String(node.className).slice(0, 80)})),
      target_size_failures: targets.filter((target) => target.width < 44 || target.height < 44).map((target) => ({
        selector: target.selector, width: target.width, height: target.height})),
      target_gap_failures, layout_boxes};
  });
  measurements.push({equivalent200});
  if (equivalent200.document.scrollWidth > equivalent200.document.clientWidth ||
      equivalent200.body.scrollWidth > equivalent200.body.clientWidth || equivalent200.panel_overflow.length ||
      equivalent200.clipped || equivalent200.target_size_failures.length || equivalent200.target_gap_failures.length) {
    console.log(`${label}_200_PERCENT_DIAGNOSTIC ${JSON.stringify(equivalent200)}`);
  }
  requireSafe(equivalent200.root_font_size === '32px' &&
    equivalent200.document.scrollWidth <= equivalent200.document.clientWidth &&
    equivalent200.body.scrollWidth <= equivalent200.body.clientWidth && equivalent200.panel_overflow.length === 0 &&
    equivalent200.clipped === 0 && equivalent200.target_size_failures.length === 0 && equivalent200.target_gap_failures.length === 0,
  `${label}_200_PERCENT_REFLOW_FAILED`);
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 900});
  console.log(`${label}_FULL_APP_LAYOUT ${JSON.stringify(measurements.map((measurement) => {
    if (measurement.equivalent200) return {equivalent200: {
      root_font_size: measurement.equivalent200.root_font_size,
      document: measurement.equivalent200.document, body: measurement.equivalent200.body,
      panel_overflow_count: measurement.equivalent200.panel_overflow.length,
      clipped: measurement.equivalent200.clipped,
      clipped_nodes: measurement.equivalent200.clipped_nodes,
      target_size_failures: measurement.equivalent200.target_size_failures,
      target_gap_failures: measurement.equivalent200.target_gap_failures.length,
    }};
    return {...measurement, target_gap_failures: measurement.target_gap_failures.length};
  }))}`);
  return measurements;
}

function assertTargetGapGeometryContract() {
  const first = {left: 0, top: 0, right: 44, bottom: 44};
  requireSafe(targetGapPx(first, {left: 52, top: 0, right: 96, bottom: 44}) === 8,
    'TARGET_GAP_SAME_ROW_GEOMETRY_FAILED');
  requireSafe(targetGapPx(first, {left: 0, top: 52, right: 44, bottom: 96}) === 8,
    'TARGET_GAP_WRAPPED_ROW_GEOMETRY_FAILED');
  requireSafe(targetGapPx(first, {left: 40, top: 40, right: 84, bottom: 84}) === 0,
    'TARGET_GAP_OVERLAP_NOT_DETECTED');
  requireSafe(targetGapPx(first, {left: 51.99, top: 0, right: 95.99, bottom: 44}) < 8,
    'TARGET_GAP_SHORT_HORIZONTAL_NOT_DETECTED');
  requireSafe(targetGapPx(first, {left: 0, top: 51.99, right: 44, bottom: 95.99}) < 8,
    'TARGET_GAP_SHORT_VERTICAL_NOT_DETECTED');
  requireSafe(targetGapPx(first, {left: 48, top: 48, right: 92, bottom: 92}) < 8,
    'TARGET_GAP_SHORT_DIAGONAL_NOT_DETECTED');
  requireSafe(0 - first.right < 8 && targetGapPx(first, {left: 0, top: 52, right: 44, bottom: 96}) === 8,
    'TARGET_GAP_WRAP_FALSE_FAILURE_REPRODUCTION_FAILED');
}

async function openReviewCase(page, index = 0, useLegacy = true) {
  if (useLegacy) await page.evaluate(() => window.workspaceNavigation.setLegacyDetailForTests(true));
  await page.locator(`#review-case-link-${index}`).click();
  await page.locator('#case-detail-view').waitFor({state: 'visible'});
  return page.locator('#case-detail-view .case-card');
}

function summarizeMs(values) {
  const ordered = [...values].sort((a, b) => a - b);
  return {samples: ordered.length, median_ms: Number(ordered[Math.floor(ordered.length / 2)].toFixed(3)),
    p95_ms: Number(ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * .95) - 1)].toFixed(3)),
    max_ms: Number(ordered.at(-1).toFixed(3))};
}

async function unusedPort() {
  const server = createServer();
  await new Promise((ok, fail) => server.once('error', fail).listen(0, '127.0.0.1', ok));
  const port = server.address().port;
  await new Promise((ok) => server.close(ok));
  return port;
}

async function startServer(home) {
  const port = await unusedPort();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(join(ROOT, '.venv', 'bin', 'python'), [
    '-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port),
    '--no-access-log',
  ], {
    cwd: ROOT, stdio: 'ignore',
    env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config'), PYTHONDONTWRITEBYTECODE: '1'},
  });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error('LOOPBACK_SERVER_START_FAILED');
    try {
      const response = await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)});
      if (response.ok) return {child, origin, port};
    } catch { /* Server is still starting. */ }
    await new Promise((ok) => setTimeout(ok, 50));
  }
  child.kill('SIGINT');
  throw new Error('LOOPBACK_SERVER_TIMEOUT');
}

async function stopServer(child, origin) {
  if (child.exitCode === null) await new Promise((ok, fail) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); fail(new Error('LOOPBACK_SERVER_STOP_TIMEOUT')); }, 5000);
    child.once('exit', () => { clearTimeout(timer); ok(); });
    child.kill('SIGINT');
  });
  let listening = false;
  try { await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)}); listening = true; }
  catch { /* Expected after graceful stop. */ }
  requireSafe(!listening, 'LOOPBACK_LISTENER_REMAINED');
}

function status(state = 'RUNNING') {
  const failed = state === 'DEGRADED' || state === 'FAILED';
  return {
    schema_version: '2', service_state: state, session_id: SESSION, source_role: 'ssh',
    worker_state: failed ? state : 'READY', publication_state: failed ? 'CLOSED' : 'OPEN',
    latest_detection_revision: 0, available_event_count: 0,
    earliest_event_id: null, latest_event_id: null, active_observation_count: 0,
    published_total: 0, evicted_total: 0, replay_gap_total: 0,
    max_event_items: 32, max_event_bytes: 16384, max_connections: 2, active_connections: 0,
    fixed_error_code: failed ? `LIVE_RUNNER_${state}` : null,
    recovery_action: failed ? '터미널 안내를 확인하고 서버를 다시 시작하십시오.' : null,
    analysis_available: true, analysis_revision: 0, active_relation_count: 0,
    active_risk_count: 0, active_case_count: 0, analysis_state: failed ? 'FAILED' : 'AVAILABLE',
    interpretation_notices: [
      '규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.',
      '지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다.',
    ],
    capabilities: ['READ_ONLY_STATUS', 'BOUNDED_SSE_REPLAY', 'AUTOMATIC_POLLING', 'NO_LLM'],
  };
}

function pairStatus() {
  const role = (name) => ({role: name, service_state: 'RUNNING', detection_revision: 0,
    analysis_revision: 0, active_observation_count: 0, active_relation_count: 0,
    active_risk_count: 0, active_case_count: 0, checkpoint_available: false, last_step_code: 'NO_DATA'});
  return {schema_version: '3', service_state: 'RUNNING', session_id: SESSION,
    roles: [role('application'), role('ssh')], available_event_count: 0, event_byte_count: 0,
    earliest_event_id: null, latest_event_id: null, published_total: 0, evicted_total: 0,
    replay_gap_total: 0, max_event_items: 32, max_event_bytes: 16384, max_connections: 2,
    active_connections: 0, fixed_error_code: null,
    interpretation_notices: ['규칙 기반 관찰이며 침해를 확정하지 않습니다.', '지연 또는 replay gap이 있을 수 있습니다.'],
    capabilities: ['READ_ONLY_STATUS', 'BOUNDED_SSE_REPLAY', 'AUTOMATIC_POLLING', 'NO_LLM']};
}

function snapshot() {
  return {
    schema_version: '2', state: 'OPEN', session_id: SESSION, item_count: 0,
    byte_count: 0, max_items: 32, max_bytes: 16384,
    earliest_available_event_id: null, latest_available_event_id: null,
    latest_committed_detection_revision: 0, published_total: 0, evicted_total: 0,
    rejected_oversized_total: 0, replay_gap_total: 0, active_observation_count: 0,
    last_created_count: 0, last_updated_count: 0, last_no_longer_matches_count: 0,
    analysis: {schema_version: '1', analysis_available: true, revision: 0,
      relation_count: 0, risk_count: 0, case_count: 0, independent_observation_count: 0,
      relations: [], risks: [], cases: [], bounded_warnings: []},
  };
}

function observation() {
  return {
    event_id: eventId(1), session_id: SESSION, revision: 1,
    event_type: 'DETECTION_CHANGE', created_count: 1, updated_count: 0,
    no_longer_matches_count: 0, active_observation_count: 1,
    published_observation_count: 1, observations: [{
      observation_id: 'LIVE-OBS-000001', observation_revision: 1,
      change_type: 'CREATED', state: 'ACTIVE', detection_type: 'brute_force',
      accumulator_revision: 1,
    }],
  };
}

function analysis() {
  return {
    event_id: eventId(2), session_id: SESSION, revision: 1,
    event_type: 'ANALYSIS_CHANGE', source_role: 'ssh',
    relation_changes: [{relation_id: 'LIVE-REL-000001', revision: 1,
      relation_type: 'brute_force_to_successful_login', state: 'ACTIVE',
      delta_seconds: 2, change_type: 'RELATION_CREATED'}],
    risk_changes: [{risk_id: 'LIVE-RISK-000001', revision: 1, state: 'CURRENT',
      risk_level: 'HIGH', confidence: 'HIGH', change_type: 'RISK_CREATED'}],
    case_changes: [{case_id: 'LIVE-CASE-000001', revision: 1, state: 'CURRENT',
      rule_id: 'CASE-BRUTE-SUCCESS-01', included_highest_risk: 'HIGH',
      included_highest_confidence: 'HIGH', relation_count: 1, observation_count: 1,
      supporting_relation_count: 0, account_reference_status: 'ACCOUNT_REFERENCE_UNAVAILABLE',
      change_type: 'CASE_CREATED'}],
    summary: {relation_count: 1, risk_count: 1, case_count: 1}, bounded_warnings: [],
  };
}

// The browser sees the shipped JS and CSS; only EventSource is synthetic.
function eventSourceStub() {
  window.__syntheticStreams = [];
  window.EventSource = class {
    constructor(url) {
      this.url = url;
      this.handlers = {};
      this.closed = false;
      window.__syntheticStreams.push(this);
      queueMicrotask(() => { if (!this.closed && this.onopen) this.onopen(); });
    }
    addEventListener(type, handler) { this.handlers[type] = handler; }
    close() { this.closed = true; }
    emit(type, value, lastEventId = '') {
      if (!this.closed) this.handlers[type]({data: JSON.stringify(value), lastEventId});
    }
  };
}

async function emit(page, type, value, id = '') {
  await page.evaluate(({type, value, id}) => {
    window.__syntheticStreams.at(-1).emit(type, value, id);
  }, {type, value, id});
}

async function scan(page, state) {
  await page.waitForLoadState('networkidle');
  const structure = await page.evaluate(() => {
    const shown = (node) => node && !node.closest('[hidden]');
    const inputs = [...document.querySelectorAll('input')].filter(shown);
    const buttons = [...document.querySelectorAll('button')].filter(shown);
    const ids = [...document.querySelectorAll('[id]')].map((node) => node.id);
    return {
      title: Boolean(document.title.trim()), h1: [...document.querySelectorAll('h1')].filter(shown).length,
      landmarks: ['nav', 'header', 'main'].every((tag) => document.querySelector(tag)) &&
        document.querySelector('nav').compareDocumentPosition(document.querySelector('header')) === Node.DOCUMENT_POSITION_FOLLOWING &&
        document.querySelector('header').compareDocumentPosition(document.querySelector('main')) === Node.DOCUMENT_POSITION_FOLLOWING,
      labels: inputs.every((node) => document.querySelector(`label[for="${node.id}"]`)),
      buttons: buttons.every((node) => Boolean(node.textContent.trim() || node.getAttribute('aria-label'))),
      idsUnique: ids.length === new Set(ids).size,
      hiddenLive: document.querySelector('#live-monitoring').hidden,
      status: document.querySelector('#live-connection-state').getAttribute('role') === 'status',
      alert: document.querySelector('#live-error').getAttribute('role') === 'alert',
      pendingLive: document.querySelector('#live-pending-status').getAttribute('aria-live') === 'polite',
    };
  });
  const hiddenExpected = state.startsWith('checklist-') || state.startsWith('checklist_') ||
    state.startsWith('workspace-checklist-') ||
    ['base', 'guidance', 'applied', 'no-longer-matches', 'checkpoint-reset-explanation',
      'three-file-error', 'linux-audit-error', 'text-input', 'TEXT_API_REAL', 'review-list', 'review-detail', 'review-route-expired',
      'workspace-projection-shell', 'workspace-timeline', 'workspace-direct-entry-expired', 'workspace-checklist-race',
      'workspace-evidence',
      'workspace-checklist-invalid-response',
      'workspace-tasks-evidence-available'].includes(state);
  requireSafe(structure.hiddenLive === hiddenExpected, 'HIDDEN_LIVE_CONTRACT_FAILED');
  for (const [key, value] of Object.entries(structure)) {
    if (key === 'hiddenLive') continue;
    requireSafe(key === 'h1' ? value === 1 : value === true,
      `STRUCTURE_${key.toUpperCase()}_FAILED`);
  }
  let results;
  try { results = await new AxeBuilder({page}).analyze(); }
  catch { throw new Error('AXE_ANALYSIS_FAILED'); }
  const summary = results.violations
    .map((item) => ({impact: item.impact, id: item.id, nodes: item.nodes.length}))
    .sort((a, b) => a.id.localeCompare(b.id));
  console.log(`${state} ${JSON.stringify(summary)}`);
  requireSafe(summary.length === 0, 'AXE_VIOLATIONS_PRESENT');
}

async function main() {
  assertTargetGapGeometryContract();
  const start = performance.now();
  const home = await mkdtemp(join(tmpdir(), 'ui-a11y-28-1-'));
  await mkdir(join(home, 'config'));
  if (UI1_SCREENSHOTS) await mkdir(UI1_SCREENSHOTS, {recursive: true});
  let server;
  let browser;
  let context;
  let externalRequests = 0;
  let stateForPage = 'DISABLED';
  let checklistRouteCalls = 0;
  let cachedSyntheticSampleBody = null;
  try {
    server = await startServer(home);
    const response = await fetch(`${server.origin}/`);
    const csp = response.headers.get('content-security-policy') || '';
    requireSafe(csp.includes("script-src 'self'") && csp.includes("connect-src 'self'") &&
      csp.includes("img-src 'none'") && !csp.includes('unsafe-inline') &&
      response.headers.get('x-content-type-options') === 'nosniff', 'CSP_CONTRACT_FAILED');
    browser = await chromium.launch({headless: true, args: [
      '--disable-background-networking', '--no-first-run',
      '--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE 127.0.0.1',
    ]});
    context = await browser.newContext({
      serviceWorkers: 'block', acceptDownloads: true,
      proxy: {server: 'http://127.0.0.1:9', bypass: '127.0.0.1,localhost'},
    });
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== server.origin) {
        externalRequests++;
        await route.abort();
      } else if (url.pathname === '/assets/style.css' && UI1_BASELINE_CSS !== null) {
        await route.fulfill({status: 200, contentType: 'text/css', body: UI1_BASELINE_CSS});
      } else if (url.pathname === '/api/v1/live/status') {
        if (stateForPage === 'DISABLED') await route.continue();
        else await route.fulfill({status: 200, contentType: 'application/json',
          body: JSON.stringify(stateForPage === 'MULTI' ? pairStatus() : status(stateForPage))});
      } else if (url.pathname === '/api/v1/investigations/text') {
        await route.continue();
      } else if (url.pathname === '/api/v1/investigations') {
        await route.continue();
      } else if (url.pathname === '/api/v1/investigations/sample') {
        if (cachedSyntheticSampleBody !== null) {
          await route.fulfill({status: 200, contentType: 'application/json', body: cachedSyntheticSampleBody});
        } else {
          const sampleResponse = await route.fetch();
          const sampleBody = await sampleResponse.text();
          if (!sampleResponse.ok) throw new Error('SYNTHETIC_SAMPLE_FIXTURE_UNAVAILABLE');
          cachedSyntheticSampleBody = sampleBody;
          await route.fulfill({response: sampleResponse, body: sampleBody});
        }
      } else if (url.pathname === '/api/v1/investigations/guidance') {
        if (stateForPage === 'GUIDANCE_REAL') await route.continue();
        else await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({
            schema_version: 1, status: 'AVAILABLE',
            message: '조사 도움말입니다. 기존 탐지·관계·위험도·사례 결과를 변경하지 않습니다.',
            corpus_digest: 'fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6',
            citations: [{citation_id: 'investigation-case:supporting-relation',
              title: '조사 사례와 지원 관계', summary: '합성 검증용 승인 문장입니다.',
              source_ref: 'docs/live_analysis_correlation_case_design.md'}],
          })});
      } else if (url.pathname === '/api/v1/investigations/checklist') {
        if (stateForPage === 'CHECKLIST_REAL') await route.continue();
        else if (stateForPage === 'CHECKLIST_RENDER_EXCEPTION') await route.fulfill({status: 200,
          contentType: 'application/json', body: JSON.stringify(checklistPayload(stateForPage))});
        else if (stateForPage === 'CHECKLIST_NETWORK') await route.abort('failed');
        else if (stateForPage === 'WORKSPACE_RACE') {
          await new Promise((resolveRequest) => setTimeout(resolveRequest, 300));
          await route.fulfill({status: 200, contentType: 'application/json',
            body: JSON.stringify(checklistPayload('CHECKLIST_AVAILABLE'))});
        } else if (stateForPage === 'CHECKLIST_MALFORMED') {
          const malformed = checklistPayload('CHECKLIST_AVAILABLE');
          malformed.account = 'account-response-canary';
          await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(malformed)});
        } else if (stateForPage === 'CHECKLIST_INVALID_CITATION') {
          const malformed = checklistPayload('CHECKLIST_AVAILABLE');
          malformed.steps[0].citation_ids = ['forged:unverified'];
          await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(malformed)});
        }
        else if (stateForPage === 'CHECKLIST_LOADING') {
          await new Promise((resolveRequest) => setTimeout(resolveRequest, 150));
          await route.fulfill({status: 200, contentType: 'application/json',
            body: JSON.stringify(checklistPayload('CHECKLIST_REFUSED'))});
        } else if (stateForPage === 'CHECKLIST_STALE') {
          await route.fulfill({status: 404, contentType: 'application/json',
            body: JSON.stringify({error_code: 'NOT_FOUND', user_message: '현재 분석 결과에서 사례를 찾을 수 없습니다.'})});
        } else if (stateForPage === 'CHECKLIST_TIMEOUT') {
          await route.fulfill({status: 503, contentType: 'application/json',
            body: JSON.stringify({error_code: 'TIMEOUT', user_message: '조사 점검표 준비 시간이 초과되었습니다.'})});
        } else if (stateForPage === 'CHECKLIST_RATE') {
          await route.fulfill({status: 429, contentType: 'application/json',
            body: JSON.stringify({error_code: 'RATE_LIMITED', user_message: '조사 점검표 요청 한도에 도달했습니다.'})});
        } else if (stateForPage === 'CHECKLIST_UNAVAILABLE' ||
                   (stateForPage === 'CHECKLIST_RETRY' && checklistRouteCalls++ === 0)) {
          await route.fulfill({status: 503, contentType: 'application/json',
            body: JSON.stringify({error_code: 'UNAVAILABLE', user_message: '승인 근거를 확인할 수 없어 점검표를 준비하지 못했습니다.'})});
        } else {
          await route.fulfill({status: 200, contentType: 'application/json',
            body: JSON.stringify(checklistPayload(stateForPage === 'CHECKLIST_AVAILABLE' ||
              stateForPage === 'CHECKLIST_RETRY' ? 'CHECKLIST_AVAILABLE' : 'CHECKLIST_REFUSED'))});
        }
      } else if (['/', '/assets/style.css', '/assets/app.js',
        '/assets/linux-audit.js', '/assets/live-monitoring.js',
        '/assets/multi-source-live.js'].includes(url.pathname)) {
        await route.continue();
      } else {
        throw new Error('UNEXPECTED_LOOPBACK_REQUEST');
      }
    });

    for (const stateName of STATES) {
      currentScenario = stateName;
      stateForPage = stateName === 'base' || stateName.includes('error') ||
        stateName === 'checkpoint-reset-explanation' ? 'DISABLED' :
        stateName === 'degraded' ? 'DEGRADED' : stateName === 'failed' ? 'FAILED' : 'RUNNING';
      const page = await context.newPage();
      await page.addInitScript(eventSourceStub);
      await page.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
      if (stateForPage !== 'DISABLED') {
        await page.locator('#nav-group-tools > summary').click();
        await page.locator('#nav-live').waitFor({state: 'visible'});
        await page.locator('#nav-live').click();
        await page.waitForFunction(() => !document.querySelector('#live-monitoring').hidden);
        const expectedIcon = stateForPage === 'DEGRADED' ? '#icon-triangle-alert' :
          stateForPage === 'FAILED' ? '#icon-circle-x' : '#icon-activity';
        requireSafe(await page.locator('#live-state-icon-use').getAttribute('href') === expectedIcon &&
          await page.locator('#live-state-cell').getAttribute('data-service-state') === stateForPage,
          'LIVE_STATE_VISUAL_TEXT_CONTRACT_FAILED');
      }
      if (stateName === 'base') {
        requireSafe(await page.locator('#nav-start').getAttribute('aria-current') === 'page' &&
          await page.locator('#nav-live').isHidden() && await page.locator('#nav-results').isHidden(),
          'WORKSPACE_INITIAL_STATE_FAILED');
        const theme = await page.evaluate(() => ({
          background: getComputedStyle(document.documentElement).getPropertyValue('--cyber-bg').trim(),
          cyan: getComputedStyle(document.documentElement).getPropertyValue('--cyber-cyan').trim(),
          bodyFont: parseFloat(getComputedStyle(document.body).fontSize),
          sidebarWidth: Math.round(document.querySelector('.workspace-nav').getBoundingClientRect().width),
          activeBorder: getComputedStyle(document.querySelector('.workspace-nav button[aria-current="page"]')).borderInlineStartColor,
        }));
        if (UI1_BASELINE_CSS === null) {
          requireSafe(theme.background === '#070b18' && theme.cyan === '#00d9f5' && theme.bodyFont >= 16 &&
            theme.sidebarWidth >= 240 && theme.activeBorder === 'rgb(0, 217, 245)',
          'CYBERPUNK_WORKSPACE_THEME_FAILED');
          console.log(`CYBERPUNK_THEME ${JSON.stringify(theme)}`);
        }
        if (UI1_SCREENSHOTS) await page.screenshot({path: join(UI1_SCREENSHOTS, 'start-1440.png'), fullPage: true});
        await page.locator('#nav-local').focus();
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('#local-upload').isVisible() &&
          await page.locator('#nav-local').getAttribute('aria-current') === 'page' &&
          await page.locator('.workspace-panel:visible').count() === 1,
          'WORKSPACE_KEYBOARD_NAV_FAILED');
        if (!await page.locator('#nav-group-tools').evaluate((node) => node.open))
          await page.locator('#nav-group-tools > summary').click();
        await page.locator('#nav-audit').click();
        requireSafe(await page.locator('#linux-audit-upload').isVisible() &&
          await page.locator('.workspace-panel:visible').count() === 1,
          'WORKSPACE_AUDIT_SELECTION_FAILED');
        await page.locator('#nav-start').click();
        requireSafe(await page.locator('#live-monitoring').isHidden(), 'HIDDEN_LIVE_FAILED');
        requireSafe(await page.getByRole('heading', {name: '실시간 로그 모니터링'}).count() === 0,
          'HIDDEN_LIVE_ACCESSIBILITY_TREE');
        await page.locator('#local-choice-button').focus();
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('#local-choice-details').evaluate((node) => node.open) &&
          await page.evaluate(() => document.activeElement.id === 'application-file'),
          'LOCAL_CHOICE_KEYBOARD_FAILED');
        await page.locator('#local-choice-details summary').focus();
        await page.keyboard.press('Enter');
        requireSafe(!(await page.locator('#local-choice-details').evaluate((node) => node.open)),
          'DISCLOSURE_KEYBOARD_FAILED');
        await page.emulateMedia({reducedMotion: 'reduce'});
        requireSafe(await page.locator('#sample-button').evaluate((node) =>
          getComputedStyle(node).transitionDuration === '0s'), 'REDUCED_MOTION_FAILED');
      } else if (['live-empty', 'pending', 'applied', 'paused', 'no-longer-matches',
        'private-event-rejected', 'replay-gap'].includes(stateName)) {
        if (stateName === 'pending') {
          const count = await page.evaluate(() => window.__syntheticStreams.length);
          await page.locator('#nav-start').click();
          await page.locator('#nav-live').click();
          requireSafe(await page.evaluate(() => window.__syntheticStreams.length) === count && count === 1,
            'WORKSPACE_DUPLICATE_EVENTSOURCE');
        }
        await emit(page, 'snapshot', snapshot());
        if (stateName !== 'live-empty' && stateName !== 'replay-gap') {
          if (stateName === 'pending' || stateName === 'applied')
            await page.locator('#live-pause').focus();
          const before = await page.evaluate(() => ({focus: document.activeElement.id, scroll: scrollY}));
          const first = observation();
          if (stateName === 'private-event-rejected') first.observations[0].private_account = CANARY;
          await emit(page, 'observation_changes', first, eventId(1));
          if (stateName === 'private-event-rejected') {
            requireSafe(await page.locator('#live-error').isVisible() &&
              await page.locator('#live-observations li').count() === 0,
              'PRIVATE_EVENT_ACCEPTED');
          } else {
            await emit(page, 'analysis_changes', analysis(), eventId(2));
            const after = await page.evaluate(() => ({focus: document.activeElement.id, scroll: scrollY}));
            requireSafe(before.focus === after.focus && before.scroll === after.scroll, 'SSE_FOCUS_SCROLL_CHANGED');
            requireSafe(await page.locator('#live-observations li').count() === 0, 'PENDING_AUTO_APPLIED');
            if (stateName === 'applied' || stateName === 'no-longer-matches') {
              await page.locator('#live-show-pending').click();
              requireSafe(await page.locator('#workspace-results').isVisible() &&
                await page.locator('#live-results-heading').isVisible() &&
                await page.locator('#nav-results').getAttribute('aria-current') === 'page',
                'WORKSPACE_RESULT_NOT_SELECTED');
              requireSafe(await page.locator('#live-results-heading').evaluate((node) => {
                const rect = node.getBoundingClientRect();
                return rect.top >= 0 && rect.top < innerHeight;
              }), 'WORKSPACE_RESULT_REQUIRES_SCROLL');
              requireSafe(await page.locator('#live-result-details').evaluate((node) => node.open),
                'APPLIED_DETAIL_HIDDEN');
              for (const id of ['live-observations', 'live-relations', 'live-risks', 'live-cases'])
                requireSafe(await page.locator(`#${id} li`).count() === 1, 'APPLIED_RESULT_MISSING');
            }
            if (stateName === 'no-longer-matches') {
              const update = observation();
              update.event_id = eventId(3); update.revision = 2;
              update.created_count = 0; update.no_longer_matches_count = 1;
              update.active_observation_count = 0;
              update.observations[0].observation_revision = 2;
              update.observations[0].accumulator_revision = 2;
              update.observations[0].change_type = 'NO_LONGER_MATCHES';
              update.observations[0].state = 'NO_LONGER_MATCHES_CURRENT_RESULT';
              const riskUpdate = analysis();
              riskUpdate.event_id = eventId(4); riskUpdate.revision = 2;
              riskUpdate.relation_changes = []; riskUpdate.case_changes = [];
              riskUpdate.risk_changes[0].revision = 2;
              riskUpdate.risk_changes[0].risk_level = 'MEDIUM';
              riskUpdate.risk_changes[0].change_type = 'RISK_UPDATED';
              await emit(page, 'observation_changes', update, eventId(3));
              await emit(page, 'analysis_changes', riskUpdate, eventId(4));
              await page.locator('#nav-live').click();
              await page.locator('#live-show-pending').click();
              const words = await page.locator('#live-results').textContent();
              requireSafe(words.includes('현재 탐지 결과에는 더 이상 일치하지 않음') &&
                words.includes('안전이나 해결을 뜻하지 않습니다') &&
                !words.includes('해결됐습니다'), 'NO_LONGER_MATCHES_SEMANTICS_FAILED');
            }
            if (stateName === 'paused') {
              await page.locator('#live-pause').click();
              requireSafe(await page.locator('#live-show-pending').isHidden(), 'PAUSE_CONTRACT_FAILED');
            }
          }
        } else {
          await emit(page, 'replay_gap', {code: 'EVICTED_EVENT_ID', snapshot: snapshot(),
            earliest_event_id: null, latest_event_id: null,
            recovery_action: '최신 상태부터 다시 확인하십시오.'});
          requireSafe(await page.locator('#live-stale').isVisible() &&
            await page.locator('#live-reconnect').isVisible(), 'REPLAY_GAP_RECOVERY_MISSING');
        }
      } else if (stateName === 'degraded' || stateName === 'failed') {
        requireSafe(await page.locator('#live-error').isVisible(), 'TERMINAL_RECOVERY_MISSING');
        const text = await page.locator('#live-service-state').textContent();
        requireSafe(text.includes(stateName === 'failed' ? '모니터링 종료됨' : '연결에 문제가 있음'),
          'TERMINAL_AS_ZERO');
      } else if (stateName === 'checkpoint-reset-explanation') {
        // Reset is CLI-only in v0.3; this test-only equivalent never claims to be shipped UI.
        await page.evaluate(() => {
          const section = document.createElement('section');
          section.setAttribute('aria-labelledby', 'synthetic-reset-heading');
          const heading = document.createElement('h2');
          heading.id = 'synthetic-reset-heading';
          heading.textContent = '분석 연속성 초기화';
          const copy = document.createElement('p');
          copy.textContent = 'checkpoint만 삭제하며 원본 로그는 보존합니다. 다음 실행은 새 epoch에서 시작합니다.';
          section.append(heading, copy);
          document.querySelector('main').append(section);
        });
      } else if (stateName === 'three-file-error') {
        await page.locator('#local-choice-button').click();
        await page.locator('#local-form').evaluate((form) => form.requestSubmit());
        requireSafe(await page.locator('#error-summary').isVisible() &&
          await page.locator('#application-file').getAttribute('aria-invalid') === 'true' &&
          await page.locator('#application-error').isVisible(), 'THREE_FILE_ERROR_LINK_FAILED');
      } else if (stateName === 'linux-audit-error') {
        if (!await page.locator('#nav-group-tools').evaluate((node) => node.open))
          await page.locator('#nav-group-tools > summary').click();
        await page.locator('#nav-audit').click();
        await page.locator('#linux-audit-form').evaluate((form) => form.requestSubmit());
        requireSafe(await page.locator('#linux-audit-error').isVisible() &&
          await page.locator('#linux-audit-file').getAttribute('aria-invalid') === 'true' &&
          await page.locator('#linux-audit-field-error').isVisible(), 'LINUX_ERROR_LINK_FAILED');
      }
      if (stateName === 'text-input') {
        await page.locator('#nav-local').click();
        if (!(await page.locator('#local-choice-details').evaluate((node) => node.open)))
          await page.locator('#local-choice-details summary').click();
        await page.locator('#input-mode-text').check();
        requireSafe(await page.locator('#text-input-panel').isVisible() &&
          await page.locator('#log-text').isVisible() && await page.locator('#text-source').isVisible(),
        'TEXT_INPUT_CONTROLS_MISSING');
        await page.locator('#log-text').fill('보안');
        requireSafe(await page.locator('#text-byte-count').textContent() === '6' &&
          await page.locator('#text-line-count').textContent() === '1', 'TEXT_UTF8_COUNTER_FAILED');
        await page.locator('#text-clear').click();
        requireSafe(await page.locator('#log-text').inputValue() === '' &&
          await page.locator('#text-byte-count').textContent() === '0', 'TEXT_CLEAR_CONTROL_FAILED');
        requireSafe(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          'TEXT_INPUT_HORIZONTAL_OVERFLOW');
        await assertWorkspaceReflow(page, 'TEXT_INPUT');
      }
      for (const width of [320, 640, 1024, 1440]) {
        await page.setViewportSize({width, height: 900});
        requireSafe(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          'HORIZONTAL_OVERFLOW');
      }
      requireSafe(!(await page.locator('body').textContent()).includes(CANARY), 'DOM_CANARY_LEAK');
      await scan(page, stateName);
      await page.close();
    }
    stateForPage = 'DISABLED';
    currentScenario = 'TEXT_API_REAL';
    const textApiPage = await context.newPage();
    await textApiPage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await textApiPage.locator('#nav-local').click();
    if (!(await textApiPage.locator('#local-choice-details').evaluate((node) => node.open)))
      await textApiPage.locator('#local-choice-details summary').click();
    await textApiPage.locator('#input-mode-text').check();
    await textApiPage.locator('#text-source').selectOption('ssh');
    const textCanary = 'TEXT_E2E_PRIVATE_CANARY';
    const syntheticSsh = (await readFile(join(ROOT, 'sample_logs', 'ssh_auth.log'), 'utf8'))
      .replace('admin', textCanary);
    const textConsoleMessages = [];
    textApiPage.on('console', (message) => textConsoleMessages.push(message.text()));
    textApiPage.on('pageerror', (error) => textConsoleMessages.push(error.name));
    await textApiPage.locator('#log-text').fill(syntheticSsh);
    const textRequests = [];
    textApiPage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/text') textRequests.push(request);
    });
    requireSafe(textRequests.length === 0, 'TEXT_API_AUTOMATIC_POST');
    await textApiPage.locator('#local-button').click();
    await textApiPage.locator('#results').waitFor({state: 'visible'});
    await textApiPage.waitForFunction(() => document.querySelector('#local-status')?.textContent.includes('완료'));
    const textResponse = await (await textRequests[0].response()).json();
    const textRequestBody = JSON.parse(textRequests[0].postData() || '{}');
    requireSafe(textRequests.length === 1 && textResponse.schema_version === '1' &&
      textResponse.input_scope.mode === 'text' && textResponse.input_scope.source === 'ssh' &&
      textResponse.input_scope.notice_code === 'PARTIAL_SINGLE_SOURCE' &&
      Object.keys(textRequestBody).sort().join(',') === 'log_text,schema_version,source' &&
      textRequestBody.source === 'ssh' && textRequestBody.schema_version === 1 &&
      await textApiPage.locator('#text-input-scope-notice').isVisible() &&
      await textApiPage.locator('#text-input-source-label').textContent().then((text) => text === 'SSH 인증 로그') &&
      await textApiPage.locator('#log-text').inputValue().then((value) => value === '') &&
      await textApiPage.locator('#text-input-scope-notice').textContent().then((text) =>
        text.includes('다른 로그나 누락된 시간대') && text.includes('검증된 역할')),
    'TEXT_API_REAL_SCOPE_OR_CLEAR_FAILED');
    const storageState = await textApiPage.evaluate(async () => ({
      local: localStorage.length,
      session: sessionStorage.length,
      databases: typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).length : 0
    }));
    requireSafe(!JSON.stringify(textResponse).includes(textCanary) &&
      !textConsoleMessages.some((message) => message.includes(textCanary)) &&
      !textApiPage.url().includes(textCanary) && storageState.local === 0 &&
      storageState.session === 0 && storageState.databases === 0,
    'TEXT_API_PRIVACY_BOUNDARY_FAILED');
    requireSafe(textRequestBody.log_text.includes(textCanary), 'TEXT_API_EXPLICIT_BODY_MISSING_SYNTHETIC_INPUT');
    const textReport = textResponse.result.report_export.html;
    requireSafe(textReport.includes('입력한 로그 범위에서만 분석한 결과입니다') &&
      textReport.includes('다른 로그나 누락된 시간대') && !textReport.includes(textCanary),
    'TEXT_API_REPORT_SCOPE_NOTICE_MISSING');
    const textDownload = textApiPage.waitForEvent('download');
    await textApiPage.locator('#report-button').click();
    const downloadedReport = await textDownload;
    const downloadedPath = await downloadedReport.path();
    requireSafe(downloadedPath && !(await readFile(downloadedPath, 'utf8')).includes(textCanary),
      'TEXT_API_DOWNLOADED_REPORT_PRIVACY_FAILED');
    await downloadedReport.delete();
    const textChecklistCalls = [];
    textApiPage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/checklist')
        textChecklistCalls.push(request);
    });
    const textCaseCard = await openReviewCase(textApiPage, 0, false);
    await textApiPage.getByRole('tab', {name: '확인할 작업'}).click();
    requireSafe(textChecklistCalls.length === 0, 'TEXT_RESULT_CHECKLIST_TAB_AUTOMATIC_POST');
    await textCaseCard.locator('.workspace-checklist-request-36-6e').click();
    await textCaseCard.locator('.workspace-checklist-status-36-6e').waitFor({state: 'visible'});
    await textApiPage.waitForFunction(() => {
      const status = document.querySelector('.workspace-checklist-status-36-6e');
      return status && status.dataset.checklistState !== 'loading';
    });
    const textChecklistResponse = await (await textChecklistCalls[0].response()).json();
    const textChecklistUi = {
      requests: textChecklistCalls.length,
      schemaOk: textChecklistResponse.schema === 'investigation-checklist/v2',
      responseStatus: textChecklistResponse.status,
      responseSteps: Array.isArray(textChecklistResponse.steps) ? textChecklistResponse.steps.length : -1,
      taskChoices: await textCaseCard.locator('.workspace-task-choice-36-6e').count(),
      uiStatus: await textCaseCard.locator('.workspace-checklist-status-36-6e').getAttribute('data-checklist-state'),
      failureMessage: await textCaseCard.locator('.workspace-checklist-status-36-6e').textContent()
        .then((text) => text.includes('점검표를 준비하지 못했습니다'))
    };
    console.log(`TEXT_CHECKLIST_STATE ${JSON.stringify(textChecklistUi)}`);
    requireSafe(textChecklistUi.requests === 1 && textChecklistUi.schemaOk &&
      ['available', 'refused', 'unavailable'].includes(textChecklistUi.responseStatus) &&
      textChecklistUi.uiStatus === textChecklistUi.responseStatus && !textChecklistUi.failureMessage &&
      (textChecklistUi.responseStatus === 'available' ?
        textChecklistUi.taskChoices === textChecklistUi.responseSteps : textChecklistUi.taskChoices === 0),
    'TEXT_RESULT_EXPLICIT_CHECKLIST_E2E_FAILED');
    const textAllRendered = await textApiPage.locator('#results').innerText();
    const finalStorage = await textApiPage.evaluate(async () => ({
      local: localStorage.length,
      session: sessionStorage.length,
      databases: typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).length : 0
    }));
    requireSafe(!textAllRendered.includes(textCanary) && !textApiPage.url().includes(textCanary) &&
      finalStorage.local === 0 && finalStorage.session === 0 && finalStorage.databases === 0,
    'TEXT_RESULT_RENDERED_PRIVACY_FAILED');
    await textApiPage.setViewportSize({width: 320, height: 568});
    requireSafe(await textApiPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      'TEXT_RESULT_320_OVERFLOW');
    await scan(textApiPage, 'TEXT_API_REAL');
    await textApiPage.close();
    for (const source of ['application', 'access']) {
      currentScenario = `TEXT_API_REAL_${source.toUpperCase()}`;
      const sourcePage = await context.newPage();
      await sourcePage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
      await sourcePage.locator('#nav-local').click();
      if (!(await sourcePage.locator('#local-choice-details').evaluate((node) => node.open)))
        await sourcePage.locator('#local-choice-details summary').click();
      await sourcePage.locator('#input-mode-text').check();
      await sourcePage.locator('#text-source').selectOption(source);
      const logText = await readFile(join(ROOT, 'sample_logs',
        source === 'application' ? 'brute_force.log' : 'web_shell.log'), 'utf8');
      await sourcePage.locator('#log-text').fill(logText);
      const requests = [];
      sourcePage.on('request', (request) => {
        if (new URL(request.url()).pathname === '/api/v1/investigations/text') requests.push(request);
      });
      requireSafe(requests.length === 0, `TEXT_API_${source.toUpperCase()}_AUTOMATIC_POST`);
      await sourcePage.locator('#local-button').click();
      await sourcePage.locator('#results').waitFor({state: 'visible'});
      await sourcePage.waitForFunction(() => document.querySelector('#local-status')?.textContent.includes('완료'));
      const responseBody = await (await requests[0].response()).json();
      requireSafe(requests.length === 1 && responseBody.input_scope.source === source &&
        await sourcePage.locator('#text-input-source-label').textContent().then((text) =>
          text === (source === 'application' ? '애플리케이션 인증 로그' : '웹 접근 로그')) &&
        responseBody.result.report_export.html.includes('입력한 로그 범위에서만 분석한 결과입니다'),
      `TEXT_API_${source.toUpperCase()}_REAL_RESULT_FAILED`);
      if (source === 'access') requireSafe(responseBody.result.case_summary.case_count === 0 &&
        responseBody.result.case_summary.independent_observation_count > 0 &&
        await sourcePage.locator('#result-empty').isHidden(), 'TEXT_API_ACCESS_SCOPE_MISREPRESENTED');
      console.log(`TEXT_API_REAL_SOURCE source=${source} cases=${responseBody.result.case_summary.case_count} independent=${responseBody.result.case_summary.independent_observation_count}`);
      await sourcePage.close();
    }
    currentScenario = 'FILE_API_REAL';
    const fileApiPage = await context.newPage();
    await fileApiPage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await fileApiPage.locator('#nav-local').click();
    if (!(await fileApiPage.locator('#local-choice-details').evaluate((node) => node.open)))
      await fileApiPage.locator('#local-choice-details summary').click();
    const filePaths = [
      join(ROOT, 'sample_logs', 'brute_force.log'),
      join(ROOT, 'sample_logs', 'ssh_auth.log'),
      join(ROOT, 'sample_logs', 'web_shell.log'),
    ];
    for (const [index, field] of ['application-file', 'ssh-file', 'access-file'].entries())
      await fileApiPage.locator(`#${field}`).setInputFiles(filePaths[index]);
    const fileRequests = [];
    fileApiPage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations') fileRequests.push(request);
    });
    await fileApiPage.locator('#local-button').click();
    await fileApiPage.locator('#results').waitFor({state: 'visible'});
    requireSafe(fileRequests.length === 1 &&
      (await fileRequests[0].response()).status() === 200 &&
      !await fileApiPage.locator('#text-input-scope-notice').isVisible(),
    'FILE_UPLOAD_EXISTING_ENDPOINT_REGRESSION');
    console.log('FILE_API_REAL status=200 posts=1 text_scope_notice=false');
    await fileApiPage.close();
    stateForPage = 'DISABLED';
    const guidancePage = await context.newPage();
    await guidancePage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await guidancePage.locator('#sample-button').click();
    await guidancePage.locator('#case-list .case-card').nth(1).waitFor({state: 'attached'});
    const guidanceCard = await openReviewCase(guidancePage);
    requireSafe(await guidancePage.locator('.guidance-request').count() === 1,
      'GUIDANCE_CASE_CONTROLS_MISSING');
    const guidanceButton = guidanceCard.locator('.guidance-request');
    const helpCalls = [];
    guidancePage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/guidance') helpCalls.push(request);
    });
    requireSafe(helpCalls.length === 0, 'GUIDANCE_AUTOMATIC_REQUEST');
    await guidanceButton.focus();
    await guidancePage.keyboard.press('Enter');
    await guidanceCard.locator('.guidance-citation').waitFor({state: 'visible'});
    requireSafe(helpCalls.length === 1 &&
      await guidanceCard.locator('.guidance-citation script').count() === 0 &&
      await guidanceCard.locator('.guidance-citation').textContent().then((text) =>
        text.includes('합성 검증용 승인 문장입니다.')) &&
      await guidanceCard.locator('.guidance-status').textContent().then((text) =>
        text.includes('결과를 변경하지 않습니다')),
    'GUIDANCE_DOM_OR_OPT_IN_FAILED');
    for (const width of [1440, 1024, 768, 390, 320]) {
      await guidancePage.setViewportSize({width, height: 900});
      requireSafe(await guidancePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'GUIDANCE_HORIZONTAL_OVERFLOW');
    }
    await scan(guidancePage, 'guidance');
    await guidancePage.close();
    stateForPage = 'GUIDANCE_REAL';
    const realGuidancePage = await context.newPage();
    await realGuidancePage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await realGuidancePage.locator('#sample-button').click();
    const realGuidanceCard = await openReviewCase(realGuidancePage);
    const realGuidanceCalls = [];
    realGuidancePage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/guidance')
        realGuidanceCalls.push(request);
    });
    const analysisText = () => realGuidancePage.locator('#results').evaluate((node) => {
      const clone = node.cloneNode(true);
      clone.querySelectorAll('.investigation-guidance').forEach((item) => item.remove());
      return clone.innerText;
    });
    const beforeGuidance = await analysisText();
    requireSafe(realGuidanceCalls.length === 0, 'REAL_GUIDANCE_AUTOMATIC_REQUEST');
    await realGuidanceCard.locator('.guidance-request').click();
    await realGuidanceCard.locator('.guidance-status').waitFor({state: 'visible'});
    await realGuidancePage.waitForFunction(() => {
      const status = document.querySelector('.guidance-status')?.textContent || '';
      return !status.includes('확인하고 있습니다');
    });
    const realGuidanceStatus = await realGuidanceCard.locator('.guidance-status').textContent();
    requireSafe(realGuidanceCalls.length === 1 &&
      realGuidanceStatus.includes('조사 도움말입니다') &&
      await realGuidanceCard.locator('.guidance-citation').count() > 0 &&
      await analysisText().then((text) => text === beforeGuidance),
    'REAL_GUIDANCE_STALE_OR_MUTATED');
    await realGuidancePage.close();
    for (const checklistState of CHECKLIST_STATES) {
      currentScenario = checklistState;
      stateForPage = checklistState;
      checklistRouteCalls = 0;
      const checklistPage = await context.newPage();
      await checklistPage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
      await checklistPage.locator('#sample-button').click();
      const workspaceChecklist = checklistState === 'CHECKLIST_REAL';
      const card = await openReviewCase(checklistPage, 0, !workspaceChecklist);
      if (workspaceChecklist) await checklistPage.getByRole('tab', {name: '확인할 작업'}).click();
      const control = card.locator('.checklist-request');
      const calls = [];
      checklistPage.on('request', (request) => {
        if (new URL(request.url()).pathname === '/api/v1/investigations/checklist') calls.push(request);
      });
      const before = await checklistPage.locator('#results').evaluate((node) => {
        const copy = node.cloneNode(true); copy.querySelectorAll('.investigation-checklist').forEach((item) => item.remove());
        copy.querySelectorAll('.workspace-checklist-evidence-36-6e').forEach((item) => item.replaceChildren());
        copy.querySelectorAll('.workspace-detail-header-36-6c .review-role-pending').forEach((item) => { item.textContent = 'ROLE_PRESENTATION'; });
        copy.querySelectorAll('.workspace-detail-header-36-6c .review-priority-pending').forEach((item) => { item.textContent = 'PRIORITY_PRESENTATION'; });
        return copy.innerText;
      });
      requireSafe(calls.length === 0, 'CHECKLIST_AUTOMATIC_REQUEST');
      requireSafe(await control.getAttribute('type') === 'button' && await control.evaluate((node) => node.tabIndex >= 0),
        'CHECKLIST_KEYBOARD_CONTROL_MISSING');
      await control.focus();
      await checklistPage.keyboard.press('Enter');
      if (checklistState === 'CHECKLIST_LOADING') {
        requireSafe(await card.locator('.checklist-status').textContent().then((text) => text.includes('확인하고 있습니다')) &&
          await control.isDisabled(), 'CHECKLIST_LOADING_STATE_MISSING');
        await control.evaluate((node) => node.click());
      }
      await checklistPage.waitForFunction(() => !document.querySelector('.checklist-status')?.textContent.includes('확인하고 있습니다'));
      if (checklistState === 'CHECKLIST_RETRY') {
        await control.click();
        await checklistPage.waitForSelector('.checklist-result .checklist-tasks > li');
      }
      if (checklistState === 'CHECKLIST_REAL') {
        console.log(`CHECKLIST_REQUEST_COUNT scenario=${checklistState} count=${calls.length}`);
      }
      requireSafe(calls.length === (checklistState === 'CHECKLIST_RETRY' ? 2 : 1), 'CHECKLIST_OPT_IN_COUNT_FAILED');
      const requestBody = JSON.parse(calls[0].postData() || '{}');
      requireSafe(Object.keys(requestBody).sort().join(',') === 'case_ref,schema_version' &&
        /^c_[0-9a-f]{24}$/.test(requestBody.case_ref), 'CHECKLIST_REQUEST_PRIVACY_FAILED');
      const rendered = await card.locator('.investigation-checklist').innerText();
      if (checklistState === 'CHECKLIST_REAL') {
        const responsePayload = await (await calls[0].response()).json();
        const verifiedRole = await card.locator('.workspace-detail-header-36-6c .review-role-pending').textContent();
        const verifiedPriority = await card.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent();
        console.log(`CHECKLIST_REAL_STATE status=${responsePayload.status} steps=${responsePayload.steps.length} role=${responsePayload.source_role} priority=${responsePayload.review_priority} ui_state=${await card.locator('.workspace-checklist-status-36-6e').getAttribute('data-checklist-state')} task_buttons=${await card.locator('.workspace-task-choice-36-6e').count()} error_copy=${rendered.includes('점검표를 준비하지 못했습니다')} verified_role=${verifiedRole?.includes('SSH 인증 로그') === true} verified_priority=${verifiedPriority?.includes('우선 확인') === true}`);
        requireSafe(await card.locator('.workspace-checklist-status-36-6e').getAttribute('data-checklist-state') === 'available' &&
          !rendered.includes('점검표를 준비하지 못했습니다') &&
          await card.locator('.workspace-task-choice-36-6e').count() > 0 &&
          await card.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('SSH 인증 로그')) &&
          await card.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('우선 확인')) &&
          !rendered.includes('역할 정보 미확인'), 'CHECKLIST_REAL_AVAILABLE_UI_STATE_MISMATCH');
      }
      if (checklistState === 'CHECKLIST_AVAILABLE' || checklistState === 'CHECKLIST_RETRY' ||
          checklistState === 'CHECKLIST_REAL') {
        requireSafe(rendered.includes('이 점검표는 기존 탐지·관계·위험도·사례 결과를 변경하지 않습니다.'),
          'CHECKLIST_ANALYSIS_INVARIANCE_EXPLANATION_MISSING');
        requireSafe((checklistState === 'CHECKLIST_REAL' ?
          await card.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('우선 확인')) :
          rendered.includes('우선 확인')) && !rendered.includes('review_soon'),
          'CHECKLIST_PRIORITY_RENDER_FAILED');
        const why = card.locator(checklistState === 'CHECKLIST_REAL' ?
          '.workspace-task-references-36-6e' : '.checklist-task details').first();
        requireSafe(await why.count() === 1 && !(await why.evaluate((node) => node.open)),
          'CHECKLIST_CITATION_NOT_PROGRESSIVE');
        const whySummary = why.locator('summary').first();
        requireSafe(await whySummary.count() === 1, 'CHECKLIST_WHY_SUMMARY_MISSING');
        await whySummary.press('Enter');
        requireSafe(await why.evaluate((node) => node.open), 'CHECKLIST_WHY_DISCLOSURE_FAILED');
        const expandedChecklist = await card.locator('.investigation-checklist').innerText();
        requireSafe((checklistState === 'CHECKLIST_REAL' ?
          expandedChecklist.includes('일반적인 조사 참고자료이며 이 사례의 직접 증거가 아닙니다') :
          expandedChecklist.includes('일반 조사 방법과 한계') &&
            expandedChecklist.includes('이 사례의 직접 증거가 아닙니다')),
        'CHECKLIST_CITATION_BOUNDARY_RENDER_FAILED');
        if (checklistState === 'CHECKLIST_REAL') {
          requireSafe(await card.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('SSH 인증 로그')) &&
            !rendered.includes('역할 정보 미확인'), 'CHECKLIST_VERIFIED_ROLE_LABEL_MISSING');
        }
      } else if (checklistState === 'CHECKLIST_STALE' || checklistState === 'CHECKLIST_TIMEOUT' ||
                 checklistState === 'CHECKLIST_RATE' || checklistState === 'CHECKLIST_UNAVAILABLE' ||
                 checklistState === 'CHECKLIST_NETWORK') {
        requireSafe(rendered.length > 0, 'CHECKLIST_FIXED_ERROR_NOT_RENDERED');
      } else {
        requireSafe(rendered.includes('안전 또는 비위험 판정이 아닙니다'), 'CHECKLIST_REFUSAL_SEMANTICS_FAILED');
        if (checklistState === 'CHECKLIST_REFUSED') {
          requireSafe(rendered.includes('신뢰된 내부 관찰에서 단일 역할을 확인할 수 없어 역할을 추측하지 않았습니다') &&
            rendered.includes('이는 낮은 위험이나 검토 불필요를 뜻하지 않습니다') &&
            rendered.includes('기존 분석 결과를 확인하세요'), 'CHECKLIST_UNKNOWN_ROLE_EXPLANATION_MISSING');
        }
      }
      requireSafe(await checklistPage.locator('#results').evaluate((node) => {
        const copy = node.cloneNode(true); copy.querySelectorAll('.investigation-checklist').forEach((item) => item.remove());
        copy.querySelectorAll('.workspace-checklist-evidence-36-6e').forEach((item) => item.replaceChildren());
        copy.querySelectorAll('.workspace-detail-header-36-6c .review-role-pending').forEach((item) => { item.textContent = 'ROLE_PRESENTATION'; });
        copy.querySelectorAll('.workspace-detail-header-36-6c .review-priority-pending').forEach((item) => { item.textContent = 'PRIORITY_PRESENTATION'; });
        return copy.innerText;
      }) === before, 'CHECKLIST_ANALYSIS_MUTATION');
      if (checklistState === 'CHECKLIST_REAL') {
        await checklistPage.evaluate(() => {
          const originalReplaceChildren = Element.prototype.replaceChildren;
          Element.prototype.replaceChildren = function (...nodes) {
            const result = originalReplaceChildren.apply(this, nodes);
            if (this.matches('.workspace-task-detail-36-6e') && !window.__checklistRenderFailureInjected) {
              window.__checklistRenderFailureInjected = true;
              throw new Error('SYNTHETIC_RENDER_FAILURE_CANARY');
            }
            return result;
          };
        });
        stateForPage = 'CHECKLIST_RENDER_EXCEPTION';
        currentScenario = 'CHECKLIST_RENDER_EXCEPTION';
        calls.length = 0;
        await control.click();
        await checklistPage.waitForFunction(() => document.querySelector('.workspace-checklist-status-36-6e')?.dataset.checklistState === 'error');
        const failedRender = await card.locator('.investigation-checklist').innerText();
        requireSafe(calls.length === 1 &&
          await card.locator('.workspace-checklist-status-36-6e').getAttribute('data-checklist-state') === 'error' &&
          failedRender.includes('점검표를 준비하지 못했습니다') &&
          await card.locator('.workspace-task-choice-36-6e').count() === 0 &&
          await card.locator('.workspace-checklist-evidence-36-6e .workspace-evidence-citation-36-6e').count() === 0 &&
          await card.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('역할 미확인')) &&
          await card.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('확인 순서 미정')) &&
          !failedRender.includes('SYNTHETIC_RENDER_FAILURE_CANARY'), 'CHECKLIST_RENDER_EXCEPTION_PARTIAL_UI_REMAINS');
        console.log('CHECKLIST_RENDER_EXCEPTION count=1 status=error partial_steps=0 role=unknown priority=undetermined');
        requireSafe(await checklistPage.locator('#results').evaluate((node) => {
          const copy = node.cloneNode(true); copy.querySelectorAll('.investigation-checklist').forEach((item) => item.remove());
          copy.querySelectorAll('.workspace-checklist-evidence-36-6e').forEach((item) => item.replaceChildren());
          copy.querySelectorAll('.workspace-detail-header-36-6c .review-role-pending').forEach((item) => { item.textContent = 'ROLE_PRESENTATION'; });
          copy.querySelectorAll('.workspace-detail-header-36-6c .review-priority-pending').forEach((item) => { item.textContent = 'PRIORITY_PRESENTATION'; });
          return copy.innerText;
        }) === before, 'CHECKLIST_RENDER_EXCEPTION_ANALYSIS_MUTATION');
      }
      for (const width of [320, 640, 1024, 1440]) {
        await checklistPage.setViewportSize({width, height: 900});
        requireSafe(await checklistPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
          'CHECKLIST_HORIZONTAL_OVERFLOW');
      }
      await checklistPage.setViewportSize({width: 640, height: 900});
      await checklistPage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
      requireSafe(await checklistPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'CHECKLIST_200_PERCENT_TEXT_OVERFLOW');
      await checklistPage.evaluate(() => { document.documentElement.style.fontSize = ''; });
      await scan(checklistPage, checklistState.toLowerCase());
      await checklistPage.close();
    }
    stateForPage = 'DISABLED';
    const reviewWorkspacePage = await context.newPage();
    await reviewWorkspacePage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await assertWorkspaceReflow(reviewWorkspacePage, 'WORKSPACE_START');
    await reviewWorkspacePage.evaluate(() => window.workspaceNavigation.setLegacyDetailForTests(true));
    await reviewWorkspacePage.locator('#sample-button').click();
    await reviewWorkspacePage.locator('#case-list .case-card').nth(1).waitFor({state: 'attached'});
    requireSafe(await reviewWorkspacePage.locator('#results-heading').textContent() === '분석 결과' &&
      await reviewWorkspacePage.locator('#results-dashboard.workspace-dashboard-36-6c').isVisible() &&
      await reviewWorkspacePage.locator('#summary-cards .workspace-summary-card-36-6c').count() === 4,
    'WORKSPACE_DASHBOARD_STRUCTURE_MISSING');
    if (UI1_SCREENSHOTS) {
      await reviewWorkspacePage.setViewportSize({width: 1440, height: 1000});
      await reviewWorkspacePage.screenshot({path: join(UI1_SCREENSHOTS, 'dashboard-1440.png'), fullPage: true});
    }
    const dashboardCounts = await reviewWorkspacePage.locator('#summary-cards .workspace-summary-card-36-6c').allTextContents();
    requireSafe(dashboardCounts.some((value) => value.includes('확인된 활동') && value.includes('5')) &&
      dashboardCounts.some((value) => value.includes('연결된 활동') && value.includes('3')) &&
      dashboardCounts.some((value) => value.includes('검토 건') && value.includes('2')) &&
      dashboardCounts.some((value) => value.includes('독립 관찰') && value.includes('4')) &&
      !dashboardCounts.some((value) => value.includes('추가 확인 필요')),
    'WORKSPACE_DASHBOARD_COUNTS_MISMATCH');
    requireSafe(await reviewWorkspacePage.locator('#independent-list .independent-card').count() === 4,
      'WORKSPACE_INDEPENDENT_OBSERVATION_AGGREGATE_MISMATCH');
    await assertWorkspaceReflow(reviewWorkspacePage, 'WORKSPACE_DASHBOARD');
    await reviewWorkspacePage.locator('#workspace-nav-details').evaluate((node) => { node.open = true; });
    const workspaceNavigationGeometry = [];
    for (const width of [1440, 1024, 768, 390, 320]) {
      await reviewWorkspacePage.setViewportSize({width, height: width === 768 ? 1024 : 844});
      await reviewWorkspacePage.waitForTimeout(50);
      if (!await reviewWorkspacePage.locator('#workspace-nav-details').evaluate((node) => node.open)) {
        await reviewWorkspacePage.locator('#workspace-nav-toggle').click();
      }
      const geometry = await reviewWorkspacePage.locator('#workspace-nav-toggle, .workspace-nav-list button').evaluateAll((nodes) =>
        nodes.filter((node) => {
          const rect = node.getBoundingClientRect();
          const style = getComputedStyle(node);
          return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden';
        }).map((node) => {
          const rect = node.getBoundingClientRect();
          return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
            width: rect.width, height: rect.height};
        }));
      const adjacentGapPx = geometry.slice(1).map((rect, index) => targetGapPx(geometry[index], rect));
      workspaceNavigationGeometry.push({width, geometry, adjacent_gap_px: adjacentGapPx});
      console.log(`WORKSPACE_PRIMARY_NAV_GEOMETRY ${JSON.stringify(workspaceNavigationGeometry.at(-1))}`);
      requireSafe(geometry.length > 1 && geometry.every((rect) => rect.width >= 44 && rect.height >= 44) &&
        adjacentGapPx.every((gap) => gap >= 8), 'WORKSPACE_PRIMARY_NAV_TARGET_GEOMETRY_FAILED');
    }
    console.log(`WORKSPACE_PRIMARY_NAV_GEOMETRY ${JSON.stringify(workspaceNavigationGeometry)}`);
    await reviewWorkspacePage.locator('#workspace-nav-toggle').click();
    requireSafe(!await reviewWorkspacePage.locator('#workspace-nav-details').evaluate((node) => node.open) &&
      !await reviewWorkspacePage.locator('#nav-results').isVisible(),
    'WORKSPACE_CLOSED_NAV_CONTENT_REMAINS_VISIBLE');
    await reviewWorkspacePage.locator('#workspace-nav-toggle').click();
    requireSafe(await reviewWorkspacePage.locator('#nav-results').isVisible(),
      'WORKSPACE_OPEN_NAV_CONTENT_MISSING');
    await reviewWorkspacePage.setViewportSize({width: 1280, height: 900});
    requireSafe(await reviewWorkspacePage.locator('#case-list').evaluate((node) =>
      getComputedStyle(node).gridTemplateColumns.split(' ').length === 1),
    'WORKSPACE_DASHBOARD_CASES_NOT_SINGLE_COLUMN');
    requireSafe(await reviewWorkspacePage.locator('#case-list .case-detail').count() === 0 &&
      await reviewWorkspacePage.locator('#case-list .timeline').count() === 0 &&
      await reviewWorkspacePage.locator('#case-list .checklist-result').count() === 0 &&
      await reviewWorkspacePage.locator('#case-list .progressive-knowledge, #case-list .technical-details, #case-list .investigation-checklist').count() === 0,
    'REVIEW_LIST_RENDERED_DETAIL');
    requireSafe(await reviewWorkspacePage.locator('#case-list-heading').isVisible() &&
      await reviewWorkspacePage.locator('#case-list-heading').textContent() === '검토 건',
      'REVIEW_LIST_HEADING_FAILED');
    requireSafe(await reviewWorkspacePage.locator('#case-list').getByRole('link', {name: '상세 분석 보기'}).count() === 2,
      'REVIEW_LIST_LINKS_FAILED');
    const caseCards = reviewWorkspacePage.locator('#case-list .review-case-card');
    for (let index = 0; index < await caseCards.count(); index += 1) {
      const card = caseCards.nth(index);
      const badges = card.locator('.review-status-badges .review-status-badge');
      requireSafe(await badges.count() === 3 &&
        (await badges.nth(0).textContent()).includes('위험도') &&
        (await badges.nth(1).textContent()).includes('확인 순서 미정') &&
        (await badges.nth(2).textContent()).includes('역할 미확인') &&
        !(await card.textContent()).includes('목록 위치'),
      'REVIEW_LIST_STATUS_HIERARCHY_FAILED');
      requireSafe(await card.locator('.review-card-facts').count() === 1 &&
        await card.locator('.review-card-facts').getByRole('time').count() >= 1,
      'REVIEW_LIST_FACTS_NOT_COMPACT_FAILED');
      requireSafe(await card.evaluate((node) => node.getBoundingClientRect().width >= 400),
        'REVIEW_LIST_CARD_WIDTH_FAILED');
      const spacing = await card.evaluate((node) => {
        const px = (value) => Number.parseFloat(value) || 0;
        const style = getComputedStyle(node);
        const badgesStyle = getComputedStyle(node.querySelector('.review-status-badges'));
        const factsStyle = getComputedStyle(node.querySelector('.review-card-facts'));
        const summary = node.querySelector('.review-card-summary');
        const summaryStyle = getComputedStyle(summary);
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        context.font = summaryStyle.font;
        const chWidth = context.measureText('0').width;
        const linkStyle = getComputedStyle(node.querySelector('.review-detail-link'));
        return {
          paddingInline: px(style.paddingLeft) + px(style.paddingRight),
          paddingBlock: px(style.paddingTop) + px(style.paddingBottom),
          rowGap: px(style.rowGap),
          badgeGap: px(badgesStyle.columnGap),
          lineHeightRatio: px(summaryStyle.lineHeight) / px(summaryStyle.fontSize),
          summaryMaxWidthCh: px(summaryStyle.maxWidth) / chWidth,
          lineClamp: summaryStyle.webkitLineClamp,
          summaryButtonGap: px(style.rowGap) + px(linkStyle.marginTop),
          cardGap: px(getComputedStyle(node.parentElement).columnGap),
        };
      });
      requireSafe(spacing.paddingInline >= 40 && spacing.paddingBlock >= 36 &&
        spacing.rowGap >= 12 && spacing.badgeGap >= 8 && spacing.lineHeightRatio >= 1.55 &&
        spacing.summaryMaxWidthCh >= 55 && spacing.summaryMaxWidthCh <= 65 && spacing.lineClamp === '2' &&
        spacing.summaryButtonGap >= 16 && spacing.cardGap >= 16,
      'REVIEW_CARD_SPACING_FAILED');
    }
    requireSafe(await reviewWorkspacePage.locator('#case-list').evaluate((node) =>
      Array.from(node.children).filter((child) => child.matches('.review-case-card')).length === 2 &&
      Array.from(node.children).filter((child) => child.matches('.review-case-card'))
        .every((child) => child.querySelector('.workspace-detail-header-36-6c, .timeline, .checklist-result') === null)),
    'WORKSPACE_LIST_DETAIL_DOM_DUPLICATION');
    await reviewWorkspacePage.setViewportSize({width: 320, height: 900});
    await reviewWorkspacePage.locator('.review-card-summary').first().evaluate((node) => {
      node.textContent = '합성 검수용 긴 한국어 문장입니다. 레이아웃이 줄바꿈과 두 줄 제한을 유지해야 합니다. '.repeat(8) +
        'Synthetic long English summary checks wrapping, clipping, and card boundaries. '.repeat(8);
    });
    await reviewWorkspacePage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    const zoomOverflow = await reviewWorkspacePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    const zoomCardSafe = await reviewWorkspacePage.locator('.review-case-card').first().evaluate((node) => {
        const card = getComputedStyle(node);
        const summary = node.querySelector('.review-card-summary');
        const summaryStyle = getComputedStyle(summary);
        return Number.parseFloat(card.paddingLeft) >= 20 && Number.parseFloat(card.paddingRight) >= 20 &&
          summaryStyle.webkitLineClamp === '2' && summary.scrollWidth <= summary.clientWidth;
      });
    requireSafe(zoomOverflow && zoomCardSafe, 'REVIEW_CARD_SMALL_ZOOM_REFLOW_FAILED');
    await reviewWorkspacePage.evaluate(() => { document.documentElement.style.fontSize = ''; });
    await reviewWorkspacePage.setViewportSize({width: 1280, height: 900});
    await reviewWorkspacePage.evaluate(() => {
      const firstLink = document.querySelector('#case-list a[data-review-case-ref]');
      const projection = window.workspaceNavigation.projectionForRef(firstLink?.dataset.reviewCaseRef);
      const firstSummary = document.querySelector('#case-list .review-card-summary');
      if (projection && firstSummary) firstSummary.textContent = projection.summary;
    });
    await scan(reviewWorkspacePage, 'review-list');
    for (const width of [1440, 1024, 768, 390, 320]) {
      await reviewWorkspacePage.setViewportSize({width, height: 900});
      requireSafe(await reviewWorkspacePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'REVIEW_LIST_HORIZONTAL_OVERFLOW');
    }
    await reviewWorkspacePage.setViewportSize({width: 1280, height: 900});
    const checklistCallsBeforeRoute = [];
    reviewWorkspacePage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/checklist')
        checklistCallsBeforeRoute.push(request);
    });
    const dashboardBeforeRoute = await reviewWorkspacePage.locator('#results-dashboard').textContent();
    const detailLink = reviewWorkspacePage.locator('#case-list').getByRole('link', {name: '상세 분석 보기'}).first();
    const targetMetrics = await detailLink.evaluate((link) => {
      const rect = link.getBoundingClientRect();
      const previous = link.previousElementSibling?.getBoundingClientRect();
      const card = link.closest('.review-case-card').getBoundingClientRect();
      return {width: rect.width, height: rect.height,
        gapAbove: previous ? rect.top - previous.bottom : 0,
        insideCard: rect.left >= card.left && rect.right <= card.right};
    });
    requireSafe(targetMetrics.width >= 44 && targetMetrics.height >= 44 && targetMetrics.gapAbove >= 8 &&
      targetMetrics.insideCard, 'REVIEW_DETAIL_LINK_TARGET_OR_SPACING_FAILED');
    await detailLink.focus();
    await reviewWorkspacePage.keyboard.press('Enter');
    await reviewWorkspacePage.getByRole('heading', {name: /검토 건 #1/}).waitFor({state: 'visible'});
    requireSafe(/^#\/investigations\/c_[0-9a-f]{24}$/.test(new URL(reviewWorkspacePage.url()).hash) &&
      await reviewWorkspacePage.locator('#case-detail-view .case-detail').count() === 1 &&
      await reviewWorkspacePage.locator('#case-list .case-detail').count() === 0 &&
      checklistCallsBeforeRoute.length === 0,
    'REVIEW_DETAIL_ROUTE_OR_OPT_IN_FAILED');
    await assertWorkspaceReflow(reviewWorkspacePage, 'REVIEW_DETAIL');
    requireSafe(await reviewWorkspacePage.evaluate(() => {
      const state = history.state;
      return Object.keys(state || {}).sort().join(',') === 'reviewWorkspaceDetail' &&
        JSON.stringify(state).length < 64 && !location.hash.includes('account') && !location.hash.includes('hostname');
    }), 'REVIEW_ROUTE_HISTORY_PRIVACY_FAILED');
    requireSafe(await reviewWorkspacePage.evaluate(() =>
      document.activeElement?.matches('#workspace-current-title')),
    'REVIEW_DETAIL_FOCUS_FAILED');
    requireSafe(await reviewWorkspacePage.evaluate(() => {
      const heading = document.activeElement;
      return heading && heading.matches('#workspace-current-title') &&
        (getComputedStyle(heading).outlineStyle !== 'none' || getComputedStyle(heading).boxShadow !== 'none');
    }), 'REVIEW_DETAIL_FOCUS_INDICATOR_MISSING');
    await scan(reviewWorkspacePage, 'review-detail');
    if (UI1_SCREENSHOTS) {
      await reviewWorkspacePage.setViewportSize({width: 1440, height: 1000});
      await reviewWorkspacePage.screenshot({path: join(UI1_SCREENSHOTS, 'case-detail-1440.png'), fullPage: true});
    }
    for (const width of [320, 640, 1024, 1440]) {
      await reviewWorkspacePage.setViewportSize({width, height: 900});
      requireSafe(await reviewWorkspacePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'REVIEW_DETAIL_HORIZONTAL_OVERFLOW');
    }
    await reviewWorkspacePage.setViewportSize({width: 640, height: 900});
    await reviewWorkspacePage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    requireSafe(await reviewWorkspacePage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      'REVIEW_DETAIL_200_PERCENT_REFLOW_FAILED');
    await reviewWorkspacePage.evaluate(() => { document.documentElement.style.fontSize = ''; });
    await reviewWorkspacePage.setViewportSize({width: 1280, height: 900});
    await reviewWorkspacePage.goBack();
    await reviewWorkspacePage.waitForFunction(() => location.hash === '');
    requireSafe(await reviewWorkspacePage.locator('#case-list').isVisible() &&
      await reviewWorkspacePage.evaluate(() => document.activeElement?.textContent?.includes('상세 분석 보기')) &&
      await reviewWorkspacePage.locator('#results-dashboard').textContent() === dashboardBeforeRoute &&
      checklistCallsBeforeRoute.length === 0,
    'REVIEW_BACK_FOCUS_OR_OPT_IN_FAILED');
    const reviewTransitionTimes = [];
    let reviewDomNodes = 0;
    let reviewHtmlBytes = 0;
    for (let iteration = 0; iteration < 40; iteration += 1) {
      const started = performance.now();
      await detailLink.click();
      await reviewWorkspacePage.getByRole('heading', {name: /검토 건 #1/}).waitFor({state: 'visible'});
      const detailStats = await reviewWorkspacePage.locator('#case-detail-view').evaluate((node) => ({
        nodes: node.querySelectorAll('*').length,
        bytes: new TextEncoder().encode(new XMLSerializer().serializeToString(node)).length,
      }));
      await reviewWorkspacePage.locator('#review-back-link').click();
      await reviewWorkspacePage.waitForFunction(() => location.hash === '');
      if (iteration >= 10) reviewTransitionTimes.push(performance.now() - started);
      reviewDomNodes = detailStats.nodes;
      reviewHtmlBytes = detailStats.bytes;
    }
    console.log(`REVIEW_WORKSPACE_BENCHMARK warmup=10 samples=30 transition_ms=${JSON.stringify(summarizeMs(reviewTransitionTimes))} detail_dom_nodes=${reviewDomNodes} detail_html_bytes=${reviewHtmlBytes}`);
    const expiredRoutePage = await context.newPage();
    const expiredChecklistCalls = [];
    expiredRoutePage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/checklist') expiredChecklistCalls.push(request);
    });
    await expiredRoutePage.goto(`${server.origin}/#/investigations/c_0123456789abcdef01234567`, {waitUntil: 'networkidle'});
    requireSafe(await expiredRoutePage.locator('#review-route-expired').isVisible() &&
      await expiredRoutePage.getByRole('button', {name: '분석 결과로 돌아가기'}).isVisible() &&
      expiredChecklistCalls.length === 0, 'REVIEW_EXPIRED_ROUTE_FALLBACK_FAILED');
    await scan(expiredRoutePage, 'review-route-expired');
    await expiredRoutePage.getByRole('button', {name: '분석 결과로 돌아가기'}).click();
    requireSafe(new URL(expiredRoutePage.url()).hash === '', 'REVIEW_EXPIRED_RETURN_FAILED');
    await expiredRoutePage.close();

    stateForPage = 'DISABLED';
    const projectionShellPage = reviewWorkspacePage;
    let shellChecklistCalls = 0;
    let shellAnalysisCalls = 0;
    let shellGuidanceCalls = 0;
    projectionShellPage.on('request', (request) => {
      const path = new URL(request.url()).pathname;
      if (path === '/api/v1/investigations/checklist') shellChecklistCalls += 1;
      if (path === '/api/v1/investigations/sample') shellAnalysisCalls += 1;
      if (path === '/api/v1/investigations/guidance') shellGuidanceCalls += 1;
    });
    await projectionShellPage.evaluate(() => window.workspaceNavigation.setLegacyDetailForTests(false));
    await projectionShellPage.locator('#case-list .review-case-card').nth(1).waitFor({state: 'attached'});
    requireSafe(await projectionShellPage.evaluate(async () => {
      const source = await fetch('/assets/app.js', {cache: 'no-store'}).then((response) => response.text());
      return source.includes('element("p", projection.summary, "review-card-summary")') &&
        source.includes('caseByRef.set(projection.case_ref, {item, index, projection,') &&
        source.includes('timeline: createWorkspaceTimelineProjection(item, projection, index)') &&
        source.includes('limitation_count: item.limitations.length') &&
        !source.includes('limitation_count: item.unverified_items.length');
    }), 'WORKSPACE_PROJECTION_SOURCE_NOT_SERVED');
    const firstProjection = await projectionShellPage.evaluate(() => {
      const ref = document.querySelector('#case-list a[data-review-case-ref]')?.dataset.reviewCaseRef;
      return window.workspaceNavigation.projectionForRef(ref);
    });
    requireSafe(await projectionShellPage.locator('#case-list a[data-review-case-ref]').evaluateAll((nodes) =>
      new Set(nodes.map((node) => node.dataset.reviewCaseRef)).size === nodes.length),
    'WORKSPACE_DUPLICATE_CASE_REF');
    requireSafe(firstProjection && firstProjection.schema_version === 'investigation-workspace-ui/v1' &&
      Object.keys(firstProjection).sort().join(',') === [
        'case_ref', 'category', 'checklist_status', 'display_order', 'display_title', 'limitation_count',
        'observation_count', 'relation_count', 'review_priority', 'risk_band', 'schema_version',
        'source_role', 'start_time_kst', 'start_time_utc', 'subject_alias', 'summary', 'task_count',
        'end_time_kst', 'end_time_utc'
      ].sort().join(',') && firstProjection.source_role === 'unknown' &&
      firstProjection.review_priority === 'undetermined' && firstProjection.checklist_status === 'not_requested',
    'WORKSPACE_CLOSED_PROJECTION_MISSING');
    requireSafe(!Object.hasOwn(firstProjection, 'unverified_items') &&
      !Object.hasOwn(firstProjection, 'additional_confirmation_count'),
    'WORKSPACE_LIMITATION_COUNT_SEMANTICS_FAILED');
    const projectionSnapshotContract = await projectionShellPage.evaluate(() => {
      const ref = document.querySelector('#case-list a[data-review-case-ref]')?.dataset.reviewCaseRef;
      const projection = window.workspaceNavigation.projectionForRef(ref);
      const card = document.querySelector('#case-list a[data-review-case-ref]')?.closest('.review-case-card');
      return {
        frozen: Object.isFrozen(projection), key_count: Object.keys(projection).length,
        stable_reference: projection === window.workspaceNavigation.projectionForRef(ref),
        card_reference_matches: card.querySelector('a[data-review-case-ref]')?.dataset.reviewCaseRef === ref,
        title_matches: card.querySelector('.review-card-title')?.textContent === projection.display_title,
        summary_matches: card.querySelector('.review-card-summary')?.textContent === projection.summary,
      };
    });
    console.log(`WORKSPACE_PROJECTION_CONTRACT ${JSON.stringify(projectionSnapshotContract)}`);
    requireSafe(projectionSnapshotContract.frozen && projectionSnapshotContract.key_count === 19 &&
      projectionSnapshotContract.stable_reference && projectionSnapshotContract.card_reference_matches &&
      projectionSnapshotContract.title_matches && projectionSnapshotContract.summary_matches,
    'WORKSPACE_PROJECTION_NOT_IMMUTABLE');
    requireSafe(await projectionShellPage.evaluate(() => {
      const ref = document.querySelector('#case-list a[data-review-case-ref]')?.dataset.reviewCaseRef;
      return window.workspaceNavigation.rejectProjectionMutationForTest(ref, {additions: {
        account: 'account-canary', ip: '192.0.2.44', hostname: 'host-canary',
        raw_log: 'raw-line-canary', input_path: '/private/input.log', output_path: '/private/output.html',
        credential: 'token-canary', internal_exception: 'exception-canary', other_case: 'other-case-canary'
      }});
    }), 'WORKSPACE_PROJECTION_CANARY_ACCEPTED');
    requireSafe(await projectionShellPage.evaluate(() => {
      const ref = document.querySelector('#case-list a[data-review-case-ref]')?.dataset.reviewCaseRef;
      return window.workspaceNavigation.rejectProjectionMutationForTest(ref, {remove_key: 'timeline'}) &&
        window.workspaceNavigation.rejectProjectionMutationForTest(ref, {overrides: {observation_count: true}});
    }), 'WORKSPACE_PROJECTION_MISSING_OR_TYPE_ACCEPTED');
    const firstRef = await projectionShellPage.locator('#case-list a[data-review-case-ref]').nth(0).getAttribute('data-review-case-ref');
    const secondRef = await projectionShellPage.locator('#case-list a[data-review-case-ref]').nth(1).getAttribute('data-review-case-ref');
    const secondProjection = await projectionShellPage.evaluate((ref) =>
      window.workspaceNavigation.projectionForRef(ref), secondRef);
    requireSafe(firstRef !== secondRef, 'WORKSPACE_CASE_REFS_NOT_DISTINCT');
    const analysisBeforeShellRoute = await projectionShellPage.evaluate(() => document.querySelector('#results-dashboard').textContent);
    await projectionShellPage.locator(`#review-case-link-0`).click();
    await projectionShellPage.getByRole('heading', {name: '검토 건 상세'}).waitFor({state: 'visible'});
    requireSafe(new URL(projectionShellPage.url()).hash === `#/investigations/${firstRef}` &&
      await projectionShellPage.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === firstRef &&
      await projectionShellPage.locator('#case-detail-view .case-detail').count() === 0 &&
      shellChecklistCalls === 0 && shellAnalysisCalls === 0 &&
      await projectionShellPage.locator('#results-dashboard').textContent() === analysisBeforeShellRoute,
    'WORKSPACE_SHELL_ROUTE_OR_INVARIANCE_FAILED');
    await projectionShellPage.locator('#review-back-link').focus();
    await projectionShellPage.keyboard.press('Tab');
    requireSafe(await projectionShellPage.evaluate(() => document.activeElement?.matches('#workspace-overview-tab-36-6d')),
      'WORKSPACE_KEYBOARD_TAB_ORDER_FAILED');
    await projectionShellPage.keyboard.press('Shift+Tab');
    requireSafe(await projectionShellPage.evaluate(() => document.activeElement?.matches('#review-back-link')),
      'WORKSPACE_KEYBOARD_REVERSE_TAB_ORDER_FAILED');
    await projectionShellPage.getByRole('tab', {name: '개요'}).focus();
    await projectionShellPage.keyboard.press('Space');
    requireSafe(await projectionShellPage.getByRole('tab', {name: '개요'}).getAttribute('aria-selected') === 'true' &&
      shellChecklistCalls === 0 && shellGuidanceCalls === 0,
    'WORKSPACE_KEYBOARD_SPACE_TAB_OR_AUTOMATIC_REQUEST_FAILED');
    const initialTimelineContract = await projectionShellPage.evaluate((ref) => {
      const tabs = [...document.querySelectorAll('[role="tab"]')].map((tab) => tab.textContent.trim());
      const list = document.querySelector('#workspace-timeline-panel-36-6d ol[aria-label="시간순 활동"]');
      const projection = window.workspaceNavigation.projectionForRef(ref);
      const timeline = window.workspaceNavigation.timelineForRef?.(ref);
      return {
        tabs,
        list_items: list ? [...list.children].map((item) => item.dataset.sequence) : [],
        initial_panel_hidden: document.querySelector('#workspace-timeline-panel-36-6d')?.hidden,
        projection_fields: projection ? Object.keys(projection).length : 0,
        timeline_frozen: Boolean(timeline && Object.isFrozen(timeline) && Object.isFrozen(timeline.items) &&
          timeline.items.every(Object.isFrozen)),
        timeline_case_matches: timeline?.case_ref === ref,
        kinds: timeline?.items.map((item) => item.kind) || [],
        rendered_sequences_match: list && timeline ?
          [...list.children].map((item) => item.dataset.sequence).join(',') ===
            timeline.items.map((item) => String(item.sequence)).join(',') : false,
        rendered_titles_match: list && timeline ?
          [...list.children].map((item) => item.querySelector('strong')?.textContent || '').join('|') ===
            timeline.items.map((item) => item.title).join('|') : false,
        safe_keys: timeline?.items.every((item) => Object.keys(item).sort().join(',') ===
          'datetime,description,end_datetime,end_timestamp_kst,kind,sequence,timestamp_kst,title') || false,
      };
    }, firstRef);
    console.log(`WORKSPACE_TIMELINE_INITIAL ${JSON.stringify(initialTimelineContract)}`);
    requireSafe(initialTimelineContract.tabs.includes('활동 흐름') &&
      initialTimelineContract.list_items.length > 0 && initialTimelineContract.timeline_frozen &&
      initialTimelineContract.initial_panel_hidden && initialTimelineContract.timeline_case_matches &&
      initialTimelineContract.rendered_sequences_match && initialTimelineContract.rendered_titles_match &&
      initialTimelineContract.safe_keys && initialTimelineContract.projection_fields === 19,
    'WORKSPACE_TIMELINE_VIEW_OR_CLOSED_ADAPTER_MISSING');
    requireSafe(initialTimelineContract.tabs.includes('확인할 작업') &&
      initialTimelineContract.tabs.includes('근거와 한계'),
    'WORKSPACE_TASKS_EVIDENCE_TABS_MISSING');
    const tasksTabContract = projectionShellPage.getByRole('tab', {name: '확인할 작업'});
    const evidenceTabContract = projectionShellPage.getByRole('tab', {name: '근거와 한계'});
    requireSafe(await projectionShellPage.locator('#workspace-tasks-panel-36-6e').isHidden() &&
      await projectionShellPage.locator('#workspace-evidence-panel-36-6e').isHidden(),
    'WORKSPACE_TASKS_EVIDENCE_PANEL_ARIA_MISSING');
    await tasksTabContract.click();
    requireSafe(await tasksTabContract.getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e').isVisible() &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-list-36-6e').count() === 0 &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .checklist-request').count() === 1 &&
      shellChecklistCalls === 0,
    'WORKSPACE_CHECKLIST_NOT_EXPLICIT_OR_PREMATURE_TASKS');
    stateForPage = 'CHECKLIST_AVAILABLE';
    const workspaceChecklistCalls = [];
    projectionShellPage.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/v1/investigations/checklist') workspaceChecklistCalls.push(request);
    });
    await projectionShellPage.locator('#workspace-tasks-panel-36-6e .checklist-request').evaluate((button) => {
      button.click(); button.click(); button.click();
    });
    await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-choice-36-6e').first().waitFor({state: 'visible'});
    requireSafe(workspaceChecklistCalls.length === 1 &&
      await workspaceChecklistCalls[0].method() === 'POST' &&
      JSON.stringify(workspaceChecklistCalls[0].postDataJSON()).includes(firstRef) &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-choice-36-6e').count() === 1 &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-detail-36-6e').isVisible() &&
      await projectionShellPage.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('우선 확인')) &&
      await projectionShellPage.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('애플리케이션 로그')) &&
      await projectionShellPage.locator('.workspace-detail-header-36-6c .risk-high').count() === 1,
    'WORKSPACE_CHECKLIST_MASTER_DETAIL_OR_VERIFIED_ROLE_FAILED');
    await projectionShellPage.locator('.workspace-task-choice-36-6e').first().focus();
    await projectionShellPage.keyboard.press('Enter');
    requireSafe(await projectionShellPage.locator('.workspace-task-choice-36-6e').first().getAttribute('aria-pressed') === 'true',
      'WORKSPACE_TASK_KEYBOARD_SELECTION_FAILED');
    requireSafe(workspaceChecklistCalls.length === 1, 'WORKSPACE_TASK_SELECTION_REQUESTED_NETWORK');
    await assertWorkspaceReflow(projectionShellPage, 'WORKSPACE_TASKS_AVAILABLE');
    await tasksTabContract.click();
    const taskTabViewportGeometry = [];
    for (const width of [1440, 1024, 768, 390, 320]) {
      await projectionShellPage.setViewportSize({width, height: 844});
      const layout = await projectionShellPage.evaluate(() => {
        const tablist = document.querySelector('.workspace-detail-tabs-36-6d');
        const style = getComputedStyle(tablist);
        const rects = [...tablist.querySelectorAll('[role="tab"]')].map((node) => {
          const rect = node.getBoundingClientRect();
          return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
            width: rect.width, height: rect.height};
        });
        return {overflow: document.documentElement.scrollWidth > innerWidth || tablist.scrollWidth > tablist.clientWidth,
          row_gap: style.rowGap, column_gap: style.columnGap, flex_wrap: style.flexWrap, font_size: style.fontSize, rects};
      });
      taskTabViewportGeometry.push({width, ...layout});
      requireSafe(!layout.overflow &&
        await projectionShellPage.locator('.workspace-task-master-detail-36-6e').evaluate((node) => node.scrollWidth <= node.clientWidth),
      'WORKSPACE_TASKS_RESPONSIVE_OVERFLOW');
      requireSafe(layout.rects.every((rect) => rect.width >= 44 && rect.height >= 44) &&
        layout.rects.slice(1).every((rect, index) => targetGapPx(layout.rects[index], rect) >= 8),
      'WORKSPACE_TASK_TAB_TARGET_GEOMETRY_OR_SPACING_FAILED');
    }
    console.log(`WORKSPACE_TASK_TAB_VIEWPORT_GEOMETRY ${JSON.stringify(taskTabViewportGeometry)}`);
    const taskTarget = await projectionShellPage.locator('.workspace-task-choice-36-6e').first().boundingBox();
    requireSafe(taskTarget && taskTarget.height >= 44, 'WORKSPACE_TASK_TARGET_BELOW_MINIMUM');
    const taskTargets = await projectionShellPage.evaluate(() => {
      const selectors = ['#workspace-tasks-tab-36-6e', '#workspace-evidence-tab-36-6e',
        '.workspace-checklist-request-36-6e', '.workspace-task-choice-36-6e',
        '.workspace-task-detail-36-6e summary'];
      return selectors.map((selector) => {
        const rect = document.querySelector(selector).getBoundingClientRect();
        return {selector, width: rect.width, height: rect.height, top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right};
      });
    });
    requireSafe(taskTargets.every((target) => target.width >= 44 && target.height >= 44),
      'WORKSPACE_TASK_FOCUS_TARGET_GEOMETRY_FAILED');
    requireSafe(targetGapPx(taskTargets[0], taskTargets[1]) >= 8,
      'WORKSPACE_TASK_TAB_TARGET_SPACING_FAILED');
    console.log(`WORKSPACE_TASK_TARGET_GEOMETRY ${JSON.stringify(taskTargets)}`);
    await projectionShellPage.setViewportSize({width: 320, height: 844});
    await projectionShellPage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    requireSafe(await projectionShellPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth) &&
      await projectionShellPage.locator('.workspace-task-master-detail-36-6e').evaluate((node) => node.scrollWidth <= node.clientWidth),
    'WORKSPACE_TASKS_200_PERCENT_REFLOW_FAILED');
    const zoomTabGeometry = await projectionShellPage.evaluate(() => {
      const tablist = document.querySelector('.workspace-detail-tabs-36-6d');
      const style = getComputedStyle(tablist);
      const rects = [...tablist.querySelectorAll('[role="tab"]')].map((node) => {
        const rect = node.getBoundingClientRect();
        return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
          width: rect.width, height: rect.height};
      });
      return {row_gap: style.rowGap, column_gap: style.columnGap, flex_wrap: style.flexWrap,
        font_size: style.fontSize, rects};
    });
    requireSafe(zoomTabGeometry.rects.every((rect) => rect.width >= 44 && rect.height >= 44) &&
      zoomTabGeometry.rects.slice(1).every((rect, index) => targetGapPx(zoomTabGeometry.rects[index], rect) >= 8),
    'WORKSPACE_TASK_TAB_200_PERCENT_TARGET_GEOMETRY_FAILED');
    console.log(`WORKSPACE_TASK_TAB_200_PERCENT_GEOMETRY ${JSON.stringify(zoomTabGeometry)}`);
    await projectionShellPage.evaluate(() => { document.documentElement.style.fontSize = ''; });
    await projectionShellPage.setViewportSize({width: 1280, height: 900});
    await scan(projectionShellPage, 'workspace-checklist-available');
    await evidenceTabContract.click();
    const meaningDisclosureSummary = projectionShellPage.locator('#workspace-evidence-panel-36-6e .workspace-evidence-disclosure-36-6e summary').first();
    await meaningDisclosureSummary.focus();
    await projectionShellPage.keyboard.press('Space');
    requireSafe(await meaningDisclosureSummary.evaluate((node) => node.parentElement.open) &&
      workspaceChecklistCalls.length === 1 && shellGuidanceCalls === 0,
    'WORKSPACE_EVIDENCE_DISCLOSURE_KEYBOARD_OR_REQUEST_FAILED');
    await projectionShellPage.keyboard.press('Space');
    requireSafe(!(await meaningDisclosureSummary.evaluate((node) => node.parentElement.open)),
      'WORKSPACE_EVIDENCE_DISCLOSURE_CLOSE_FAILED');
    const guidanceTargets = await projectionShellPage.evaluate(() =>
      ['.workspace-evidence-panel-36-6e .guidance-request', '.workspace-evidence-panel-36-6e select',
        '.workspace-evidence-panel-36-6e details summary'].map((selector) => {
        const rect = document.querySelector(selector).getBoundingClientRect();
        return {selector, width: rect.width, height: rect.height, left: rect.left, top: rect.top,
          right: rect.right, bottom: rect.bottom};
      }));
    console.log(`WORKSPACE_GUIDANCE_TARGET_GEOMETRY ${JSON.stringify(guidanceTargets)}`);
    requireSafe(guidanceTargets.every((target) => target.width >= 44 && target.height >= 44),
      'WORKSPACE_EVIDENCE_TARGET_GEOMETRY_FAILED');
    requireSafe(targetGapPx(guidanceTargets[0], guidanceTargets[1]) >= 8,
      'WORKSPACE_GUIDANCE_TARGET_SPACING_FAILED');
    console.log(`WORKSPACE_EVIDENCE_TARGET_GEOMETRY ${JSON.stringify(guidanceTargets)}`);
    requireSafe(await evidenceTabContract.getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-evidence-panel-36-6e').isVisible() &&
      (await projectionShellPage.locator('#workspace-evidence-panel-36-6e').innerText()).includes('일반 조사 참고자료') &&
      (await projectionShellPage.locator('#workspace-evidence-panel-36-6e').innerText()).includes('직접 증거가 아닙니다') &&
      await projectionShellPage.locator('#workspace-evidence-panel-36-6e').getByText(`분석 한계 ${firstProjection.limitation_count}개`).count() === 1 &&
      await projectionShellPage.locator('#workspace-evidence-panel-36-6e .workspace-evidence-citation-36-6e').count() === 1 &&
      await projectionShellPage.locator('#workspace-evidence-panel-36-6e .guidance-request').count() === 1 &&
      shellGuidanceCalls === 0,
    'WORKSPACE_EVIDENCE_REFERENCE_SEMANTICS_FAILED');
    await projectionShellPage.locator('#workspace-evidence-panel-36-6e .guidance-request').click();
    await projectionShellPage.locator('#workspace-evidence-panel-36-6e .guidance-citation').waitFor({state: 'visible'});
    requireSafe(shellGuidanceCalls === 1 && workspaceChecklistCalls.length === 1,
      'WORKSPACE_GUIDANCE_NOT_EXPLICIT_OR_MIXED');
    await assertWorkspaceReflow(projectionShellPage, 'WORKSPACE_EVIDENCE_GUIDANCE_AVAILABLE');
    requireSafe(await projectionShellPage.locator('#results-dashboard').textContent() === analysisBeforeShellRoute &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-choice-36-6e').count() === 1,
    'WORKSPACE_ANALYSIS_MUTATION_OR_GUIDANCE_CHECKLIST_MIX_FAILED');
    const workspaceTaskPanelStats = await projectionShellPage.locator('#workspace-tasks-panel-36-6e').evaluate((node) => ({
      steps: node.querySelectorAll('.workspace-task-choice-36-6e').length,
      dom_nodes: node.querySelectorAll('*').length,
      html_bytes: new TextEncoder().encode(new XMLSerializer().serializeToString(node)).byteLength,
    }));
    const checklistResponse = await workspaceChecklistCalls[0].response();
    const checklistResponseBytes = (await checklistResponse.body()).byteLength;
    const evidenceSwitchSamples = [];
    for (let sample = 0; sample < 110; sample += 1) {
      const elapsed = await projectionShellPage.evaluate(() => {
        const tasks = document.querySelector('#workspace-tasks-tab-36-6e');
        const evidence = document.querySelector('#workspace-evidence-tab-36-6e');
        const started = performance.now();
        tasks.click(); evidence.click();
        return performance.now() - started;
      });
      if (sample >= 10) evidenceSwitchSamples.push(elapsed);
    }
    console.log(`WORKSPACE_TASK_EVIDENCE_BENCHMARK warmup=10 samples=100 steps=${workspaceTaskPanelStats.steps} task_panel_nodes=${workspaceTaskPanelStats.dom_nodes} task_panel_html_bytes=${workspaceTaskPanelStats.html_bytes} checklist_response_bytes=${checklistResponseBytes} tasks_evidence_switch_ms=${JSON.stringify(summarizeMs(evidenceSwitchSamples))}`);
    await scan(projectionShellPage, 'workspace-tasks-evidence-available');
    const workspaceRequestCountsAfterExplicit = {checklist: shellChecklistCalls, guidance: shellGuidanceCalls};
    stateForPage = 'DISABLED';
    const timelineSafetyContract = await projectionShellPage.evaluate((ref) => {
      const timeline = window.workspaceNavigation.timelineForRef(ref);
      const projection = window.workspaceNavigation.projectionForRef(ref);
      const source = timeline.items.map((item) => item.sequence);
      const relations = timeline.items.filter((item) => item.kind === 'relation');
        const noTime = window.workspaceNavigation.timelineNoTimeForTest(ref);
        const noTimeRender = window.workspaceNavigation.timelineRenderForTest(ref, 1);
      const canaryRejected = window.workspaceNavigation.timelineCanaryRejectedForTest(ref, 'RAW-FACT-CANARY');
      const result = {
        schema: timeline.schema_version,
        total: timeline.items.length,
        expected_total: projection.observation_count + projection.relation_count,
        sequences: source,
        observation_count: timeline.items.filter((item) => item.kind !== 'relation').length,
        expected_observations: projection.observation_count,
        relations: relations.length,
        expected_relations: projection.relation_count,
        relation_copy_safe: relations.every((item) => item.description.includes('인과관계') &&
          !item.title.includes('→') && item.kind === 'relation'),
        no_time_safe: Boolean(noTime && noTime.timestamp_kst === null && noTime.datetime === null),
        no_time_rendered: Boolean(noTimeRender && noTimeRender.rendered_text.includes('시간 정보 없음')),
        canary_rejected: canaryRejected === true
      };
      return result;
    }, firstRef);
    console.log(`WORKSPACE_TIMELINE_SEMANTICS ${JSON.stringify(timelineSafetyContract)}`);
    requireSafe(timelineSafetyContract.schema === 'investigation-workspace-timeline-ui/v1' &&
      timelineSafetyContract.total === timelineSafetyContract.expected_total &&
      timelineSafetyContract.sequences.every((value, index) => value === index + 1) &&
      timelineSafetyContract.observation_count === timelineSafetyContract.expected_observations &&
      timelineSafetyContract.relations === timelineSafetyContract.expected_relations &&
      timelineSafetyContract.relation_copy_safe && timelineSafetyContract.no_time_safe &&
      timelineSafetyContract.no_time_rendered && timelineSafetyContract.canary_rejected,
    'WORKSPACE_TIMELINE_SEMANTICS_OR_PRIVACY_FAILED');
    requireSafe(await projectionShellPage.evaluate((ref) => {
      const api = window.workspaceNavigation;
      return api.rejectTimelineMutationForTest(ref, {index: 0, add_key: 'raw_log'}) &&
        api.rejectTimelineMutationForTest(ref, {index: 0, sequence: 2}) &&
        api.rejectTimelineMutationForTest(ref, {index: 0, category: 'UNKNOWN'}) &&
        api.rejectTimelineMutationForTest(ref, {index: 0, fact: 'RAW-LOG-CANARY'}) &&
        api.rejectTimelineMutationForTest(ref, {index: 0, utc: 'not-a-time'});
    }, firstRef), 'WORKSPACE_TIMELINE_INVALID_INPUT_ACCEPTED');
    const timelineTab = projectionShellPage.getByRole('tab', {name: '활동 흐름'});
    await timelineTab.click();
    requireSafe(await timelineTab.getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d').isVisible() &&
      await projectionShellPage.locator('#workspace-overview-panel-36-6d').isHidden() &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d ol > li').count() === initialTimelineContract.list_items.length &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d .workspace-timeline-relation-36-6d').count() === firstProjection.relation_count &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d li:not(.workspace-timeline-relation-36-6d)').count() === firstProjection.observation_count &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d').getByText('분석상 연결 · 인과관계 미확정').count() === firstProjection.relation_count &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d .workspace-timeline-relation-36-6d .workspace-timeline-event-card').count() === 0,
    'WORKSPACE_TIMELINE_TAB_OR_RELATION_RENDER_FAILED');
    requireSafe(await projectionShellPage.locator('#workspace-timeline-panel-36-6d time').evaluateAll((nodes) =>
      nodes.every((node) => Boolean(node.getAttribute('datetime')) && node.textContent.includes('KST'))),
    'WORKSPACE_TIMELINE_TIME_SEMANTICS_FAILED');
    requireSafe(await projectionShellPage.locator('#workspace-timeline-panel-36-6d').getByText('확인된 사실').count() > 0 &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d').getByText('탐지된 활동').count() > 0 &&
      await projectionShellPage.locator('[role="tab"][aria-controls="workspace-timeline-panel-36-6d"]').getAttribute('id') === 'workspace-timeline-tab-36-6d' &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d').getAttribute('aria-labelledby') === 'workspace-timeline-tab-36-6d',
    'WORKSPACE_TIMELINE_KIND_OR_ARIA_FAILED');
    await timelineTab.focus();
    await projectionShellPage.keyboard.press('ArrowLeft');
    requireSafe(await projectionShellPage.getByRole('tab', {name: '개요'}).getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-overview-panel-36-6d').isVisible(),
    'WORKSPACE_TIMELINE_KEYBOARD_LEFT_FAILED');
    await projectionShellPage.keyboard.press('ArrowRight');
    requireSafe(await timelineTab.getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d').isVisible(),
    'WORKSPACE_TIMELINE_KEYBOARD_RIGHT_FAILED');
    await projectionShellPage.keyboard.press('ArrowRight');
    requireSafe(await projectionShellPage.getByRole('tab', {name: '확인할 작업'}).getAttribute('aria-selected') === 'true' &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e').isVisible() &&
      shellChecklistCalls === workspaceRequestCountsAfterExplicit.checklist && shellAnalysisCalls === 0,
    'WORKSPACE_TIMELINE_KEYBOARD_RIGHT_OR_AUTOMATIC_REQUEST_FAILED');
    await projectionShellPage.keyboard.press('Home');
    requireSafe(await projectionShellPage.getByRole('tab', {name: '개요'}).getAttribute('aria-selected') === 'true',
      'WORKSPACE_TIMELINE_KEYBOARD_HOME_FAILED');
    await projectionShellPage.keyboard.press('ArrowRight');
    await assertWorkspaceReflow(projectionShellPage, 'WORKSPACE_TIMELINE');
    await scan(projectionShellPage, 'workspace-timeline');
    await evidenceTabContract.click();
    await projectionShellPage.keyboard.press('End');
    requireSafe(await evidenceTabContract.getAttribute('aria-selected') === 'true', 'WORKSPACE_TIMELINE_KEYBOARD_END_FAILED');
    await assertWorkspaceReflow(projectionShellPage, 'WORKSPACE_EVIDENCE');
    await scan(projectionShellPage, 'workspace-evidence');
    const timelinePanelMetrics = await projectionShellPage.locator('#workspace-timeline-panel-36-6d').evaluate((node) => ({
      items: node.querySelectorAll('.workspace-timeline-item-36-6d').length,
      nodes: node.querySelectorAll('*').length,
      html_bytes: new TextEncoder().encode(new XMLSerializer().serializeToString(node)).byteLength,
    }));
    const tabTransitionSamples = [];
    for (let sample = 0; sample < 110; sample += 1) {
      const elapsed = await projectionShellPage.evaluate(() => {
        const tablist = document.querySelector('.workspace-detail-tabs-36-6d');
        const started = performance.now();
        tablist.querySelector('#workspace-overview-tab-36-6d').click();
        tablist.querySelector('#workspace-timeline-tab-36-6d').click();
        return performance.now() - started;
      });
      if (sample >= 10) tabTransitionSamples.push(elapsed);
    }
    const timelineBenchmarks = [];
    for (const count of [1, 32, 256]) {
      for (let warmup = 0; warmup < 10; warmup += 1) {
        await projectionShellPage.evaluate(({ref, size}) => window.workspaceNavigation.timelineProjectionBatchForTest(ref, size),
          {ref: firstRef, size: count});
        await projectionShellPage.evaluate(({ref, size}) => window.workspaceNavigation.timelineRenderForTest(ref, size),
          {ref: firstRef, size: count});
      }
      const projectionTimes = [];
      const renderTimes = [];
      let projectionStats = null;
      let renderStats = null;
      for (let sample = 0; sample < 100; sample += 1) {
        projectionStats = await projectionShellPage.evaluate(({ref, size}) => {
          const started = performance.now();
          const result = window.workspaceNavigation.timelineProjectionBatchForTest(ref, size);
          return {elapsed: performance.now() - started, result};
        }, {ref: firstRef, size: count});
        renderStats = await projectionShellPage.evaluate(({ref, size}) => {
          const started = performance.now();
          const result = window.workspaceNavigation.timelineRenderForTest(ref, size);
          return {elapsed: performance.now() - started, result};
        }, {ref: firstRef, size: count});
        projectionTimes.push(projectionStats.elapsed);
        renderTimes.push(renderStats.elapsed);
      }
      timelineBenchmarks.push({count, projection: summarizeMs(projectionTimes),
        render: summarizeMs(renderTimes), input_bytes: projectionStats.result.input_bytes,
        adapter_output_bytes: projectionStats.result.output_bytes, rendered_dom_nodes: renderStats.result.dom_nodes,
        rendered_html_bytes: renderStats.result.html_bytes});
    }
    console.log(`WORKSPACE_TIMELINE_PANEL_SIZE ${JSON.stringify(timelinePanelMetrics)}`);
    console.log(`WORKSPACE_TIMELINE_TAB_TRANSITION ${JSON.stringify(summarizeMs(tabTransitionSamples))}`);
    console.log(`WORKSPACE_TIMELINE_BENCHMARK warmup=10 samples=100 batches=${JSON.stringify(timelineBenchmarks)}`);
    await projectionShellPage.emulateMedia({reducedMotion: 'reduce'});
    requireSafe(await projectionShellPage.locator('#workspace-timeline-panel-36-6d').evaluate((panel) => {
      const style = getComputedStyle(panel.querySelector('.workspace-timeline-item-36-6d'));
      return style.animationDuration === '0s' && style.transitionDuration === '0s';
    }), 'WORKSPACE_TIMELINE_REDUCED_MOTION_FAILED');
    await projectionShellPage.emulateMedia({reducedMotion: 'no-preference'});
    for (const width of [1440, 1024, 768, 390, 320]) {
      await projectionShellPage.setViewportSize({width, height: 844});
      requireSafe(await projectionShellPage.evaluate(() => {
        const panel = document.querySelector('#workspace-timeline-panel-36-6d');
        const rows = [...panel.querySelectorAll('.workspace-timeline-item-36-6d')];
        const rects = rows.map((row) => row.getBoundingClientRect());
        return document.documentElement.scrollWidth <= innerWidth && panel.scrollWidth <= panel.clientWidth &&
          rects.every((rect) => rect.left >= 0 && rect.right <= innerWidth) &&
          rects.every((rect, index) => index === 0 || rect.top >= rects[index - 1].bottom);
      }),
      'WORKSPACE_TIMELINE_RESPONSIVE_OVERFLOW');
      const tabRects = await projectionShellPage.locator('[role="tab"]').evaluateAll((nodes) =>
        nodes.map((node) => {
          const rect = node.getBoundingClientRect();
          return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom,
            width: rect.width, height: rect.height};
        }));
      requireSafe(tabRects.every((rect) => rect.width >= 44 && rect.height >= 44) &&
        tabRects.slice(1).every((rect, index) => targetGapPx(tabRects[index], rect) >= 8),
      'WORKSPACE_TIMELINE_TAB_TARGET_TOO_SMALL');
    }
    await projectionShellPage.setViewportSize({width: 640, height: 900});
    await projectionShellPage.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    requireSafe(await projectionShellPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth &&
      document.querySelector('#workspace-timeline-panel-36-6d').scrollWidth <=
      document.querySelector('#workspace-timeline-panel-36-6d').clientWidth),
    'WORKSPACE_TIMELINE_200_PERCENT_REFLOW_FAILED');
    await projectionShellPage.evaluate(() => { document.documentElement.style.fontSize = ''; });
    await projectionShellPage.setViewportSize({width: 1280, height: 900});
    await projectionShellPage.goBack();
    await projectionShellPage.waitForFunction(() => location.hash === '');
    await projectionShellPage.goForward();
    await projectionShellPage.waitForFunction((expected) => location.hash === `#/investigations/${expected}`, firstRef);
    requireSafe(await projectionShellPage.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === firstRef &&
      shellChecklistCalls === workspaceRequestCountsAfterExplicit.checklist && shellAnalysisCalls === 0, 'WORKSPACE_HISTORY_OR_AUTOMATIC_POST_FAILED');
    await projectionShellPage.locator('#review-back-link').click();
    await projectionShellPage.waitForFunction(() => location.hash === '');
    await projectionShellPage.evaluate(() => window.workspaceNavigation.setLegacyDetailForTests(true));
    await projectionShellPage.locator('#review-case-link-0').click();
    await projectionShellPage.locator('#case-detail-view .case-detail .timeline').waitFor({state: 'visible'});
    requireSafe(await projectionShellPage.locator('#case-detail-view .investigation-checklist button').count() === 1 &&
      shellChecklistCalls === workspaceRequestCountsAfterExplicit.checklist && shellAnalysisCalls === 0,
    'WORKSPACE_TIMELINE_ROLLBACK_RENDERER_FAILED');
    await projectionShellPage.locator('#review-back-link').click();
    await projectionShellPage.waitForFunction(() => location.hash === '');
    await projectionShellPage.evaluate(() => window.workspaceNavigation.setLegacyDetailForTests(false));
    await projectionShellPage.locator('#review-case-link-1').click();
    await projectionShellPage.getByRole('heading', {name: '검토 건 상세'}).waitFor({state: 'visible'});
    const secondTimeline = await projectionShellPage.evaluate((ref) => window.workspaceNavigation.timelineForRef(ref), secondRef);
    requireSafe(await projectionShellPage.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === secondRef &&
      await projectionShellPage.locator('.workspace-detail-shell-36-6b .workspace-overview-title').textContent() === secondProjection.display_title &&
      (await projectionShellPage.locator('.workspace-detail-shell-36-6b').textContent()).includes(`${secondProjection.observation_count}건`) &&
      !(await projectionShellPage.locator('.workspace-detail-shell-36-6b').textContent()).includes(firstRef) &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d .workspace-timeline-item-36-6d').count() === secondTimeline.items.length &&
      await projectionShellPage.locator('#workspace-timeline-panel-36-6d .workspace-timeline-title-36-6d').allTextContents().then((titles) =>
        titles.join('|') === secondTimeline.items.map((item) => item.title).join('|')) &&
      shellChecklistCalls === workspaceRequestCountsAfterExplicit.checklist &&
      shellGuidanceCalls === workspaceRequestCountsAfterExplicit.guidance && shellAnalysisCalls === 0, 'WORKSPACE_CASE_ISOLATION_FAILED');
    const projectionBenchmarks = [];
    for (const count of [1, 32, 256]) {
      for (let warmup = 0; warmup < 10; warmup += 1) {
        await projectionShellPage.evaluate((size) => window.workspaceNavigation.projectionBatchForTest(size), count);
      }
      const samples = [];
      let outputBytes = 0;
      let inputBytes = 0;
      for (let sample = 0; sample < 100; sample += 1) {
        const measured = await projectionShellPage.evaluate((size) => {
          const start = performance.now();
          const result = window.workspaceNavigation.projectionBatchForTest(size);
          return {elapsed: performance.now() - start, result};
        }, count);
        samples.push(measured.elapsed);
        outputBytes = new TextEncoder().encode(JSON.stringify(measured.result.projections)).byteLength;
        inputBytes = measured.result.input_bytes * count;
      }
      projectionBenchmarks.push({count, ...summarizeMs(samples), input_bytes: inputBytes, output_bytes: outputBytes});
    }
    const shellRouteTimes = [];
    for (let iteration = 0; iteration < 10; iteration += 1) {
      const started = performance.now();
      await projectionShellPage.locator('#review-back-link').click();
      await projectionShellPage.waitForFunction(() => location.hash === '');
      await projectionShellPage.locator('#review-case-link-0').click();
      await projectionShellPage.locator('.workspace-overview-36-6c').waitFor({state: 'visible'});
      const overviewContract = await projectionShellPage.locator('.workspace-detail-shell-36-6b').evaluate((node) => ({
        title: node.querySelector('.workspace-overview-title')?.textContent,
        labels: [...node.querySelector('.workspace-overview-metrics-36-6c').querySelectorAll('dt')].map((item) => item.textContent),
        values: [...node.querySelector('.workspace-overview-metrics-36-6c').querySelectorAll('dd')].map((item) => item.textContent),
        has_limitations: Boolean(node.querySelector('.workspace-overview-limit')),
        forbidden_panels: node.querySelectorAll('.timeline, .checklist-result, .progressive-knowledge').length,
        content: node.textContent,
      }));
      requireSafe(overviewContract.title === firstProjection.display_title &&
        overviewContract.labels.includes('확인된 활동') && overviewContract.labels.includes('연결 근거') &&
        overviewContract.labels.includes('분석 한계') && !overviewContract.labels.includes('추가 확인 필요') &&
        !overviewContract.labels.includes('확인할 작업') &&
        overviewContract.values.includes(`${firstProjection.observation_count}건`) &&
        overviewContract.values.includes(`${firstProjection.relation_count}건`) &&
        overviewContract.values.includes(`${firstProjection.limitation_count}개`) &&
        overviewContract.has_limitations && overviewContract.forbidden_panels === 0,
      'WORKSPACE_OVERVIEW_PANEL_CONTRACT_FAILED');
      requireSafe(!/추가 확인 필요\s*\d+/.test(overviewContract.content) &&
        !/확인할 작업\s*0/.test(overviewContract.content), 'WORKSPACE_OVERVIEW_INFERRED_COUNT_PRESENT');
      if (iteration >= 2) shellRouteTimes.push(performance.now() - started);
    }
    const shellDomNodes = await projectionShellPage.locator('#case-detail-view').evaluate((node) => node.querySelectorAll('*').length);
    const shellHtmlBytes = await projectionShellPage.locator('#case-detail-view').evaluate((node) =>
      new TextEncoder().encode(new XMLSerializer().serializeToString(node)).byteLength);
    const overviewStats = await projectionShellPage.evaluate(() => {
      const dashboard = document.querySelector('#results-dashboard');
      const detail = document.querySelector('#case-detail-view .workspace-detail-shell-36-6b');
      const assetBytes = performance.getEntriesByType('resource')
        .filter((entry) => /\/assets\/(?:app\.js|style\.css)$/.test(new URL(entry.name).pathname))
        .reduce((sum, entry) => sum + (entry.transferSize || entry.encodedBodySize || 0), 0);
      const bytes = (node) => new TextEncoder().encode(new XMLSerializer().serializeToString(node)).length;
      return {dashboard_nodes: dashboard.querySelectorAll('*').length, dashboard_html_bytes: bytes(dashboard),
        overview_nodes: detail.querySelectorAll('*').length, overview_html_bytes: bytes(detail), asset_bytes: assetBytes};
    });
    console.log(`WORKSPACE_36_6B_PROJECTION_BENCHMARK warmup=10 samples=100 batches=${JSON.stringify(projectionBenchmarks)}`);
    console.log(`WORKSPACE_36_6B_ROUTE_BENCHMARK warmup=2 samples=8 transition_ms=${JSON.stringify(summarizeMs(shellRouteTimes))} dom_nodes=${shellDomNodes} html_bytes=${shellHtmlBytes}`);
    console.log(`WORKSPACE_36_6C_DOM_SIZE ${JSON.stringify(overviewStats)}`);
    await scan(projectionShellPage, 'workspace-projection-shell');
    stateForPage = 'WORKSPACE_RACE';
    const raceResponsePending = projectionShellPage.waitForRequest((request) =>
      new URL(request.url()).pathname === '/api/v1/investigations/checklist');
    await projectionShellPage.getByRole('tab', {name: '확인할 작업'}).click();
    await projectionShellPage.locator('.workspace-checklist-request-36-6e').click();
    const raceRequest = await raceResponsePending;
    requireSafe(await projectionShellPage.locator('.workspace-checklist-status-36-6e').getAttribute('data-checklist-state') === 'loading',
      'WORKSPACE_CHECKLIST_LOADING_STATE_MISSING');
    const raceFirstRef = firstRef;
    const raceSecondRef = secondRef;
    await projectionShellPage.locator('#review-back-link').click();
    await projectionShellPage.waitForFunction(() => location.hash === '');
    await projectionShellPage.locator('#review-case-link-1').click();
    await projectionShellPage.getByRole('heading', {name: '검토 건 상세'}).waitFor({state: 'visible'});
    await projectionShellPage.waitForTimeout(400);
    requireSafe(raceRequest.postDataJSON().case_ref === raceFirstRef && raceFirstRef !== raceSecondRef &&
      shellChecklistCalls === workspaceRequestCountsAfterExplicit.checklist + 1 && shellAnalysisCalls === 0 &&
      await projectionShellPage.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === raceSecondRef &&
      await projectionShellPage.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('역할 미확인')) &&
      await projectionShellPage.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('확인 순서 미정')) &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .checklist-status').getAttribute('data-checklist-state') === 'not_requested' &&
      await projectionShellPage.locator('#workspace-tasks-panel-36-6e .workspace-task-choice-36-6e').count() === 0 &&
      !(await projectionShellPage.locator('#case-detail-view').textContent()).includes('합성 자료의 coverage를 확인하세요'),
    'WORKSPACE_CHECKLIST_ASYNC_CASE_ISOLATION_FAILED');
    await scan(projectionShellPage, 'workspace-checklist-race');
    await projectionShellPage.getByRole('tab', {name: '확인할 작업'}).click();
    const stateButton = projectionShellPage.locator('.workspace-checklist-request-36-6e');
    for (const [scenario, expected] of [
      ['CHECKLIST_REFUSED', 'refused'], ['CHECKLIST_STALE', 'stale'],
      ['CHECKLIST_TIMEOUT', 'error'], ['CHECKLIST_RATE', 'error'],
      ['CHECKLIST_UNAVAILABLE', 'unavailable'], ['CHECKLIST_MALFORMED', 'unavailable'],
      ['CHECKLIST_INVALID_CITATION', 'unavailable']
    ]) {
      stateForPage = scenario;
      await stateButton.click();
      await projectionShellPage.waitForFunction((state) =>
        document.querySelector('.workspace-checklist-status-36-6e')?.dataset.checklistState === state, expected);
      requireSafe(await projectionShellPage.locator('.workspace-task-choice-36-6e').count() === 0 &&
        await projectionShellPage.locator('.workspace-detail-header-36-6c .review-role-pending').textContent().then((text) => text.includes('역할 미확인')) &&
        await projectionShellPage.locator('.workspace-detail-header-36-6c .review-priority-pending').textContent().then((text) => text.includes('확인 순서 미정')) &&
        !(await projectionShellPage.locator('#case-detail-view').textContent()).includes('account-response-canary'),
      'WORKSPACE_CHECKLIST_FAILURE_STATE_PRIVACY_FAILED');
      if (scenario === 'CHECKLIST_REFUSED') requireSafe(
        (await projectionShellPage.locator('.workspace-checklist-status-36-6e').textContent()).includes('안전 판정이 아닙니다'),
        'WORKSPACE_CHECKLIST_REFUSAL_MEANING_FAILED');
      await scan(projectionShellPage, `workspace-checklist-${scenario.toLowerCase()}`);
      await assertWorkspaceReflow(projectionShellPage, `WORKSPACE_CHECKLIST_${scenario}`);
    }
    const workspaceRequestCountsAfterRace = {checklist: shellChecklistCalls, guidance: shellGuidanceCalls};
    stateForPage = 'DISABLED';
    await projectionShellPage.reload({waitUntil: 'networkidle'});
    requireSafe(await projectionShellPage.locator('#review-route-expired').isVisible() &&
      shellChecklistCalls === workspaceRequestCountsAfterRace.checklist && shellAnalysisCalls === 0,
    'WORKSPACE_DIRECT_ENTRY_DID_NOT_EXPIRE');
    await scan(projectionShellPage, 'workspace-direct-entry-expired');
    await projectionShellPage.close();

    stateForPage = 'MULTI';
    const pairPage = await context.newPage();
    await pairPage.addInitScript(eventSourceStub);
    await pairPage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await pairPage.locator('#nav-group-tools > summary').click();
    await pairPage.locator('#nav-live').waitFor({state: 'visible'});
    await pairPage.locator('#nav-live').click();
    requireSafe(await pairPage.locator('#live-monitoring').isVisible() &&
      await pairPage.locator('#pair-role-heading').textContent() === '애플리케이션 로그인 로그',
      'MULTI_SOURCE_ROLE_SCREEN_FAILED');
    await emit(pairPage, 'snapshot', pairStatus());
    const pairObservation = {schema_version: '3', event_id: eventId(1), session_id: SESSION,
      revision: 1, event_type: 'observation_changes', source_role: 'application', detection_revision: 1,
      analysis_revision: 1, created_count: 1, updated_count: 0, no_longer_matches_count: 0,
      active_observation_count: 1, published_observation_count: 1, observations: [{
        observation_id: 'LIVE-OBS-000001', observation_revision: 1, change_type: 'CREATED',
        state: 'ACTIVE', detection_type: 'brute_force', accumulator_revision: 1,
      }]};
    const focusBefore = await pairPage.evaluate(() => ({focus: document.activeElement.id, scroll: scrollY}));
    await emit(pairPage, 'observation_changes', pairObservation, eventId(1));
    requireSafe(await pairPage.locator('#pair-apply').isVisible() &&
      await pairPage.locator('#pair-observations li').count() === 0, 'MULTI_SOURCE_NOT_STAGED');
    const focusAfter = await pairPage.evaluate(() => ({focus: document.activeElement.id, scroll: scrollY}));
    requireSafe(focusBefore.focus === focusAfter.focus && focusBefore.scroll === focusAfter.scroll,
      'MULTI_SOURCE_FOCUS_SCROLL_CHANGED');
    await pairPage.locator('#pair-apply').click();
    requireSafe(await pairPage.locator('#pair-observations li').count() === 1,
      'MULTI_SOURCE_STAGED_APPLY_FAILED');
    await pairPage.locator('[data-pair-role="ssh"]').click();
    requireSafe(await pairPage.locator('#pair-role-heading').textContent() === 'SSH 인증 로그' &&
      await pairPage.locator('#pair-observations li').count() === 0, 'MULTI_SOURCE_ROLE_ISOLATION_FAILED');
    const roleSwitchTimes = [];
    const domApplyTimes = [];
    let uiPayloadBytes = 0;
    for (let n = 2; n <= 6; n++) {
      const targetRole = n % 2 === 0 ? 'application' : 'ssh';
      roleSwitchTimes.push(await pairPage.locator(`[data-pair-role="${targetRole}"]`).evaluate((button) => {
        const before = performance.now(); button.click(); return performance.now() - before;
      }));
      const id = eventId(n);
      const value = {...pairObservation, event_id: id, revision: n, source_role: targetRole,
        detection_revision: n, analysis_revision: n, observations: [{...pairObservation.observations[0],
          observation_revision: n, accumulator_revision: n, change_type: 'UPDATED'}]};
      uiPayloadBytes = new TextEncoder().encode(JSON.stringify(value)).length;
      domApplyTimes.push(await pairPage.evaluate(({value, id}) => {
        const before = performance.now();
        window.__syntheticStreams.at(-1).emit('observation_changes', value, id);
        document.querySelector('#pair-apply').click();
        return performance.now() - before;
      }, {value, id}));
    }
    await emit(pairPage, 'replay_gap', {schema_version: '3', code: 'EVICTED_EVENT_ID',
      affected_roles: ['application'], stale: true, recovery_action: 'refresh'});
    requireSafe(await pairPage.locator('#pair-recovery').isVisible(), 'MULTI_SOURCE_GAP_RECOVERY_FAILED');
    for (const width of [320, 640, 1024, 1440]) {
      await pairPage.setViewportSize({width, height: 900});
      requireSafe(await pairPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        'MULTI_SOURCE_HORIZONTAL_OVERFLOW');
    }
    await scan(pairPage, 'multi-source-live-empty');
    console.log(`schema3_role_switch ${JSON.stringify(summarizeMs(roleSwitchTimes))}`);
    console.log(`schema3_dom_apply ${JSON.stringify({...summarizeMs(domApplyTimes), payload_bytes: uiPayloadBytes})}`);
    await pairPage.close();
    requireSafe(externalRequests === 0, 'EXTERNAL_NETWORK_REQUEST');
    console.log(`states=${STATES.length + CHECKLIST_STATES.length + 1} external_requests=${externalRequests} elapsed_ms=${Math.round(performance.now() - start)}`);
  } finally {
    let cleanupFailed = false;
    for (const cleanup of [
      () => context?.close(),
      () => browser?.close(),
      () => server && stopServer(server.child, server.origin),
      () => rm(home, {recursive: true, force: true}),
    ]) {
      try { await cleanup(); }
      catch { cleanupFailed = true; }
    }
    requireSafe(!cleanupFailed, 'CLEANUP_FAILED');
  }
}

main().catch((error) => {
  const safe = /^([A-Z0-9_]+)$/.test(error.message) ? error.message : 'ACCESSIBILITY_PILOT_FAILED';
  const kind = /^[A-Za-z]+$/.test(error?.name || '') ? error.name : 'Error';
  const line = /ui_accessibility_axe_pilot_28_1\.mjs:(\d+):(\d+)/.exec(error?.stack || '');
  console.error(`${safe} scenario=${currentScenario} kind=${kind}${line ? ` line=${line[1]}` : ''}`);
  process.exitCode = 1;
});
