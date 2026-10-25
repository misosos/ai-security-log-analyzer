// Development-only browser checks. Print rule IDs/counts, never axe nodes or DOM text.
import AxeBuilder from '@axe-core/playwright';
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {performance} from 'node:perf_hooks';

const ROOT = resolve(import.meta.dirname, '..');
const SESSION = 'LIVE-SESSION-000001';
const eventId = (n) => `LIVE-EVENT-000001-${String(n).padStart(6, '0')}`;
const CANARY = ['synthetic', 'private', 'account', '28', '1'].join('-');
const STATES = [
  'base', 'live-empty', 'pending', 'applied', 'paused', 'no-longer-matches',
  'private-event-rejected', 'degraded', 'failed', 'replay-gap', 'checkpoint-reset-explanation',
  'three-file-error', 'linux-audit-error',
];

function requireSafe(condition, code) {
  if (!condition) throw new Error(code);
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
      title: Boolean(document.title.trim()), h1: document.querySelectorAll('h1').length,
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
  const hiddenExpected = ['base', 'guidance', 'applied', 'no-longer-matches', 'checkpoint-reset-explanation',
    'three-file-error', 'linux-audit-error'].includes(state);
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
  requireSafe(!summary.some((item) => item.impact === 'serious' || item.impact === 'critical'),
    'AXE_SERIOUS_OR_CRITICAL');
}

async function main() {
  const start = performance.now();
  const home = await mkdtemp(join(tmpdir(), 'ui-a11y-28-1-'));
  await mkdir(join(home, 'config'));
  let server;
  let browser;
  let context;
  let externalRequests = 0;
  let stateForPage = 'DISABLED';
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
      serviceWorkers: 'block', acceptDownloads: false,
      proxy: {server: 'http://127.0.0.1:9', bypass: '127.0.0.1,localhost'},
    });
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== server.origin) {
        externalRequests++;
        await route.abort();
      } else if (url.pathname === '/api/v1/live/status') {
        if (stateForPage === 'DISABLED') await route.continue();
        else await route.fulfill({status: 200, contentType: 'application/json',
          body: JSON.stringify(stateForPage === 'MULTI' ? pairStatus() : status(stateForPage))});
      } else if (url.pathname === '/api/v1/investigations/sample') {
        await route.continue();
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
      } else if (['/', '/assets/style.css', '/assets/app.js',
        '/assets/linux-audit.js', '/assets/live-monitoring.js',
        '/assets/multi-source-live.js'].includes(url.pathname)) {
        await route.continue();
      } else {
        throw new Error('UNEXPECTED_LOOPBACK_REQUEST');
      }
    });

    for (const stateName of STATES) {
      stateForPage = stateName === 'base' || stateName.includes('error') ||
        stateName === 'checkpoint-reset-explanation' ? 'DISABLED' :
        stateName === 'degraded' ? 'DEGRADED' : stateName === 'failed' ? 'FAILED' : 'RUNNING';
      const page = await context.newPage();
      await page.addInitScript(eventSourceStub);
      await page.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
      if (stateForPage !== 'DISABLED') {
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
        await page.locator('#nav-local').focus();
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('#local-upload').isVisible() &&
          await page.locator('#nav-local').getAttribute('aria-current') === 'page' &&
          await page.locator('.workspace-panel:visible').count() === 1,
          'WORKSPACE_KEYBOARD_NAV_FAILED');
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
        await page.locator('#nav-audit').click();
        await page.locator('#linux-audit-form').evaluate((form) => form.requestSubmit());
        requireSafe(await page.locator('#linux-audit-error').isVisible() &&
          await page.locator('#linux-audit-file').getAttribute('aria-invalid') === 'true' &&
          await page.locator('#linux-audit-field-error').isVisible(), 'LINUX_ERROR_LINK_FAILED');
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
    const guidancePage = await context.newPage();
    await guidancePage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
    await guidancePage.locator('#sample-button').click();
    await guidancePage.locator('.guidance-request').first().waitFor({state: 'attached'});
    requireSafe(await guidancePage.locator('.guidance-request').count() === 2,
      'GUIDANCE_CASE_CONTROLS_MISSING');
    const guidanceCard = guidancePage.locator('#case-list .case-card').first();
    await guidanceCard.locator(':scope > summary').focus();
    await guidancePage.keyboard.press('Enter');
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
    for (const width of [320, 640, 1024, 1440]) {
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
    const realGuidanceCard = realGuidancePage.locator('#case-list .case-card').first();
    await realGuidanceCard.locator(':scope > summary').focus();
    await realGuidancePage.keyboard.press('Enter');
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
    stateForPage = 'MULTI';
    const pairPage = await context.newPage();
    await pairPage.addInitScript(eventSourceStub);
    await pairPage.goto(`${server.origin}/`, {waitUntil: 'networkidle'});
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
    console.log(`states=${STATES.length + 1} external_requests=${externalRequests} elapsed_ms=${Math.round(performance.now() - start)}`);
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
  console.error(safe);
  process.exitCode = 1;
});
