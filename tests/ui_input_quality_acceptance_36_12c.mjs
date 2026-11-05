import { chromium } from '@playwright/test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = process.cwd();
const scenario = process.argv[2] || 'file-complete';
const width = Number(process.argv[3] || 1440);
const reflow200 = process.argv[4] === '200';
const origin = process.env.INPUT_QUALITY_REVIEW_ORIGIN || 'http://127.0.0.1:18765';
const externalRequests = [];
const pageErrors = [];
const consoleErrors = [];
const consoleCategories = [];
const httpErrorCategories = [];
let context;
let reviewPage;
let tempRoot;
let stage = 'setup';
let observedApiStatus = null;
let observedErrorCode = null;
let qualityDiagnostics = [];
let cspHeader = null;
let keyboardDisclosureVerified = false;
let focusVisibleVerified = false;
let layoutDiagnostics = null;

const reasons = () => ({unsupported_format: 0, invalid_timestamp: 0, invalid_address: 0,
  invalid_port: 0, invalid_header: 0, incomplete_record: 0, blank_line: 0,
  ignored_record: 0, other_rejected: 0});
const limits = ['INPUT_RECORD_RECOGNITION_ONLY', 'NOT_COLLECTION_COMPLETENESS_OR_DETECTION_ACCURACY'];
function summary(source, total, recognized, unrecognized, status, reasonOverrides = {}) {
  const reasonCounts = {...reasons(), ...reasonOverrides};
  return {schema_version: '1', source, total_lines: total, nonempty_lines: total,
    recognized_lines: recognized, unrecognized_lines: unrecognized, ignored_lines: 0,
    recognition_status: status, reason_counts: reasonCounts, limitations: limits};
}
function fileFixture() {
  const bySource = [summary('application', 5, 5, 0, 'complete'),
    summary('ssh', 2, 1, 1, 'partial', {incomplete_record: 1}),
    summary('access', 1, 0, 1, 'none', {unsupported_format: 1})];
  const aggregate = summary('aggregate', 8, 6, 2, 'partial',
    {incomplete_record: 1, unsupported_format: 1});
  return {schema_version: '1', by_source: bySource, aggregate};
}
function textFixture(status) {
  if (status === 'partial') return {schema_version: '1',
    by_source: [summary('application', 2, 1, 1, 'partial', {unsupported_format: 1})],
    aggregate: summary('aggregate', 2, 1, 1, 'partial', {unsupported_format: 1})};
  if (status === 'none') return {schema_version: '1',
    by_source: [summary('application', 1, 0, 1, 'none', {unsupported_format: 1})],
    aggregate: summary('aggregate', 1, 0, 1, 'none', {unsupported_format: 1})};
  if (status === 'empty') return {schema_version: '1',
    by_source: [summary('application', 0, 0, 0, 'empty')],
    aggregate: summary('aggregate', 0, 0, 0, 'empty')};
  return null;
}
function completeFixture() {
  const bySource = [summary('application', 5, 5, 0, 'complete'),
    summary('ssh', 2, 2, 0, 'complete'), summary('access', 1, 1, 0, 'complete')];
  return {schema_version: '1', by_source: bySource,
    aggregate: summary('aggregate', 8, 8, 0, 'complete')};
}

const appLog = (await readFile(join(root, 'sample_logs', 'brute_force.log'), 'utf8'))
  .replaceAll('alice', 'synthetic_user_a').replaceAll('admin', 'synthetic_user_b')
  .replaceAll('bob', 'synthetic_user_c').replaceAll('guest', 'synthetic_user_d')
  .replaceAll('192.168.1.10', '192.0.2.10').replaceAll('192.168.1.20', '192.0.2.20')
  .replaceAll('192.168.1.30', '192.0.2.30').replaceAll('192.168.1.40', '192.0.2.40');
const sshLog = '2026-11-01 10:31:00 sshd[1234]: Failed password for synthetic_ssh from 198.51.100.10 port 54321 ssh2';
const accessLog = '192.0.2.20 - - [01/Nov/2026:10:32:00 +0000] "GET / HTTP/1.1" 200 42 "-" "SyntheticBrowser/1.0"';
const files = {application_file: appLog, ssh_file: sshLog, access_file: accessLog};
const canary = 'QA_CANARY_36_12C_PRIVATE';
const liveStatusFixture = {
  schema_version: '2', service_state: 'STOPPED', session_id: 'LIVE-SESSION-123456',
  source_role: 'ssh', worker_state: 'STOPPED', publication_state: 'CLOSED',
  latest_detection_revision: 0, available_event_count: 0, earliest_event_id: null,
  latest_event_id: null, active_observation_count: 0, published_total: 0, evicted_total: 0,
  replay_gap_total: 0, max_event_items: 32, max_event_bytes: 16384, max_connections: 2,
  active_connections: 0, fixed_error_code: null, recovery_action: null,
  interpretation_notices: [
    '규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.',
    '지연 또는 replay gap이 있을 수 있으며 무유실·즉시 처리를 보장하지 않습니다.'
  ], capabilities: ['READ_ONLY_STATUS', 'BOUNDED_SSE_REPLAY', 'AUTOMATIC_POLLING', 'NO_LLM'],
  analysis_available: true, analysis_revision: 0, active_relation_count: 0,
  active_risk_count: 0, active_case_count: 0, analysis_state: 'AVAILABLE'
};

function applyTestLabel(page) {
  const testOnly = ['file-mixed', 'file-disclosure', 'text-partial', 'text-empty', 'text-none-fixture', 'legacy'].includes(scenario);
  return page.evaluate((testOnly) => {
    const label = document.createElement('aside');
    label.id = 'acceptance-synthetic-label';
    label.className = 'sample-notice';
    label.textContent = testOnly ?
      'TEST_ONLY_SYNTHETIC_STATE — 품질 요약은 사용자 이해도 검수용 합성 fixture입니다. 실제 API 상태가 아닙니다.' :
      '합성 입력 검수 — 화면의 고정 시각과 로그 내용은 실제 사용자 자료가 아닙니다.';
    document.body.prepend(label);
  }, testOnly);
}

async function prepareLocal(page) {
  stage = 'open_production_page';
  await page.goto(origin, {waitUntil: 'networkidle'});
  const navigation = page.locator('#workspace-nav-toggle');
  if (await navigation.count() && !(await navigation.evaluate((node) => node.parentElement.open)))
    await navigation.click();
  stage = 'open_local_workspace';
  await page.locator('#nav-local').click();
  const details = page.locator('#local-choice-details');
  if (!(await details.evaluate((node) => node.open))) await details.locator('summary').click();
}

async function submitFiles(page, fixture = false) {
  await prepareLocal(page);
  stage = 'select_synthetic_files';
  for (const [field, content] of Object.entries(files)) {
    await page.locator(`#${field.replace('_', '-')}`).setInputFiles({name: 'synthetic.txt',
      mimeType: 'text/plain', buffer: Buffer.from(content)});
  }
  await page.locator('#local-button').click();
  stage = 'file_analysis_response';
  await page.waitForFunction(() => !document.querySelector('#local-button').disabled);
}

async function submitText(page, value) {
  await prepareLocal(page);
  stage = 'prepare_synthetic_text';
  if (!(await page.locator('#input-mode-text').isChecked())) await page.locator('#input-mode-text').check();
  await page.locator('#text-source input[value="application"]').check();
  await page.locator('#log-text').fill(value);
  await page.locator('#local-button').click();
  stage = 'text_analysis_response';
  await page.waitForFunction(() => !document.querySelector('#local-button').disabled);
}

async function benchmarkRenderer(page) {
  return page.evaluate(({complete, partial, none}) => {
    const host = document.createElement('div');
    host.hidden = true;
    document.body.append(host);
    const projections = [
      ['file_3source_complete', complete, null],
      ['file_3source_partial', partial, null],
      ['text_none', none, 'application'],
      ['reason_disclosure_open', partial, null]
    ];
    const report = projections.map(([name, projection, source]) => {
      const samples = [];
      for (let index = 0; index < 15; index += 1) {
        const start = performance.now();
        window.inputQualityUi36_12b.render(host, projection, source);
        if (name === 'reason_disclosure_open') {
          const disclosure = host.querySelector('details');
          if (disclosure) disclosure.open = true;
        }
        const elapsed = performance.now() - start;
        if (index >= 5) samples.push(elapsed);
      }
      const sorted = [...samples].sort((left, right) => left - right);
      return {state: name, warmup_samples: 5, samples: samples.length,
        render_ms_median: Number(sorted[Math.floor(sorted.length * 0.5)].toFixed(3)),
        render_ms_p95: Number(sorted[Math.ceil(sorted.length * 0.95) - 1].toFixed(3)),
        render_ms_max: Number(Math.max(...samples).toFixed(3)),
        dom_nodes: host.querySelectorAll('*').length,
        serialized_html_bytes: new TextEncoder().encode(host.outerHTML).length,
        viewport_css_px: {width: innerWidth, height: innerHeight}};
    });
    host.remove();
    return report;
  }, {complete: completeFixture(), partial: fileFixture(),
    none: {schema_version: '1', by_source: [summary('application', 1, 0, 1, 'none', {unsupported_format: 1})],
      aggregate: summary('aggregate', 1, 0, 1, 'none', {unsupported_format: 1})}});
}

async function main() {
  stage = 'start_isolated_chromium';
  tempRoot = await mkdtemp(join(tmpdir(), 'phase-36-12c-browser-'));
  context = await chromium.launchPersistentContext(join(tempRoot, 'profile'), {
    headless: true, viewport: {width, height: 900}, serviceWorkers: 'block',
    args: ['--disable-background-networking', '--no-first-run']
  });
  await context.route('**/*', async (route) => {
    const requestUrl = new URL(route.request().url());
    const requestOrigin = requestUrl.origin;
    if (requestOrigin !== origin) {
      externalRequests.push('blocked');
      await route.abort();
      return;
    }
    if (requestUrl.pathname === '/api/v1/live/status') {
      await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(liveStatusFixture)});
      return;
    }
    if (reflow200 && requestUrl.pathname === '/assets/style.css') {
      const response = await route.fetch();
      const stylesheet = await response.text();
      await route.fulfill({response, contentType: 'text/css',
        body: `${stylesheet}\n#acceptance-synthetic-label{overflow-wrap:anywhere}`});
      return;
    }
    await route.continue();
  });
  const fixtures = [];
  if (['file-mixed', 'file-disclosure'].includes(scenario))
    fixtures.push(['/api/v1/investigations', fileFixture()]);
  if (scenario === 'text-partial' || scenario === 'text-empty')
    fixtures.push(['/api/v1/investigations/text', textFixture(scenario === 'text-partial' ? 'partial' : 'empty')]);
  if (scenario === 'text-none-fixture')
    fixtures.push(['/api/v1/investigations/text', textFixture('none')]);
  for (const [path, projection] of fixtures) {
    if (!projection) continue;
    await context.route(`${origin}${path}`, async (route) => {
      try {
        const upstream = await route.fetch();
        const payload = await upstream.json();
        if (payload.result && path.endsWith('/text')) payload.result.input_quality = projection;
        else payload.input_quality = projection;
        await route.fulfill({response: upstream, body: JSON.stringify(payload)});
      } catch {
        await route.abort().catch(() => {});
      }
    });
  }
  if (scenario === 'legacy') {
    await context.route(`${origin}/api/v1/investigations/text`, async (route) => {
      try {
        const upstream = await route.fetch();
        const payload = await upstream.json();
        if (payload.result) delete payload.result.input_quality;
        await route.fulfill({response: upstream, body: JSON.stringify(payload)});
      } catch {
        await route.abort().catch(() => {});
      }
    });
  }
  const page = reviewPage = await context.newPage();
  page.on('pageerror', () => pageErrors.push('pageerror'));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    consoleErrors.push('console_error');
    const text = message.text();
    consoleCategories.push(/content security policy/i.test(text) ? 'csp' :
      /failed to load resource|404/i.test(text) ? 'resource' :
      /net::err_|blocked/i.test(text) ? 'network' : 'other');
  });
  page.on('response', async (response) => {
    if (response.status() >= 400) {
      const path = new URL(response.url()).pathname;
      httpErrorCategories.push(path === '/favicon.ico' ? 'favicon' :
        path === '/api/v1/live/status' ? 'live_status' : path === '/api/v1/live/events' ? 'live_events' :
        path.endsWith('/investigations') || path.endsWith('/investigations/text') ? 'analysis' :
        path.endsWith('/guidance') ? 'guidance' : path.endsWith('/checklist') ? 'checklist' :
        path.endsWith('/sample') ? 'sample' : path.endsWith('/health') ? 'health' :
        path.startsWith('/api/') ? 'other_api' : path.startsWith('/assets/') ? 'asset' : 'other');
    }
    if (new URL(response.url()).pathname === '/')
      cspHeader = await response.headerValue('content-security-policy');
    if (!response.url().includes('/api/v1/investigations')) return;
    if (!['/api/v1/investigations', '/api/v1/investigations/text'].includes(new URL(response.url()).pathname)) return;
    observedApiStatus = response.status();
    if (!response.ok()) {
      try { observedErrorCode = (await response.json()).error_code || 'UNKNOWN_API_ERROR'; }
      catch { observedErrorCode = 'MALFORMED_API_ERROR'; }
    }
  });
  await page.setViewportSize({width, height: 900});

  if (scenario.startsWith('file-')) {
    const useFixture = ['file-mixed', 'file-disclosure'].includes(scenario);
    await submitFiles(page, useFixture);
    if (scenario === 'file-disclosure') {
      stage = 'open_reason_disclosure';
      const disclosureSummary = page.locator('#input-quality-summary-36-12b details summary').first();
      await disclosureSummary.focus();
      await page.keyboard.press('Space');
      keyboardDisclosureVerified = await page.locator('#input-quality-summary-36-12b details').first()
        .evaluate((node) => node.open);
      focusVisibleVerified = await disclosureSummary.evaluate((node) => node.matches(':focus-visible'));
      if (!keyboardDisclosureVerified || !focusVisibleVerified)
        throw Object.assign(new Error(), {code: 'KEYBOARD_DISCLOSURE_OR_FOCUS'});
    }
  } else if (scenario === 'text-complete') {
    await submitText(page, appLog.split('\n')[0]);
  } else if (scenario === 'text-partial') {
    await submitText(page, appLog.split('\n')[0]);
  } else if (scenario === 'text-none-fixture') {
    await submitText(page, appLog.split('\n')[0]);
  } else if (scenario === 'text-none') {
    await submitText(page, `UNSUPPORTED_${canary}`);
    await page.locator('#error-summary').waitFor({state: 'visible'});
  } else if (scenario === 'text-empty') {
    await submitText(page, appLog.split('\n')[0]);
  } else if (scenario === 'legacy') {
    await submitText(page, appLog.split('\n')[0]);
  } else if (scenario === 'parser-incompatible') {
    await prepareLocal(page);
    if (!(await page.locator('#input-mode-text').isChecked())) await page.locator('#input-mode-text').check();
    await page.locator('#text-source input[value="access"]').check();
    await page.locator('#log-text').fill(`UNSUPPORTED_${canary}`);
    await page.locator('#local-button').click();
    await page.locator('#error-summary').waitFor({state: 'visible'});
  } else {
    throw Object.assign(new Error(), {code: 'UNKNOWN_SCENARIO'});
  }

  stage = 'validate_rendered_state';
  if (reflow200) await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  const errorVisible = await page.locator('#error-summary').isVisible().catch(() => false);
  const summarySelector = errorVisible ? '#error-input-quality-36-12b' : '#input-quality-summary-36-12b';
  qualityDiagnostics = await page.evaluate(() => [...document.querySelectorAll('#input-quality-summary-36-12b, #error-input-quality-36-12b')].map((container) => ({
    id: container.id, hidden: container.hidden, children: container.childElementCount,
    status_present: Boolean(container.querySelector('#input-quality-status-36-12b')),
    status_text: container.querySelector('#input-quality-status-36-12b')?.textContent?.slice(0, 36) || ''
  })));
  const status = qualityDiagnostics.find((item) => item.id === summarySelector.slice(1) && !item.hidden)?.status_text || '';
  if (scenario === 'file-mixed' || scenario === 'file-disclosure') {
    const sourceText = await page.locator(summarySelector).innerText();
    if (!['애플리케이션 로그', 'SSH 인증 로그', '웹 접근 로그'].every((label) => sourceText.includes(label)))
      throw Object.assign(new Error(), {code: 'FILE_SOURCE_LABELS'});
  }
  if (scenario !== 'legacy' && !status) throw Object.assign(new Error(), {code: observedErrorCode === 'PARSER_INCOMPATIBLE' ? 'UNEXPECTED_PARSER_INCOMPATIBLE' : 'QUALITY_STATUS_MISSING'});
  await applyTestLabel(page);

  const visibleText = await page.locator('body').innerText();
  const forbidden = ['synthetic_admin', 'synthetic_ssh', '192.0.2.10', '198.51.100.10',
    'SyntheticBrowser', 'synthetic.txt', canary, 'QA_CANARY_36_12C_PRIVATE', 'synthetic_user_a',
    'synthetic_user_b', 'synthetic_user_c', 'synthetic_user_d'];
  if (forbidden.some((value) => visibleText.includes(value)) || /192\.168\.1\.|10\.0\.0\./.test(visibleText))
    throw Object.assign(new Error(), {code: 'PRIVATE_VALUE_VISIBLE'});
  const ariaText = await page.locator('body').evaluate((body) => [...body.querySelectorAll('*')]
    .map((node) => [node.getAttribute('aria-label'), node.getAttribute('title'), node.getAttribute('data-testid')].join(' ')).join('\n'));
  if (forbidden.some((value) => ariaText.includes(value)) || /192\.168\.1\.|10\.0\.0\./.test(ariaText))
    throw Object.assign(new Error(), {code: 'PRIVATE_ATTRIBUTE_VISIBLE'});
  if (!cspHeader || !cspHeader.includes("script-src 'self'")) throw Object.assign(new Error(), {code: 'CSP_MISSING'});
  const expectedParserErrorResource = ['parser-incompatible', 'text-none'].includes(scenario) &&
    observedApiStatus === 400 && observedErrorCode === 'PARSER_INCOMPATIBLE' &&
    consoleErrors.length === 1 && consoleCategories[0] === 'resource' &&
    httpErrorCategories.length === 1 && httpErrorCategories[0] === 'analysis';
  if (externalRequests.length || pageErrors.length ||
      (consoleErrors.length && !expectedParserErrorResource))
    throw Object.assign(new Error(), {code: 'BROWSER_PRIVACY_OR_CONSOLE_FAILURE'});

  const screenshot = join(tempRoot, `${scenario}-${width}.png`);
  stage = 'capture_full_screen';
  const layout = layoutDiagnostics = await page.evaluate(() => {
    const summary = document.querySelector('#input-quality-summary-36-12b, #error-input-quality-36-12b');
    const rect = summary?.getBoundingClientRect();
    const docWidth = document.documentElement.scrollWidth;
    const clientWidth = document.documentElement.clientWidth;
    const qualityWidth = summary?.scrollWidth || 0;
    const qualityClientWidth = summary?.clientWidth || 0;
    return {viewport_css_px: innerWidth, document_scroll_width: docWidth,
      document_client_width: clientWidth,
      root_font_size: getComputedStyle(document.documentElement).fontSize,
      quality_panel_inside_viewport: Boolean(rect && rect.left >= 0 && rect.right <= innerWidth + 1),
      quality_scroll_width: qualityWidth, quality_client_width: qualityClientWidth,
      horizontal_overflow: docWidth > clientWidth,
      overflow_nodes: [...document.querySelectorAll('body *')].filter((node) => {
        const nodeRect = node.getBoundingClientRect();
        return (nodeRect.right > innerWidth + 1 || node.scrollWidth > node.clientWidth + 1) && nodeRect.width > 0;
      }).slice(0, 8).map((node) => ({tag: node.tagName.toLowerCase(), id: node.id,
        class_name: typeof node.className === 'string' ? node.className.slice(0, 80) : '',
        scroll_width: node.scrollWidth, client_width: node.clientWidth,
        rect_right: Number(node.getBoundingClientRect().right.toFixed(1))}))};
  });
  if (layout.horizontal_overflow || !layout.quality_panel_inside_viewport)
    throw Object.assign(new Error(), {code: 'RESPONSIVE_OVERFLOW'});
  if (reflow200 && layout.root_font_size !== '32px')
    throw Object.assign(new Error(), {code: 'EQUIVALENT_200_REFLOW_SETUP'});
  const caseCount = await page.locator('#case-list .case-card').count().catch(() => 0);
  const detectionText = await page.locator('#results-dashboard').innerText().catch(() => '');
  stage = 'benchmark_renderer';
  const benchmarkGlobals = await page.evaluate(() => ({renderer: typeof window.inputQualityUi36_12b,
    textEncoder: typeof TextEncoder, performance: typeof performance, viewport: typeof innerWidth}));
  if (benchmarkGlobals.renderer !== 'object' || benchmarkGlobals.textEncoder !== 'function' ||
      benchmarkGlobals.performance !== 'object' || benchmarkGlobals.viewport !== 'number')
    throw Object.assign(new Error(), {code: 'BENCHMARK_GLOBAL_CONTRACT'});
  const benchmark = await benchmarkRenderer(page);
  stage = 'capture_full_screen';
  await page.screenshot({path: screenshot, fullPage: true});
  console.log(JSON.stringify({status, api_status: observedApiStatus, error_code: observedErrorCode,
    case_count: caseCount,
    dashboard_visible: await page.locator('#results-dashboard').isVisible().catch(() => false),
    error_visible: await page.locator('#error-summary').isVisible().catch(() => false),
    detection_copy_present: /탐지|위험|사례/.test(detectionText), screenshot,
    external_requests: externalRequests.length, console_errors: consoleErrors.length, page_errors: pageErrors.length,
    keyboard_disclosure_verified: keyboardDisclosureVerified, focus_visible_verified: focusVisibleVerified,
    layout, render_benchmark: benchmark}));
  await context.close();
  context = null;
}

main().catch(async (error) => {
  const knownCategories = new Set(['UNKNOWN_SCENARIO', 'KEYBOARD_DISCLOSURE_OR_FOCUS',
    'FILE_SOURCE_LABELS', 'UNEXPECTED_PARSER_INCOMPATIBLE', 'QUALITY_STATUS_MISSING',
    'PRIVATE_VALUE_VISIBLE', 'PRIVATE_ATTRIBUTE_VISIBLE', 'CSP_MISSING',
    'BROWSER_PRIVACY_OR_CONSOLE_FAILURE', 'RESPONSIVE_OVERFLOW',
    'EQUIVALENT_200_REFLOW_SETUP', 'BENCHMARK_GLOBAL_CONTRACT']);
  const category = knownCategories.has(error?.code) ? error.code :
    error?.name === 'TimeoutError' ? 'timeout' : 'unexpected';
  const dom = await reviewPage?.evaluate(() => ({
    quality_node: Boolean(document.querySelector('#input-quality-summary-36-12b, #error-input-quality-36-12b')),
    quality_visible: [...document.querySelectorAll('#input-quality-summary-36-12b, #error-input-quality-36-12b')].some((node) => !node.hidden),
    results_visible: Boolean(document.querySelector('#results-dashboard') && !document.querySelector('#results-dashboard').hidden),
    error_visible: Boolean(document.querySelector('#error-summary') && !document.querySelector('#error-summary').hidden)
  })).catch(() => null);
  console.log(`UI_INPUT_QUALITY_36_12C_FAIL stage=${stage} category=${category}`);
  await context?.close();
  if (tempRoot) await rm(tempRoot, {recursive: true, force: true});
  process.exitCode = 1;
});
