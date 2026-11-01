// Synthetic local input quality UI contract checks.
import {chromium} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, readFile, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const home = await mkdtemp(join(tmpdir(), 'ui-quality-36-12b-'));
await mkdir(join(home, 'config'));
const socket = createServer();
await new Promise((done) => socket.listen(0, '127.0.0.1', done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const origin = `http://127.0.0.1:${port}`;
const child = spawn(join(root, '.venv', 'bin', 'python'), [
  '-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log',
], {cwd: root, stdio: 'ignore', env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config')}});
let browser;
let externalRequests = 0;
function ensure(value, code) { if (!value) throw new Error(code); }

async function benchmarkQualityMarkup(page, label, selector) {
  const result = await page.locator(selector).evaluate((source, label) => {
    const sourceHtml = source.outerHTML;
    const nodeCount = source.querySelectorAll('*').length + 1;
    const bytes = new TextEncoder().encode(sourceHtml).byteLength;
    const viewport = innerWidth;
    const host = document.createElement('div');
    Object.assign(host.style, {position: 'fixed', inset: '0 auto auto 0', width: `${viewport - 40}px`,
      visibility: 'hidden', pointerEvents: 'none', zIndex: '-1'});
    document.body.append(host);
    const times = [];
    for (let index = 0; index < 35; index += 1) {
      const start = performance.now();
      host.replaceChildren(source.cloneNode(true));
      void host.getBoundingClientRect().height;
      const duration = performance.now() - start;
      if (index >= 5) times.push(duration);
    }
    host.remove();
    times.sort((a, b) => a - b);
    return {label, viewport, warmup: 5, samples: times.length,
      median_ms: times[Math.floor(times.length / 2)],
      p95_ms: times[Math.ceil(times.length * .95) - 1], max_ms: times[times.length - 1],
      dom_nodes: nodeCount, html_bytes: bytes};
  }, label);
  console.log(`UI_QUALITY_BENCH ${JSON.stringify(result)}`);
  return result;
}

try {
  let ready = false;
  for (let i = 0; i < 100; i += 1) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; }
    catch { /* local server startup */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'UI_QUALITY_SERVER_START_FAILED');
  browser = await chromium.launch({headless: true, args: ['--disable-background-networking', '--no-first-run']});
  const context = await browser.newContext({serviceWorkers: 'block'});
  let responseMutation = null;
  let textSuccessPayload = null;
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      externalRequests += 1;
      await route.abort();
      return;
    }
    await route.continue();
  });
  await context.route(`${origin}/api/v1/investigations/text`, async (route) => {
    if (!responseMutation) return route.continue();
    const upstream = textSuccessPayload === null ? await route.fetch() : null;
    const payload = textSuccessPayload === null ? await upstream.json() : structuredClone(textSuccessPayload);
    responseMutation(payload);
    await route.fulfill({status: upstream?.status() ?? 200,
      headers: upstream?.headers() ?? {'content-type': 'application/json'}, body: JSON.stringify(payload)});
    responseMutation = null;
  });
  const page = await context.newPage();
  let browserErrors = 0;
  let pageErrors = 0;
  const pageErrorNames = [];
  page.on('pageerror', (error) => { browserErrors += 1; pageErrors += 1; pageErrorNames.push(error.name); });
  await page.addInitScript(() => {
    window.__inputQualityConsoleErrors = 0;
    console.error = () => { window.__inputQualityConsoleErrors += 1; };
  });
  page.on('dialog', (dialog) => dialog.accept());
  const requests = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && ['/api/v1/investigations/text', '/api/v1/investigations',
      '/api/v1/investigations/checklist'].includes(url.pathname)) requests.push(request);
  });
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(origin, {waitUntil: 'networkidle'});
  await page.locator('#nav-local').click();
  if (!(await page.locator('#local-choice-details').evaluate((node) => node.open)))
    await page.locator('#local-choice-details summary').click();
  const fixture = (name) => join(root, 'sample_logs', name);
  for (const [id, name] of [['application-file', 'brute_force.log'],
    ['ssh-file', 'ssh_auth.log'], ['access-file', 'web_shell.log']]) {
    await page.locator(`#${id}`).setInputFiles(fixture(name));
  }
  await page.locator('#local-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  ensure(await page.locator('#input-quality-summary-36-12b').isVisible(),
    'UI_QUALITY_FILE_COMPLETE_SUMMARY_MISSING');
  ensure(await page.locator('#input-quality-summary-36-12b').textContent().then((text) =>
    text.includes('전체 입력 줄') && text.includes('로그 종류별 상태') &&
    text.includes('애플리케이션 로그') && text.includes('SSH 인증 로그') &&
    text.includes('웹 접근 로그') && text.includes('로그 인식 상태는 입력 형식의 처리 범위') &&
    !/PRIVATE_[A-Z_]+|192\.0\.2\.|10\.0\.0\.|hostname|\.log/.test(text)),
  'UI_QUALITY_FILE_SUMMARY_CONTENT_OR_PRIVACY_FAILED');
  const fileSourceRows = await page.locator('#input-quality-summary-36-12b .input-quality-source-list-36-12b > div').allInnerTexts();
  ensure(fileSourceRows.length === 3 && fileSourceRows.every((text) => text.includes('모두 인식')),
    'UI_QUALITY_FILE_SOURCE_ROWS_MIXED');
  ensure(await page.locator('#input-quality-summary-36-12b .input-quality-reasons-36-12b[open]').count() === 0 &&
    await page.locator('#input-quality-summary-36-12b .input-quality-reason-list-36-12b dd').evaluateAll((nodes) =>
      nodes.every((node) => Number(node.textContent) > 0)) &&
    await page.locator('#input-quality-summary-36-12b .input-quality-reasons-36-12b').evaluateAll((nodes) =>
      nodes.every((node) => node.textContent.includes('처리 사유 보기') && node.textContent.trim() !== 'Details')),
  'UI_QUALITY_ZERO_REASON_SHOULD_BE_HIDDEN');
  console.log(`UI_QUALITY_FILE_COMPLETE status=${await page.locator('#input-quality-status-36-12b').innerText()}`);
  await page.screenshot({path: join(tmpdir(), 'input-quality-ui-36-12b-1440.png'), fullPage: true});
  const benchmarkResults = [await benchmarkQualityMarkup(page, 'file_3_source_complete', '#input-quality-summary-36-12b')];
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({width, height: 850});
    if (width === 320)
      await page.screenshot({path: join(tmpdir(), 'input-quality-ui-36-12b-320.png'), fullPage: true});
    const measured = await page.evaluate(() => ({
      docWidth: document.documentElement.scrollWidth,
      viewport: innerWidth,
      qualityWidth: document.querySelector('#input-quality-summary-36-12b').getBoundingClientRect().width,
      countOverflow: [...document.querySelectorAll('.input-quality-counts-36-12b > div, .input-quality-source-list-36-12b > div')]
        .some((node) => node.scrollWidth > node.clientWidth + 1)
    }));
    ensure(measured.docWidth === measured.viewport && measured.qualityWidth > 0 && !measured.countOverflow,
      `UI_QUALITY_REFLOW_FAILED_${width}`);
  }
  await page.evaluate(() => { document.documentElement.style.fontSize = '32px'; });
  ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth),
    'UI_QUALITY_200_PERCENT_REFLOW_FAILED');
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 900});
  const axe = await new AxeBuilder({page}).analyze();
  ensure(axe.violations.length === 0,
    `UI_QUALITY_AXE_VIOLATIONS_${axe.violations.map((violation) => `${violation.id}_${violation.nodes.map((node) => node.target.join('-')).join('|')}`).join('_')}`);
  await page.setViewportSize({width: 320, height: 568});
  const axeMobile = await new AxeBuilder({page}).analyze();
  ensure(axeMobile.violations.length === 0, 'UI_QUALITY_MOBILE_AXE_FAILED');
  await page.setViewportSize({width: 1440, height: 900});
  const resultRequestsBeforeNav = requests.length;
  await page.locator('#case-list a[data-review-case-ref]').first().click();
  ensure(await page.locator('#case-detail-view').isVisible() &&
    await page.locator('#case-detail-view #input-quality-summary-36-12b').count() === 0,
  'UI_QUALITY_SHOULD_NOT_REPEAT_IN_CASE_DETAIL');
  await page.goBack();
  ensure(await page.locator('#input-quality-summary-36-12b').isVisible(), 'UI_QUALITY_HISTORY_BACK_LOST');
  await page.goForward();
  ensure(await page.locator('#case-detail-view').isVisible(), 'UI_QUALITY_HISTORY_FORWARD_FAILED');
  await page.goBack();
  ensure(requests.length === resultRequestsBeforeNav, 'UI_QUALITY_NAVIGATION_ADDED_REQUEST');
  await page.locator('#nav-local').click();
  if (!(await page.locator('#local-choice-details').evaluate((node) => node.open)))
    await page.locator('#local-choice-details summary').click();
  const mixedFiles = [
    ['application-file', Buffer.from('2026-11-01 10:30:12 INFO login_failed user=synthetic ip=192.0.2.10\nnot supported')],
    ['ssh-file', await readFile(fixture('ssh_auth.log'))],
    ['access-file', await readFile(fixture('web_shell.log'))]
  ];
  for (const [id, buffer] of mixedFiles)
    await page.locator(`#${id}`).setInputFiles({name: 'synthetic.txt', mimeType: 'text/plain', buffer});
  await page.locator('#local-button').click();
  await page.locator('#error-summary').waitFor({state: 'visible'});
  const partialSourceRows = await page.locator('#error-input-quality-36-12b .input-quality-source-list-36-12b > div').allInnerTexts();
  ensure(await page.locator('#error-input-quality-36-12b').isVisible() &&
    await page.locator('#error-input-quality-36-12b #input-quality-status-36-12b').innerText().then((text) => text.startsWith('일부 인식')) &&
    partialSourceRows.length === 3 && partialSourceRows.some((text) => text.includes('애플리케이션 로그') && text.includes('일부 인식')) &&
    partialSourceRows.some((text) => text.includes('SSH 인증 로그') && text.includes('모두 인식')) &&
    partialSourceRows.some((text) => text.includes('웹 접근 로그') && text.includes('모두 인식')) &&
    await page.locator('#results-dashboard').isHidden() && await page.locator('#case-list .case-card').count() === 0,
  'UI_QUALITY_FILE_PARTIAL_ADMISSION_FAILED');
  console.log('UI_QUALITY_FILE_PARTIAL error=PARSER_INCOMPATIBLE summary=partial analysis=not_admitted');
  benchmarkResults.push(await benchmarkQualityMarkup(page, 'file_3_source_partial', '#error-input-quality-36-12b'));
  const textSource = 'application';
  const textForm = async (value, expectedStatus) => {
    await page.locator('#nav-local').click();
    if (!(await page.locator('#local-choice-details').evaluate((node) => node.open)))
      await page.locator('#local-choice-details summary').click();
    if (!(await page.locator('#input-mode-text').isChecked())) await page.locator('#input-mode-text').check();
    await page.locator('#text-source').selectOption(textSource);
    await page.locator('#log-text').fill(value);
    const previousRequests = requests.length;
    await page.locator('#local-button').click();
    await page.waitForFunction(() => !document.querySelector('#local-button').disabled);
    ensure(requests.length === previousRequests + 1, 'UI_QUALITY_TEXT_REQUEST_COUNT_FAILED');
    const summary = page.locator('#input-quality-summary-36-12b');
    const errorSummary = page.locator('#error-input-quality-36-12b');
    if (expectedStatus === 'legacy') {
      ensure(!await summary.isVisible() && await page.locator('#results-dashboard').isVisible(),
        'UI_QUALITY_LEGACY_RESULT_BROKEN');
      return null;
    }
    if (expectedStatus === 'malformed') {
      ensure(!await summary.isVisible() &&
        await page.locator('#error-message').textContent().then((text) => text === '결과 형식을 확인할 수 없습니다.') &&
        !await page.locator('body').textContent().then((text) => text.includes('INPUT_QUALITY_CANARY_36_12B')),
      'UI_QUALITY_MALFORMED_OR_CANARY_PRIVACY_FAILED');
      return null;
    }
    const target = await summary.isVisible() ? summary : errorSummary;
    ensure(await target.isVisible(), `UI_QUALITY_TEXT_${expectedStatus.toUpperCase()}_MISSING`);
    const renderedStatus = await target.locator('#input-quality-status-36-12b').innerText();
    ensure(renderedStatus.startsWith({complete: '모두 인식', partial: '일부 인식', none: '인식하지 못함',
      empty: '분석할 내용 없음'}[expectedStatus]),
    `UI_QUALITY_TEXT_${expectedStatus.toUpperCase()}_STATE_FAILED_${renderedStatus.slice(0, 40)}`);
    ensure(await target.textContent().then((text) => text.includes('애플리케이션 로그') &&
      !/PRIVATE_[A-Z_]+|quality-canary|192\.0\.2\./.test(text)),
    'UI_QUALITY_TEXT_SOURCE_OR_PRIVACY_FAILED');
    return target;
  };
  const appLine = '2026-11-01 10:30:12 INFO login_failed user=synthetic ip=192.0.2.10';
  const textComplete = await textForm(appLine, 'complete');
  textSuccessPayload = await requests.at(-1).response().then((response) => response.json());
  ensure(await page.locator('#input-quality-summary-36-12b .input-quality-source-list-36-12b > div').count() === 1 &&
    !await page.locator('#error-input-quality-36-12b').isVisible(), 'UI_QUALITY_TEXT_SOURCE_OR_STALE_ERROR_FAILED');
  const partial = await textForm(`${appLine}\nnot a supported application record`, 'partial');
  const reasonButton = partial.locator('summary').filter({hasText: '처리 사유 보기'});
  ensure(await reasonButton.count() === 1 &&
    !(await reasonButton.evaluate((node) => node.parentElement.open)), 'UI_QUALITY_REASON_DISCLOSURE_DEFAULT_OPEN');
  await reasonButton.focus();
  await page.keyboard.press('Enter');
  ensure(await reasonButton.evaluate((node) => node.parentElement.open) &&
    await partial.locator('.input-quality-reason-list-36-12b').innerText().then((text) =>
      text.includes('지원하지 않는 형식') || text.includes('기타 거부')),
  'UI_QUALITY_REASON_DISCLOSURE_KEYBOARD_FAILED');
  const axeDisclosure = await new AxeBuilder({page}).analyze();
  ensure(axeDisclosure.violations.length === 0, 'UI_QUALITY_DISCLOSURE_AXE_FAILED');
  benchmarkResults.push(await benchmarkQualityMarkup(page, 'reason_disclosure_open', '#error-input-quality-36-12b'));
  const textNone = await textForm('not a supported application record', 'none');
  benchmarkResults.push(await benchmarkQualityMarkup(page, 'text_none', '#error-input-quality-36-12b'));
  responseMutation = (payload) => {
    const reasonCounts = Object.fromEntries(['unsupported_format', 'invalid_timestamp', 'invalid_address',
      'invalid_port', 'invalid_header', 'incomplete_record', 'blank_line', 'ignored_record',
      'other_rejected'].map((code) => [code, 1]));
    const sourceSummary = {schema_version: '1', source: 'application', total_lines: 9,
      nonempty_lines: 8, recognized_lines: 0, unrecognized_lines: 7, ignored_lines: 2,
      recognition_status: 'none', reason_counts: reasonCounts,
      limitations: ['INPUT_RECORD_RECOGNITION_ONLY', 'NOT_COLLECTION_COMPLETENESS_OR_DETECTION_ACCURACY']};
    payload.result.input_quality = {schema_version: '1', by_source: [sourceSummary],
      aggregate: {...sourceSummary, source: 'aggregate'}};
  };
  const allReasons = await textForm(appLine, 'none');
  const allReasonButton = allReasons.locator('summary').filter({hasText: '처리 사유 보기'});
  await allReasonButton.focus();
  await page.keyboard.press('Enter');
  const reasonLabels = await allReasons.locator('.input-quality-reason-list-36-12b dt').allTextContents();
  ensure(reasonLabels.length === 9 && reasonLabels.join('|') === [
    '지원하지 않는 형식', '올바르지 않은 시각', '올바르지 않은 주소', '올바르지 않은 포트',
    '올바르지 않은 헤더', '완성되지 않은 레코드', '빈 줄', '무시된 기록', '기타 거부'
  ].join('|'), 'UI_QUALITY_REASON_LABEL_MAP_INCOMPLETE');
  responseMutation = (payload) => {
    const emptySummary = (source) => ({schema_version: '1', source, total_lines: 0, nonempty_lines: 0,
      recognized_lines: 0, unrecognized_lines: 0, ignored_lines: 0, recognition_status: 'empty',
      reason_counts: {unsupported_format: 0, invalid_timestamp: 0, invalid_address: 0,
        invalid_port: 0, invalid_header: 0, incomplete_record: 0, blank_line: 0,
        ignored_record: 0, other_rejected: 0},
      limitations: ['INPUT_RECORD_RECOGNITION_ONLY', 'NOT_COLLECTION_COMPLETENESS_OR_DETECTION_ACCURACY']});
    payload.result.input_quality = {schema_version: '1', by_source: [emptySummary('application')],
      aggregate: emptySummary('aggregate')};
  };
  const emptyQuality = await textForm(appLine, 'empty');
  ensure(await emptyQuality.textContent().then((text) => text.includes('분석할 내용 없음')),
    'UI_QUALITY_EMPTY_STATUS_FAILED');
  responseMutation = (payload) => { delete payload.result.input_quality; };
  await textForm(appLine, 'legacy');
  ensure(await page.evaluate(() => window.__inputQualityConsoleErrors) === 0,
    'UI_QUALITY_LEGACY_RESPONSE_CONSOLE_ERROR');
  responseMutation = (payload) => {
    payload.result.input_quality.aggregate.reason_counts.private_canary = 'INPUT_QUALITY_CANARY_36_12B';
  };
  await textForm(appLine, 'malformed');
  responseMutation = (payload) => { payload.result.input_quality.aggregate.recognition_status = 'unexpected_status'; };
  await textForm(appLine, 'malformed');
  responseMutation = (payload) => { payload.result.input_quality.aggregate.recognized_lines += 1; };
  await textForm(appLine, 'malformed');
  await page.locator('#nav-local').click();
  if (!(await page.locator('#local-choice-details').evaluate((node) => node.open)))
    await page.locator('#local-choice-details summary').click();
  if (!(await page.locator('#input-mode-text').isChecked())) await page.locator('#input-mode-text').check();
  await page.locator('#text-source').selectOption(textSource);
  await page.locator('#log-text').fill('   ');
  await page.locator('#local-button').click();
  await page.locator('#error-summary').waitFor({state: 'visible'});
  ensure(!await page.locator('#input-quality-summary-36-12b').isVisible() &&
    !await page.locator('#error-input-quality-36-12b').isVisible(),
    'UI_QUALITY_EMPTY_WAS_FABRICATED');
  ensure(await page.locator('#input-quality-status-36-12b').count() === 0,
    'UI_QUALITY_STALE_SUMMARY_AFTER_EMPTY_INPUT');
  const expiredPage = await context.newPage();
  await expiredPage.goto(`${origin}/#/investigations/c_${'a'.repeat(24)}`, {waitUntil: 'networkidle'});
  ensure(await expiredPage.locator('#review-route-expired').isVisible() &&
    !await expiredPage.locator('#input-quality-summary-36-12b').isVisible(),
  'UI_QUALITY_EXPIRED_ROUTE_REUSED_STALE_SUMMARY');
  await expiredPage.close();
  ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth),
    'UI_QUALITY_BASELINE_HORIZONTAL_OVERFLOW');
  ensure(externalRequests === 0 && browserErrors === 0 &&
    await page.evaluate(() => window.__inputQualityConsoleErrors) === 0,
  `UI_QUALITY_EXTERNAL_REQUESTS_OR_BROWSER_ERRORS_${externalRequests}_${browserErrors}_${pageErrors}_${pageErrorNames.join('_')}`);
  await browser.close();
  browser = null;
  console.log(`UI_INPUT_QUALITY_36_12B_PASS external_requests=${externalRequests} axe_violations=${axe.violations.length}`);
} finally {
  await browser?.close();
  child.kill('SIGTERM');
  await rm(home, {recursive: true, force: true});
}
