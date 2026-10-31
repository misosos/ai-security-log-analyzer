// Synthetic Chromium navigation check. Screenshots are opt-in, local, and never uploaded.
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const home = await mkdtemp(join(tmpdir(), 'ui-workspace-home-'));
await mkdir(join(home, 'config'));
const portServer = createServer();
await new Promise((done) => portServer.listen(0, '127.0.0.1', done));
const port = portServer.address().port;
await new Promise((done) => portServer.close(done));
const origin = `http://127.0.0.1:${port}`;
const child = spawn(join(root, '.venv', 'bin', 'python'), [
  '-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log',
], {cwd: root, stdio: 'ignore', env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config')}});
const shots = process.env.UI_WORKSPACE_SCREENSHOTS;
if (shots) await mkdir(shots, {recursive: true});
let browser;
let context;
let external = 0;
let unexpected = 0;
let disabled404 = 0;
let sampleRequests = 0;
let guidanceRequests = 0;
let guidanceRequestBytes = 0;
let guidanceResponseBytes = 0;
function ensure(value, code) { if (!value) throw new Error(code); }
try {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; }
    catch { /* Starting. */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'LOOPBACK_START_FAILED');
  const response = await fetch(origin);
  const csp = response.headers.get('content-security-policy') || '';
  ensure(response.ok && csp.includes("script-src 'self'") && csp.includes("connect-src 'self'") &&
    !csp.includes('unsafe-inline'), 'CSP_CONTRACT_FAILED');
  browser = await chromium.launch({headless: true, args: ['--disable-background-networking', '--no-first-run']});
  context = await browser.newContext({serviceWorkers: 'block', acceptDownloads: false});
  await context.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) { external++; await route.abort(); return; }
    if (url.pathname === '/api/v1/investigations/sample') sampleRequests++;
    if (url.pathname === '/api/v1/investigations/guidance') {
      guidanceRequests++;
      const body = route.request().postDataJSON();
      guidanceRequestBytes = route.request().postDataBuffer().byteLength;
      ensure(Object.keys(body).sort().join('|') === 'case|category|corpus_digest|schema_version' &&
        Object.keys(body.case).sort().join('|') ===
          'case_id|confidence|observation_count|review_order|risk_level|supported_detections|supported_relations|supporting_relation_count' &&
        !JSON.stringify(body).includes('subject') && !JSON.stringify(body).includes('timeline'),
      'GUIDANCE_REQUEST_NOT_MINIMIZED');
      const status = body.category === 'EXPLAIN_RISK' ? 'REFUSED' :
        body.category === 'NEXT_CHECKS' ? 'STALE' : 'AVAILABLE';
      const responseBody = JSON.stringify({
        schema_version: 1, status,
        message: status === 'AVAILABLE' ? '조사 도움말입니다. 기존 탐지·관계·위험도·사례 결과를 변경하지 않습니다.' :
          status === 'STALE' ? '현재 사례와 도움말 요청을 연결하지 못했습니다. 최신 분석 결과에서 다시 선택하십시오.' :
            '이 항목에는 승인된 근거 도움말이 없습니다.',
        corpus_digest: 'fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6',
        citations: status === 'AVAILABLE' ? [{citation_id: 'investigation-case:supporting-relation',
          title: '조사 사례와 지원 관계', summary: '<script>synthetic canary</script>',
          source_ref: 'docs/live_analysis_correlation_case_design.md'}] : [],
      });
      guidanceResponseBytes = Buffer.byteLength(responseBody);
      await route.fulfill({status: 200, contentType: 'application/json', body: responseBody});
      return;
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', () => { unexpected++; });
  page.on('response', (value) => {
    const path = new URL(value.url()).pathname;
    if (value.status() === 404 && path === '/api/v1/live/status') disabled404++;
    else if (value.status() >= 400) unexpected++;
  });
  page.on('console', (value) => {
    if (value.type() === 'error' &&
      !(disabled404 && value.text().startsWith('Failed to load resource'))) unexpected++;
  });
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(origin, {waitUntil: 'networkidle'});
  ensure(await page.locator('.workspace-panel:visible').count() === 1 &&
    await page.locator('#nav-start').getAttribute('aria-current') === 'page' &&
    await page.locator('#nav-live').isHidden() && await page.locator('#nav-results').isHidden(),
    'INITIAL_WORKSPACE_FAILED');
  ensure(await page.evaluate(() =>
    document.querySelectorAll('#analysis-flow .flow-step').length === 4 &&
    [...document.querySelectorAll('svg:not(#icon-sprite)')].every((node) =>
      node.getAttribute('aria-hidden') === 'true' && node.getAttribute('focusable') === 'false') &&
    [...document.querySelectorAll('svg use')].every((node) =>
      (node.getAttribute('href') || '').startsWith('#icon-')) &&
    [...document.querySelectorAll('button')].every((node) => node.textContent.trim().length > 0)),
  'ICON_OR_FLOW_ACCESSIBILITY_FAILED');
  if (shots) await page.screenshot({path: join(shots, 'start.png'), fullPage: true});
  await page.locator('#sample-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  ensure(await page.locator('#nav-results').getAttribute('aria-current') === 'page' &&
    await page.locator('.workspace-panel:visible').count() === 1 &&
    await page.locator('#results-heading').evaluate((node) => {
      const rect = node.getBoundingClientRect(); return rect.top >= 0 && rect.top < innerHeight;
  }) && !new URL(page.url()).hash, 'RESULT_REQUIRES_SCROLL');
  ensure(await page.locator('.guidance-request').count() === 2 && guidanceRequests === 0,
    'GUIDANCE_MUST_BE_OPT_IN');
  const resultMetrics = await page.evaluate(() => ({
    viewport: innerWidth,
    workspace: Math.round(document.querySelector('.app-shell').getBoundingClientRect().width),
    content: Math.round(document.querySelector('#workspace-results').getBoundingClientRect().width),
    height: document.documentElement.scrollHeight,
    cases: document.querySelectorAll('#case-list .case-card').length,
    caseColumns: getComputedStyle(document.querySelector('#case-list')).gridTemplateColumns,
    railRightOfCases: document.querySelector('#result-rail').getBoundingClientRect().left >
      document.querySelector('#case-section').getBoundingClientRect().right,
    paragraphCh: getComputedStyle(document.querySelector('#results > p')).maxWidth,
    resultFontPx: parseFloat(getComputedStyle(document.querySelector('#results')).fontSize),
    lineHeightPx: parseFloat(getComputedStyle(document.querySelector('#results')).lineHeight),
    summaryColumns: getComputedStyle(document.querySelector('#summary-cards')).gridTemplateColumns.split(' ').length,
    summaryIcons: document.querySelectorAll('#summary-cards .summary-icon').length,
    sidebarLeft: Math.round(document.querySelector('.workspace-nav').getBoundingClientRect().left),
    summaryTextLines: [...document.querySelectorAll('#case-list .case-summary')].reduce((total, summary) => {
      const walker = document.createTreeWalker(summary, NodeFilter.SHOW_TEXT);
      let lines = 0;
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (!node.textContent.trim()) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        lines += range.getClientRects().length;
      }
      return total + lines;
    }, 0),
    summaryTimeCount: document.querySelectorAll('#case-list .case-short-time').length,
    lastCaseBottom: Math.round([...document.querySelectorAll('#case-list .case-card')].at(-1).getBoundingClientRect().bottom),
    viewportHeight: innerHeight,
  }));
  resultMetrics.expandedHeight = await page.evaluate(() => {
    const details = [...document.querySelectorAll('#case-list details')];
    details.forEach((node) => { node.open = true; });
    const height = document.documentElement.scrollHeight;
    details.reverse().forEach((node) => { node.open = false; });
    return height;
  });
  const caseSummaryForGuidance = page.locator('#case-list .case-card').first().locator(':scope > summary');
  const guidanceCard = page.locator('#case-list .case-card').first();
  await caseSummaryForGuidance.focus();
  await page.keyboard.press('Enter');
  const guidanceButton = page.locator('.guidance-request').first();
  await guidanceButton.focus();
  const guidanceDomSamples = [];
  for (let sample = 0; sample < 9; sample++) {
    await guidanceButton.focus();
    const started = await page.evaluate(() => performance.now());
    await page.keyboard.press('Enter');
    await page.locator('.guidance-citation').waitFor({state: 'visible'});
    await page.waitForFunction(() => {
      const button = document.querySelector('.guidance-request');
      return button && !button.disabled && document.querySelector('.guidance-citation');
    });
    const elapsed = await page.evaluate((start) => performance.now() - start, started);
    if (sample > 0) guidanceDomSamples.push(elapsed);
  }
  const guidanceChecks = {
    requestCount: guidanceRequests,
    statusHasLimit: await page.locator('.guidance-status').first().textContent().then((text) => text.includes('결과를 변경하지 않습니다')),
    activeScriptCount: await page.locator('.guidance-citation script').count(),
    payloadRenderedLiterally: await page.locator('.guidance-citation').first().textContent().then((text) => text.includes('<script>synthetic canary</script>')),
  };
  console.log(`guidance_checks=${JSON.stringify(guidanceChecks)}`);
  ensure(guidanceChecks.requestCount === 9 && guidanceChecks.statusHasLimit &&
    guidanceChecks.activeScriptCount === 0 && guidanceChecks.payloadRenderedLiterally,
  'GUIDANCE_SAFE_TEXT_RENDER_FAILED');
  guidanceDomSamples.sort((a, b) => a - b);
  console.log(`guidance_dom_samples=${JSON.stringify({warmup: 1, samples: guidanceDomSamples.length,
    median_ms: guidanceDomSamples[Math.floor(guidanceDomSamples.length / 2)],
    p95_ms: guidanceDomSamples[Math.ceil(guidanceDomSamples.length * 0.95) - 1],
    max_ms: guidanceDomSamples.at(-1), request_payload_bytes: guidanceRequestBytes,
    response_payload_bytes: guidanceResponseBytes})}`);
  const guidanceCategory = guidanceCard.locator('select[aria-label="근거 도움말 주제"]');
  await guidanceCategory.selectOption('EXPLAIN_RISK');
  await guidanceButton.focus();
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => !document.querySelector('.guidance-request').disabled &&
    document.querySelector('.guidance-status').textContent.includes('승인된 근거 도움말'));
  ensure(await guidanceCard.locator('.guidance-citation').count() === 0,
    'GUIDANCE_REFUSAL_RENDER_FAILED');
  await guidanceCategory.selectOption('NEXT_CHECKS');
  await guidanceButton.focus();
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => !document.querySelector('.guidance-request').disabled &&
    document.querySelector('.guidance-status').textContent.includes('최신 분석 결과에서 다시 선택'));
  ensure(await guidanceCard.locator('.guidance-citation').count() === 0,
    'GUIDANCE_STALE_RENDER_FAILED');
  await caseSummaryForGuidance.focus();
  await page.keyboard.press('Enter');
  console.log(`result_metrics=${JSON.stringify(resultMetrics)}`);
  ensure(resultMetrics.workspace === 1440 && resultMetrics.sidebarLeft === 0 &&
    resultMetrics.summaryColumns === 4 && resultMetrics.summaryIcons === 4 && resultMetrics.cases === 2 &&
    resultMetrics.caseColumns.split(' ').length === 2 && resultMetrics.railRightOfCases &&
    resultMetrics.summaryTextLines < 32 && resultMetrics.summaryTimeCount === 2 &&
    resultMetrics.height < 1253 && resultMetrics.lastCaseBottom <= resultMetrics.viewportHeight &&
    resultMetrics.expandedHeight > resultMetrics.height &&
    parseFloat(resultMetrics.paragraphCh) >= 600 && parseFloat(resultMetrics.paragraphCh) <= 760 &&
    resultMetrics.resultFontPx >= 16 &&
    resultMetrics.lineHeightPx >= 24 && resultMetrics.height < 1926,
    'WIDE_RESULT_LAYOUT_NOT_COMPACT');
  const caseSummary = page.locator('#case-list .case-card').first().locator(':scope > summary');
  ensure((await page.locator('#case-list .case-summary').allTextContents()).some((value) =>
    value.includes('로그인 실패 후 성공 기록 포함')), 'CASE_RELATION_CONTEXT_MISSING');
  ensure(!(await page.locator('#case-list .case-card').first().evaluate((node) => node.open)),
    'CASE_DETAIL_DEFAULT_OPEN');
  await caseSummary.focus();
  await page.keyboard.press('Enter');
  ensure(await page.locator('#case-list .case-card').first().evaluate((node) => node.open) &&
    !(await page.locator('#case-list .timeline-disclosure').first().evaluate((node) => node.open)),
    'CASE_DETAIL_KEYBOARD_OPEN_FAILED');
  const timelineSummary = page.locator('#case-list .timeline-disclosure').first().locator('summary');
  await timelineSummary.focus();
  await page.keyboard.press('Space');
  ensure(await page.locator('#case-list .timeline-disclosure').first().evaluate((node) => node.open) &&
    await page.locator('#case-list .timeline-item').count() >= 5,
    'TIMELINE_KEYBOARD_OPEN_FAILED');
  await page.keyboard.press('Space');
  ensure(!(await page.locator('#case-list .timeline-disclosure').first().evaluate((node) => node.open)),
    'TIMELINE_KEYBOARD_CLOSE_FAILED');
  await caseSummary.focus();
  await page.keyboard.press('Enter');
  ensure(!(await page.locator('#case-list .case-card').first().evaluate((node) => node.open)),
    'CASE_DETAIL_KEYBOARD_CLOSE_FAILED');
  if (shots) await page.screenshot({path: join(shots, 'result.png'), fullPage: true});
  await page.locator('#nav-local').click();
  ensure(await page.locator('#local-upload').isVisible() &&
    await page.locator('#local-form').isVisible() &&
    await page.locator('.workspace-panel:visible').count() === 1, 'LOCAL_PANEL_FAILED');
  if (shots) await page.screenshot({path: join(shots, 'local.png'), fullPage: true});
  if (!await page.locator('#nav-group-tools').evaluate((node) => node.open))
    await page.locator('#nav-group-tools > summary').click();
  await page.locator('#nav-audit').click();
  ensure(await page.locator('#linux-audit-upload').isVisible() &&
    await page.locator('.workspace-panel:visible').count() === 1, 'AUDIT_PANEL_FAILED');
  await page.keyboard.press('Shift+Tab');
  ensure(await page.locator('#nav-results').evaluate((node) =>
    document.activeElement === node && node.matches(':focus-visible')),
    'NAV_FOCUS_NOT_VISIBLE');
  await page.keyboard.press('Enter');
  ensure(await page.locator('#results-heading').isVisible(), 'KEYBOARD_RESULT_NAV_FAILED');
  let wideMetrics;
  let wideStartMetrics;
  for (const width of [320, 640, 767, 768, 1024, 1200, 1440, 1600, 2000]) {
    await page.setViewportSize({width, height: 900});
    await page.waitForFunction(() =>
      document.getElementById('workspace-nav-details').open === (innerWidth >= 768));
    if (width === 1600) ensure(await page.locator('.app-shell').evaluate((node) =>
      Math.round(node.getBoundingClientRect().width) === 1600), 'WIDE_SHELL_FAILED');
    for (const key of ['start', 'local', 'audit', 'results']) {
      if (width <= 767 && !(await page.locator('#workspace-nav-details').evaluate((node) => node.open)))
        await page.locator('#workspace-nav-toggle').click();
      if (shots && width === 320 && key === 'start')
        await page.screenshot({path: join(shots, 'mobile-nav-open.png'), fullPage: true});
      if (width <= 767) ensure(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        `OPEN_NAV_OVERFLOW_${width}`);
      await page.locator(`#nav-${key}`).click();
      ensure(await page.locator('.workspace-panel:visible').count() === 1 &&
        await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
        `WORKSPACE_OVERFLOW_${width}`);
      if (width <= 767) ensure(!(await page.locator('#workspace-nav-details').evaluate((node) => node.open)) &&
        (await page.locator('#workspace-nav-toggle').textContent()).includes('현재 영역') &&
        await page.evaluate((expected) => document.activeElement.id === expected,
          {start: 'page-title', local: 'local-heading', audit: 'linux-audit-heading', results: 'results-heading'}[key]),
      `MOBILE_NAV_COLLAPSE_${width}`);
      if (width === 767 || width === 768) ensure(await page.locator('.app-shell').evaluate((node, expected) =>
        getComputedStyle(node).gridTemplateColumns.split(' ').length === expected, width === 767 ? 1 : 2),
      `NAV_BREAKPOINT_${width}`);
      if (key === 'start' && width === 2000) wideStartMetrics = await page.evaluate(() => ({
        panelHeight: Math.round(document.querySelector('#workspace-start').getBoundingClientRect().height),
        panelBackground: getComputedStyle(document.querySelector('#workspace-start')).backgroundColor,
        actionCards: document.querySelectorAll('.action-card:not([hidden])').length,
        actionColumns: getComputedStyle(document.querySelector('.start-actions')).gridTemplateColumns.split(' ').length,
        heroParagraphMax: getComputedStyle(document.querySelector('#workspace-start .lead')).maxWidth,
      }));
      if (key === 'start' && width === 320) ensure(await page.evaluate(() =>
        getComputedStyle(document.querySelector('.start-actions')).gridTemplateColumns.split(' ').length === 1),
      'MOBILE_START_ACTION_COLUMNS_FAILED');
      if (key === 'results' && width === 1024) ensure(await page.evaluate(() =>
        getComputedStyle(document.querySelector('#result-body')).gridTemplateColumns.split(' ').length === 1 &&
        getComputedStyle(document.querySelector('#case-list')).gridTemplateColumns.split(' ').length === 1),
      'MID_RESULT_COLUMNS_FAILED');
      if (key === 'results' && width === 2000) wideMetrics = await page.evaluate(() => ({
        viewport: innerWidth,
        workspace: Math.round(document.querySelector('.app-shell').getBoundingClientRect().width),
        sidebar: Math.round(document.querySelector('.workspace-nav').getBoundingClientRect().width),
        main: Math.round(document.querySelector('.app-area').getBoundingClientRect().width),
        height: document.documentElement.scrollHeight,
        sidebarLeft: Math.round(document.querySelector('.workspace-nav').getBoundingClientRect().left),
        headerLeft: Math.round(document.querySelector('.site-header').getBoundingClientRect().left),
        mainLeft: Math.round(document.querySelector('.app-content').getBoundingClientRect().left),
      }));
      if (shots && width === 320 && key === 'results')
        await page.screenshot({path: join(shots, 'result-320.png'), fullPage: true});
      if (shots && width === 2000 && key === 'results')
        await page.screenshot({path: join(shots, 'result-2000.png'), fullPage: true});
    }
  }
  await page.setViewportSize({width: 320, height: 900});
  await page.waitForFunction(() => !document.getElementById('workspace-nav-details').open);
  await page.locator('#workspace-nav-toggle').focus();
  await page.keyboard.press('Enter');
  ensure(await page.locator('#workspace-nav-details').evaluate((node) => node.open), 'MOBILE_NAV_ENTER_FAILED');
  await page.keyboard.press('Escape');
  ensure(!(await page.locator('#workspace-nav-details').evaluate((node) => node.open)) &&
    await page.locator('#workspace-nav-toggle').evaluate((node) =>
      document.activeElement === node && node.matches(':focus-visible')),
  'MOBILE_NAV_ESCAPE_FOCUS_FAILED');
  console.log(`wide_start_metrics=${JSON.stringify(wideStartMetrics)}`);
  ensure(wideStartMetrics.actionCards === 3 && wideStartMetrics.actionColumns === 3 &&
    wideStartMetrics.panelBackground === 'rgba(0, 0, 0, 0)' &&
    parseFloat(wideStartMetrics.heroParagraphMax) >= 550 &&
    parseFloat(wideStartMetrics.heroParagraphMax) <= 760, 'START_SHELL_OR_READING_WIDTH');
  console.log(`wide_result_metrics=${JSON.stringify(wideMetrics)}`);
  ensure(wideMetrics.workspace === wideMetrics.viewport &&
    wideMetrics.sidebar >= 220 && wideMetrics.sidebar <= 250 &&
    wideMetrics.main === wideMetrics.viewport - wideMetrics.sidebar &&
    wideMetrics.sidebarLeft === 0 && wideMetrics.headerLeft === wideMetrics.sidebar &&
    wideMetrics.mainLeft === wideMetrics.sidebar,
  'WIDE_WORKSPACE_UNDERUSED');
  await page.emulateMedia({reducedMotion: 'reduce'});
  ensure(await page.locator('#nav-start').evaluate((node) => getComputedStyle(node).transitionDuration === '0s'),
    'REDUCED_MOTION_FAILED');
  await page.emulateMedia({forcedColors: 'active'});
  ensure(await page.locator('#results .risk').evaluateAll((nodes) =>
    nodes.length >= 2 && nodes.every((node) => ['HIGH', 'MEDIUM', 'LOW'].includes(node.textContent.trim()))) &&
    await page.locator('#nav-results').textContent() !== '', 'FORCED_COLORS_TEXT_FAILED');
  ensure(sampleRequests === 1 && guidanceRequests === 11 && external === 0 && unexpected === 0, 'NETWORK_OR_CONSOLE_FAILED');
  console.log(`panels=4 widths=320,640,767,768,1024,1200,1440,1600,2000 sample_requests=${sampleRequests} guidance_requests=${guidanceRequests} external=${external} unexpected_errors=${unexpected} expected_disabled_status_404=${disabled404}`);
} finally {
  await context?.close();
  await browser?.close();
  if (child.exitCode === null) await new Promise((done) => { child.once('exit', done); child.kill('SIGINT'); });
  await rm(home, {recursive: true, force: true});
  let listening = false;
  try { await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(250)}); listening = true; }
  catch { /* Expected. */ }
  ensure(!listening, 'LOOPBACK_LISTENER_REMAINED');
}
