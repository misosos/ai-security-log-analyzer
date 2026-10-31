// Current Dashboard/Case Detail navigation contract; synthetic sample data only.
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const home = await mkdtemp(join(tmpdir(), 'ui3-navigation-home-'));
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
let context;
let externalRequests = 0;
let samplePosts = 0;
let checklistPosts = 0;
let guidancePosts = 0;
let releaseGuidance;
let guidanceStarted;
let guidanceResponseSent;
function ensure(value, code) { if (!value) throw new Error(code); }

try {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; }
    catch { /* Local server is starting. */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'UI3_LOOPBACK_START_FAILED');
  const html = await fetch(origin);
  const csp = html.headers.get('content-security-policy') || '';
  ensure(html.ok && csp.includes("script-src 'self'") && csp.includes("connect-src 'self'") &&
    !csp.includes('unsafe-inline'), 'UI3_CSP_CONTRACT_FAILED');

  browser = await chromium.launch({headless: true, args: ['--disable-background-networking', '--no-first-run']});
  context = await browser.newContext({serviceWorkers: 'block', acceptDownloads: false});
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      externalRequests++;
      await route.abort();
      return;
    }
    await route.continue();
  });
  guidanceStarted = new Promise((resolveStarted) => { globalThis.resolveGuidanceStarted = resolveStarted; });
  guidanceResponseSent = new Promise((resolveSent) => { globalThis.resolveGuidanceSent = resolveSent; });
  await context.route(`${origin}/api/v1/investigations/guidance`, async (route) => {
    guidancePosts++;
    const body = route.request().postDataJSON();
    ensure(route.request().method() === 'POST' &&
      Object.keys(body).sort().join('|') === 'case|category|corpus_digest|schema_version' &&
      Object.keys(body.case).sort().join('|') ===
        'case_id|confidence|observation_count|review_order|risk_level|supported_detections|supported_relations|supporting_relation_count' &&
      !JSON.stringify(body).includes('PRIVATE_GUIDANCE_CANARY') &&
      !JSON.stringify(body).includes('raw_log'), 'UI3_GUIDANCE_REQUEST_SCOPE_FAILED');
    globalThis.resolveGuidanceStarted(body);
    await new Promise((resolveRelease) => { releaseGuidance = resolveRelease; });
    const payload = JSON.stringify({schema_version: 1, status: 'AVAILABLE',
      message: '합성 지연 응답입니다. 분석 결과를 변경하지 않습니다.',
      corpus_digest: 'fe7cc8cbd77319c4ce9a1af731da004eeffc08d272c0ee04174db96eb2897ac6',
      citations: [{citation_id: 'investigation-case:supporting-relation', title: '지연 응답',
        summary: '<script>PRIVATE_GUIDANCE_CANARY</script>',
        source_ref: 'docs/live_analysis_correlation_case_design.md'}]});
    await route.fulfill({status: 200, contentType: 'application/json', body: payload});
    globalThis.resolveGuidanceSent();
  });

  const page = await context.newPage();
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && url.pathname === '/api/v1/investigations/sample' && request.method() === 'POST') samplePosts++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/checklist' && request.method() === 'POST') checklistPosts++;
  });
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(origin, {waitUntil: 'networkidle'});
  ensure(await page.locator('#nav-start').getAttribute('aria-current') === 'page', 'UI3_START_NAV_FAILED');
  ensure(await page.locator('.brand-name').innerText() === 'Security Log' &&
    await page.locator('#nav-group-investigate').evaluate((node) => node.open), 'UI4_BRAND_OR_ACTIVE_GROUP_FAILED');
  const sidebarToggle = page.locator('#workspace-sidebar-toggle');
  ensure(await sidebarToggle.evaluate((node) => node.closest('.brand-lockup') !== null) &&
    !await page.locator('.workspace-nav > #workspace-sidebar-toggle').count() &&
    await sidebarToggle.getAttribute('aria-label') === '사이드바 접기' &&
    await sidebarToggle.evaluate((node) => getComputedStyle(node.querySelector('.panel-close-icon')).display !== 'none'),
    'UI4A_HEADER_TOGGLE_PLACEMENT_FAILED');
  const expandedHeaderGeometry = await page.locator('.brand-lockup').evaluate((node) => {
    const mark = node.querySelector('.brand-mark').getBoundingClientRect();
    const copy = node.querySelector('.brand-copy').getBoundingClientRect();
    const toggle = node.querySelector('#workspace-sidebar-toggle').getBoundingClientRect();
    return {markRight: mark.right, copyRight: copy.right, toggleLeft: toggle.left,
      overlap: mark.right > toggle.left || copy.right > toggle.left};
  });
  ensure(!expandedHeaderGeometry.overlap && expandedHeaderGeometry.toggleLeft >= expandedHeaderGeometry.copyRight,
    'UI4A_HEADER_ITEMS_OVERLAP');
  for (const width of [1920, 1440, 1280, 1024, 768, 390, 320]) {
    await page.setViewportSize({width, height: 900});
    const headerGeometry = await page.locator('.brand-lockup').evaluate((node) => {
      const nav = node.closest('.workspace-nav').getBoundingClientRect();
      const mark = node.querySelector('.brand-mark').getBoundingClientRect();
      const copy = node.querySelector('.brand-copy').getBoundingClientRect();
      const toggle = node.querySelector('#workspace-sidebar-toggle').getBoundingClientRect();
      const horizontalOverlap = mark.right > toggle.left && mark.left < toggle.right ||
        copy.right > toggle.left && copy.left < toggle.right;
      return {horizontalOverlap, width: toggle.width, height: toggle.height,
        withinSidebar: toggle.left >= nav.left && toggle.right <= nav.right};
    });
    ensure(!headerGeometry.horizontalOverlap && headerGeometry.width >= 44 && headerGeometry.height >= 44 &&
      headerGeometry.withinSidebar, `UI4A_HEADER_REFLOW_FAILED_${width}`);
    ensure(await page.evaluate(() => document.documentElement.scrollWidth === window.innerWidth),
      `UI4A_HEADER_OVERFLOW_${width}`);
  }
  await page.evaluate(() => { document.documentElement.style.fontSize = '32px'; });
  ensure(await page.evaluate(() => document.documentElement.scrollWidth === window.innerWidth), 'UI4A_HEADER_200_PERCENT_OVERFLOW');
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 900});
  await sidebarToggle.click();
  ensure(await page.locator('#workspace-nav').evaluate((node) => node.classList.contains('sidebar-collapsed')) &&
    await page.locator('.app-shell').evaluate((node) => Math.round(getComputedStyle(node).gridTemplateColumns.split(' ')[0].replace('px', ''))) === 88 &&
    await sidebarToggle.getAttribute('aria-label') === '사이드바 펼치기' &&
    await sidebarToggle.evaluate((node) => getComputedStyle(node.querySelector('.panel-open-icon')).display !== 'none') &&
    await page.locator('#nav-start').getAttribute('title') === '시작' &&
    await page.locator('#nav-start > span').innerText() === '시작', 'UI4_SIDEBAR_COLLAPSE_FAILED');
  await page.keyboard.press('Enter');
  ensure(!await page.locator('#workspace-nav').evaluate((node) => node.classList.contains('sidebar-collapsed')) &&
    await page.locator('#nav-start').getAttribute('aria-current') === 'page' &&
    !await page.locator('#nav-group-tools').evaluate((node) => node.open), 'UI4_SIDEBAR_EXPAND_FAILED');
  const toolsGroupToggle = page.locator('#nav-group-tools > summary');
  await toolsGroupToggle.focus();
  await page.keyboard.press('Space');
  ensure(await page.locator('#nav-group-tools').evaluate((node) => node.open), 'UI4_GROUP_KEYBOARD_OPEN_FAILED');
  await page.keyboard.press('Space');
  ensure(!await page.locator('#nav-group-tools').evaluate((node) => node.open), 'UI4_GROUP_KEYBOARD_CLOSE_FAILED');
  await page.setViewportSize({width: 390, height: 844});
  await page.waitForFunction(() => window.matchMedia('(max-width: 47.9375rem)').matches &&
    !document.querySelector('#workspace-nav-details').open);
  ensure(await sidebarToggle.isVisible() && await sidebarToggle.getAttribute('aria-label') === '사이드바 펼치기' &&
    await sidebarToggle.getAttribute('aria-controls') === 'workspace-nav-details', 'UI4A_MOBILE_TOGGLE_STATE_FAILED');
  await sidebarToggle.click();
  ensure(await sidebarToggle.getAttribute('aria-label') === '사이드바 접기' &&
    await page.locator('#workspace-nav-details').evaluate((node) => node.open), 'UI4A_MOBILE_NAV_OPEN_FAILED');
  await sidebarToggle.click();
  ensure(await sidebarToggle.getAttribute('aria-label') === '사이드바 펼치기' &&
    !await page.locator('#workspace-nav-details').evaluate((node) => node.open), 'UI4A_MOBILE_NAV_CLOSE_FAILED');
  await page.setViewportSize({width: 1440, height: 900});
  await page.locator('#sample-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  ensure(!await page.locator('#nav-group-results').evaluate((node) => node.hidden) &&
    await page.locator('#nav-group-results').evaluate((node) => node.open), 'UI4_RESULT_GROUP_AVAILABILITY_FAILED');
  await page.locator('#case-list a[data-review-case-ref]').nth(1).waitFor({state: 'attached'});
  const refs = await page.locator('#case-list a[data-review-case-ref]').evaluateAll((nodes) =>
    nodes.map((node) => node.dataset.reviewCaseRef));
  ensure(samplePosts === 1 && refs.length >= 2 && refs.every((ref) => /^c_[0-9a-f]{24}$/.test(ref)) &&
    guidancePosts === 0 && checklistPosts === 0, 'UI3_SAMPLE_DASHBOARD_OR_OPT_IN_FAILED');

  const caseALink = page.locator(`#review-case-link-${refs.indexOf(refs[0])}`);
  await caseALink.focus();
  await caseALink.hover();
  await caseALink.press('Enter');
  await page.locator('.workspace-detail-shell-36-6b').waitFor({state: 'visible'});
  ensure(new URL(page.url()).hash === `#/investigations/${refs[0]}` &&
    await page.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === refs[0] &&
    guidancePosts === 0, 'UI3_CASE_A_ROUTE_FAILED');

  const tasksTab = page.getByRole('tab', {name: '확인할 작업'});
  const evidenceTab = page.getByRole('tab', {name: '근거와 한계'});
  await tasksTab.focus();
  await tasksTab.hover();
  await tasksTab.click();
  ensure(await page.locator('.workspace-checklist-request-36-6e').count() === 1 && guidancePosts === 0 && checklistPosts === 0,
    'UI3_TASKS_TAB_CHANGED_REQUEST_STATE');
  await evidenceTab.focus();
  await evidenceTab.hover();
  await evidenceTab.click();
  const guidanceButton = page.locator('#workspace-evidence-panel-36-6e .guidance-request');
  ensure(await guidanceButton.count() === 1 && guidancePosts === 0 && checklistPosts === 0,
    'UI3_EVIDENCE_TAB_CHANGED_REQUEST_STATE');
  const disclosure = page.locator('#workspace-evidence-panel-36-6e details summary').first();
  if (await disclosure.count()) {
    await disclosure.focus();
    await page.keyboard.press('Space');
    await page.keyboard.press('Space');
  }
  ensure(guidancePosts === 0 && checklistPosts === 0, 'UI3_DISCLOSURE_TRIGGERED_GUIDANCE');

  await guidanceButton.focus();
  const started = page.waitForRequest((request) =>
    new URL(request.url()).pathname === '/api/v1/investigations/guidance');
  await page.keyboard.press('Enter');
  const guidanceRequest = await started;
  const submitted = await guidanceStarted;
  ensure(submitted.case.case_id && guidancePosts === 1 && guidanceRequest.method() === 'POST' &&
    await guidanceButton.isDisabled(), 'UI3_GUIDANCE_EXPLICIT_LOADING_FAILED');

  await page.goBack();
  await page.locator('#case-list').waitFor({state: 'visible'});
  await page.goForward();
  await page.locator('.workspace-detail-shell-36-6b').waitFor({state: 'visible'});
  ensure(new URL(page.url()).hash === `#/investigations/${refs[0]}` && guidancePosts === 1,
    'UI3_HISTORY_RESTORED_WRONG_CASE_OR_POSTED');
  await page.locator('#review-back-link').click();
  await page.locator('#case-list').waitFor({state: 'visible'});
  await page.locator(`#review-case-link-${refs.indexOf(refs[1])}`).click();
  await page.locator('.workspace-detail-shell-36-6b').waitFor({state: 'visible'});
  ensure(new URL(page.url()).hash === `#/investigations/${refs[1]}` &&
    await page.locator('.workspace-detail-shell-36-6b').getAttribute('data-case-ref') === refs[1],
    'UI3_CASE_B_ROUTE_FAILED');

  releaseGuidance();
  await guidanceResponseSent;
  await page.getByRole('tab', {name: '근거와 한계'}).click();
  await page.waitForTimeout(250);
  const caseBText = await page.locator('.workspace-detail-shell-36-6b').innerText();
  ensure(guidancePosts === 1 && !caseBText.includes('PRIVATE_GUIDANCE_CANARY') &&
    !caseBText.includes('지연 응답') && await page.locator('.guidance-citation script').count() === 0,
    'UI3_GUIDANCE_CASE_ISOLATION_OR_TEXT_RENDERING_FAILED');

  const staleRef = refs[0];
  const staleRoutePage = await context.newPage();
  await staleRoutePage.goto(`${origin}/#/investigations/${staleRef}`, {waitUntil: 'networkidle'});
  ensure(await staleRoutePage.locator('#review-route-expired').isVisible() &&
    await staleRoutePage.getByRole('button', {name: '분석 결과로 돌아가기'}).isVisible() && guidancePosts === 1,
    'UI3_DIRECT_OR_PREVIOUS_ANALYSIS_ROUTE_NOT_EXPIRED');
  await staleRoutePage.close();

  const badRoute = await context.newPage();
  await badRoute.goto(`${origin}/#/investigations/not-a-case-reference`, {waitUntil: 'networkidle'});
  await badRoute.goto(`${origin}/#/investigations/c_000000000000000000000000`, {waitUntil: 'networkidle'});
  ensure(await badRoute.locator('#review-route-expired').isVisible(), 'UI3_INVALID_CASE_ROUTE_NOT_EXPIRED');
  const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  ensure(externalRequests === 0 && !horizontalOverflow, 'UI3_EXTERNAL_REQUEST_OR_OVERFLOW');
  console.log(`UI3_NAVIGATION_CLOSURE ${JSON.stringify({samplePosts, guidancePosts, checklistPosts,
    refs: refs.length, delayedCaseResponseIsolated: true, invalidAndStaleRoutesExpired: true,
    externalRequests, cspVerified: true})}`);
  await badRoute.close();
} finally {
  if (releaseGuidance) releaseGuidance();
  await context?.close();
  await browser?.close();
  if (child.exitCode === null) await new Promise((done) => { child.once('exit', done); child.kill('SIGINT'); });
  await rm(home, {recursive: true, force: true});
  let listening = false;
  try { await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(250)}); listening = true; }
  catch { /* Expected once the isolated server has stopped. */ }
  ensure(!listening, 'UI3_LOOPBACK_LISTENER_REMAINED');
}
