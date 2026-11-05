// Phase 36.13A review queue interaction contract; synthetic sample only.
import {chromium, webkit} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm, stat} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const chooseRadio = (group, value) => group.locator(`input[type="radio"][value="${value}"]`).check();
const selectedRadio = (group) => group.locator('input[type="radio"]:checked').inputValue();
const home = await mkdtemp(join(tmpdir(), 'review-queue-36-13a-'));
await mkdir(join(home, 'config'));
const socket = createServer();
await new Promise((done) => socket.listen(0, '127.0.0.1', done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const origin = `http://127.0.0.1:${port}`;
const child = spawn(join(root, '.venv', 'bin', 'python'), [
  '-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log',
], {cwd: root, stdio: 'ignore', env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config') }});
let browser;
let context;
let externalRequests = 0;
let apiRequests = 0;
let checklistPosts = 0;
let samplePosts = 0;
let pageErrors = 0;
let consoleErrors = 0;
const consoleErrorCategories = {favicon: 0, asset_resource: 0, sample_api_resource: 0,
  checklist_api_resource: 0, text_api_resource: 0, file_api_resource: 0,
  other_api_resource: 0, other_resource: 0, csp: 0, runtime: 0, other: 0};
const consoleErrorDetails = [];
let syntheticBenchmark = null;
let productionAssetBytes = null;
const ensure = (value, code) => { if (!value) throw new Error(code); };

try {
  let ready = false;
  for (let index = 0; index < 100; index++) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; }
    catch { /* local server startup */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'QUEUE_SERVER_START_FAILED');
  const browserType = process.env.UI_BROWSER === 'webkit' ? webkit : chromium;
  if (!['chromium', 'webkit'].includes(process.env.UI_BROWSER || 'chromium')) throw new Error('QUEUE_UNSUPPORTED_BROWSER');
  browser = await browserType.launch({headless: true, args: ['--disable-background-networking', '--no-first-run']});
  context = await browser.newContext({serviceWorkers: 'block'});
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      externalRequests++;
      await route.abort();
      return;
    }
    await route.continue();
  });
  await context.route(`${origin}/api/v1/live/status`, async (route) => {
    await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({
      schema_version: '2', service_state: 'STOPPED', session_id: 'SYNTHETIC-QUEUE-SESSION',
      source_role: 'ssh', worker_state: 'STOPPED', publication_state: 'CLOSED',
      latest_detection_revision: 0, available_event_count: 0, earliest_event_id: null,
      latest_event_id: null, active_observation_count: 0, published_total: 0, evicted_total: 0,
      replay_gap_total: 0, max_event_items: 32, max_event_bytes: 16384, max_connections: 2,
      active_connections: 0, fixed_error_code: null, recovery_action: null,
      interpretation_notices: ['규칙 기반의 로컬 관찰이며 침해나 공격 성공을 확정하지 않습니다.'],
      capabilities: ['READ_ONLY_STATUS', 'NO_LLM'], analysis_available: true,
      analysis_revision: 0, active_relation_count: 0, active_risk_count: 0,
      active_case_count: 0, analysis_state: 'AVAILABLE'
    })});
  });
  const page = await context.newPage();
  page.on('pageerror', () => { pageErrors++; });
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    consoleErrors++;
    const text = message.text();
    let category;
    if (text.toLowerCase().includes('favicon')) category = 'favicon';
    else if (text.includes('Failed to load resource')) {
      const path = new URL(message.location().url || 'http://127.0.0.1/').pathname;
      category = path.startsWith('/assets/') ? 'asset_resource' :
        path === '/api/v1/investigations/sample' ? 'sample_api_resource' :
        path === '/api/v1/investigations/checklist' ? 'checklist_api_resource' :
        path === '/api/v1/investigations/text' ? 'text_api_resource' :
        path === '/api/v1/investigations' ? 'file_api_resource' :
        path.startsWith('/api/') ? 'other_api_resource' : 'other_resource';
    } else if (text.includes('Content Security Policy')) category = 'csp';
    else if (text.includes('Uncaught')) category = 'runtime';
    else category = 'other';
    consoleErrorCategories[category]++;
    consoleErrorDetails.push({category, text, location: message.location()});
  });
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && url.pathname.startsWith('/api/')) apiRequests++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/sample' && request.method() === 'POST') samplePosts++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/checklist' && request.method() === 'POST') checklistPosts++;
  });
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(origin, {waitUntil: 'networkidle'});
  await page.locator('#sample-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  const requestsBeforeQueueInteractions = apiRequests;
  const queueHeadingCount = await page.locator('#case-list-heading').count();
  ensure(queueHeadingCount === 1, `QUEUE_CONTROLS_MISSING_${queueHeadingCount}`);
  const cards = page.locator('#case-list .review-case-card');
  const total = await cards.count();
  ensure(total > 0 && (await page.locator('#review-queue-count-36-13a').innerText()) ===
    `${total}건`, 'QUEUE_INITIAL_ORDER_OR_COUNT_FAILED');
  ensure(await page.locator('#review-queue-filter-panel-36-13a').count() === 1 &&
    !(await page.locator('#review-queue-filter-panel-36-13a').evaluate((node) => node.open)) &&
    await page.locator('#review-queue-risk-36-13a').isHidden() &&
    await page.locator('#review-queue-reset-36-13a').isHidden() &&
    await page.locator('#review-queue-filter-chips-36-13a').isHidden(),
  'QUEUE_COMPACT_DEFAULT_DENSITY_FAILED');
  const filterToggle = page.locator('#review-queue-filter-toggle-36-13a');
  ensure(await filterToggle.getAttribute('aria-expanded') === 'false' &&
    await filterToggle.getAttribute('aria-controls') === 'review-queue-filter-panel-36-13a',
  'QUEUE_FILTER_DISCLOSURE_RELATION_FAILED');
  const cardsTop = await cards.first().evaluate((node) => node.getBoundingClientRect().top);
  const controlsHeight = await page.locator('#review-queue-controls-36-13a')
    .evaluate((node) => node.getBoundingClientRect().height);
  ensure(controlsHeight < 180 && cardsTop < 900, 'QUEUE_COMPACT_VERTICAL_DENSITY_FAILED');
  const qualityPanel = page.locator('#input-quality-summary-36-12b');
  await page.evaluate(() => {
    const panel = document.getElementById('input-quality-summary-36-12b');
    const heading = document.createElement('h3');
    heading.id = 'input-quality-heading-36-12b';
    heading.textContent = 'TEST_ONLY_SYNTHETIC_STATE — 입력 품질 요약';
    panel.replaceChildren(heading);
    panel.hidden = false;
  });
  const qualityPanelText = await qualityPanel.innerText();
  const search = page.getByRole('searchbox', {name: '검토 건 검색'});
  const firstTitle = await cards.first().locator('.review-card-title').innerText();
  const firstRef = await cards.first().locator('a[data-review-case-ref]').getAttribute('data-review-case-ref');
  const initialTitles = await cards.locator('.review-card-title').allInnerTexts();
  await search.fill(`  ${firstTitle}  `);
  ensure(await cards.count() === 1 && await page.locator('#review-queue-count-36-13a').innerText() ===
    `전체 ${total}건 중 1건`, 'QUEUE_TRIMMED_SEARCH_FAILED');
  ensure(!page.url().includes(firstTitle), 'QUEUE_SEARCH_LEAKED_IN_URL');
  await search.fill('검색 결과 없음');
  ensure(await cards.count() === 0 && await page.locator('#review-queue-empty-36-13a').isVisible() &&
    (await page.locator('#review-queue-empty-36-13a').innerText()).includes('분석 결과가 없다는 뜻은 아닙니다'),
  'QUEUE_EMPTY_STATE_SEMANTICS_FAILED');
  ensure(await qualityPanel.isVisible() && await qualityPanel.innerText() === qualityPanelText,
    'QUEUE_FILTER_HID_INPUT_QUALITY_SUMMARY');
  await page.locator('#review-queue-empty-36-13a button').click();
  ensure(await cards.count() === total && await search.inputValue() === '', 'QUEUE_EMPTY_RESET_FAILED');

  await filterToggle.click();
  ensure(await filterToggle.getAttribute('aria-expanded') === 'true' &&
    await page.locator('#review-queue-filter-panel-36-13a').isVisible(), 'QUEUE_FILTER_PANEL_OPEN_FAILED');
  const risk = page.locator('#review-queue-risk-36-13a');
  await chooseRadio(risk, 'HIGH');
  ensure(await cards.count() === 1 && (await cards.first().locator('.review-status-badge').first().innerText()).includes('높음'),
    'QUEUE_RISK_FILTER_FAILED');
  ensure(await page.locator('#review-queue-filter-count-36-13a').innerText() === '1개' &&
    await page.locator('#review-queue-filter-chips-36-13a').isVisible(), 'QUEUE_ACTIVE_FILTER_CHIP_MISSING');
  await page.waitForFunction(() => document.getElementById('review-queue-count-announcement-36-13a').textContent === '전체 2건 중 1건');
  await chooseRadio(risk, 'MEDIUM');
  ensure(await cards.count() === 0, 'QUEUE_RISK_MEDIUM_FILTER_FAILED');
  const role = page.locator('#review-queue-role-36-13a');
  await chooseRadio(role, 'application');
  ensure(await cards.count() === 0, 'QUEUE_ROLE_FILTER_FAILED');
  ensure(await page.locator('#review-queue-active-chip-list-36-13a [data-review-queue-chip="role"]').count() === 1,
    'QUEUE_ROLE_FILTER_CHIP_MISSING');
  await page.locator('#review-queue-active-chip-list-36-13a [data-review-queue-chip="role"]').click();
  ensure(await selectedRadio(role) === 'all' && await selectedRadio(risk) === 'MEDIUM', 'QUEUE_FILTER_CHIP_REMOVE_FAILED');
  await chooseRadio(role, 'unknown');
  const priority = page.locator('#review-queue-priority-36-13a');
  await chooseRadio(priority, 'review_now');
  ensure(await cards.count() === 0, 'QUEUE_PRIORITY_FILTER_FAILED');
  await chooseRadio(priority, 'undetermined');
  await chooseRadio(risk, 'all');
  await page.locator('#review-queue-filter-close-36-13a').click();
  ensure(await page.locator('#review-queue-filter-panel-36-13a').isHidden() &&
    await page.evaluate(() => document.activeElement.id) === 'review-queue-filter-toggle-36-13a',
  'QUEUE_FILTER_CLOSE_FOCUS_FAILED');
  await filterToggle.click();
  await page.keyboard.press('Escape');
  ensure(await page.locator('#review-queue-filter-panel-36-13a').isHidden() &&
    await page.evaluate(() => document.activeElement.id) === 'review-queue-filter-toggle-36-13a',
  'QUEUE_FILTER_ESCAPE_FOCUS_FAILED');
  await search.fill(firstTitle);
  ensure(await cards.count() === 1, 'QUEUE_AND_FILTER_COMBINATION_FAILED');

  await search.fill('');
  await filterToggle.click();
  await chooseRadio(priority, 'all');
  await page.locator('#review-queue-filter-close-36-13a').click();
  const sort = page.locator('#review-queue-sort-36-13a');
  await chooseRadio(sort, 'oldest');
  const oldestTitles = await cards.locator('.review-card-title').allInnerTexts();
  await chooseRadio(sort, 'newest');
  const newestTitles = await cards.locator('.review-card-title').allInnerTexts();
  ensure(oldestTitles.length === total && newestTitles.length === total &&
    (total < 2 || oldestTitles[0] !== newestTitles[0]), 'QUEUE_TIME_SORT_FAILED');
  await chooseRadio(sort, 'title');
  const titleSorted = await cards.locator('.review-card-title').allInnerTexts();
  ensure(JSON.stringify(titleSorted) === JSON.stringify([...titleSorted].sort((a, b) => {
    const left = a.normalize('NFKC').trim().toLowerCase();
    const right = b.normalize('NFKC').trim().toLowerCase();
    return left < right ? -1 : left > right ? 1 : 0;
  })), 'QUEUE_TITLE_SORT_FAILED');
  await chooseRadio(sort, 'default');
  ensure(JSON.stringify(await cards.locator('.review-card-title').allInnerTexts()) === JSON.stringify(initialTitles),
    'QUEUE_DEFAULT_ORDER_NOT_PRESERVED');
  ensure(apiRequests === requestsBeforeQueueInteractions, 'QUEUE_FILTER_TRIGGERED_API_REQUEST');

  const axe = await new AxeBuilder({page}).analyze();
  ensure(axe.violations.length === 0, `QUEUE_AXE_VIOLATIONS_${axe.violations.map((item) => item.id).join('_')}`);
  let focusOutline;
  if (process.env.UI_BROWSER === 'webkit') {
    // Playwright's macOS WebKit honors the platform setting that Tab skips buttons.
    // Focus the native button explicitly, then exercise its keyboard activation.
    await filterToggle.focus();
    focusOutline = await filterToggle.evaluate((node) => getComputedStyle(node).outlineStyle !== 'none');
    await page.keyboard.press('Enter');
  } else {
    await search.click();
    await page.keyboard.press('Tab');
    focusOutline = await filterToggle.evaluate((node) => getComputedStyle(node).outlineStyle !== 'none');
    ensure(await page.evaluate(() => document.activeElement.id) === 'review-queue-filter-toggle-36-13a',
      'QUEUE_FILTER_BUTTON_KEYBOARD_FOCUS_FAILED');
    await page.keyboard.press('Enter');
  }
  ensure(await filterToggle.getAttribute('aria-expanded') === 'true', 'QUEUE_FILTER_BUTTON_KEYBOARD_TOGGLE_FAILED');
  if (process.env.UI_BROWSER === 'webkit') {
    const allRisk = risk.locator('input[value="all"]');
    await allRisk.focus();
    await page.keyboard.press('ArrowRight');
    const webkitRadioResult = {selected: await selectedRadio(risk), focusVisible:
      await allRisk.evaluate((node) => node.matches(':focus-visible')),
      active: await page.evaluate(() => ({name: document.activeElement.name, value: document.activeElement.value}))};
    ensure(webkitRadioResult.selected === 'HIGH' && webkitRadioResult.active.name === 'review-queue-risk-36-13a',
      `QUEUE_WEBKIT_RADIO_KEYBOARD_OPERATION_FAILED_${JSON.stringify(webkitRadioResult)}`);
  } else {
    const tabOrder = [await page.evaluate(() => document.activeElement.id)];
    for (let index = 0; index < 9; index++) {
      await page.keyboard.press('Tab');
      tabOrder.push(await page.evaluate(() => document.activeElement.name || document.activeElement.id ||
        (document.activeElement.dataset.reviewQueueChip ? `chip-${document.activeElement.dataset.reviewQueueChip}` :
          document.activeElement.tagName.toLowerCase())));
    }
    ensure(focusOutline && JSON.stringify(tabOrder) === JSON.stringify([
      'review-queue-filter-toggle-36-13a', 'review-queue-sort-36-13a',
      'review-queue-risk-36-13a', 'review-queue-role-36-13a', 'review-queue-priority-36-13a',
      'review-queue-state-36-14d', 'review-queue-filter-close-36-13a', 'chip-role', 'review-queue-reset-36-13a', 'review-case-link-0'
    ]), `QUEUE_KEYBOARD_ORDER_FAILED_${tabOrder.join('_')}`);
  }
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({width, height: 900});
    ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth), `QUEUE_HORIZONTAL_OVERFLOW_${width}`);
    const controls = await page.locator('#review-queue-controls-36-13a').evaluate((node) => ({
      width: node.getBoundingClientRect().width,
      targets: [...node.querySelectorAll('input[type="search"],button,.review-queue-radio-options-36-13a label')].filter((target) => target.getClientRects().length > 0).map((target) => ({
        width: target.getBoundingClientRect().width, height: target.getBoundingClientRect().height
      }))
    }));
    ensure(controls.width > 0 && controls.targets.every((target) => target.width > 0 && target.height >= 44),
      `QUEUE_CONTROL_TARGET_SIZE_${width}`);
  }
  await page.evaluate(() => { document.documentElement.style.fontSize = '32px'; });
  ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth), 'QUEUE_200_PERCENT_REFLOW_OVERFLOW');
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 900});

  await search.fill(firstTitle);
  await page.locator('#case-list a[data-review-case-ref]').click();
  await page.locator('.workspace-detail-shell-36-6b').waitFor({state: 'visible'});
  ensure(new URL(page.url()).hash === `#/investigations/${firstRef}` && checklistPosts === 0,
    'QUEUE_DETAIL_ROUTE_OR_OPT_IN_FAILED');
  await page.goBack();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  ensure(await search.inputValue() === firstTitle && await cards.count() === 1,
    'QUEUE_IN_MEMORY_BACK_RESTORE_FAILED');
  ensure(samplePosts === 1 && checklistPosts === 0, 'QUEUE_FILTERS_TRIGGERED_REQUEST');
  await page.locator('#nav-start').click();
  await page.locator('#sample-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible'});
  ensure(await search.inputValue() === '' && await cards.count() === total,
    'QUEUE_NEW_ANALYSIS_DID_NOT_RESET');
  const stale = await context.newPage();
  await stale.setViewportSize({width: 1440, height: 900});
  await stale.goto(`${origin}/#/investigations/${firstRef}`, {waitUntil: 'networkidle'});
  await stale.locator('#review-route-expired').waitFor({state: 'visible'});
  ensure(await stale.locator('#review-queue-controls-36-13a').isHidden() &&
    await stale.locator('#case-list .review-case-card').count() === 0, 'QUEUE_STALE_ROUTE_REUSED_SUMMARY');
  await stale.close();

  const fixture = await context.newPage();
  await fixture.setContent(`<!doctype html><html lang="ko"><head><title>합성 큐 검사</title></head><body><main><h1>검토 작업 목록</h1>
    <section id="review-queue-controls-36-13a" aria-labelledby="review-queue-heading-36-13a">
      <h2 id="review-queue-heading-36-13a">검토 건 찾기</h2>
      <label for="review-queue-search-36-13a">검토 건 검색<input id="review-queue-search-36-13a" type="search" maxlength="100"></label>
      <button id="review-queue-filter-toggle-36-13a" aria-expanded="false" aria-controls="review-queue-filter-panel-36-13a">필터 <span id="review-queue-filter-count-36-13a">0개</span></button>
      <div id="review-queue-filter-panel-36-13a" hidden>
        <fieldset id="review-queue-risk-36-13a"><legend>위험도</legend><label><input type="radio" name="review-queue-risk-36-13a" value="all" checked>전체</label><label><input type="radio" name="review-queue-risk-36-13a" value="HIGH">높음</label><label><input type="radio" name="review-queue-risk-36-13a" value="MEDIUM">보통</label><label><input type="radio" name="review-queue-risk-36-13a" value="LOW">낮음</label></fieldset>
        <fieldset id="review-queue-role-36-13a"><legend>로그 역할</legend><label><input type="radio" name="review-queue-role-36-13a" value="all" checked>전체</label><label><input type="radio" name="review-queue-role-36-13a" value="application">애플리케이션 로그</label><label><input type="radio" name="review-queue-role-36-13a" value="ssh">SSH 인증 로그</label><label><input type="radio" name="review-queue-role-36-13a" value="access">접근 로그</label><label><input type="radio" name="review-queue-role-36-13a" value="unknown">역할 미확인</label></fieldset>
        <fieldset id="review-queue-priority-36-13a"><legend>확인 순서</legend><label><input type="radio" name="review-queue-priority-36-13a" value="all" checked>전체</label><label><input type="radio" name="review-queue-priority-36-13a" value="review_now">먼저 확인</label><label><input type="radio" name="review-queue-priority-36-13a" value="review_soon">우선 확인</label><label><input type="radio" name="review-queue-priority-36-13a" value="review_later">일반 확인</label><label><input type="radio" name="review-queue-priority-36-13a" value="undetermined">확인 순서 미정</label></fieldset>
        <button id="review-queue-filter-close-36-13a" type="button">닫기</button>
      </div>
      <fieldset id="review-queue-sort-36-13a"><legend>정렬</legend><label><input type="radio" name="review-queue-sort-36-13a" value="default" checked>기본 검토 순서</label><label><input type="radio" name="review-queue-sort-36-13a" value="risk">위험도 높은 순</label><label><input type="radio" name="review-queue-sort-36-13a" value="newest">최근 관찰 순</label><label><input type="radio" name="review-queue-sort-36-13a" value="oldest">오래된 관찰 순</label><label><input type="radio" name="review-queue-sort-36-13a" value="title">제목 순</label></fieldset>
      <div id="review-queue-filter-chips-36-13a" hidden><div id="review-queue-active-chip-list-36-13a"></div><button id="review-queue-reset-36-13a" type="button">조건 초기화</button></div>
      <span id="review-queue-total-36-13a"></span>
      <p id="review-queue-count-36-13a"></p><span id="review-queue-count-announcement-36-13a" class="review-queue-sr-only-36-13a" aria-live="polite" aria-atomic="true"></span>
      <div id="review-queue-empty-36-13a" hidden><p>현재 조건에 맞는 검토 건이 없습니다. 분석 결과가 없다는 뜻은 아닙니다.</p><button data-review-queue-reset type="button">조건 초기화</button></div>
    </section><div id="case-list" role="list"></div></main></body></html>`);
  await fixture.addScriptTag({path: join(root, 'frontend/review-queue-ui-36-13a.js')});
  const fixtureResult = await fixture.evaluate(() => {
    const queue = window.reviewQueueUi36_13a.create();
    const rows = Array.from({length: 100}, (_, index) => {
      const title = index === 0 ? 'Brute Force' : index === 1 ? '카페 관찰' :
        index === 70 ? 'Brute Force' : `Synthetic case ${String(index).padStart(3, '0')}`;
      const projection = {
        schema_version: 'investigation-workspace-ui/v1', case_ref: `c_${index.toString(16).padStart(24, '0')}`,
        display_title: title, category: 'authentication', summary: '고정 합성 요약 문구',
        risk_band: ['HIGH', 'MEDIUM', 'LOW'][index % 3],
        source_role: ['application', 'ssh', 'access', 'unknown'][index % 4],
        review_priority: ['review_now', 'review_soon', 'review_later', 'undetermined'][index % 4],
        start_time_utc: index % 11 === 0 ? null : new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
        end_time_utc: index % 11 === 0 ? null : new Date(Date.UTC(2026, 0, 1, 0, 1, 99 - index)).toISOString(),
        account: 'QUEUE_ACCOUNT_CANARY', ip: 'QUEUE_IP_CANARY', hostname: 'QUEUE_HOST_CANARY',
        checkpoint: 'QUEUE_CHECKPOINT_CANARY', input_path: 'QUEUE_PATH_CANARY',
        credential: 'QUEUE_CREDENTIAL_CANARY', citation: 'QUEUE_CITATION_CANARY',
        raw_log: 'QUEUE_RAW_CANARY'
      };
      const card = document.createElement('div');
      card.setAttribute('role', 'listitem');
      card.dataset.testRow = String(index);
      const titleNode = document.createElement('h3');
      titleNode.textContent = title;
      const priorityBadge = document.createElement('span');
      const roleBadge = document.createElement('span');
      card.append(titleNode, priorityBadge, roleBadge);
      return {projection, card, priorityBadge, roleBadge, index};
    });
    const durations = {initial: [], search: [], combined: [], risk_sort: [], title_sort: [], reset: []};
    const search = document.getElementById('review-queue-search-36-13a');
    const risk = document.getElementById('review-queue-risk-36-13a');
    const role = document.getElementById('review-queue-role-36-13a');
    const priority = document.getElementById('review-queue-priority-36-13a');
    const sort = document.getElementById('review-queue-sort-36-13a');
    const choose = (group, value) => { group.querySelector(`input[value="${value}"]`).checked = true; };
    const measure = (fn) => { const start = performance.now(); fn(); return performance.now() - start; };
    for (let run = 0; run < 25; run++) {
      queue.begin(true);
      const initial = measure(() => { rows.forEach((row) => queue.add(row.projection, row.card,
        row.index, row.priorityBadge, row.roleBadge)); queue.render(); });
      search.value = 'synthetic case 042';
      const searched = measure(() => search.dispatchEvent(new Event('input', {bubbles: true})));
      search.value = 'synthetic case 042'; choose(risk, 'HIGH'); choose(role, 'access'); choose(priority, 'review_later');
      const combined = measure(() => [risk, role, priority].forEach((control) =>
        control.dispatchEvent(new Event('change', {bubbles: true}))));
      search.value = ''; [risk, role, priority].forEach((control) => choose(control, 'all'));
      choose(sort, 'risk');
      const riskSort = measure(() => sort.dispatchEvent(new Event('change', {bubbles: true})));
      choose(sort, 'title');
      const titleSort = measure(() => sort.dispatchEvent(new Event('change', {bubbles: true})));
      const reset = measure(() => document.getElementById('review-queue-reset-36-13a').click());
      if (run >= 5) {
        durations.initial.push(initial); durations.search.push(searched); durations.combined.push(combined);
        durations.risk_sort.push(riskSort); durations.title_sort.push(titleSort); durations.reset.push(reset);
      }
    }
    const percentile = (values, fraction) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * fraction) - 1];
    const stats = Object.fromEntries(Object.entries(durations).map(([key, values]) => [key, {
      median_ms: Number(percentile(values, .5).toFixed(3)),
      p95_ms: Number(percentile(values, .95).toFixed(3)),
      max_ms: Number(Math.max(...values).toFixed(3)), samples: values.length
    }]));
    const domNodes = document.querySelectorAll('*').length;
    const htmlBytes = new TextEncoder().encode(document.body.innerHTML).byteLength;
    const searchBound = search.maxLength;
    search.value = 'ＢＲＵＴＥ ＦＯＲＣＥ';
    search.dispatchEvent(new Event('input', {bubbles: true}));
    const normalizedSearchCount = document.querySelectorAll('#case-list [data-test-row]').length;
    search.value = '카페 관찰'.normalize('NFD');
    search.dispatchEvent(new Event('input', {bubbles: true}));
    const unicodeSearchCount = document.querySelectorAll('#case-list [data-test-row]').length;
    for (const canary of ['QUEUE_ACCOUNT_CANARY', 'QUEUE_IP_CANARY', 'QUEUE_HOST_CANARY',
      'QUEUE_CHECKPOINT_CANARY', 'QUEUE_PATH_CANARY', 'QUEUE_CREDENTIAL_CANARY',
      'QUEUE_CITATION_CANARY', 'QUEUE_RAW_CANARY', rows[0].projection.case_ref]) {
      search.value = canary;
      search.dispatchEvent(new Event('input', {bubbles: true}));
      if (document.querySelectorAll('#case-list [data-test-row]').length !== 0) throw new Error('QUEUE_SEARCH_SCOPE_FAILED');
    }
    const canaryDomLeak = document.body.innerHTML.includes('QUEUE_');
    search.value = '<img src=x onerror=alert(1)>';
    search.dispatchEvent(new Event('input', {bubbles: true}));
    const injectionElements = document.querySelectorAll('#case-list img, #case-list script').length;
    const riskOrder = (() => {
      search.value = ''; choose(risk, 'all'); choose(role, 'all'); choose(priority, 'all'); choose(sort, 'risk');
      sort.dispatchEvent(new Event('change', {bubbles: true}));
      return [...document.querySelectorAll('#case-list [data-test-row]')].slice(0, 5).map((node) => Number(node.dataset.testRow));
    })();
    const roleCounts = {};
    for (const roleValue of ['application', 'ssh', 'access', 'unknown']) {
      choose(role, roleValue); role.dispatchEvent(new Event('change', {bubbles: true}));
      roleCounts[roleValue] = document.querySelectorAll('#case-list [data-test-row]').length;
    }
    choose(role, 'all'); role.dispatchEvent(new Event('change', {bubbles: true}));
    const priorityCounts = {};
    for (const priorityValue of ['review_now', 'review_soon', 'review_later', 'undetermined']) {
      choose(priority, priorityValue); priority.dispatchEvent(new Event('change', {bubbles: true}));
      priorityCounts[priorityValue] = document.querySelectorAll('#case-list [data-test-row]').length;
    }
    choose(priority, 'all'); priority.dispatchEvent(new Event('change', {bubbles: true}));
    search.value = 'synthetic case 042'; choose(risk, 'HIGH'); choose(role, 'access'); choose(priority, 'review_later');
    search.dispatchEvent(new Event('input', {bubbles: true}));
    const andFilterCount = document.querySelectorAll('#case-list [data-test-row]').length;
    search.value = ''; [risk, role, priority].forEach((control) => choose(control, 'all'));
    [search, risk, role, priority].forEach((control) => control.dispatchEvent(new Event(
      control === search ? 'input' : 'change', {bubbles: true})));
    const newestOrder = (() => {
      choose(sort, 'newest'); sort.dispatchEvent(new Event('change', {bubbles: true}));
      return [...document.querySelectorAll('#case-list [data-test-row]')].map((node) => Number(node.dataset.testRow));
    })();
    const oldestOrder = (() => {
      choose(sort, 'oldest'); sort.dispatchEvent(new Event('change', {bubbles: true}));
      return [...document.querySelectorAll('#case-list [data-test-row]')].map((node) => Number(node.dataset.testRow));
    })();
    const titleOrder = (() => {
      choose(sort, 'title'); sort.dispatchEvent(new Event('change', {bubbles: true}));
      return [...document.querySelectorAll('#case-list [data-test-row]')].map((node) => Number(node.dataset.testRow));
    })();
    const finalOrder = (() => {
      choose(sort, 'default'); sort.dispatchEvent(new Event('change', {bubbles: true}));
      return [...document.querySelectorAll('#case-list [data-test-row]')].map((node) => Number(node.dataset.testRow));
    })();
    const labelNames = ['검토 건 검색', '위험도', '로그 역할', '확인 순서', '정렬']
      .map((label, index) => index === 0 ?
        [...document.querySelectorAll('label')].some((node) => node.textContent.includes(label)) :
        [...document.querySelectorAll('fieldset')].some((node) => node.querySelector('legend')?.textContent === label));
    return {stats, domNodes, htmlBytes, searchBound, normalizedSearchCount, unicodeSearchCount,
      canaryDomLeak, injectionElements, riskOrder, roleCounts, priorityCounts, andFilterCount,
      titleTieStable: titleOrder.indexOf(0) < titleOrder.indexOf(70), newestOrder: newestOrder.slice(-10),
      newestFirst: newestOrder[0], oldestFirst: oldestOrder[0],
      newestTailHasNoTime: newestOrder.slice(-10).every((value) => value % 11 === 0),
      finalOrderMatchesOriginal: finalOrder.every((value, index) => value === index), labelNames};
  });
  ensure(fixtureResult.searchBound === 100 && fixtureResult.normalizedSearchCount === 2 &&
    fixtureResult.unicodeSearchCount === 1 && !fixtureResult.canaryDomLeak && fixtureResult.injectionElements === 0 &&
    fixtureResult.andFilterCount === 1 && Object.values(fixtureResult.roleCounts).every((count) => count === 25) &&
    Object.values(fixtureResult.priorityCounts).every((count) => count === 25) &&
    fixtureResult.titleTieStable && fixtureResult.newestFirst === 1 && fixtureResult.oldestFirst === 98 &&
    fixtureResult.newestTailHasNoTime && fixtureResult.finalOrderMatchesOriginal &&
    fixtureResult.labelNames.every(Boolean), 'QUEUE_SYNTHETIC_FIXTURE_CONTRACT_FAILED');
  const fixtureAxe = await new AxeBuilder({page: fixture}).analyze();
  ensure(fixtureAxe.violations.length === 0,
    `QUEUE_FIXTURE_AXE_FAILED_${fixtureAxe.violations.map((violation) => violation.id).join('_')}`);
  await fixture.close();
  syntheticBenchmark = fixtureResult;
  productionAssetBytes = Object.fromEntries(await Promise.all([
    'frontend/app.js', 'frontend/review-queue-ui-36-13a.js', 'frontend/style.css'
  ].map(async (path) => [path, (await stat(join(root, path))).size])));

  const requestCount = samplePosts + checklistPosts;
  ensure(externalRequests === 0, 'QUEUE_EXTERNAL_REQUESTS_NONZERO');
  ensure(pageErrors === 0, 'QUEUE_BROWSER_PAGE_ERROR');
  ensure(consoleErrors === 0, `QUEUE_BROWSER_CONSOLE_ERROR_${JSON.stringify({categories: consoleErrorCategories,
    details: consoleErrorDetails})}`);
  ensure(requestCount === 2 && samplePosts === 2 && checklistPosts === 0, 'QUEUE_ANALYSIS_REQUEST_COUNT_MISMATCH');
} finally {
  if (context) await context.close();
  if (browser) await browser.close();
  child.kill('SIGTERM');
  await new Promise((resolveChild) => child.once('exit', resolveChild));
  await rm(home, {recursive: true, force: true});
}
console.log(JSON.stringify({marker: 'REVIEW_QUEUE_36_13A_PASS', external_requests: externalRequests,
  api_requests: apiRequests, page_errors: pageErrors, console_errors: consoleErrors,
  sample_posts: samplePosts, checklist_posts: checklistPosts,
  axe_violations: 0, synthetic_benchmark: syntheticBenchmark, production_asset_bytes: productionAssetBytes}));
