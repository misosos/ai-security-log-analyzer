// Phase 36.14D: synthetic-only browser contract for in-document review state.
import {chromium} from '@playwright/test';
import {readFile, stat} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
const root = resolve(import.meta.dirname, '..');
const vector = JSON.parse(await readFile(join(root, 'tests/fixtures/investigation_review_state_v1_contract.json'), 'utf8'));
const home = await mkdtemp(join(tmpdir(), 'review-state-36-14d-'));
await mkdir(join(home, 'config'));
const socket = createServer(); await new Promise((done) => socket.listen(0, '127.0.0.1', done));
const port = socket.address().port; await new Promise((done) => socket.close(done));
const origin = `http://127.0.0.1:${port}`;
const child = spawn(join(root, '.venv', 'bin', 'python'), ['-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log'],
  {cwd: root, stdio: 'ignore', env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config')}});
let browser; let context; let externalRequests = 0; let apiRequests = 0; let checklistPosts = 0; let samplePosts = 0; let pageErrors = 0; let consoleErrors = 0;
const ensure = (condition, code) => { if (!condition) throw new Error(code); };
try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; } catch { /* startup */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'REVIEW_STATE_SERVER_START_FAILED');
  browser = await chromium.launch({headless: true, args: ['--disable-background-networking', '--no-first-run']});
  context = await browser.newContext({serviceWorkers: 'block'});
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) { externalRequests++; await route.abort(); return; }
    await route.continue();
  });
  await context.route(`${origin}/api/v1/live/status`, (route) => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({
    schema_version: '2', service_state: 'STOPPED', session_id: 'SYNTHETIC', source_role: 'ssh', worker_state: 'STOPPED',
    publication_state: 'CLOSED', latest_detection_revision: 0, available_event_count: 0, earliest_event_id: null,
    latest_event_id: null, active_observation_count: 0, published_total: 0, evicted_total: 0, replay_gap_total: 0,
    max_event_items: 32, max_event_bytes: 16384, max_connections: 2, active_connections: 0, fixed_error_code: null,
    recovery_action: null, interpretation_notices: ['합성 상태'], capabilities: ['READ_ONLY_STATUS'], analysis_available: true,
    analysis_revision: 0, active_relation_count: 0, active_risk_count: 0, active_case_count: 0, analysis_state: 'AVAILABLE'
  })}));

  const vectorPage = await context.newPage();
  await vectorPage.setContent('<!doctype html><html lang="ko"><head><title>합성 상태 계약</title></head><body></body></html>');
  await vectorPage.addScriptTag({path: join(root, 'frontend/investigation-review-state-36-14d.js')});
  const vectorResult = await vectorPage.evaluate((contract) => {
    const api = window.investigationReviewState36_14d;
    const refs = contract.synthetic_refs;
    let generationNo = 0;
    const fixedCrypto = {getRandomValues(bytes) { bytes.fill(++generationNo); return bytes; }};
    const allowed = new Set(contract.allowed_transitions.map(([from, to]) => `${from}:${to}`));
    const outcomes = [];
    for (const from of contract.review_states) for (const to of contract.review_states) {
      const store = api.createStore(fixedCrypto);
      const generation = store.beginGeneration([refs.case_ref]);
      const identity = {schema_version: 1, analysis_ref: generation.analysis_ref, case_ref: refs.case_ref};
      let revision = 0;
      if (from !== 'unreviewed') { const first = store.transition(identity, from, revision); if (!first.ok) throw new Error('VECTOR_SETUP_FAILED'); revision++; }
      const result = store.transition(identity, to, revision);
      const shouldPass = allowed.has(`${from}:${to}`);
      if (result.ok !== shouldPass) throw new Error('VECTOR_TRANSITION_MISMATCH');
      if (shouldPass && (result.snapshot.review_state !== to || result.snapshot.revision !== revision + 1)) throw new Error('VECTOR_REVISION_MISMATCH');
      if (!shouldPass && (result.code !== 'INVALID_TRANSITION' || store.snapshot(identity).snapshot.review_state !== from)) throw new Error('VECTOR_FAILURE_MUTATED_STATE');
      outcomes.push(result.ok ? 'success' : result.code);
    }
    const store = api.createStore(fixedCrypto);
    const generation = store.beginGeneration([refs.case_ref]);
    const identity = {schema_version: 1, analysis_ref: generation.analysis_ref, case_ref: refs.case_ref};
    const first = store.transition(identity, 'in_review', 0);
    const stale = store.transition(identity, 'reviewed', 0);
    const reset = store.reset(identity, 1);
    const next = store.beginGeneration([refs.case_ref]);
    const oldGeneration = store.snapshot(identity);
    const nextIdentity = {schema_version: 1, analysis_ref: next.analysis_ref, case_ref: refs.case_ref};
    const unknownCase = store.snapshot({...nextIdentity, case_ref: refs.unknown_case_ref});
    const privacyCanary = 'WORKFLOW_PRIVATE_CANARY_36_14D';
    const invalidRef = api.createStore(fixedCrypto).beginGeneration([privacyCanary]);
    const cap = api.createStore(fixedCrypto).beginGeneration(Array.from({length: 129}, (_, index) => `c_${index.toString(16).padStart(24, '0')}`));
    const summary = {states: api.STATES, outcomes, firstRevision: first.snapshot.revision,
      staleCode: stale.code, resetState: reset.snapshot.review_state, resetRevision: reset.snapshot.revision,
      newGenerationState: next.snapshots[0].review_state, oldGenerationCode: oldGeneration.code,
      unknownCaseCode: unknownCase.code, invalidRefCode: invalidRef.code,
      invalidRefRedacted: !JSON.stringify(invalidRef).includes(privacyCanary),
      capCode: cap.code, savedKeys: Object.keys(next.snapshots[0]).sort()};
    return summary;
  }, vector);
  ensure(vectorResult.states.join(',') === vector.review_states.join(',') &&
    vectorResult.firstRevision === 1 && vectorResult.staleCode === 'STALE_REVISION' &&
    vectorResult.resetState === 'unreviewed' && vectorResult.resetRevision === 2 &&
    vectorResult.newGenerationState === 'unreviewed' && vectorResult.oldGenerationCode === 'UNKNOWN_ANALYSIS' &&
    vectorResult.unknownCaseCode === 'UNKNOWN_CASE' && vectorResult.capCode === 'CAPACITY_EXCEEDED' &&
    vectorResult.invalidRefCode === 'INVALID_IDENTIFIER' && vectorResult.invalidRefRedacted &&
    vectorResult.savedKeys.join(',') === [...vector.state_fields].sort().join(','), 'REVIEW_STATE_VECTOR_CONTRACT_FAILED');
  await vectorPage.close();

  const page = await context.newPage();
  page.setDefaultTimeout(25000);
  page.on('pageerror', () => { pageErrors++; console.log('BROWSER_PAGE_ERROR'); });
  page.on('console', (message) => { if (message.type() === 'error') consoleErrors++; });
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && url.pathname.startsWith('/api/')) apiRequests++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/sample' && request.method() === 'POST') samplePosts++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/checklist' && request.method() === 'POST') checklistPosts++;
  });
  await page.setViewportSize({width: 1440, height: 1000});
  await page.goto(origin, {waitUntil: 'networkidle'});
  await page.locator('#sample-button').click();
  await page.waitForTimeout(500);
  await page.locator('#results-heading:visible, #error-summary:visible').first().waitFor({state: 'visible'});
  await page.locator('#review-workflow-summary-36-14d').waitFor({state: 'visible'});
  const screenshotDirectory = '/tmp/phase36-14d-after';
  await (await import('node:fs/promises')).mkdir(screenshotDirectory, {recursive: true});
  await page.screenshot({path: join(screenshotDirectory, 'queue-1440.png'), fullPage: true});
  for (const width of [390, 320]) {
    await page.setViewportSize({width, height: 900});
    ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth), `WORKFLOW_INITIAL_HORIZONTAL_OVERFLOW_${width}`);
    await page.screenshot({path: join(screenshotDirectory, `queue-${width}.png`), fullPage: true});
  }
  await page.setViewportSize({width:1440,height:1000});
  const qualityBefore = await page.locator('#input-quality-summary-36-12b').innerText().catch(() => '');
  const qualityHtmlBefore = await page.locator('#input-quality-summary-36-12b').evaluate((node)=>node.innerHTML);
  const resultSummaryBefore = await page.locator('#summary-cards').innerText();
  const cards = page.locator('#case-list .review-case-card');
  ensure(await cards.count() === 2 && await cards.first().locator('.review-workflow-control-card-36-14d select').inputValue() === 'unreviewed', 'WORKFLOW_INITIAL_STATE_FAILED');
  ensure((await page.locator('#review-workflow-counts-36-14d').innerText()).includes('검토 전 2') &&
    (await page.locator('#review-workflow-note-36-14d').innerText()).includes('안전·해결 판정이 아닙니다'), 'WORKFLOW_SUMMARY_OR_COPY_FAILED');
  const initialApiRequests = apiRequests;
  const firstControl = cards.first().locator('.review-workflow-control-card-36-14d select');
  await firstControl.focus();
  ensure(await firstControl.evaluate((node) => document.activeElement === node && node.matches(':focus-visible')),
    'WORKFLOW_KEYBOARD_FOCUS_FAILED');
  await page.keyboard.press('Tab');
  ensure(await page.evaluate(() => document.activeElement?.tagName === 'A'), 'WORKFLOW_KEYBOARD_TAB_EXIT_FAILED');
  await firstControl.focus();
  await firstControl.selectOption('in_review');
  ensure(await firstControl.evaluate((node) => node.isConnected && document.activeElement === node),
    'WORKFLOW_FOCUS_LOST_AFTER_TRANSITION');
  ensure(await firstControl.inputValue() === 'in_review' && (await page.locator('#review-workflow-counts-36-14d').innerText()).includes('검토 중 1'), 'WORKFLOW_TRANSITION_FAILED');
  await firstControl.selectOption('deferred');
  ensure(await firstControl.inputValue() === 'deferred', 'WORKFLOW_SECOND_CAS_FAILED');
  const firstLink = cards.first().locator('a.review-detail-link');
  const caseHash = await firstLink.getAttribute('href');
  await firstLink.click();
  ensure(page.url().endsWith(caseHash) && !page.url().includes('in_review') && !page.url().includes('deferred'), 'WORKFLOW_ROUTE_STATE_LEAK');
  const detailControl = page.locator('#case-detail-content .review-workflow-control-detail-36-14d select');
  ensure(await detailControl.inputValue() === 'deferred', 'WORKFLOW_LIST_DETAIL_STATE_MISMATCH');
  await detailControl.selectOption('reviewed');
  ensure(await detailControl.inputValue() === 'reviewed', 'WORKFLOW_DETAIL_TRANSITION_FAILED');
  await page.locator('#review-back-link').click();
  ensure(await cards.first().locator('.review-workflow-control-card-36-14d select').inputValue() === 'reviewed', 'WORKFLOW_BACK_STATE_NOT_RESTORED');
  await page.locator('#review-queue-filter-toggle-36-13a').click();
  const stateFilter = page.locator('#review-queue-state-36-14d');
  await stateFilter.selectOption('unreviewed');
  ensure(await cards.count() === 1, 'WORKFLOW_STATUS_FILTER_FAILED');
  ensure((await page.locator('#review-workflow-counts-36-14d').innerText()).includes('검토함 1'),
    'WORKFLOW_GENERATION_COUNTS_TRACKED_FILTERED_SUBSET');
  const filteredControl = cards.first().locator('.review-workflow-control-card-36-14d select');
  await filteredControl.focus();
  await filteredControl.selectOption('in_review');
  ensure(await cards.count() === 0 && await page.evaluate(() => document.activeElement.id) === 'review-queue-state-36-14d',
    'WORKFLOW_FILTERED_CARD_FOCUS_FALLBACK_FAILED');
  await page.locator('#review-queue-risk-36-13a').selectOption('HIGH');
  ensure(await cards.count() === 0, 'WORKFLOW_AND_FILTER_FAILED');
  await page.locator('#review-queue-reset-36-13a').click();
  ensure(await cards.count() === 2 && await cards.first().locator('.review-workflow-control-card-36-14d select').inputValue() === 'reviewed', 'QUEUE_RESET_CHANGED_WORKFLOW_STATE');
  ensure((await page.locator('#summary-cards').innerText()) === resultSummaryBefore &&
    (await page.locator('#input-quality-summary-36-12b').innerText().catch(() => '')) === qualityBefore &&
    (await page.locator('#input-quality-summary-36-12b').evaluate((node)=>node.innerHTML)) === qualityHtmlBefore,
  'WORKFLOW_CHANGED_ANALYSIS_OR_INPUT_QUALITY_SUMMARY');
  const reviewedControl = cards.first().locator('.review-workflow-control-card-36-14d select');
  await reviewedControl.selectOption('__reset__');
  ensure(await reviewedControl.inputValue() === 'unreviewed', 'WORKFLOW_EXPLICIT_RESET_FAILED');
  await page.locator('#review-queue-filter-toggle-36-13a').click();
  await page.locator('#review-queue-state-36-14d').selectOption('reviewed');
  ensure(await cards.count() === 0 && await page.locator('#review-queue-empty-36-13a').isVisible(), 'WORKFLOW_EMPTY_FILTER_FAILED');
  await page.locator('#review-queue-reset-36-13a').click();
  ensure(await cards.count() === 2, 'WORKFLOW_FILTER_RESET_FAILED');
  ensure(apiRequests === initialApiRequests && checklistPosts === 0 && !page.url().includes('a_'), 'WORKFLOW_INTERACTION_SIDE_EFFECT');
  ensure(await documentHasStorageState(page) && !page.url().includes('reviewed') && !page.url().includes('deferred'), 'WORKFLOW_STATE_PERSISTED_OR_LEAKED');
  const forbiddenRefs = await page.locator('[data-analysis-ref], [data-review-state], [data-workflow-state]').count();
  ensure(forbiddenRefs === 0, 'WORKFLOW_CASE_REF_IN_DOM');
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({width, height: 900});
    ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth), `WORKFLOW_HORIZONTAL_OVERFLOW_${width}`);
    ensure(await page.locator('#review-queue-search-36-13a').isVisible() &&
      await page.locator('#review-queue-filter-toggle-36-13a').isVisible() &&
      await page.locator('#review-queue-sort-36-13a').isVisible(), `WORKFLOW_QUEUE_CONTROLS_NOT_VISIBLE_${width}`);
    const queueControlBounds = await page.locator('#review-queue-search-36-13a, #review-queue-filter-toggle-36-13a, #review-queue-sort-36-13a')
      .evaluateAll((nodes)=>nodes.map((node)=>{const rect=node.getBoundingClientRect();return {left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom};}));
    ensure(queueControlBounds.every((rect)=>rect.left>=0&&rect.right<=width+1&&rect.bottom>=0), `WORKFLOW_QUEUE_CONTROL_BOUNDS_${width}`);
    const controlSizes = await page.locator('.review-workflow-control-36-14d select').evaluateAll((items) => items.filter((item) => item.getClientRects().length > 0).map((item) => ({w:item.getBoundingClientRect().width,h:item.getBoundingClientRect().height})));
    ensure(controlSizes.every((size) => size.w > 0 && size.h >= 44), `WORKFLOW_TARGET_SIZE_${width}`);
  }
  await page.evaluate(() => { document.documentElement.style.zoom = '2'; });
  ensure(await page.evaluate(() => document.documentElement.scrollWidth === innerWidth), 'WORKFLOW_200_EQUIVALENT_OVERFLOW');
  await page.evaluate(() => { document.documentElement.style.zoom = ''; });
  await page.setViewportSize({width:640,height:900});
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  const fontReflow = await page.evaluate(() => ({scrollWidth:document.documentElement.scrollWidth, width:innerWidth,
    overflow:[...document.querySelectorAll('body *')].filter((node)=>node.getBoundingClientRect().right>innerWidth+1)
      .slice(0,8).map((node)=>({id:node.id,classes:typeof node.className==='string'?node.className:'svg'}))}));
  if (fontReflow.scrollWidth !== fontReflow.width) console.log(JSON.stringify({fontReflow}));
  ensure(fontReflow.scrollWidth === fontReflow.width, 'WORKFLOW_FONT_REFLOW_OVERFLOW');
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 1000});
  const axe = await (await import('@axe-core/playwright')).default;
  const violations = await new axe({page}).analyze();
  ensure(violations.violations.length === 0, `WORKFLOW_AXE_${violations.violations.map((item) => item.id).join('_')}`);
  await page.evaluate(() => document.activeElement?.blur());
  const detailAsset = await stat(join(root, 'frontend/investigation-review-state-36-14d.js'));
  const appAsset = await stat(join(root, 'frontend/app.js'));
  const cssAsset = await stat(join(root, 'frontend/style.css'));
  ensure(detailAsset.size <= 160 * 1024 && appAsset.size <= 160 * 1024 && cssAsset.size <= 160 * 1024,
    'WORKFLOW_STATIC_ASSET_BOUND_EXCEEDED');
  const benchmark = await page.evaluate(() => {
    const api = window.investigationReviewState36_14d;
    const refs = Array.from({length:100}, (_, index) => `c_${index.toString(16).padStart(24, '0')}`);
    let generation = 0;
    const cryptoProvider = {getRandomValues(bytes) { bytes.fill(++generation); return bytes; }};
    const operations = {
      store_init() { const store=api.createStore(cryptoProvider); store.beginGeneration(refs); },
      single_transition() { const store=api.createStore(cryptoProvider); const gen=store.beginGeneration(refs); store.transition({schema_version:1,analysis_ref:gen.analysis_ref,case_ref:refs[0]},'in_review',0); },
      state_filter() { const store=api.createStore(cryptoProvider); const gen=store.beginGeneration(refs); const key=(case_ref)=>({schema_version:1,analysis_ref:gen.analysis_ref,case_ref}); store.transition(key(refs[0]),'in_review',0); store.list().filter(item=>item.review_state==='in_review').length; },
      compound_and_state_filter() { const store=api.createStore(cryptoProvider); const gen=store.beginGeneration(refs); const key=(case_ref)=>({schema_version:1,analysis_ref:gen.analysis_ref,case_ref}); for(let i=0;i<refs.length;i+=4) store.transition(key(refs[i]),'in_review',0); store.list().filter((item,index)=>index%2===0&&item.review_state==='in_review').length; },
      list_detail_list_restore() { const store=api.createStore(cryptoProvider); const gen=store.beginGeneration(refs); const key={schema_version:1,analysis_ref:gen.analysis_ref,case_ref:refs[0]}; store.transition(key,'in_review',0); store.snapshot(key); store.snapshot(key); },
      generation_replace() { const store=api.createStore(cryptoProvider); store.beginGeneration(refs); store.beginGeneration(refs); }
    };
    const result={case_count:refs.length,warmup:5,samples:25,operations:{}};
    for(const [name,operation] of Object.entries(operations)) {
      for(let i=0;i<result.warmup;i++) operation();
      const values=[];
      for(let i=0;i<result.samples;i++) { const start=performance.now(); operation(); values.push(performance.now()-start); }
      values.sort((a,b)=>a-b);
      result.operations[name]={median_ms:values[12],p95_ms:values[23],max_ms:values[24]};
    }
    return result;
  });

  // Secure-random failure degrades only workflow metadata, never the analyzed results.
  const unavailablePage = await context.newPage();
  await unavailablePage.addInitScript(() => Object.defineProperty(window, 'crypto', {configurable:true,value:null}));
  await unavailablePage.goto(origin, {waitUntil:'networkidle'});
  await unavailablePage.locator('#sample-button').click();
  await unavailablePage.locator('#results-heading').waitFor({state:'visible'});
  ensure(await unavailablePage.locator('#case-list .review-case-card').count() === 2 &&
    await unavailablePage.locator('.review-workflow-control-36-14d').count() === 0 &&
    (await unavailablePage.locator('#review-workflow-note-36-14d').innerText()).includes('분석 결과는 계속 표시됩니다'),
  'WORKFLOW_RANDOM_UNAVAILABLE_DID_NOT_DEGRADE_SAFELY');
  await unavailablePage.close();
  const workflowNodes = await page.locator('.review-workflow-control-36-14d, #review-workflow-summary-36-14d, #review-workflow-note-36-14d, #review-workflow-feedback-36-14d').count();
  const workflowHtmlBytes = await page.evaluate(() => new TextEncoder().encode([
    ...document.querySelectorAll('.review-workflow-control-36-14d, #review-workflow-summary-36-14d, #review-workflow-note-36-14d, #review-workflow-feedback-36-14d')
  ].map((node)=>node.outerHTML).join('')).length);

  // A fresh result gets a fresh state generation; the same case references start unreviewed again.
  await page.locator('#nav-start').click();
  await page.locator('#sample-button').click();
  await page.locator('#review-workflow-summary-36-14d').waitFor({state: 'visible'});
  ensure(await cards.first().locator('.review-workflow-control-card-36-14d select').inputValue() === 'unreviewed', 'WORKFLOW_NEW_GENERATION_REUSED_STATE');

  // Rollback switch OFF is exercised by serving a test-only copy of app.js with only its fixed switch changed.
  const rollbackPage = await context.newPage();
  await rollbackPage.route(`${origin}/assets/app.js`, async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace('const REVIEW_WORKFLOW_STATE_UI_ENABLED = true;', 'const REVIEW_WORKFLOW_STATE_UI_ENABLED = false;');
    await route.fulfill({response, body});
  });
  await rollbackPage.goto(origin, {waitUntil: 'networkidle'});
  await rollbackPage.locator('#sample-button').click();
  await rollbackPage.locator('#results-heading').waitFor({state: 'visible'});
  ensure(await rollbackPage.locator('.review-workflow-control-36-14d').count() === 0 &&
    await rollbackPage.locator('#review-workflow-summary-36-14d').isHidden() &&
    await rollbackPage.locator('#review-queue-state-filter-label-36-14d').isHidden() &&
    await rollbackPage.locator('#case-list .review-case-card').count() === 2, 'WORKFLOW_ROLLBACK_OFF_FAILED');
  await rollbackPage.close();
  const stateApiPaths = await page.evaluate(() => performance.getEntriesByType('resource').map((entry) => new URL(entry.name).pathname)
    .filter((path) => path.startsWith('/api/') && path.includes('review-state')));
  ensure(stateApiPaths.length === 0, 'WORKFLOW_STATE_API_RESOURCE_REQUESTED');
  ensure(externalRequests === 0 && pageErrors === 0 && consoleErrors === 0 && checklistPosts === 0,
    'WORKFLOW_BROWSER_SECURITY_REGRESSION');
  console.log(JSON.stringify({marker: 'REVIEW_STATE_36_14D_PASS', vector_pairs: vectorResult.outcomes.length,
    api_requests: apiRequests, sample_posts: samplePosts, checklist_posts: checklistPosts, state_api_requests: 0,
    external_requests: externalRequests, page_errors: pageErrors, console_errors: consoleErrors, axe_violations: 0,
    workflow_asset_bytes: detailAsset.size, app_asset_bytes: appAsset.size, stylesheet_bytes: cssAsset.size,
    workflow_dom_nodes: workflowNodes, workflow_html_bytes: workflowHtmlBytes, benchmark,
    screenshots: ['queue-1440.png', 'queue-390.png', 'queue-320.png']}));
} finally {
  if (context) await context.close(); if (browser) await browser.close();
  child.kill('SIGTERM'); await new Promise((done) => { child.once('exit', done); setTimeout(done, 2500).unref(); });
  await rm(home, {recursive: true, force: true});
}
function documentHasStorageState(page) {
  return page.evaluate(() => ({local: localStorage.length, session: sessionStorage.length, cookies: document.cookie}))
    .then((state) => state.local === 0 && state.session === 0 && state.cookies === '');
}
