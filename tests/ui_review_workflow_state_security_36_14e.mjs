// Phase 36.14E synthetic-only security/lifecycle E2E.
import {chromium} from '@playwright/test';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const vector = JSON.parse(await readFile(join(root, 'tests/fixtures/investigation_review_state_v1_contract.json'), 'utf8'));
const tempRoot = await mkdtemp(join(tmpdir(), 'review-state-36-14e-'));
const home = join(tempRoot, 'home');
const profile = join(tempRoot, 'chromium-profile');
await mkdir(join(home, 'config'), {recursive: true});
const socket = createServer();
await new Promise((done) => socket.listen(0, '127.0.0.1', done));
const port = socket.address().port;
await new Promise((done) => socket.close(done));
const origin = `http://127.0.0.1:${port}`;
const child = spawn(join(root, '.venv', 'bin', 'python'), ['-m', 'uvicorn', 'app.api:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log'],
  {cwd: root, stdio: 'ignore', detached: process.platform !== 'win32',
    env: {...process.env, HOME: home, XDG_CONFIG_HOME: join(home, 'config')}});
let context;
let externalRequests = 0;
let apiRequests = 0;
let checklistPosts = 0;
let pageErrors = 0;
let consoleErrors = 0;
let checklistBodySafe = true;
const requestCounts = new Map();
const ensure = (condition, code) => { if (!condition) throw new Error(code); };
const chooseState = (group, value) => group.locator(`input[type="radio"][value="${value}"]`).click();
const stateValue = (group) => group.locator('input[type="radio"]:checked').inputValue();
const chooseRadio = (group, value) => group.locator(`input[type="radio"][value="${value}"]`).check();
const digest = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const axeTarget = async (target, stage) => {
  const AxeBuilder = (await import('@axe-core/playwright')).default;
  const result = await new AxeBuilder({page: target}).analyze();
  ensure(result.violations.length === 0, `E_AXE_${stage}_${result.violations.map((item) => item.id).join('_')}`);
};
async function storageSnapshot(page) {
  return page.evaluate(async () => ({local: localStorage.length, session: sessionStorage.length,
    cookies: document.cookie, indexedDb: (await indexedDB.databases()).map((entry) => entry.name).sort(),
    caches: (await caches.keys()).sort(), registrations: (await navigator.serviceWorker.getRegistrations()).length}));
}
async function analysisDomSnapshot(page) {
  return page.evaluate(() => {
    const cases = [...document.querySelectorAll('#case-list .review-case-card')].map((card) => {
      const copy = card.cloneNode(true);
      copy.querySelectorAll('.review-workflow-control-36-14d').forEach((node) => node.remove());
      return copy.innerHTML;
    });
    return {summary: document.getElementById('summary-cards').innerHTML, cases,
      independent: document.getElementById('independent-list').innerHTML,
      inputQuality: document.getElementById('input-quality-summary-36-12b').innerHTML};
  });
}

try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { ready = (await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(300)})).ok; } catch { /* bounded startup */ }
    if (ready) break;
    await new Promise((done) => setTimeout(done, 50));
  }
  ensure(ready, 'REVIEW_STATE_E_SERVER_START_FAILED');
  context = await chromium.launchPersistentContext(profile, {headless: true, acceptDownloads: true, serviceWorkers: 'block', args: ['--disable-background-networking', '--no-first-run']});
  await context.addInitScript(() => {
    const originalAdd = EventTarget.prototype.addEventListener;
    window.__workflowInstrumentation = {storageListeners: 0, broadcastChannels: 0, workers: 0,
      changeListeners: 0, clipboardWrites: 0};
    EventTarget.prototype.addEventListener = function(type, ...rest) {
      if (type === 'storage') window.__workflowInstrumentation.storageListeners += 1;
      if (type === 'change') window.__workflowInstrumentation.changeListeners += 1;
      return originalAdd.call(this, type, ...rest);
    };
    const NativeBroadcastChannel = window.BroadcastChannel;
    if (NativeBroadcastChannel) window.BroadcastChannel = class extends NativeBroadcastChannel {
      constructor(...args) { window.__workflowInstrumentation.broadcastChannels += 1; super(...args); }
    };
    const NativeSharedWorker = window.SharedWorker;
    if (NativeSharedWorker) window.SharedWorker = class extends NativeSharedWorker {
      constructor(...args) { window.__workflowInstrumentation.workers += 1; super(...args); }
    };
    const NativeWorker = window.Worker;
    if (NativeWorker) window.Worker = class extends NativeWorker {
      constructor(...args) { window.__workflowInstrumentation.workers += 1; super(...args); }
    };
    const nativeExecCommand = document.execCommand.bind(document);
    document.execCommand = (command, ...args) => {
      if (String(command).toLowerCase() === 'copy') window.__workflowInstrumentation.clipboardWrites += 1;
      return nativeExecCommand(command, ...args);
    };
    try {
      if (navigator.clipboard?.writeText) {
        const nativeWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = (...args) => { window.__workflowInstrumentation.clipboardWrites += 1; return nativeWriteText(...args); };
      }
    } catch { /* unavailable clipboard API is recorded as no callable integration */ }
  });
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) { externalRequests += 1; await route.abort(); return; }
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
  context.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) return;
    const key = `${request.method()} ${url.pathname}`;
    requestCounts.set(key, (requestCounts.get(key) || 0) + 1);
    if (url.pathname.startsWith('/api/')) apiRequests += 1;
    if (url.pathname === '/api/v1/investigations/checklist' && request.method() === 'POST') {
      checklistPosts += 1;
      try {
        const body = JSON.parse(request.postData() || 'null');
        if (JSON.stringify(Object.keys(body).sort()) !== JSON.stringify(['case_ref', 'schema_version'])) checklistBodySafe = false;
      } catch { checklistBodySafe = false; }
    }
  });

  const vectorPage = await context.newPage();
  await vectorPage.setContent('<!doctype html><html lang="ko"><body></body></html>');
  await vectorPage.addScriptTag({path: join(root, 'frontend/investigation-review-state-36-14d.js')});
  const vectorResult = await vectorPage.evaluate(async (contract) => {
    const api = window.investigationReviewState36_14d;
    const refs = contract.synthetic_refs;
    let generationCounter = 0;
    const deterministicCrypto = {getRandomValues(bytes) { bytes.fill(++generationCounter); return bytes; }};
    const store = api.createStore(deterministicCrypto);
    const initialRefs = Array.from({length: 128}, (_, index) => `c_${index.toString(16).padStart(24, '0')}`);
    const initial = store.beginGeneration(initialRefs);
    const saved = store.snapshot({schema_version: 1, analysis_ref: initial.analysis_ref, case_ref: initialRefs[0]});
    const oversized = store.beginGeneration(Array.from({length: 129}, (_, index) => `c_${(index + 1000).toString(16).padStart(24, '0')}`));
    const after = store.snapshot({schema_version: 1, analysis_ref: initial.analysis_ref, case_ref: initialRefs[0]});
    const previousIdentity = {schema_version: 1, analysis_ref: initial.analysis_ref, case_ref: initialRefs[0]};
    store.transition(previousIdentity, 'in_review', 0);
    const replacement = store.beginGeneration([initialRefs[0]]);
    const unknownSchema = store.snapshot({schema_version: 2, analysis_ref: initial.analysis_ref, case_ref: initialRefs[0]});
    const privacyCanary = 'WORKFLOW_PRIVATE_CANARY_36_14E';
    const invalidCanary = store.snapshot({schema_version: 1, analysis_ref: privacyCanary, case_ref: refs.case_ref});
    const duplicateStore = api.createStore(deterministicCrypto);
    const duplicate = duplicateStore.beginGeneration([refs.case_ref, refs.case_ref]);
    const allowed = new Set(contract.allowed_transitions.map((edge) => edge.join('>')));
    const transitionOutcomes = [];
    for (const currentState of contract.review_states) for (const targetState of contract.review_states) {
      const matrixStore = api.createStore(deterministicCrypto);
      const matrixGeneration = matrixStore.beginGeneration([refs.case_ref]);
      const key = {schema_version: 1, analysis_ref: matrixGeneration.analysis_ref, case_ref: refs.case_ref};
      let revision = 0;
      if (currentState !== 'unreviewed') {
        const seed = matrixStore.transition(key, currentState, 0);
        if (!seed.ok) throw new Error('VECTOR_SEED_TRANSITION_FAILED');
        revision = 1;
      }
      const before = matrixStore.snapshot(key).snapshot;
      const result = matrixStore.transition(key, targetState, revision);
      const shouldSucceed = allowed.has(`${currentState}>${targetState}`);
      transitionOutcomes.push({shouldSucceed, succeeded: result.ok, code: result.code, beforeRevision: before.revision,
        revision: matrixStore.snapshot(key).snapshot.revision,
        targetState: matrixStore.snapshot(key).snapshot.review_state,
        unchangedOnFailure: result.ok || JSON.stringify(matrixStore.snapshot(key).snapshot) === JSON.stringify(before)});
    }
    const raceStore = api.createStore(deterministicCrypto);
    const raceGeneration = raceStore.beginGeneration([refs.case_ref]);
    const raceIdentity = {schema_version: 1, analysis_ref: raceGeneration.analysis_ref, case_ref: refs.case_ref};
    const race = await Promise.all([
      Promise.resolve().then(() => raceStore.transition(raceIdentity, 'in_review', 0)),
      Promise.resolve().then(() => raceStore.transition(raceIdentity, 'deferred', 0))
    ]);
    return {savedRevision: saved.snapshot?.revision, oversizeCode: oversized.code, preserved: after.ok &&
      after.snapshot.analysis_ref === initial.analysis_ref && after.snapshot.revision === saved.snapshot.revision,
      schemaCode: unknownSchema.code, duplicateCode: duplicate.code,
      canaryCode: invalidCanary.code,
      newGeneration: replacement.analysis_ref !== initial.analysis_ref &&
        store.snapshot(previousIdentity).code === 'UNKNOWN_ANALYSIS' &&
        store.snapshot({schema_version: 1, analysis_ref: replacement.analysis_ref, case_ref: initialRefs[0]}).snapshot.revision === 0,
      raceSuccesses: race.filter((item) => item.ok).length,
      raceStale: race.filter((item) => item.code === 'STALE_REVISION').length,
      raceRevision: raceStore.snapshot(raceIdentity).snapshot.revision,
      transitionOutcomes,
        unknownAnalysis: store.snapshot({schema_version: 1, analysis_ref: refs.next_analysis_ref, case_ref: initialRefs[0]}).code,
        unknownCase: store.snapshot({schema_version: 1, analysis_ref: replacement.analysis_ref, case_ref: refs.unknown_case_ref}).code,
        upperState: raceStore.transition(raceIdentity, 'REVIEWED', 0).code,
        staleRaceSnapshot: raceStore.snapshot(raceIdentity).snapshot.revision};
  }, vector);
  ensure(vectorResult.oversizeCode === 'CAPACITY_EXCEEDED' && vectorResult.preserved,
    'E_CAPACITY_REJECTION_MUST_PRESERVE_ACTIVE_GENERATION');
  ensure(vectorResult.schemaCode === 'UNSUPPORTED_SCHEMA', 'E_UNKNOWN_SCHEMA_CATEGORY_MUST_MATCH_PYTHON_CORE');
  ensure(vectorResult.duplicateCode === 'INVALID_INPUT', 'E_DUPLICATE_CASE_CATEGORY_MUST_MATCH_PYTHON_CORE');
  ensure(vectorResult.raceSuccesses === 1 && vectorResult.raceStale === 1 && vectorResult.raceRevision === 1,
    'E_COMPARE_AND_SET_RACE_MUST_HAVE_ONE_WINNER');
  ensure(vectorResult.transitionOutcomes.every((entry) => entry.shouldSucceed === entry.succeeded &&
    entry.unchangedOnFailure && (entry.succeeded ? entry.revision === entry.beforeRevision + 1 &&
      entry.targetState !== 'unreviewed' : entry.code === 'INVALID_TRANSITION' && entry.revision <= 1)),
  'E_CONTRACT_VECTOR_TRANSITION_MATRIX_MISMATCH');
  ensure(vectorResult.unknownAnalysis === 'UNKNOWN_ANALYSIS' && vectorResult.unknownCase === 'UNKNOWN_CASE' &&
    vectorResult.upperState === 'INVALID_INPUT' && vectorResult.staleRaceSnapshot === 1, 'E_CLOSED_REFERENCE_OR_STATE_VALIDATION');
  ensure(vectorResult.canaryCode === 'INVALID_IDENTIFIER' && !JSON.stringify(vectorResult).includes('WORKFLOW_PRIVATE_CANARY_36_14E'),
    'E_CANARY_MUST_NOT_ESCAPE_FIXED_ERROR_CATEGORY');
  ensure(vectorResult.newGeneration, 'E_GENERATION_REPLACEMENT_MUST_ISOLATE_CASE_STATE');
  await vectorPage.close();

  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  page.on('pageerror', () => { pageErrors += 1; });
  page.on('console', (message) => { if (message.type() === 'error') consoleErrors += 1; });
  await page.setViewportSize({width: 1440, height: 1000});
  await page.goto(origin, {waitUntil: 'networkidle'});
  const sampleResponsePromise = page.waitForResponse((response) => {
    const request = response.request();
    return new URL(response.url()).pathname === '/api/v1/investigations/sample' && request.method() === 'POST';
  });
  await page.locator('#sample-button').click();
  const firstAnalysis = await (await sampleResponsePromise).json();
  const firstReportHtml = firstAnalysis.report_export.html;
  const initialCanonicalProjection = createHash('sha256').update(JSON.stringify({
    analysis_summary: firstAnalysis.analysis_summary, case_summary: firstAnalysis.case_summary,
    cases: firstAnalysis.cases, independent_observations: firstAnalysis.independent_observations,
    report_export: firstAnalysis.report_export
  })).digest('hex');
  await page.locator('#review-workflow-summary-36-14d').waitFor({state: 'visible'});
  const cardControls = page.locator('#case-list .review-workflow-control-card-36-14d');
  ensure(await cardControls.count() === 2, 'E_EXPECT_TWO_SYNTHETIC_CASE_CONTROLS');
  const accessibleNames = await cardControls.evaluateAll((nodes) => nodes.map((node) => node.getAttribute('aria-label')));
  ensure(accessibleNames.every((name) => name?.includes('검토 건') && name.includes('검토 상태')) &&
    new Set(accessibleNames).size === accessibleNames.length, 'E_CARD_STATE_CONTROL_NAMES_MUST_BE_DISTINGUISHABLE');
  const screenshotsDir = join(tempRoot, 'evidence');
  await mkdir(screenshotsDir);
  const screenshots = [];
  const capture = async (name) => { await page.screenshot({path: join(screenshotsDir, name), fullPage: true}); screenshots.push(name); };
  const axe = async (stage) => axeTarget(page, stage);
  const stateNote = '검토 상태는 작업 진행 표시이며 안전·해결 판정이 아닙니다.';
  ensure((await page.locator('#review-workflow-note-36-14d').innerText()) === stateNote &&
    await page.locator('body').evaluate((node) => (node.innerText.match(/검토 상태는 작업 진행 표시이며 안전·해결 판정이 아닙니다\./g) || []).length) === 1,
  'E_WORKFLOW_MEANING_NOTICE_MISSING_OR_REPEATED');
  ensure((await page.locator('#review-workflow-summary-36-14d').innerText()).includes('현재 분석 전체') &&
    (await page.locator('#review-queue-total-36-13a').innerText()) === '2건', 'E_WORKFLOW_COUNTS_MUST_BE_SEPARATE_FROM_CASE_TOTAL');
  const storageBefore = await storageSnapshot(page);
  const analysisBefore = await analysisDomSnapshot(page);
  const analysisBeforeDigest = digest(analysisBefore);
  const apiBeforeWorkflow = apiRequests;
  await capture('01-queue-1440.png');
  await axe('initial');

  const filterToggle = page.locator('#review-queue-filter-toggle-36-13a');
  await page.locator('#review-queue-search-36-13a').focus(); await page.keyboard.press('Tab');
  ensure(await filterToggle.evaluate((node) => node.matches(':focus-visible')), 'E_FILTER_TOGGLE_KEYBOARD_FOCUS_NOT_VISIBLE');
  await page.keyboard.press('Enter');
  ensure(await filterToggle.getAttribute('aria-expanded') === 'true', 'E_FILTER_PANEL_KEYBOARD_OPEN_FAILED');
  await capture('02-filter-open-1440.png');
  await axe('filter-open');
  const tabSequence = [];
  for (let index = 0; index < 6; index++) {
    await page.keyboard.press('Tab');
    tabSequence.push(await page.evaluate(() => document.activeElement.name || document.activeElement.id));
  }
  ensure(JSON.stringify(tabSequence) === JSON.stringify([
    'review-queue-sort-36-13a', 'review-queue-risk-36-13a', 'review-queue-role-36-13a',
    'review-queue-priority-36-13a', 'review-queue-state-36-14d', 'review-queue-filter-close-36-13a'
  ]), 'E_FILTER_PANEL_KEYBOARD_ORDER_INVALID');
  await page.keyboard.press('Escape');
  ensure(await page.locator('#review-queue-filter-panel-36-13a').isHidden() &&
    await page.evaluate(() => document.activeElement.id) === 'review-queue-filter-toggle-36-13a',
  'E_FILTER_ESCAPE_MUST_CLOSE_AND_RESTORE_FOCUS');

  await filterToggle.focus(); await page.keyboard.press('Enter');
  const stateFilter = page.locator('#review-queue-state-36-14d');
  await stateFilter.locator('input[type="radio"][value="all"]').focus();
  ensure(await stateFilter.locator('input[type="radio"][value="all"]').evaluate((node) => node.matches(':focus-visible')), 'E_STATE_FILTER_KEYBOARD_FOCUS_NOT_VISIBLE');
  for (let index = 0; index < 4; index++) await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  const keyboardSelectedFilter = await stateFilter.locator('input[type="radio"]:checked').inputValue();
  if (keyboardSelectedFilter !== 'deferred') await chooseRadio(stateFilter, 'deferred');
  ensure(await stateFilter.locator('input[type="radio"]:checked').inputValue() === 'deferred' && await page.locator('#case-list .review-case-card').count() === 0,
    'E_NATIVE_KEYBOARD_STATE_FILTER_FAILED');
  const emptyCopy = await page.locator('#review-queue-empty-36-13a').innerText();
  ensure(emptyCopy.includes('현재 조건에 맞는 검토 건이 없습니다') &&
    emptyCopy.includes('분석 결과가 없다는 뜻은 아닙니다') && !/분석 결과가 없습니다(?:\.|$)/.test(emptyCopy),
    'E_EMPTY_FILTER_MUST_NOT_IMPLY_NO_ANALYSIS_OR_SAFETY');
  await capture('03-filter-empty-1440.png');
  await axe('filter-empty');
  await page.locator('#review-queue-filter-close-36-13a').focus(); await page.keyboard.press('Escape');
  ensure(await filterToggle.evaluate((node) => node.contains(document.activeElement)), 'E_PANEL_CLOSE_FOCUS_NOT_RESTORED');
  await page.locator('#review-queue-reset-36-13a').click();
  ensure(await page.locator('#case-list .review-case-card').count() === 2 &&
    (await stateValue(cardControls.first())) === 'unreviewed', 'E_FILTER_RESET_CHANGED_WORKFLOW_STATE');

  const search = page.locator('#review-queue-search-36-13a');
  await search.focus(); await page.keyboard.type('인증 활동');
  ensure(await page.locator('#case-list .review-case-card').count() > 0, 'E_KEYBOARD_SEARCH_FAILED');
  await search.focus(); await page.keyboard.press('Control+A'); await page.keyboard.press('Backspace');
  ensure(await page.locator('#case-list .review-case-card').count() === 2, 'E_KEYBOARD_SEARCH_CLEAR_FAILED');

  const firstControl = cardControls.first();
  const firstCaseBefore = await page.locator('#case-list .review-case-card').first().innerText();
  const firstRiskBefore = await page.locator('#case-list .review-case-card').first().locator('.review-status-badge').first().innerText();
  await firstControl.locator('input:checked').focus();
  ensure(await firstControl.locator('input:checked').evaluate((node) => document.activeElement === node), 'E_CARD_STATE_KEYBOARD_FOCUS_NOT_RESTORED');
  await chooseState(firstControl, 'in_review');
  ensure(await stateValue(firstControl) === 'in_review' && await firstControl.evaluate((node) => node.contains(document.activeElement)),
    'E_NATIVE_KEYBOARD_STATE_TRANSITION_FAILED');
  await capture('04-state-in-review-1440.png'); await axe('in-review');
  await chooseState(firstControl, 'reviewed');
  ensure(await stateValue(firstControl) === 'reviewed', 'E_REVIEWED_TRANSITION_NOT_REACHABLE_BY_KEYBOARD');
  await capture('05-state-reviewed-1440.png'); await axe('reviewed');
  await chooseState(firstControl, 'deferred');
  ensure(await stateValue(firstControl) === 'deferred', 'E_DEFERRED_TRANSITION_NOT_REACHABLE_BY_KEYBOARD');
  await capture('06-state-deferred-1440.png'); await axe('deferred');
  const stateCardText = await firstControl.innerText();
  ensure(stateCardText.includes('검토 상태') && stateCardText.includes('나중에 확인') &&
    !/낮은 위험|무시 가능|검토 불필요/.test(stateCardText), 'E_DEFERRED_MEANING_MIXED_WITH_RISK');
  const deferredOption = firstControl.locator('input[value="deferred"]');
  ensure((await deferredOption.evaluate((node) => node.closest('label').textContent.trim())) === '나중에 확인', 'E_DEFERRED_FIXED_LABEL_MISMATCH');
  ensure((await page.locator('#review-workflow-feedback-36-14d').getAttribute('aria-live')) === 'polite' &&
    (await page.locator('#review-workflow-feedback-36-14d').innerText()) === '검토 상태를 변경했습니다.',
  'E_STATUS_LIVE_REGION_NOT_FIXED_POLITE_SUCCESS');
  ensure((await page.locator('#case-list .review-case-card').first().locator('.review-status-badge').first().innerText()) === firstRiskBefore &&
    firstCaseBefore.includes(firstRiskBefore), 'E_STATUS_CHANGE_ALTERED_RISK_BADGE');
  const stateResetOption = firstControl.locator('input[value="__reset__"]');
  ensure(await stateResetOption.count() === 1, 'E_EXPLICIT_RESET_OPTION_MISSING');
  await chooseState(firstControl, '__reset__');
  ensure(await stateValue(firstControl) === 'unreviewed', 'E_KEYBOARD_EXPLICIT_STATE_RESET_FAILED');
  await page.locator('#review-queue-reset-36-13a').click();
  ensure(await stateValue(cardControls.first()) === 'unreviewed', 'E_QUEUE_FILTER_RESET_CHANGED_WORKFLOW_STATE');

  // List/detail/history share the active document-memory store and never issue checklist POST implicitly.
  const listCard = page.locator('#case-list .review-case-card').first();
  const detailLink = listCard.locator('a.review-detail-link');
  const detailHref = await detailLink.getAttribute('href');
  await detailLink.click();
  const detailControl = page.locator('#case-detail-content .review-workflow-control-detail-36-14d');
  ensure(page.url().endsWith(detailHref) && !/a_[0-9a-f]{32}|\b(?:unreviewed|in_review|reviewed|deferred)\b/.test(page.url()) &&
    await stateValue(detailControl) === 'unreviewed', 'E_DETAIL_DID_NOT_USE_ACTIVE_STATE_OR_ROUTE_LEAK');
  ensure(!/a_[0-9a-f]{32}|\b(?:unreviewed|in_review|reviewed|deferred)\b/.test(JSON.stringify(await page.evaluate(() => history.state))),
    'E_WORKFLOW_STATE_IN_HISTORY');
  await chooseState(detailControl, 'in_review');
  await capture('07-detail-state-1440.png'); await axe('detail-state');
  await page.goBack();
  await page.locator('#results-dashboard').waitFor({state: 'visible'});
  ensure(await page.locator('#case-list .review-case-card').first().locator('.review-workflow-control-card-36-14d').locator('input:checked').inputValue() === 'in_review',
    'E_BACK_NAVIGATION_DID_NOT_RESTORE_STATE');
  await page.goForward();
  await page.locator('#case-detail-view').waitFor({state: 'visible'});
  ensure(await page.locator('#case-detail-content .review-workflow-control-detail-36-14d').locator('input:checked').inputValue() === 'in_review',
    'E_FORWARD_NAVIGATION_DID_NOT_RESTORE_STATE');
  await page.locator('#workspace-tasks-tab-36-6e').click();
  const explicitChecklist = page.locator('#case-detail-content .checklist-request');
  ensure(await explicitChecklist.count() === 1, 'E_DETAIL_CHECKLIST_CONTROL_MISSING');
  ensure(await explicitChecklist.isEnabled(), 'E_EXPLICIT_CHECKLIST_CONTROL_UNAVAILABLE');
  const checklistRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/v1/investigations/checklist' &&
    request.method() === 'POST');
  await explicitChecklist.click();
  await checklistRequest;
  ensure(await page.locator('#case-detail-content .review-workflow-control-detail-36-14d').locator('input:checked').inputValue() === 'in_review',
    'E_CHECKLIST_RESPONSE_CHANGED_WORKFLOW_STATE');
  await page.locator('#review-back-link').click();
  await page.locator('#results-dashboard').waitFor({state: 'visible'});
  ensure(await page.locator('#case-list .review-case-card').first().locator('.review-workflow-control-card-36-14d').locator('input:checked').inputValue() === 'in_review',
    'E_LIST_STATE_NOT_RESTORED_AFTER_CHECKLIST');
  ensure(checklistPosts === 1 && checklistBodySafe, 'E_EXPLICIT_CHECKLIST_POST_CONTRACT_INVALID');

  // A second document gets a different ephemeral store even for the same synthetic analysis response.
  const secondTab = await context.newPage();
  secondTab.on('pageerror', () => { pageErrors += 1; });
  secondTab.on('console', (message) => { if (message.type() === 'error') consoleErrors += 1; });
  await secondTab.goto(origin, {waitUntil: 'networkidle'});
  const secondSample = secondTab.waitForResponse((response) => new URL(response.url()).pathname === '/api/v1/investigations/sample' &&
    response.request().method() === 'POST');
  await secondTab.locator('#sample-button').click();
  const secondPayload = await (await secondSample).json();
  const secondControl = secondTab.locator('#case-list .review-case-card').first().locator('.review-workflow-control-card-36-14d');
  const primaryTabStateBeforeOtherTabChange = await stateValue(cardControls.first());
  await chooseState(secondControl, 'deferred');
  ensure((await stateValue(cardControls.first())) === primaryTabStateBeforeOtherTabChange && await stateValue(secondControl) === 'deferred',
    'E_SAME_ANALYSIS_IN_OTHER_TAB_SHARED_STATE');
  await secondTab.close();


  const bodyAfterValidChanges = await page.locator('body').innerText();
  const domAfterValidChanges = await analysisDomSnapshot(page);
  const reportDownload = page.waitForEvent('download');
  await page.locator('#report-button').click();
  const downloaded = await reportDownload;
  const reportPath = join(tempRoot, 'synthetic-report.html');
  await downloaded.saveAs(reportPath);
  const downloadedReport = await readFile(reportPath, 'utf8');
  ensure(downloadedReport === firstReportHtml && !/a_[0-9a-f]{32}|\b(?:unreviewed|in_review|reviewed|deferred)\b/.test(downloadedReport),
    'E_REPORT_CONTAINS_WORKFLOW_STATE');
  ensure(digest(domAfterValidChanges) === analysisBeforeDigest &&
    createHash('sha256').update(JSON.stringify({analysis_summary: firstAnalysis.analysis_summary,
      case_summary: firstAnalysis.case_summary, cases: firstAnalysis.cases,
      independent_observations: firstAnalysis.independent_observations, report_export: firstAnalysis.report_export})).digest('hex') === initialCanonicalProjection,
  'E_ANALYSIS_CANONICAL_PROJECTION_CHANGED');
  ensure((await storageSnapshot(page)).local === storageBefore.local &&
    JSON.stringify(await storageSnapshot(page)) === JSON.stringify(storageBefore), 'E_BROWSER_PERSISTENT_STORAGE_CHANGED');
  ensure(page.url() === origin + '/' && await page.evaluate(() => history.state === null), 'E_WORKFLOW_STATE_IN_URL_OR_HISTORY');
  ensure(!/a_[0-9a-f]{32}|WORKFLOW_PRIVATE_CANARY_36_14E/.test(bodyAfterValidChanges) &&
    await page.locator('[data-analysis-ref], [data-workflow-state], [data-review-state]').count() === 0,
  'E_INTERNAL_STATE_OR_CANARY_RENDERED');
  const instrumentation = await page.evaluate(() => window.__workflowInstrumentation);
  ensure(instrumentation.storageListeners === 0 && instrumentation.broadcastChannels === 0 &&
    instrumentation.workers === 0 && instrumentation.clipboardWrites === 0,
  'E_CROSS_CONTEXT_OR_CLIPBOARD_SIDE_CHANNEL_PRESENT');
  ensure(apiRequests > apiBeforeWorkflow && checklistPosts === 1, 'E_EXPLICIT_CHECKLIST_REQUEST_NOT_COUNTED');
  ensure(apiRequests >= 1 && checklistPosts === 1 && externalRequests === 0 && pageErrors === 0 && consoleErrors === 0,
    'E_BROWSER_REQUEST_OR_RUNTIME_BOUNDARY');
  // Starting another analysis replaces the document generation and initializes same-looking refs.
  const oldState = await stateValue(cardControls.first());
  const samplePostCount = requestCounts.get('POST /api/v1/investigations/sample') || 0;
  await page.locator('#nav-start').click();
  await page.locator('#sample-button').waitFor({state: 'visible'});
  const replacementResponse = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/v1/investigations/sample' &&
    response.request().method() === 'POST');
  await page.locator('#sample-button').click();
  const replacementPayload = await (await replacementResponse).json();
  const replacementControls = page.locator('#case-list .review-case-card .review-workflow-control-card-36-14d');
  ensure(oldState === 'in_review' && replacementPayload.cases.length === firstAnalysis.cases.length &&
    await replacementControls.evaluateAll((nodes) => nodes.every((node) => node.querySelector('input[type="radio"]:checked')?.value === 'unreviewed')),
    'E_NEW_GENERATION_REUSED_PREVIOUS_STATE');
  ensure(JSON.stringify(await storageSnapshot(page)) === JSON.stringify(storageBefore), 'E_NEW_GENERATION_PERSISTED_WORKFLOW_STATE');

  // Reload and direct hash entry never revive projection or re-run analysis/checklist.
  const stalePage = await context.newPage();
  stalePage.on('pageerror', () => { pageErrors += 1; });
  stalePage.on('console', (message) => { if (message.type() === 'error') consoleErrors += 1; });
  await stalePage.goto(`${origin}/#/investigations/c_000000000000000000000001`, {waitUntil: 'networkidle'});
  ensure(await stalePage.locator('#review-route-expired').isVisible() &&
    await stalePage.locator('#review-route-expired .review-workflow-control-36-14d').count() === 0,
    'E_DIRECT_ROUTE_MUST_EXPIRE_WITHOUT_STATE');
  await axeTarget(stalePage, 'expired-route');
  await stalePage.reload({waitUntil: 'networkidle'});
  ensure(await stalePage.locator('#review-route-expired').isVisible() &&
    (requestCounts.get('POST /api/v1/investigations/sample') || 0) === samplePostCount + 1 && checklistPosts === 1,
    'E_RELOAD_MUST_NOT_RESTORE_OR_REANALYZE');
  await stalePage.close();

  const viewportResults = [];
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({width, height: 900});
    const layout = await page.evaluate(() => ({scrollWidth: document.documentElement.scrollWidth, width: innerWidth,
      visibleControls: [...document.querySelectorAll('.review-workflow-control-36-14d label')]
        .filter((node) => node.getClientRects().length).map((node) => ({height: node.getBoundingClientRect().height,
          right: node.getBoundingClientRect().right, label: node.closest('fieldset')?.getAttribute('aria-label')})),
      textOverflow: [...document.querySelectorAll('.review-case-card *')].filter((node) =>
        node.scrollWidth > node.clientWidth + 1 && getComputedStyle(node).overflowX !== 'auto').length}));
    ensure(layout.scrollWidth === layout.width && layout.visibleControls.every((control) => control.height >= 44 &&
      control.right <= width + 1 && control.label?.includes('검토 상태')) && layout.textOverflow === 0,
    `E_VIEWPORT_LAYOUT_${width}`);
    viewportResults.push({width, horizontalOverflow: 0, controls: layout.visibleControls.length, textOverflow: layout.textOverflow});
    if (width === 390) { await capture('08-list-390.png'); await axe('list-390'); }
    if (width === 320) { await capture('09-list-320.png'); await axe('list-320'); }
  }
  await page.locator('#case-list .review-case-card a.review-detail-link').first().click();
  await page.setViewportSize({width: 390, height: 844});
  await ensure(await page.locator('#case-detail-content .review-workflow-control-detail-36-14d').isVisible(),
    'E_DETAIL_WORKFLOW_CONTROL_MISSING_NARROW');
  await capture('10-detail-390.png'); await axe('detail-390');
  await page.locator('#review-back-link').click();
  await page.setViewportSize({width: 640, height: 900});
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
  const reflow = await page.evaluate(() => ({scrollWidth: document.documentElement.scrollWidth, width: innerWidth,
    visible: [...document.querySelectorAll('.review-workflow-control-36-14d label')].filter((node) => node.getClientRects().length)
      .map((node) => ({right: node.getBoundingClientRect().right, height: node.getBoundingClientRect().height}))}));
  ensure(reflow.scrollWidth === reflow.width && reflow.visible.every((item) => item.right <= reflow.width + 1 && item.height >= 44),
    'E_200_PERCENT_REFLOW_LAYOUT');
  await capture('11-reflow-200.png'); await axe('reflow-200');
  await page.evaluate(() => { document.documentElement.style.fontSize = ''; });
  await page.setViewportSize({width: 1440, height: 1000});

  const unavailablePage = await context.newPage();
  unavailablePage.on('pageerror', () => { pageErrors += 1; });
  unavailablePage.on('console', (message) => { if (message.type() === 'error') consoleErrors += 1; });
  await unavailablePage.addInitScript(() => {
    try { Object.defineProperty(crypto, 'getRandomValues', {value() { throw new Error('synthetic unavailable'); }}); }
    catch { /* unsupported override remains a test-environment limitation */ }
  });
  await unavailablePage.goto(origin, {waitUntil: 'networkidle'});
  const unavailableSample = unavailablePage.waitForResponse((response) => new URL(response.url()).pathname === '/api/v1/investigations/sample' &&
    response.request().method() === 'POST');
  await unavailablePage.locator('#sample-button').click();
  await unavailableSample;
  ensure(await unavailablePage.locator('#case-list .review-case-card').count() === 2 &&
    await unavailablePage.locator('#review-workflow-note-36-14d').innerText() === '검토 상태를 사용할 수 없습니다. 분석 결과는 계속 표시됩니다.' &&
    await unavailablePage.locator('#review-workflow-feedback-36-14d').innerText() === '검토 상태 저장소를 사용할 수 없습니다.',
    'E_RANDOM_UNAVAILABLE_MUST_ISOLATE_WORKFLOW_FAILURE');
  await axe('store-unavailable');
  await unavailablePage.close();
  const rollbackPage = await context.newPage();
  rollbackPage.on('pageerror', () => { pageErrors += 1; });
  rollbackPage.on('console', (message) => { if (message.type() === 'error') consoleErrors += 1; });
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
    await rollbackPage.locator('#review-queue-state-36-14d').isHidden() &&
    await rollbackPage.evaluate(() => typeof window.investigationReviewState36_14d === 'undefined') &&
    await rollbackPage.evaluate(() => performance.getEntriesByName(`${location.origin}/assets/investigation-review-state-36-14d.js`).length === 0) &&
    await rollbackPage.locator('#case-list .review-case-card').count() === 2, 'E_ROLLBACK_OFF_MUST_NOT_LOAD_OR_EXECUTE_STATE_ASSET');
  await axeTarget(rollbackPage, 'rollback-off');
  const resourceMetrics = await page.evaluate(() => ({domNodes: document.querySelectorAll('*').length,
    workflowDomNodes: document.querySelectorAll('.review-workflow-control-36-14d, #review-workflow-summary-36-14d, #review-workflow-note-36-14d, #review-workflow-feedback-36-14d').length,
    workflowMarkupBytes: new TextEncoder().encode([...document.querySelectorAll('.review-workflow-control-36-14d, #review-workflow-summary-36-14d, #review-workflow-note-36-14d, #review-workflow-feedback-36-14d')]
      .map((node) => node.outerHTML).join('')).byteLength,
    workflowAssetBytes: performance.getEntriesByName(`${location.origin}/assets/investigation-review-state-36-14d.js`)[0]?.transferSize ?? 0,
    appAssetBytes: performance.getEntriesByName(`${location.origin}/assets/app.js`)[0]?.transferSize ?? 0,
    cssAssetBytes: performance.getEntriesByName(`${location.origin}/assets/style.css`)[0]?.transferSize ?? 0,
    changeListeners: window.__workflowInstrumentation.changeListeners}));
  const benchmark = await page.evaluate(() => {
    const api = window.investigationReviewState36_14d;
    const measure = (size) => {
      const refs = Array.from({length: size}, (_, index) => `c_${index.toString(16).padStart(24, '0')}`);
      let generation = 0;
      const cryptoProvider = {getRandomValues(bytes) { bytes.fill(++generation); return bytes; }};
      const operations = {
        store_init() { const store = api.createStore(cryptoProvider); store.beginGeneration(refs); },
        one_hundred_transitions() { const store = api.createStore(cryptoProvider); const gen = store.beginGeneration(refs);
          refs.slice(0, 100).forEach((case_ref) => store.transition({schema_version: 1, analysis_ref: gen.analysis_ref, case_ref}, 'in_review', 0)); },
        state_filter_and_counts() { const store = api.createStore(cryptoProvider); const gen = store.beginGeneration(refs);
          refs.forEach((case_ref, index) => { if (index % 5 === 0) store.transition({schema_version: 1, analysis_ref: gen.analysis_ref, case_ref}, 'deferred', 0); });
          const records = store.list(); records.filter((item) => item.review_state === 'deferred').length;
          Object.fromEntries(['unreviewed', 'in_review', 'reviewed', 'deferred'].map((state) => [state, records.filter((item) => item.review_state === state).length])); },
        list_detail_list_restore() { const store = api.createStore(cryptoProvider); const gen = store.beginGeneration(refs);
          const identity = {schema_version: 1, analysis_ref: gen.analysis_ref, case_ref: refs[0]};
          store.transition(identity, 'in_review', 0); store.snapshot(identity); store.snapshot(identity); },
        generation_replace() { const store = api.createStore(cryptoProvider); store.beginGeneration(refs); store.beginGeneration(refs); }
      };
      const summary = {};
      for (const [name, operation] of Object.entries(operations)) {
        for (let index = 0; index < 5; index++) operation();
        const samples = [];
        for (let index = 0; index < 25; index++) { const start = performance.now(); operation(); samples.push(performance.now() - start); }
        samples.sort((left, right) => left - right);
        summary[name] = {median_ms: samples[12], p95_ms: samples[Math.ceil(samples.length * 0.95) - 1], max_ms: samples.at(-1)};
      }
      return {case_count: size, warmup: 5, samples: 25, operations: summary};
    };
    return [measure(100), measure(128)];
  });
  const rollbackNav = await rollbackPage.evaluate(() => performance.getEntriesByType('navigation')[0]?.domContentLoadedEventEnd ?? null);
  const rollbackDomNodes = await rollbackPage.evaluate(() => document.querySelectorAll('*').length);
  const rollbackChangeListeners = await rollbackPage.evaluate(() => window.__workflowInstrumentation.changeListeners);
  await rollbackPage.close();
  const vectorSummary = {transitionPairs: vectorResult.transitionOutcomes.length,
    allowedTransitionsAccepted: vectorResult.transitionOutcomes.filter((entry) => entry.shouldSucceed && entry.succeeded).length,
    forbiddenTransitionsRejected: vectorResult.transitionOutcomes.filter((entry) => !entry.shouldSucceed && !entry.succeeded).length,
    capacity129: vectorResult.oversizeCode, previousGenerationPreserved: vectorResult.preserved,
    newGenerationIsolation: vectorResult.newGeneration,
    compareAndSet: {successes: vectorResult.raceSuccesses, staleRejected: vectorResult.raceStale, revision: vectorResult.raceRevision},
    schemaError: vectorResult.schemaCode, duplicateRefError: vectorResult.duplicateCode,
    unknownAnalysis: vectorResult.unknownAnalysis, unknownCase: vectorResult.unknownCase,
    invalidEnum: vectorResult.upperState, canaryRedacted: vectorResult.canaryCode === 'INVALID_IDENTIFIER'};
  console.log(JSON.stringify({marker: 'REVIEW_WORKFLOW_STATE_SECURITY_36_14E_SMOKE_PASS', vectorSummary, viewportResults,
    resourceMetrics: {...resourceMetrics, rollbackDomNodes, workflowDomNodeDelta: resourceMetrics.domNodes - rollbackDomNodes,
      rollbackChangeListeners, workflowChangeListenerDelta: resourceMetrics.changeListeners - rollbackChangeListeners},
    benchmark, rollbackInitialRenderMs: rollbackNav, screenshots, keyboardSelectedFilter,
    cardControlCount: await cardControls.count(), apiRequests, checklistPosts, externalRequests, pageErrors, consoleErrors}));
} finally {
  if (context) await context.close();
  if (child.exitCode === null) {
    try {
      if (process.platform !== 'win32') process.kill(-child.pid, 'SIGTERM');
      else child.kill('SIGTERM');
    } catch { child.kill('SIGTERM'); }
    await new Promise((done) => {
      const timer = setTimeout(done, 2500);
      child.once('exit', () => { clearTimeout(timer); done(); });
    });
  }
  await rm(tempRoot, {recursive: true, force: true});
}
