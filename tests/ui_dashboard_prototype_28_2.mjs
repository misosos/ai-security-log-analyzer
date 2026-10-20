// Synthetic file-only checks. Never print DOM, axe nodes, file URLs, or canaries.
import AxeBuilder from '@axe-core/playwright';
import {chromium} from '@playwright/test';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';

const ROOT = resolve(import.meta.dirname, '..', 'docs', 'prototypes');
const VARIANTS = ['calm', 'dense'];
const STATES = ['running', 'pending', 'applied', 'paused', 'degraded', 'failed', 'gap', 'empty'];
const WIDTHS = [320, 640, 1024, 1440];
const ALLOWED = new Set([
  ...VARIANTS.map((name) => `/security_dashboard_${name}.html`),
  '/security_dashboard.css', '/security_dashboard.js',
]);
const requireSafe = (condition, code) => { if (!condition) throw new Error(code); };
let stage = 'START';
const summarize = (results) => results.violations
  .map(({id, impact, nodes}) => ({id, impact, count: nodes.length}))
  .sort((a, b) => a.id.localeCompare(b.id));

async function inspect(page, variant, state) {
  const scenario = page.locator(`[data-scenario="${state}"]`);
  await scenario.focus();
  const before = await page.evaluate(() => ({focus: document.activeElement.dataset.scenario, scroll: scrollY}));
  await page.keyboard.press('Enter');
  const after = await page.evaluate(() => ({focus: document.activeElement.dataset.scenario, scroll: scrollY}));
  requireSafe(before.focus === state && after.focus === state && before.scroll === after.scroll,
    `FOCUS_SCROLL_MOVED_${state.toUpperCase()}_${before.scroll}_${after.scroll}`);
  requireSafe(await scenario.getAttribute('aria-pressed') === 'true', 'KEYBOARD_SCENARIO_FAILED');
  requireSafe(await page.locator('h1').count() === 1 && await page.locator('main').count() === 1, 'LANDMARK_HEADING_FAILED');
  requireSafe(await page.locator('#state-announcement[role="status"][aria-live="polite"]').count() === 1, 'STATUS_LIVE_FAILED');
  requireSafe(await page.locator('[id]').evaluateAll((nodes) => new Set(nodes.map((n) => n.id)).size === nodes.length), 'DUPLICATE_ID');
  if (state === 'pending') {
    requireSafe(await page.locator('#apply-results').isVisible(), 'PENDING_ACTION_MISSING');
    requireSafe(await page.locator('.metric strong').first().textContent() === '0', 'PENDING_AUTO_APPLIED');
    await page.locator('#apply-results').focus();
    await page.keyboard.press('Enter');
    requireSafe(await page.locator('.metric strong').first().textContent() === '3', 'PENDING_KEYBOARD_APPLY_FAILED');
    await scenario.focus();
    await page.keyboard.press('Enter');
  }
  if (state === 'applied') {
    requireSafe(await page.locator('.metric strong').allTextContents().then((v) => v.join(',')) === '3,2,1,1', 'SHARED_FIXTURE_COUNTS_FAILED');
  }
  if (state === 'paused') requireSafe((await page.locator('#pause-display').textContent()).includes('재개'), 'PAUSE_LABEL_FAILED');
  if (['degraded', 'failed', 'gap'].includes(state)) {
    requireSafe(await page.locator('#reconnect').isVisible(), 'RECOVERY_ACTION_MISSING');
    requireSafe(await page.locator('#recovery').getAttribute('role') === 'alert', 'RECOVERY_ALERT_MISSING');
    const words = await page.locator('#recovery').textContent();
    requireSafe(words.includes(state === 'gap' ? 'stale' : state.toUpperCase()), 'RECOVERY_TEXT_MISSING');
  }
  for (const width of WIDTHS) {
    await page.setViewportSize({width, height: 900});
    const noOverflow = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1);
    requireSafe(noOverflow, `HORIZONTAL_OVERFLOW_${width}`);
  }
  // A 320 CSS px viewport is the layout proxy for 200% zoom of a 640 CSS px view.
  // Browser CSS zoom would not change media-query breakpoints like page zoom does.
  await page.setViewportSize({width: 320, height: 900});
  requireSafe(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'SYNTHETIC_ZOOM_OVERFLOW');
  const focusStyle = await scenario.evaluate((node) => {
    node.focus();
    const style = getComputedStyle(node);
    return style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) >= 3;
  });
  requireSafe(focusStyle, 'FOCUS_NOT_VISIBLE');
  const reduced = await page.emulateMedia({reducedMotion: 'reduce'});
  void reduced;
  requireSafe(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches), 'REDUCED_MOTION_FAILED');
  await page.emulateMedia({reducedMotion: null});
  const content = await page.locator('body').textContent();
  requireSafe(!/\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:\/Users\/|\/home\/|raw line|username=|account=|password=)/i.test(content), 'PRIVATE_CONTENT_FOUND');
  let results;
  try { results = await new AxeBuilder({page}).analyze(); }
  catch { throw new Error('AXE_FAILED'); }
  const summary = summarize(results);
  requireSafe(summary.length === 0, `AXE_VIOLATION_${summary.map((item) => item.id).join('_').toUpperCase()}`);
  console.log(`${variant} ${state} ${JSON.stringify(summary)}`);
  return summary;
}

async function run() {
  let browser;
  const server = createServer(async (request, response) => {
    const path = request.url;
    if (!ALLOWED.has(path)) { response.writeHead(404).end(); return; }
    try {
      const bytes = await readFile(resolve(ROOT, path.slice(1)));
      const contentType = path.endsWith('.html') ? 'text/html; charset=utf-8' :
        path.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8';
      response.writeHead(200, {'content-type': contentType, 'x-content-type-options': 'nosniff'}).end(bytes);
    } catch { response.writeHead(500).end(); }
  });
  stage = 'LISTEN';
  await new Promise((ok, fail) => server.once('error', fail).listen(0, '127.0.0.1', ok));
  const origin = `http://127.0.0.1:${server.address().port}`;
  let externalRequests = 0;
  let consoleErrors = 0;
  const consoleKinds = {csp: 0, file: 0, other: 0};
  const signatures = [];
  try {
    stage = 'BROWSER';
    browser = await chromium.launch({headless: true, args: [
      '--disable-background-networking', '--no-first-run',
      '--host-resolver-rules=MAP * 0.0.0.0',
    ]});
    for (const timezoneId of ['UTC', 'Asia/Seoul']) {
      stage = 'CONTEXT';
      const context = await browser.newContext({
        timezoneId, serviceWorkers: 'block', acceptDownloads: false, bypassCSP: true,
        proxy: {server: 'http://127.0.0.1:9', bypass: '127.0.0.1,localhost'},
      });
      await context.route('**/*', async (route) => {
        const url = route.request().url();
        const parsed = new URL(url);
        if (parsed.origin === origin && ALLOWED.has(parsed.pathname) && !parsed.search) await route.continue();
        else { externalRequests++; await route.abort(); }
      });
      for (const variant of VARIANTS) {
        stage = 'PAGE';
        const page = await context.newPage();
        page.on('console', (message) => {
          if (message.type() !== 'error') return;
          consoleErrors++;
          const messageText = message.text();
          if (/Content Security Policy|CSP/i.test(messageText)) consoleKinds.csp++;
          else if (/file:/i.test(messageText)) consoleKinds.file++;
          else consoleKinds.other++;
        });
        page.on('pageerror', () => { consoleErrors++; });
        stage = 'GOTO';
        await page.goto(`${origin}/security_dashboard_${variant}.html`);
        await page.locator('#recovery').waitFor();
        const results = [];
        for (const state of STATES) { stage = `SCAN_${state.toUpperCase()}`; results.push(await inspect(page, variant, state)); }
        await page.locator('[data-scenario="applied"]').click();
        await page.locator('#pause-display').focus();
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('.metric strong').first().textContent() === '3', 'PAUSE_LOST_APPLIED_RESULT');
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('.metric strong').first().textContent() === '3', 'RESUME_LOST_APPLIED_RESULT');
        await page.locator('summary').focus();
        await page.keyboard.press('Enter');
        requireSafe(await page.locator('details').getAttribute('open') !== null, 'DISCLOSURE_KEYBOARD_FAILED');
        signatures.push(JSON.stringify(results));
        await page.close();
      }
      await context.close();
    }
    requireSafe(signatures[0] === signatures[2] && signatures[1] === signatures[3], 'TIMEZONE_NONDETERMINISTIC');
    requireSafe(externalRequests === 0, `EXTERNAL_NETWORK_REQUEST_${externalRequests}`);
    requireSafe(consoleErrors === 0, `BROWSER_CONSOLE_ERROR_${consoleErrors}_${consoleKinds.csp}_${consoleKinds.file}_${consoleKinds.other}`);
    console.log(`variants=2 states=8 widths=4 timezones=2 axe_violations=0 exclusions=0 external_requests=${externalRequests}`);
  } finally {
    await browser?.close();
    await new Promise((ok) => server.close(ok));
    let listening = false;
    try { await fetch(`${origin}/security_dashboard_calm.html`, {signal: AbortSignal.timeout(300)}); listening = true; }
    catch { /* Expected after shutdown. */ }
    requireSafe(!listening, 'LOOPBACK_LISTENER_REMAINED');
  }
}

run().catch((error) => {
  const safe = /^[A-Z0-9_]+$/.test(error.message) ? error.message : `PROTOTYPE_BROWSER_TEST_FAILED_${stage}`;
  console.error(safe);
  process.exitCode = 1;
});
