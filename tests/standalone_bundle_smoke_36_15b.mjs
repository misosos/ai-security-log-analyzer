import AxeBuilder from '@axe-core/playwright';
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import http from 'node:http';
import {lstatSync, readdirSync, rmSync, chmodSync, copyFileSync, mkdirSync, readlinkSync, symlinkSync} from 'node:fs';
import {mkdtemp, mkdir, readFile, readdir, rm, stat, chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const executableArg = process.argv[2];
if (!executableArg) throw new Error('STANDALONE_SMOKE_EXECUTABLE_REQUIRED');
const executable = resolve(executableArg);
const bundle = resolve(executable, '..');
const repository = resolve(fileURLToPath(new URL('..', import.meta.url)));
const manifest = JSON.parse(await readFile(join(bundle, '..', 'ai-security-log-analyzer.manifest.json'), 'utf8'));
const initialFileSet = manifest.files.map((item) => `${item.path}:${item.size_bytes}:${item.sha256}`).join('\n');
const workspace = await mkdtemp(join(tmpdir(), 'aisla-bundle-space-합성-'));
function cleanupWorkspace() {
  const restore = (directory) => {
    for (const name of readdirSync(directory)) {
      const child = join(directory, name);
      const info = lstatSync(child);
      if (info.isDirectory() && !info.isSymbolicLink()) restore(child);
    }
    chmodSync(directory, 0o700);
  };
  try { restore(workspace); rmSync(workspace, {recursive: true, force: true}); } catch { /* best-effort isolated test cleanup */ }
}
process.on('exit', cleanupWorkspace);
function reportSafeFailure(error) {
  const category = String(error?.message ?? '').match(/STANDALONE_SMOKE_[A-Z0-9_]+/)?.[0] ?? 'STANDALONE_SMOKE_HARNESS_ERROR';
  process.stderr.write(`STANDALONE_SMOKE_FAIL: ${category}.\n`);
  process.exitCode = 1;
}
process.on('uncaughtException', reportSafeFailure);
process.on('unhandledRejection', reportSafeFailure);
const appCopy = join(workspace, 'Local App Copy');
const isolatedHome = join(workspace, 'isolated home');
const browserProfile = join(workspace, 'chromium profile');
const tmp = join(workspace, 'tmp');
await mkdir(isolatedHome);
await mkdir(tmp);
const portProbe = createServer();
await new Promise((done) => portProbe.listen(0, '127.0.0.1', done));
const runtimePort = portProbe.address().port;
await new Promise((done) => portProbe.close(done));
await copyBundle(bundle, appCopy);
const copiedExecutable = join(appCopy, 'ai-security-log-analyzer');

for (const directory of await listDirectories(appCopy)) await chmod(directory, 0o555);
for (const file of await listFiles(appCopy)) {
  const info = await stat(file);
  await chmod(file, (info.mode & 0o111) ? 0o555 : 0o444);
}

function ensure(value, category) { if (!value) throw new Error(category); }
function listDirectories(root) { return walk(root, true); }
function listFiles(root) { return walk(root, false); }
async function walk(root, directories) {
  const found = [];
  for (const entry of await readdir(root, {withFileTypes: true})) {
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (directories) found.push(path);
      found.push(...await walk(path, directories));
    } else if (!directories && entry.isFile()) found.push(path);
  }
  return found;
}
async function copyBundle(source, destination) {
  const links = [];
  const copyDirectory = async (from, to) => {
    mkdirSync(to, {mode: 0o700});
    for (const entry of readdirSync(from, {withFileTypes: true}).sort((left, right) => left.name.localeCompare(right.name))) {
      const src = join(from, entry.name);
      const dst = join(to, entry.name);
      const info = lstatSync(src);
      if (info.isSymbolicLink()) links.push([src, dst]);
      else if (info.isDirectory()) await copyDirectory(src, dst);
      else if (info.isFile()) copyFileSync(src, dst);
      else throw new Error('STANDALONE_SMOKE_UNSUPPORTED_FILE_TYPE');
    }
  };
  await copyDirectory(source, destination);
  for (const [src, dst] of links) symlinkSync(readlinkSync(src), dst);
}

let proxyRequests = 0;
const proxy = http.createServer((request, response) => {
  proxyRequests++;
  request.resume();
  response.writeHead(502, {'content-type': 'text/plain'});
  response.end('blocked');
});
proxy.on('connect', (request, socket) => {
  proxyRequests++;
  socket.end('HTTP/1.1 502 Blocked\r\nConnection: close\r\n\r\n');
});
await new Promise((done) => proxy.listen(0, '127.0.0.1', done));
const proxyPort = proxy.address().port;
const origin = `http://127.0.0.1:${runtimePort}`;
const env = {
  HOME: isolatedHome,
  TMPDIR: tmp,
  TEMP: tmp,
  TMP: tmp,
  PATH: '',
  LANG: 'en_US.UTF-8',
  HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
  HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`,
  ALL_PROXY: `http://127.0.0.1:${proxyPort}`,
  http_proxy: `http://127.0.0.1:${proxyPort}`,
  https_proxy: `http://127.0.0.1:${proxyPort}`,
  all_proxy: `http://127.0.0.1:${proxyPort}`,
  NO_PROXY: '127.0.0.1,localhost',
  no_proxy: '127.0.0.1,localhost',
};
const child = spawn(copiedExecutable, ['--no-browser', '--port', String(runtimePort)], {
  cwd: workspace,
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let sourceChild;
let sourceOutput = '';
let sourcePort;
let childOutput = '';
child.stdout.on('data', (part) => { childOutput += part.toString('utf8'); });
child.stderr.on('data', (part) => { childOutput += part.toString('utf8'); });
let context;
let externalRequests = 0;
let checklistPosts = 0;
let samplePosts = 0;
let guidancePosts = 0;
let observedAssets = new Set();
let pageErrors = [];
let ready = false;
try {
  for (let attempt = 0; attempt < 600; attempt++) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(250)});
      if (response.ok && (await response.json()).status === 'ok') { ready = true; break; }
    } catch { /* wait for bounded local readiness */ }
    await new Promise((done) => setTimeout(done, 100));
  }
  ensure(ready && child.exitCode === null, 'STANDALONE_SMOKE_READINESS_FAILED');
  const sourceProbe = createServer();
  await new Promise((done) => sourceProbe.listen(0, '127.0.0.1', done));
  sourcePort = sourceProbe.address().port;
  await new Promise((done) => sourceProbe.close(done));
  const sourcePython = process.platform === 'win32'
    ? join(repository, '.venv', 'Scripts', 'python.exe')
    : join(repository, '.venv', 'bin', 'python');
  const sourceOrigin = `http://127.0.0.1:${sourcePort}`;
  const sourceEnv = {...env, PYTHONPATH: repository, PYTHON_DOTENV_DISABLED: '1'};
  sourceChild = spawn(sourcePython, ['-m', 'app.local_web', '--no-browser', '--port', String(sourcePort)], {
    cwd: repository, env: sourceEnv, stdio: ['ignore', 'pipe', 'pipe'],
  });
  sourceChild.stdout.on('data', (part) => { sourceOutput += part.toString('utf8'); });
  sourceChild.stderr.on('data', (part) => { sourceOutput += part.toString('utf8'); });
  let sourceReady = false;
  for (let attempt = 0; attempt < 600; attempt++) {
    if (sourceChild.exitCode !== null) break;
    try {
      const response = await fetch(`${sourceOrigin}/api/health`, {signal: AbortSignal.timeout(250)});
      if (response.ok && (await response.json()).status === 'ok') { sourceReady = true; break; }
    } catch { /* wait for bounded local source readiness */ }
    await new Promise((done) => setTimeout(done, 100));
  }
  ensure(sourceReady && sourceChild.exitCode === null, 'STANDALONE_SMOKE_SOURCE_BASELINE_UNAVAILABLE');
  const health = await fetch(`${origin}/api/health`);
  ensure(health.status === 200, 'STANDALONE_SMOKE_HEALTH_FAILED');
  const html = await fetch(origin);
  ensure(html.status === 200 && (await html.text()).includes('AI Security Log Analyzer'), 'STANDALONE_SMOKE_HTML_FAILED');
  const css = await fetch(`${origin}/assets/style.css`);
  ensure(css.status === 200 && (await css.text()).length > 0, 'STANDALONE_SMOKE_CSS_FAILED');
  const script = await fetch(`${origin}/assets/app.js`);
  ensure(script.status === 200 && (await script.text()).length > 0, 'STANDALONE_SMOKE_JS_FAILED');

  context = await chromium.launchPersistentContext(browserProfile, {headless: true, serviceWorkers: 'block', args: [
    '--disable-background-networking', '--disable-extensions', '--no-first-run',
    `--proxy-server=http://127.0.0.1:${proxyPort}`,
  ]});
  await context.route('**/*', async (route) => {
    if (new URL(route.request().url()).origin !== origin) {
      externalRequests++;
      await route.abort();
    } else await route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => { pageErrors.push(error.name); });
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === origin && url.pathname === '/api/v1/investigations/sample' && request.method() === 'POST') samplePosts++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/checklist' && request.method() === 'POST') checklistPosts++;
    if (url.origin === origin && url.pathname === '/api/v1/investigations/guidance' && request.method() === 'POST') guidancePosts++;
    if (url.origin === origin && url.pathname.startsWith('/assets/')) observedAssets.add(url.pathname);
  });
  await page.setViewportSize({width: 1440, height: 900});
  await page.goto(origin, {waitUntil: 'networkidle'});
  await page.locator('#sample-button').click();
  await page.locator('#results-heading').waitFor({state: 'visible', timeout: 15000});
  ensure(await page.locator('#results-dashboard').isVisible(), 'STANDALONE_SMOKE_SAMPLE_RESULT_MISSING');
  ensure(samplePosts === 1 && checklistPosts === 0, 'STANDALONE_SMOKE_SAMPLE_OR_CHECKLIST_CONTRACT_FAILED');
  ensure(observedAssets.has('/assets/input-quality-ui-36-12b.js') &&
    observedAssets.has('/assets/review-queue-ui-36-13a.js') &&
    observedAssets.has('/assets/investigation-review-state-36-14d.js'), 'STANDALONE_SMOKE_ASSET_MISSING');
  const axe = await new AxeBuilder({page}).analyze();
  ensure(axe.violations.length === 0, 'STANDALONE_SMOKE_AXE_FAILED');
  for (const [source, filename] of [
    ['application', 'brute_force.log'], ['ssh', 'ssh_auth.log'], ['access', 'web_shell.log'],
  ]) {
    const logText = await readFile(join(appCopy, '_internal', 'sample_logs', filename), 'utf8');
    const parsed = await page.evaluate(async ({source, logText}) => {
      const response = await fetch('/api/v1/investigations/text', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({schema_version: 1, source, log_text: logText}),
      });
      return {status: response.status, body: await response.json()};
    }, {source, logText});
    const sourceParsedResponse = await fetch(`${sourceOrigin}/api/v1/investigations/text`, {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({schema_version: 1, source, log_text: logText}),
    });
    const sourceParsed = await sourceParsedResponse.json();
    const canonical = (value) => JSON.stringify(value, (_key, item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        return Object.fromEntries(Object.entries(item).sort(([left], [right]) => left.localeCompare(right)));
      }
      return item;
    });
    ensure(parsed.status === sourceParsedResponse.status &&
      canonical(parsed.body.input_scope) === canonical(sourceParsed.input_scope) &&
      canonical(parsed.body.result?.input_quality) === canonical(sourceParsed.result?.input_quality),
    `STANDALONE_SMOKE_SOURCE_PARITY_${source.toUpperCase()}`);
    const qualitySources = parsed.body.result?.input_quality?.by_source?.map((item) => item.source).join('_').toUpperCase() ?? 'MISSING';
    const errorCode = /^[A-Z0-9_]+$/.test(parsed.body.error_code ?? '') ? parsed.body.error_code : 'NONE';
    ensure(parsed.status === 200 && parsed.body.input_scope.source === source &&
      parsed.body.result.input_quality.by_source.length === 1 &&
      parsed.body.result.input_quality.by_source[0].source === source,
    `STANDALONE_SMOKE_SOURCE_ANALYSIS_${source.toUpperCase()}_${parsed.status}_${errorCode}_${qualitySources}`);
  }
  const firstCase = page.locator('#case-list a[data-review-case-ref]').first();
  await firstCase.waitFor({state: 'visible'});
  await firstCase.click();
  await page.locator('.workspace-detail-shell-36-6b').waitFor({state: 'visible'});
  ensure(checklistPosts === 0 && pageErrors.length === 0, 'STANDALONE_SMOKE_DETAIL_OR_PAGE_ERROR');
  await page.getByRole('tab', {name: '근거와 한계'}).click();
  const guidanceButton = page.locator('#workspace-evidence-panel-36-6e .guidance-request');
  await guidanceButton.click();
  await page.locator('#workspace-evidence-panel-36-6e .guidance-citation').first().waitFor({state: 'visible', timeout: 10000});
  ensure(guidancePosts === 1 && checklistPosts === 0, 'STANDALONE_SMOKE_RETRIEVAL_CORPUS_FAILED');
  const invalid = await page.evaluate(async () => {
    const response = await fetch('/api/v1/investigations/text', {
      method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({schema_version: 1, source: 'unsupported-synthetic', log_text: 'SYNTHETIC_INVALID_SOURCE'}),
    });
    const body = await response.json();
    return {status: response.status, error_code: body.error_code};
  });
  const sourceInvalidResponse = await fetch(`${sourceOrigin}/api/v1/investigations/text`, {
    method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({schema_version: 1, source: 'unsupported-synthetic', log_text: 'SYNTHETIC_INVALID_SOURCE'}),
  });
  const sourceInvalid = await sourceInvalidResponse.json();
  ensure(invalid.status === sourceInvalidResponse.status && invalid.error_code === sourceInvalid.error_code,
    'STANDALONE_SMOKE_SOURCE_INVALID_PARITY');
  ensure(invalid.status === 422 && invalid.error_code === 'UNKNOWN_SOURCE', 'STANDALONE_SMOKE_INVALID_INPUT_CONTRACT');
  ensure(externalRequests === 0 && proxyRequests === 0, 'STANDALONE_SMOKE_EXTERNAL_REQUESTS');
  await context.close();
  context = null;
} finally {
  if (context) await context.close().catch(() => {});
  if (sourceChild && sourceChild.exitCode === null) {
    sourceChild.kill('SIGINT');
    await Promise.race([
      new Promise((done) => sourceChild.once('exit', done)),
      new Promise((_, reject) => setTimeout(() => reject(new Error('STANDALONE_SMOKE_SOURCE_SHUTDOWN_TIMEOUT')), 8000)),
    ]).catch(() => { sourceChild.kill('SIGKILL'); });
  }
  if (child.exitCode === null) {
    child.kill('SIGINT');
    await Promise.race([
      new Promise((done) => child.once('exit', done)),
      new Promise((_, reject) => setTimeout(() => reject(new Error('STANDALONE_SMOKE_SHUTDOWN_TIMEOUT')), 8000)),
    ]).catch(() => { child.kill('SIGKILL'); });
  }
  await new Promise((done) => proxy.close(done));
}
ensure(child.exitCode === 0, 'STANDALONE_SMOKE_SHUTDOWN_FAILED');
ensure(sourceChild?.exitCode === 0, 'STANDALONE_SMOKE_SOURCE_SHUTDOWN_FAILED');
ensure(childOutput.includes(`http://127.0.0.1:${runtimePort}/`), 'STANDALONE_SMOKE_LOOPBACK_URL_MISSING');
ensure(!childOutput.includes(workspace) && !childOutput.includes('/Users/') &&
  !sourceOutput.includes(workspace) && !sourceOutput.includes('/Users/'), 'STANDALONE_SMOKE_PRIVATE_PATH_LEAK');
ensure(proxyRequests === 0 && externalRequests === 0 && checklistPosts === 0, 'STANDALONE_SMOKE_REQUEST_BOUNDARY_FAILED');
const after = JSON.parse(await readFile(join(bundle, '..', 'ai-security-log-analyzer.manifest.json'), 'utf8'));
ensure(after.files.map((item) => `${item.path}:${item.size_bytes}:${item.sha256}`).join('\n') === initialFileSet,
  'STANDALONE_SMOKE_BUNDLE_MUTATED');
await new Promise((done) => setTimeout(done, 100));
// Keep a benign responder on the default port to prove that the bundle fails
// closed instead of attaching to or probing an unrelated local server.
let collisionRequests = 0;
const sentinel = http.createServer((request, response) => {
  collisionRequests++;
  request.resume();
  response.writeHead(200, {'content-type': 'application/json'});
  response.end('{"status":"ok"}');
});
await new Promise((done) => sentinel.listen(runtimePort, '127.0.0.1', done));
const collision = spawn(copiedExecutable, ['--no-browser', '--port', String(runtimePort)], {cwd: workspace, env, stdio: 'ignore'});
await Promise.race([
  new Promise((done) => collision.once('exit', done)),
  new Promise((_, reject) => setTimeout(() => reject(new Error('STANDALONE_SMOKE_COLLISION_TIMEOUT')), 5000)),
]);
ensure(collision.exitCode !== 0 && collisionRequests === 0, 'STANDALONE_SMOKE_PORT_COLLISION_FAILED');
await new Promise((done) => sentinel.close(done));
cleanupWorkspace();
console.log('STANDALONE_ONEDIR_SMOKE_OK: loopback, synthetic API, UI route, privacy, cleanup.');
