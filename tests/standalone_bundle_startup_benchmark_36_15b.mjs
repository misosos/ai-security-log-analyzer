import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import http from 'node:http';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

const executable = resolve(process.argv[2] ?? '');
if (!process.argv[2]) throw new Error('STANDALONE_BENCH_EXECUTABLE_REQUIRED');
const workspace = await mkdtemp(join(tmpdir(), 'aisla-bundle-benchmark-합성-'));
const home = join(workspace, 'isolated home');
const tmp = join(workspace, 'temporary files');
await mkdir(home);
await mkdir(tmp);
let proxyRequests = 0;
const proxy = http.createServer((request, response) => {
  proxyRequests++;
  request.resume();
  response.writeHead(502);
  response.end();
});
proxy.on('connect', (_request, socket) => {
  proxyRequests++;
  socket.end('HTTP/1.1 502 Blocked\r\nConnection: close\r\n\r\n');
});
await new Promise((done) => proxy.listen(0, '127.0.0.1', done));
const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
const env = {
  HOME: home,
  TMPDIR: tmp,
  TMP: tmp,
  TEMP: tmp,
  PATH: '',
  LANG: 'en_US.UTF-8',
  HTTP_PROXY: proxyUrl,
  HTTPS_PROXY: proxyUrl,
  ALL_PROXY: proxyUrl,
  http_proxy: proxyUrl,
  https_proxy: proxyUrl,
  all_proxy: proxyUrl,
  NO_PROXY: '127.0.0.1,localhost',
  no_proxy: '127.0.0.1,localhost',
};

function ensure(value, code) { if (!value) throw new Error(code); }
async function port() {
  const server = createServer();
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const value = server.address().port;
  await new Promise((done) => server.close(done));
  return value;
}
async function stop(child) {
  const started = performance.now();
  child.kill('SIGINT');
  const code = await Promise.race([
    new Promise((done) => child.once('exit', done)),
    new Promise((_, reject) => setTimeout(() => reject(new Error('STANDALONE_BENCH_SHUTDOWN_TIMEOUT')), 8000)),
  ]);
  ensure(code === 0, 'STANDALONE_BENCH_SHUTDOWN_FAILED');
  return performance.now() - started;
}
async function runOnce() {
  const selectedPort = await port();
  const origin = `http://127.0.0.1:${selectedPort}`;
  const child = spawn(executable, ['--no-browser', '--port', String(selectedPort)], {
    cwd: workspace, env, stdio: 'ignore',
  });
  const start = performance.now();
  let readyAt;
  try {
    for (let attempt = 0; attempt < 600; attempt++) {
      if (child.exitCode !== null) break;
      try {
        const response = await fetch(`${origin}/api/health`, {signal: AbortSignal.timeout(250)});
        if (response.ok && (await response.json()).status === 'ok') {
          readyAt = performance.now();
          break;
        }
      } catch { /* bounded readiness poll */ }
      await new Promise((done) => setTimeout(done, 100));
    }
    ensure(readyAt !== undefined && child.exitCode === null, 'STANDALONE_BENCH_READINESS_FAILED');
    const rootStart = performance.now();
    const root = await fetch(origin);
    const rootMs = performance.now() - rootStart;
    ensure(root.status === 200, 'STANDALONE_BENCH_ROOT_FAILED');
    const analysisStart = performance.now();
    const analysis = await fetch(`${origin}/api/v1/investigations/sample`, {method: 'POST'});
    const analysisBody = await analysis.json();
    const analysisMs = performance.now() - analysisStart;
    ensure(analysis.status === 200 && analysisBody.schema_version === '2', 'STANDALONE_BENCH_SYNTHETIC_ANALYSIS_FAILED');
    const shutdownMs = await stop(child);
    return {
      readinessMs: readyAt - start,
      rootMs,
      analysisMs,
      shutdownMs,
    };
  } finally {
    if (child.exitCode === null) {
      child.kill('SIGKILL');
      await new Promise((done) => child.once('exit', done)).catch(() => {});
    }
  }
}
function summary(values) {
  const ordered = [...values].sort((a, b) => a - b);
  return {
    median_ms: Math.round((ordered[Math.floor((ordered.length - 1) / 2)] + ordered[Math.ceil((ordered.length - 1) / 2)]) / 2),
    p95_ms: Math.round(ordered[Math.ceil(ordered.length * 0.95) - 1]),
    max_ms: Math.round(ordered.at(-1)),
  };
}

let failed = false;
try {
  const cold = [];
  for (let index = 0; index < 5; index++) cold.push(await runOnce());
  await runOnce(); // one warm-up excluded from the warm sample
  const warm = [];
  for (let index = 0; index < 20; index++) warm.push(await runOnce());
  ensure(proxyRequests === 0, 'STANDALONE_BENCH_EXTERNAL_REQUESTS');
  for (const key of ['readinessMs', 'rootMs', 'analysisMs', 'shutdownMs']) {
    console.log(`${key} cold=${JSON.stringify(summary(cold.map((item) => item[key])))} warm=${JSON.stringify(summary(warm.map((item) => item[key])))}`);
  }
  console.log('STANDALONE_BENCH_COUNTS: cold=5 warmup=1 warm=20 external_requests=0');
} catch (error) {
  failed = true;
  const category = String(error?.message ?? '').match(/STANDALONE_BENCH_[A-Z0-9_]+/)?.[0] ?? 'STANDALONE_BENCH_HARNESS_ERROR';
  process.stderr.write(`STANDALONE_BENCH_FAIL: ${category}.\n`);
  process.exitCode = 1;
} finally {
  await new Promise((done) => proxy.close(done));
  await rm(workspace, {recursive: true, force: true}).catch(() => {});
}
