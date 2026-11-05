import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {webkit} from '@playwright/test';

// Diagnostic only: this isolates WebKit's native select behavior. The expected
// violation is not filtered from the production-page acceptance test.
const cases = {
  empty: '<!doctype html><html><body>plain content</body></html>',
  select: '<!doctype html><html><body><select><option>One</option></select></body></html>',
  div: '<!doctype html><html><body><div>plain content</div></body></html>',
  externalReset: '<!doctype html><html><head><link rel="stylesheet" href="/reset.css"></head><body><select><option>One</option></select></body></html>'
};
const server = createServer((request, response) => {
  if (request.url === '/reset.css') {
    response.writeHead(200, {'Content-Type': 'text/css'});
    response.end('select { appearance: none; -webkit-appearance: none; }');
    return;
  }
  const name = new URL(request.url, 'http://local.test').pathname.slice(1);
  response.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': "default-src 'none'; style-src 'self'; style-src-attr 'none'; script-src 'self'"
  });
  response.end(cases[name] || '');
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const browser = await webkit.launch({headless: true});
try {
  const counts = {};
  for (const name of Object.keys(cases)) {
    const page = await browser.newPage();
    const errors = [];
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push({text: message.text(), location: message.location()});
    });
    page.on('pageerror', (error) => errors.push({text: error.message}));
    await page.goto(`http://127.0.0.1:${server.address().port}/${name}`);
    counts[name] = errors;
    await page.close();
  }
  assert.equal(counts.empty.length, 0);
  assert.equal(counts.div.length, 0);
  assert.equal(counts.select.length, 1);
  assert.match(counts.select[0].text, /style-src/);
  assert.equal(counts.externalReset.length, 1);
  assert.match(counts.externalReset[0].text, /style-src/);
  console.log(JSON.stringify({engine: browser.version(), expectedDiagnostic: true,
    empty: counts.empty.length, select: counts.select.length, div: counts.div.length,
    externalReset: counts.externalReset.length, selectLocation: counts.select[0].location,
    csp: "unchanged"}));
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
