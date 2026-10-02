// Serves a static build directory and runs it in Chromium, Firefox and WebKit via Playwright.
// The page must set window.__QS_RESULT__ = { ok, checks, ... }.
//   node shared/browser-check.mjs <dir> [path] [--browsers=chromium,firefox,webkit]
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { chromium, firefox, webkit } from 'playwright';

const [dir, startPath = '/index.html'] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const flag = process.argv.find((a) => a.startsWith('--browsers='));
const wanted = (flag ? flag.split('=')[1] : 'chromium,firefox,webkit').split(',');
const root = resolve(dir);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.json': 'application/json', '.svg': 'image/svg+xml' };

const server = createServer(async (req, res) => {
  try {
    let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (p.endsWith('/')) p += 'index.html';
    const file = normalize(join(root, p));
    if (!file.startsWith(root)) { res.writeHead(403).end(); return; }
    let data;
    try { data = await readFile(file); } catch { data = await readFile(join(file, 'index.html')); }
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' }).end(data);
  } catch { res.writeHead(404).end('not found'); }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${server.address().port}${startPath}`;
let failed = false;
for (const name of wanted) {
  const type = { chromium, firefox, webkit }[name];
  const browser = await type.launch();
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(url);
    await page.waitForFunction(() => window.__QS_RESULT__ !== undefined, null, { timeout: 120000 });
    const result = await page.evaluate(() => window.__QS_RESULT__);
    const ok = result && result.ok === true;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name} ${JSON.stringify(result)}${errors.length ? ' pageErrors=' + JSON.stringify(errors) : ''}`);
    if (!ok) failed = true;
  } catch (e) {
    console.log(`FAIL ${name} ${e.message}`);
    failed = true;
  } finally {
    await browser.close();
  }
}
server.close();
process.exit(failed ? 1 : 0);
