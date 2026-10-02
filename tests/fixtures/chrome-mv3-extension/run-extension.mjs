import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium } from 'playwright';

const ext = resolve('ext');
const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'qs-mv3-')), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
});
try {
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 30000 });
  let result;
  for (let i = 0; i < 240 && !result; i++) {
    result = await sw.evaluate(() => self.__QS_RESULT__);
    if (!result) await new Promise((r) => setTimeout(r, 500));
  }
  console.log(JSON.stringify(result));
  process.exit(result && result.ok ? 0 : 1);
} finally {
  await ctx.close();
}
