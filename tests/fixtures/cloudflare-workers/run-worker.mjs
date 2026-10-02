import { unstable_dev } from 'wrangler';
const worker = await unstable_dev('worker.js', { config: 'wrangler.toml', local: true, experimental: { disableExperimentalWarning: true } });
let result;
try {
  const res = await worker.fetch('/');
  result = await res.json();
} finally {
  await worker.stop();
}
console.log(JSON.stringify(result));
process.exit(result && result.ok ? 0 : 1);
