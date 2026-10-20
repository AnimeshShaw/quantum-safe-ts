#!/usr/bin/env node
// Aggregates several saved benchmark runs into one table, from the files alone. Same output layout as quantum-safe-py's
// tests/bench/aggregate_runs.py (so its table scripts read it), plus a bootstrap interval over the runs.
//
//   node bench/aggregate-runs.mjs results/ts/2026-10-12/run*.json --discard-first --out results/ts/2026-10-12/aggregate.json
//
// For each benchmark: the median across runs of each run's median (not the fastest run), the fastest and slowest run median, the spread
// between runs (CoV of the run medians), and a 95% bootstrap percentile interval of that median across runs (10,000 resamples, fixed seed).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => args.includes(`--${n}`);
const value = (n) => {
  const i = args.indexOf(`--${n}`);
  return i === -1 ? null : args[i + 1];
};
const outPath = value('out');
const discardFirst = flag('discard-first');
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out').sort();

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
};
const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const stdev = (xs) => (xs.length > 1 ? Math.sqrt(xs.reduce((a, b) => a + (b - mean(xs)) ** 2, 0) / (xs.length - 1)) : 0);

// Small deterministic generator so the interval reproduces from the same files.
function mulberry32(a) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function bootstrapCi(xs, resamples = 10000) {
  const rand = mulberry32(20261012);
  const meds = new Float64Array(resamples);
  for (let r = 0; r < resamples; r++) {
    const pick = new Array(xs.length);
    for (let i = 0; i < xs.length; i++) pick[i] = xs[Math.floor(rand() * xs.length)];
    meds[r] = median(pick);
  }
  meds.sort();
  return [meds[Math.floor(resamples * 0.025)], meds[Math.min(resamples - 1, Math.floor(resamples * 0.975))]];
}

let paths = files;
if (discardFirst) {
  if (paths.length < 2) throw new Error('--discard-first needs at least two run files');
  paths = paths.slice(1);
}
if (paths.length === 0) throw new Error('no run files');

const loaded = paths.map((p) => JSON.parse(readFileSync(p, 'utf8')));
const runs = loaded.map((d) => {
  const m = new Map();
  for (const row of d.results) {
    if (m.has(row.name)) throw new Error(`duplicate benchmark name in one run: ${row.name}`);
    m.set(row.name, row.median_us);
  }
  return m;
});
const names = [...runs[0].keys()];
runs.slice(1).forEach((run, i) => {
  if (run.size !== names.length || names.some((n) => !run.has(n))) throw new Error(`run ${i + 2} (${paths[i + 1]}) has a different set of benchmarks`);
});

const r3 = (x) => Math.round(x * 1000) / 1000;
const rows = names.map((name) => {
  const medians = runs.map((run) => run.get(name));
  const spread = medians.length > 1 ? (stdev(medians) / mean(medians)) * 100 : 0;
  const [lo, hi] = medians.length > 1 ? bootstrapCi(medians) : [medians[0], medians[0]];
  return {
    name,
    runs: medians.length,
    median_of_run_medians_us: r3(median(medians)),
    fastest_run_us: r3(Math.min(...medians)),
    slowest_run_us: r3(Math.max(...medians)),
    run_to_run_cov_pct: Math.round(spread * 100) / 100,
    ci95_lo_us: r3(lo),
    ci95_hi_us: r3(hi),
  };
});
const result = { files: paths, discarded_first: discardFirst, metadata_of_first_file: loaded[0].metadata ?? {}, rows };

console.log(`${paths.length} runs${discardFirst ? ' (first discarded)' : ''}`);
console.log(`${'benchmark'.padEnd(52)} ${'median'.padStart(10)} ${'fastest'.padStart(10)} ${'slowest'.padStart(10)} ${'run CoV'.padStart(8)}  95% CI`);
for (const r of rows) {
  const cov = `${r.run_to_run_cov_pct.toFixed(1)}%`;
  console.log(
    `${r.name.padEnd(52)} ${r.median_of_run_medians_us.toFixed(2).padStart(10)} ${r.fastest_run_us.toFixed(2).padStart(10)} ${r.slowest_run_us.toFixed(2).padStart(10)} ${cov.padStart(8)}  [${r.ci95_lo_us.toFixed(2)}, ${r.ci95_hi_us.toFixed(2)}]`,
  );
}
if (outPath) {
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log(`\nSaved to ${outPath}`);
}
