#!/usr/bin/env node
// Repeats the benchmarks and aggregates, so one noisy run cannot become "the number".
//
//   node bench/run-matrix.mjs [--runs 5] [--pin auto|none] [--out results/bench_matrix.json] [--filter substring]
//
// Every benchmark runs in its OWN fresh process (bench/bench.mjs --only <name>), in a different random order each round, so heap and
// WebAssembly-memory state left by earlier benchmarks cannot colour later ones. For each benchmark the table reports the median across
// rounds of the per-round median ops/s, the min and max, and the coefficient of variation (CV) of the per-round medians.
// --pin auto pins each child to one performance-core thread (Windows: ProcessorAffinity via PowerShell; Linux: taskset) and raises its
// priority, which removes most of the hybrid-core (P/E) bimodality. The machine should be on AC power and otherwise idle.
// Results are indicative of this machine only.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { cpus, platform, release, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? dflt : process.argv[i + 1];
};
const rounds = Number(arg('runs', 5));
const pin = arg('pin', 'auto');
const outPath = arg('out', 'results/bench_matrix.json');
const benchPath = fileURLToPath(new URL('./bench.mjs', import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), 'qs-bench-'));

const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;

function runChild(name, jsonFile) {
  const args = [benchPath, '--only', name, '--json', jsonFile];
  let r;
  if (pin !== 'none' && platform() === 'win32') {
    // Node cannot pin itself; launch through PowerShell, set affinity and priority right after the process starts, then wait.
    const argList = args.map((a) => `"${a}"`).join(' ');
    const ps = [
      `$p = Start-Process -FilePath ${psQuote(process.execPath)} -ArgumentList ${psQuote(argList)} -PassThru -NoNewWindow -RedirectStandardOutput ${psQuote(`${jsonFile}.out`)} -RedirectStandardError ${psQuote(`${jsonFile}.err`)}`,
      'try { $p.ProcessorAffinity = [IntPtr]4; $p.PriorityClass = "High" } catch { }',
      '$p.WaitForExit()',
      'exit $p.ExitCode',
    ].join('; ');
    r = spawnSync('powershell', ['-NoProfile', '-Command', ps], { stdio: 'ignore' });
  } else if (pin !== 'none' && platform() === 'linux') {
    r = spawnSync('taskset', ['-c', '2', process.execPath, ...args], { stdio: 'ignore' });
  } else {
    r = spawnSync(process.execPath, args, { stdio: 'ignore' });
  }
  if (r.status !== 0) throw new Error(`benchmark '${name}' failed (${r.status})`);
  return JSON.parse(readFileSync(jsonFile, 'utf8')).results;
}

const list = spawnSync(process.execPath, [benchPath, '--list'], { encoding: 'utf8' });
const filter = arg('filter', null);
const names = JSON.parse(list.stdout.trim().split(String.fromCharCode(10)).filter((l) => l.startsWith('[')).at(-1)).filter((n) => filter === null || n.includes(filter));
console.error(`${names.length} benchmarks x ${rounds} rounds, each in its own process (pinned=${pin !== 'none'})`);

const samples = new Map(names.map((n) => [n, []]));
for (let round = 0; round < rounds; round++) {
  const order = [...names].sort(() => Math.random() - 0.5);
  console.error(`round ${round + 1}/${rounds}`);
  let i = 0;
  for (const name of order) {
    const res = runChild(name, join(tmp, `r${round}-${i++}.json`));
    for (const r of res) samples.get(r.name)?.push(r.opsPerSec);
  }
}
rmSync(tmp, { recursive: true, force: true });

const med = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const mean = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const rows = [...samples]
  .filter(([, xs]) => xs.length)
  .map(([name, xs]) => {
    const m = mean(xs);
    const sd = Math.sqrt(mean(xs.map((x) => (x - m) ** 2)));
    return { name, medianOpsPerSec: med(xs), minOpsPerSec: Math.min(...xs), maxOpsPerSec: Math.max(...xs), cvPercent: (sd / m) * 100, rounds: xs.length };
  });
const out = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: `${platform()} ${release()}`,
  cpu: cpus()[0].model,
  logicalCpus: cpus().length,
  rounds,
  isolatedProcesses: true,
  pinned: pin !== 'none',
  caveat: 'Single machine; indicative only. Each benchmark ran in its own process; per-round values are medians of >= 5 batches; this table is the median across rounds.',
  results: rows,
};
writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n');
console.log(`\n${out.cpu} | Node ${out.node} | ${rounds} rounds | isolated processes | pinned=${out.pinned}\n`);
for (const r of rows) {
  console.log(`${r.name.padEnd(52)} ${r.medianOpsPerSec.toFixed(1).padStart(9)} ops/s  [${r.minOpsPerSec.toFixed(1)} .. ${r.maxOpsPerSec.toFixed(1)}]  cv ${r.cvPercent.toFixed(1)}%`);
}
