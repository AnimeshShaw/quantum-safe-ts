#!/usr/bin/env node
// The measurement protocol for quantum-safe-ts, the same shape as quantum-safe-py's tests/bench/run_env2.sh: one discarded warm-up run, then
// the timed runs, each in a fresh process; then the leakage screen with its controls; then the aggregate, computed from the saved files.
//
//   node bench/run-protocol.mjs [--runs 15] [--iterations 3000] [--leak-iterations 20000] [--out results/ts/2026-10-12] [--pin auto|none]
//
// Run it from the repository root on an otherwise idle machine on AC power, after `npm run build` in packages/quantum-safe-ts and with a
// clean working tree, so that the commit recorded in each file is the code that ran. Nothing is typed by hand: every figure in a table
// comes from these files.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const arg = (name, dflt) => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? dflt : process.argv[i + 1];
};
const runs = Number(arg('runs', 15));
const iterations = Number(arg('iterations', 3000));
const leakIterations = Number(arg('leak-iterations', 20000));
const pin = arg('pin', 'auto');
const date = new Date().toISOString().slice(0, 10);
const out = arg('out', `results/ts/${date}`);
const here = (f) => fileURLToPath(new URL(f, import.meta.url));
mkdirSync(out, { recursive: true });

const git = (...a) => spawnSync('git', a, { encoding: 'utf8' }).stdout.trim();
if (git('status', '--porcelain', '--untracked-files=no') !== '' && !process.argv.includes('--allow-dirty')) {
  console.error('ERROR: uncommitted changes. Commit first so the recorded commit is the code that ran (or pass --allow-dirty for a rehearsal).');
  process.exit(1);
}
const commit = git('rev-parse', 'HEAD');
writeFileSync(
  join(out, 'ENVIRONMENT.txt'),
  [
    `commit: ${commit}`,
    `date: ${new Date().toISOString()}`,
    `runs: ${runs} timed + 1 discarded warm-up  iterations: ${iterations}  leakage iterations: ${leakIterations}`,
    `node: ${process.version}  v8: ${process.versions.v8}`,
    `platform: ${platform()} ${release()} ${arch()}`,
    `cpu: ${cpus()[0].model} x${cpus().length}  memory: ${Math.round(totalmem() / 2 ** 20)} MiB`,
    `pinned: ${pin !== 'none'}`,
    '',
  ].join('\n'),
);

const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;
function child(script, args, logFile) {
  const all = [here(script), ...args];
  if (pin !== 'none' && platform() === 'win32') {
    // Node cannot pin itself; launch through PowerShell, set affinity and priority right after the process starts, then wait.
    const argList = all.map((a) => `"${a}"`).join(' ');
    const ps = [
      `$p = Start-Process -FilePath ${psQuote(process.execPath)} -ArgumentList ${psQuote(argList)} -PassThru -NoNewWindow -RedirectStandardOutput ${psQuote(logFile)} -RedirectStandardError ${psQuote(`${logFile}.err`)}`,
      'try { $p.ProcessorAffinity = [IntPtr]4; $p.PriorityClass = "High" } catch { }',
      '$p.WaitForExit()',
      'exit $p.ExitCode',
    ].join('; ');
    return spawnSync('powershell', ['-NoProfile', '-Command', ps], { stdio: 'ignore' }).status;
  }
  if (pin !== 'none' && platform() === 'linux') {
    return spawnSync('taskset', ['-c', '2', process.execPath, ...all], { stdio: 'ignore' }).status;
  }
  return spawnSync(process.execPath, all, { stdio: 'ignore' }).status;
}

const total = runs + 1;
for (let i = 1; i <= total; i++) {
  const n = String(i).padStart(2, '0');
  console.error(`run ${i} of ${total}${i === 1 ? ' (warm-up, discarded)' : ''}`);
  const status = child(
    './bench.mjs',
    ['--iterations', String(iterations), '--raw-samples', '--save', join(out, `run${n}.json`)],
    join(out, `run${n}.log`),
  );
  if (status !== 0) throw new Error(`run ${i} failed (exit ${status})`);
}

console.error('leakage screen (controls included)');
const leak = child('./leakage.mjs', ['--iterations', String(leakIterations), '--json', join(out, 'leakage.json')], join(out, 'leakage.log'));
if (leak !== 0) console.error(`leakage screen exited with ${leak}; see ${join(out, 'leakage.log')}`);

const files = Array.from({ length: total }, (_, i) => join(out, `run${String(i + 1).padStart(2, '0')}.json`));
const agg = spawnSync(process.execPath, [here('./aggregate-runs.mjs'), ...files, '--discard-first', '--out', join(out, 'aggregate.json')], {
  stdio: 'inherit',
});
process.exit(agg.status ?? 1);
