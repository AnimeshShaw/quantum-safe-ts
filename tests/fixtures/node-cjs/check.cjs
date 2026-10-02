const q = require('quantum-safe-ts');
(async () => {
  const { smoke } = await import('./shared/smoke.mjs');
  const r = await smoke(q);
  console.log(JSON.stringify(r));
  if (!r.ok) process.exit(1);
})();
