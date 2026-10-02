import * as q from 'quantum-safe-ts';
import { smoke } from './shared/smoke.mjs';
const r = await smoke(q);
console.log(JSON.stringify(r));
if (!r.ok) process.exit(1);
