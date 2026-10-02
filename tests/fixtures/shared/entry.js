import * as q from 'quantum-safe-ts';
import { smoke } from './smoke.mjs';

smoke(q)
  .then((r) => { window.__QS_RESULT__ = r; })
  .catch((e) => { window.__QS_RESULT__ = { ok: false, error: String((e && e.stack) || e) }; });
