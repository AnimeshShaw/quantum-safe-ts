import * as q from 'quantum-safe-ts';
import { smoke } from './shared/smoke.mjs';

smoke(q)
  .then((r) => { self.__QS_RESULT__ = r; })
  .catch((e) => { self.__QS_RESULT__ = { ok: false, error: String((e && e.stack) || e) }; });
