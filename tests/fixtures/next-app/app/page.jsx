'use client';
import { useEffect, useState } from 'react';
import * as q from 'quantum-safe-ts';
import { smoke } from '../shared/smoke.mjs';

export default function Page() {
  const [state, setState] = useState('running');
  useEffect(() => {
    smoke(q)
      .then((r) => { window.__QS_RESULT__ = r; setState(r.ok ? 'ok' : 'failed'); })
      .catch((e) => { window.__QS_RESULT__ = { ok: false, error: String((e && e.stack) || e) }; setState('error'); });
  }, []);
  return <p>quantum-safe-ts in Next.js: {state}</p>;
}
