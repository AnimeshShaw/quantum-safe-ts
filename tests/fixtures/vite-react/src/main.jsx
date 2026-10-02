import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import * as q from 'quantum-safe-ts';
import { smoke } from '../shared/smoke.mjs';

function App() {
  const [state, setState] = useState('running');
  useEffect(() => {
    smoke(q)
      .then((r) => { window.__QS_RESULT__ = r; setState(r.ok ? 'ok' : 'failed'); })
      .catch((e) => { window.__QS_RESULT__ = { ok: false, error: String((e && e.stack) || e) }; setState('error'); });
  }, []);
  return <p id="status">quantum-safe-ts in React: {state}</p>;
}
createRoot(document.getElementById('root')).render(<App />);
