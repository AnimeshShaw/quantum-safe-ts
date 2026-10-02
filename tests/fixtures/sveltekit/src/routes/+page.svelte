<script>
  import { onMount } from 'svelte';
  import * as q from 'quantum-safe-ts';
  import { smoke } from '../../shared/smoke.mjs';
  let state = $state('running');
  onMount(() => {
    smoke(q)
      .then((r) => { window.__QS_RESULT__ = r; state = r.ok ? 'ok' : 'failed'; })
      .catch((e) => { window.__QS_RESULT__ = { ok: false, error: String((e && e.stack) || e) }; state = 'error'; });
  });
</script>
<p>quantum-safe-ts in SvelteKit: {state}</p>
