#!/usr/bin/env python3
"""Generate COSE_Sign1 vectors from the REAL quantum-safe-py (>= 0.4.0, ``quantum_safe.protocols.cose``).

Writes tests/vectors/py_cose_vectors.json; quantum-safe-ts must verify every message
(packages/quantum-safe-ts/test/cose-py-interop.test.ts).

Run from the repository root, with quantum-safe-py >= 0.4.0 installed (or on PYTHONPATH):
    python scripts/generate_py_cose_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe.protocols.cose import sign1  # noqa: E402  (absent before 0.4.0)
from quantum_safe.signatures.core import Sign  # noqa: E402

out: dict = {"generated_by": f"quantum-safe-py {quantum_safe.__version__} (protocols.cose)", "vectors": []}
for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    kp = Sign(algorithm).generate_keypair()
    cases = [
        ("tagged with kid", dict(kid=b"py-key-1"), b"", b"hello from python"),
        ("untagged", dict(tagged=False), b"", b"untagged message"),
        ("external aad", dict(external_aad=b"app-context"), b"app-context", b"bound to a context"),
        ("detached", dict(detached=True), b"", b"a detached document body"),
        ("empty payload", dict(), b"", b""),
    ]
    for name, opts, aad, payload in cases:
        message = sign1(payload, kp.secret, **opts)
        out["vectors"].append(
            {
                "algorithm": algorithm,
                "case": name,
                "public_key": kp.public.raw_bytes.hex(),
                "external_aad": aad.hex(),
                "payload": payload.hex(),
                "detached": bool(opts.get("detached", False)),
                "message": message.hex(),
            }
        )

path = pathlib.Path(__file__).resolve().parents[1] / "tests" / "vectors" / "py_cose_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {path}: {len(out['vectors'])} vectors")
