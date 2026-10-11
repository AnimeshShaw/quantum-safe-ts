#!/usr/bin/env python3
"""Generate X-Wing vectors from the REAL quantum-safe-py (>= 0.4.0, ``quantum_safe.kem.xwing.XWing``).

Writes tests/vectors/py_xwing_vectors.json. quantum-safe-ts must decapsulate every ciphertext to the same shared
secret, and a ciphertext it makes for the Python public key must decapsulate under the Python secret key
(packages/quantum-safe-ts/test/xwing-py-interop.test.ts).

Run from the repository root, with quantum-safe-py >= 0.4.0 installed (or on PYTHONPATH):
    python scripts/generate_py_xwing_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe.kem.xwing import XWing  # noqa: E402  (absent before 0.4.0)

kem = XWing()
out: dict = {"generated_by": f"quantum-safe-py {quantum_safe.__version__} (XWing)", "vectors": []}
for _ in range(6):
    kp = kem.generate_keypair()
    for _ in range(2):
        ct, ss = kem.encapsulate(kp.public)
        out["vectors"].append(
            {
                "secret_key": kp.secret.raw_bytes.hex(),
                "public_key": kp.public.raw_bytes.hex(),
                "ciphertext": bytes(ct).hex(),
                "shared_secret": bytes(ss).hex(),
            }
        )

path = pathlib.Path(__file__).resolve().parents[1] / "tests" / "vectors" / "py_xwing_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {path}: {len(out['vectors'])} vectors")
