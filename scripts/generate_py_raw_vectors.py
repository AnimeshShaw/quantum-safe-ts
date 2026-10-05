#!/usr/bin/env python3
"""Generate standard FIPS 204 ML-DSA vectors from the REAL quantum-safe-py, using ``Sign.sign_raw()``.

Writes tests/vectors/py_raw_fips204_vectors.json: for ML-DSA-44/65/87 and an empty, a short and a
255-byte context, the public key, message, context and bare signature that ``Sign.sign_raw`` produced
(it passes the message and context to FIPS 204 ML-DSA.Sign natively; nothing is prefixed or wrapped).
The TypeScript test (packages/quantum-safe-ts/test/py-raw-fips204.test.ts) must verify every one with
the library's bare FIPS 204 verifier.

Requires quantum-safe-py >= 0.3.2 (``Sign.sign_raw`` is new there). Run from the repository root:
    python scripts/generate_py_raw_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe.signatures import Sign  # noqa: E402

if not hasattr(Sign, "sign_raw"):
    raise SystemExit("this quantum-safe-py has no Sign.sign_raw; install quantum-safe-py>=0.3.2")

CONTEXTS = [b"", b"quantum-safe-ts interop", bytes(range(255))]  # empty, short, 255 bytes (the FIPS 204 maximum)
out: dict = {"generated_by": f"quantum-safe-py {quantum_safe.__version__} (Sign.sign_raw)", "vectors": []}

for level in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    signer = Sign(level)
    kp = signer.generate_keypair()
    for ctx in CONTEXTS:
        msg = b"standard FIPS 204 message for " + level.encode() + b" ctx" + str(len(ctx)).encode()
        sig = signer.sign_raw(msg, kp.secret, context=ctx)
        signer.verify_raw(msg, sig, kp.public, context=ctx)  # Python accepts its own output
        out["vectors"].append(
            {"algorithm": level, "public_key": kp.public.raw_bytes.hex(), "message": msg.hex(), "context": ctx.hex(), "signature": sig.hex()}
        )

path = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "py_raw_fips204_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
print(f"wrote {path}: {len(out['vectors'])} vectors")
