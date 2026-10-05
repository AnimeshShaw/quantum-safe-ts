#!/usr/bin/env python3
"""Generate vectors for the formats added in quantum-safe-py 0.3.1, from the REAL Python library.

Writes tests/vectors/py_v2_vectors.json: envelope v2 (pure ML-KEM-1024, HKDF-SHA-384), the ``-v2``
signature format (all eight identifiers) and RFC 9964 ``StandardJwt`` tokens. quantum-safe-ts must open and
verify all of it (packages/quantum-safe-ts/test/py-v2-interop.test.ts).

Requires quantum-safe-py >= 0.3.1 (NOT yet released: install it from the ``security/0.3.1`` branch of
quantum-safe-py, e.g. ``pip install -e <path-to-quantum_safe>``). The pin in scripts/requirements.txt is for the
0.3.0 vectors and does not have these formats; this script refuses to run on it.

Run from the repository root:
    python scripts/generate_py_v2_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

from quantum_safe import KEM, HybridSign  # noqa: E402
from quantum_safe.protocols.envelope import Envelope  # noqa: E402
from quantum_safe.protocols.standard_jwt import StandardJwt  # noqa: E402  (absent before 0.3.1)
from quantum_safe.signatures import Sign  # noqa: E402

V2_IDS = [
    "ML-DSA-44-v2", "ML-DSA-65-v2", "ML-DSA-87-v2",
    "Ed25519+ML-DSA-44-v2", "Ed25519+ML-DSA-65-v2", "Ed25519+ML-DSA-87-v2",
    "P-256+ML-DSA-44-v2", "P-256+ML-DSA-65-v2",
]

out: dict = {"generated_by": "quantum-safe-py >= 0.3.1 (security/0.3.1 branch)", "envelope_v2": [], "signatures_v2": [], "standard_jwt": []}

kp = KEM("ML-KEM-1024").generate_keypair()
for aad in (b"", b"py-v2-vector"):
    pt = b"py envelope v2 " + (b"with aad" if aad else b"no aad")
    sealed = Envelope.seal(pt, kp.public, aad=aad)
    assert sealed.version == 2
    out["envelope_v2"].append({
        "secret_key": kp.secret.raw_bytes.hex(), "plaintext": pt.hex(), "aad": aad.hex(), "sealed": sealed.to_bytes().hex(),
    })

for ident in V2_IDS:
    signer = HybridSign(*ident.split("+", 1)) if "+" in ident else Sign(ident)
    sk = signer.generate_keypair()
    for ctx in (b"", b"py-v2-ctx"):
        sm = signer.sign(b"py signed message (v2)", sk.secret, context=ctx)
        out["signatures_v2"].append({
            "algorithm": ident, "public_key": sk.public.raw_bytes.hex(), "context": ctx.hex(), "signed_message": sm.to_cbor().hex(),
        })

for alg in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    jk = StandardJwt.generate_keypair(alg)
    # expires_in=0: no exp claim, so the vector never expires.
    token = StandardJwt.sign({"sub": "py-user", "n": 7}, jk.secret, issuer="py-iss", expires_in=0, kid=f"py-{alg}")
    out["standard_jwt"].append({"algorithm": alg, "public_jwk": StandardJwt.public_jwk(jk.public, kid=f"py-{alg}"), "issuer": "py-iss", "token": token})

path = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "py_v2_vectors.json"
path.write_text(json.dumps(out, indent=1), encoding="utf-8")
print(f"wrote {path}: {len(out['envelope_v2'])} envelope, {len(out['signatures_v2'])} signature, {len(out['standard_jwt'])} jwt vectors")
