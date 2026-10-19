#!/usr/bin/env python3
"""Generate seed-key vectors from the REAL quantum-safe-py (>= 1.0.0, with the optional ``cryptography`` backend).

Writes tests/vectors/py_private_vectors.json: private AKP JWKs and private COSE keys (the 32-byte seed) made by
Python, with a token and a COSE_Sign1 each signed with them. quantum-safe-ts must derive the same public keys
from the seeds, verify Python's messages, and sign with Python's keys
(packages/quantum-safe-ts/test/private-keys-py-interop.test.ts).

Run from the repository root, with quantum-safe-py >= 1.0.0 and cryptography >= 48 installed (or on PYTHONPATH):
    python scripts/generate_py_private_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe.protocols.cose import encode_cose_private_key, sign1  # noqa: E402
from quantum_safe.protocols.standard_jwt import StandardJwt  # noqa: E402

out: dict = {
    "generated_by": f"quantum-safe-py {quantum_safe.__version__} (StandardJwt private JWKs, cose private keys; pyca backend)",
    "vectors": [],
}
for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
    private = StandardJwt.generate_private_jwk(algorithm, kid=f"py-{algorithm}")
    keypair = StandardJwt.keypair_from_private_jwk(private)
    token = StandardJwt.sign({"sub": "from-python"}, private, expires_in=0)
    out["vectors"].append(
        {
            "algorithm": algorithm,
            "private_jwk": private,
            "public_jwk": StandardJwt.public_jwk(private),
            "token": token,
            "cose_private_key": encode_cose_private_key(keypair, kid=f"py-{algorithm}".encode()).hex(),
            "cose_sign1": sign1(b"cose from python", keypair.secret, kid=f"py-{algorithm}".encode()).hex(),
            "cose_payload": b"cose from python".hex(),
        }
    )

path = pathlib.Path(__file__).resolve().parents[1] / "tests" / "vectors" / "py_private_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {path}: {len(out['vectors'])} vectors")
