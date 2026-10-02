#!/usr/bin/env python3
"""Generate cross-language parity vectors for every algorithm suite.

Unlike generate_vectors.py (fixed glue inputs), this script uses the *real*
quantum-safe-py (liboqs backend) to create keypairs, ciphertexts and sealed
envelopes for each supported suite. quantum-safe-ts must open/decapsulate every
one of them and reproduce the exact same shared secret / plaintext.

Keys are random, so regenerating changes the fixture; the committed file is the
reference. Run from the repository root:

    python scripts/generate_suite_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

from quantum_safe import KEM, HybridKEM  # noqa: E402
from quantum_safe.protocols.envelope import Envelope  # noqa: E402

HYBRID_SUITES = [
    ("X25519", "ML-KEM-512"),
    ("X25519", "ML-KEM-768"),
    ("X25519", "ML-KEM-1024"),
    ("P-256", "ML-KEM-512"),
    ("P-256", "ML-KEM-768"),
]
PURE_SUITES = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

hx = bytes.hex
vectors: dict = {"_meta": {"generator": "scripts/generate_suite_vectors.py", "quantum_safe_py": "0.3.0"}}

# ---- KEM: every suite, py encapsulates, ts must decapsulate to the same secret ----
kem_vectors = []
for classical, pqc in HYBRID_SUITES:
    kem = HybridKEM(classical=classical, pqc=pqc)
    assert kem.backend_name == "liboqs", kem.backend_name
    kp = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public)
    assert bytes(kem.decapsulate(kp.secret, ct)) == bytes(ss)
    kem_vectors.append(
        {
            "algorithm": kp.public.algorithm,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "ciphertext": hx(ct.to_bytes()),
            "shared_secret": hx(bytes(ss)),
        }
    )
for name in PURE_SUITES:
    kem = KEM(name)
    kp = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public)
    assert bytes(kem.decapsulate(kp.secret, ct)) == bytes(ss)
    kem_vectors.append(
        {
            "algorithm": name,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "ciphertext": hx(bytes(ct)),
            "shared_secret": hx(bytes(ss)),
        }
    )
vectors["kem"] = kem_vectors

# ---- Envelope: every hybrid suite, py seals, ts must open ----
env_vectors = []
for classical, pqc in HYBRID_SUITES:
    kem = HybridKEM(classical=classical, pqc=pqc)
    kp = kem.generate_keypair()
    plaintext = f"envelope for {classical}+{pqc}".encode()
    aad = b"suite-vector"
    sealed = Envelope.seal(plaintext, kp.public, aad=aad)
    assert Envelope.open(sealed, kp.secret) == plaintext
    env_vectors.append(
        {
            "algorithm": kp.public.algorithm,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "plaintext": hx(plaintext),
            "aad": hx(aad),
            "sealed": hx(sealed.to_bytes()),
        }
    )
vectors["envelope"] = env_vectors

out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "suite_vectors.json"
out.write_text(json.dumps(vectors, indent=1) + "\n")
print(f"Wrote {len(kem_vectors)} KEM and {len(env_vectors)} envelope vectors to {out}")
