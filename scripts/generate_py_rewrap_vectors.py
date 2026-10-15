#!/usr/bin/env python3
"""Generate re-wrap vectors from the REAL quantum-safe-py (>= 0.4.0, ``Envelope.rewrap``).

Writes tests/vectors/py_rewrap_vectors.json: envelopes sealed under an old key and the same messages
re-wrapped to a new key by Python, with both secret keys. quantum-safe-ts must open the re-wrapped copy
and re-wrap the original itself (packages/quantum-safe-ts/test/rewrap-py-interop.test.ts).

Run from the repository root, with quantum-safe-py on PYTHONPATH or installed:
    python scripts/generate_py_rewrap_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe import HybridKEM  # noqa: E402
from quantum_safe.protocols.envelope import Envelope  # noqa: E402

PAIRS = [
    ("X25519", "ML-KEM-768", "X25519", "ML-KEM-1024"),
    ("X25519", "ML-KEM-512", "X25519", "ML-KEM-768"),
    ("P-256", "ML-KEM-768", "X25519", "ML-KEM-1024"),
]

out: dict = {"generated_by": f"quantum-safe-py {quantum_safe.__version__} Envelope.rewrap", "vectors": []}
for c1, p1, c2, p2 in PAIRS:
    old = HybridKEM(c1, p1).generate_keypair()
    new = HybridKEM(c2, p2).generate_keypair()
    for label, plaintext, aad in (
        ("with aad", f"migrate me: {c1}+{p1}".encode(), b"record-42"),
        ("no aad", b"no context", b""),
    ):
        original = Envelope.seal(plaintext, old.public, aad=aad)
        moved = Envelope.rewrap(original, old.secret, new.public, expected_aad=aad)
        out["vectors"].append(
            {
                "label": f"{c1}+{p1} -> {c2}+{p2} ({label})",
                "from": f"{c1}+{p1}",
                "to": f"{c2}+{p2}",
                "plaintext": plaintext.hex(),
                "aad": aad.hex(),
                "old_secret_pem": old.secret.to_pem(),
                "new_secret_pem": new.secret.to_pem(),
                "new_public_pem": new.public.to_pem(),
                "original": original.to_bytes().hex(),
                "rewrapped": moved.to_bytes().hex(),
            }
        )

path = pathlib.Path(__file__).resolve().parents[1] / "tests" / "vectors" / "py_rewrap_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {path}: {len(out['vectors'])} vectors")
