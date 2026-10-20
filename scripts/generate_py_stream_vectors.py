#!/usr/bin/env python3
"""Generate streaming-envelope (format v3) vectors from the REAL quantum-safe-py (>= 1.0.0).

Writes tests/vectors/py_stream_vectors.json. quantum-safe-ts must open every stream to the plaintext
(packages/quantum-safe-ts/test/stream-py-interop.test.ts).

Run from the repository root, with quantum-safe-py >= 1.0.0 installed (or on PYTHONPATH):
    python scripts/generate_py_stream_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

import quantum_safe  # noqa: E402
from quantum_safe import KEM, HybridKEM, XWing  # noqa: E402
from quantum_safe.protocols.stream import seal_bytes  # noqa: E402  (absent before 1.0.0)

CHUNK = 1024
out: dict = {
    "generated_by": f"quantum-safe-py {quantum_safe.__version__} (protocols.stream)",
    "chunk_size": CHUNK,
    "vectors": [],
}

suites = {
    "X25519+ML-KEM-768": lambda: HybridKEM("X25519", "ML-KEM-768").generate_keypair(),
    "P-256+ML-KEM-512": lambda: HybridKEM("P-256", "ML-KEM-512").generate_keypair(),
    "P-384+ML-KEM-1024": lambda: HybridKEM("P-384", "ML-KEM-1024").generate_keypair(),
    "ML-KEM-1024": lambda: KEM("ML-KEM-1024").generate_keypair(),
    "X-Wing": lambda: XWing().generate_keypair(),
}
for algorithm, make in suites.items():
    kp = make()
    for length, aad in ((0, b""), (1, b""), (1024, b""), (1025, b"file-7"), (3000, b""), (2048, b"tenant-a")):
        plaintext = bytes((i * 31 + length) & 0xFF for i in range(length))
        stream = seal_bytes(kp.public, plaintext, aad=aad, chunk_size=CHUNK)
        out["vectors"].append(
            {
                "algorithm": algorithm,
                "secret_key": kp.secret.raw_bytes.hex(),
                "aad": aad.hex(),
                "plaintext": plaintext.hex(),
                "stream": stream.hex(),
            }
        )

path = pathlib.Path(__file__).resolve().parents[1] / "tests" / "vectors" / "py_stream_vectors.json"
path.write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {path}: {len(out['vectors'])} vectors")
