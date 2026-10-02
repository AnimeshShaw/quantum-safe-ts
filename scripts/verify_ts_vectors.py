#!/usr/bin/env python3
"""Verify, with the real quantum-safe-py, data produced by quantum-safe-ts.

This is the reverse-direction parity check (ts -> py). Run after:
    cargo run -p quantum-safe-core --example gen_ts_vectors
Exits non-zero on any mismatch.
"""
import json
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore")

from quantum_safe import KEM, HybridKEM  # noqa: E402
from quantum_safe.protocols.envelope import Envelope, SealedMessage  # noqa: E402
from quantum_safe.types import PublicKey, SecretKey  # noqa: E402
from quantum_safe.types.kem import CipherText, HybridCipherText  # noqa: E402

root = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors"
v = json.loads((root / "ts_vectors.json").read_text())
fails = 0


def check(label, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + label)
    fails += 0 if ok else 1


for k in v["kem"]:
    algo = k["algorithm"]
    sk = SecretKey(raw=bytes.fromhex(k["secret_key"]), algorithm=algo)
    ct_bytes = bytes.fromhex(k["ciphertext"])
    try:
        if "+" in algo:
            classical, pqc = algo.split("+", 1)
            kem = HybridKEM(classical=classical, pqc=pqc)
            ct = HybridCipherText.from_bytes(ct_bytes, algo)
        else:
            kem = KEM(algo)
            ct = CipherText(ct_bytes, algo)
        ss = bytes(kem.decapsulate(sk, ct))
        check(f"kem {algo}", ss.hex() == k["shared_secret"])
    except Exception as exc:  # noqa: BLE001
        check(f"kem {algo} ({type(exc).__name__}: {exc})", False)

for e in v["envelope"]:
    algo = e["algorithm"]
    try:
        sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm=algo)
        sealed = SealedMessage.from_bytes(bytes.fromhex(e["sealed"]))
        pt = Envelope.open(sealed, sk)
        check(f"envelope {algo}", pt.hex() == e["plaintext"])
    except Exception as exc:  # noqa: BLE001
        check(f"envelope {algo} ({type(exc).__name__}: {exc})", False)

sys.exit(1 if fails else 0)
