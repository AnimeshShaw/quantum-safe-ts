#!/usr/bin/env python3
"""Generate cross-language parity vectors for quantum-safe-ts.

Exercises the exact "glue" functions in quantum-safe-py that quantum-safe-ts
must reproduce bit-for-bit: the hybrid KEM shared-secret combiner, the
envelope's AAD construction, its key derivation, and its AES-256-GCM call.
Uses fixed, deterministic byte inputs -- no key generation, no randomness --
so every value here is exactly reproducible by re-running this script against
the pinned quantum-safe-py==0.3.0 in scripts/requirements.txt.

Run from the repository root:
    python scripts/generate_vectors.py
"""
import json
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from quantum_safe.protocols.envelope import Envelope
from quantum_safe.types.kem import combine_shared_secrets


def hx(b: bytes) -> str:
    return b.hex()


vectors = {}

# --- combiner: quantum_safe.types.kem.combine_shared_secrets ---
classical_ss = bytes(range(32))
pqc_ss = bytes((i * 7) % 256 for i in range(32))
classical_ct = bytes((i * 3) % 256 for i in range(32))
pqc_ct = bytes((i * 5) % 256 for i in range(1088))
algorithm = "X25519+ML-KEM-768"

combined = combine_shared_secrets(
    classical_ss=classical_ss,
    pqc_ss=pqc_ss,
    algorithm=algorithm,
    classical_ct=classical_ct,
    pqc_ct=pqc_ct,
)
vectors["combiner"] = {
    "classical_ss": hx(classical_ss),
    "pqc_ss": hx(pqc_ss),
    "classical_ct": hx(classical_ct),
    "pqc_ct": hx(pqc_ct),
    "algorithm": algorithm,
    "expected_shared_secret": hx(bytes(combined)),
}

# --- envelope enc_key derivation: SharedSecret.derive_key(info="qs-envelope-enc-v1") ---
shared_secret_bytes = bytes((i * 11) % 256 for i in range(32))
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"qs-envelope-enc-v1")
enc_key = hkdf.derive(shared_secret_bytes)
vectors["enc_key_derivation"] = {
    "shared_secret": hx(shared_secret_bytes),
    "info": "qs-envelope-enc-v1",
    "expected_enc_key": hx(enc_key),
}

# --- envelope AAD construction: Envelope._build_aad ---
built_aad = Envelope._build_aad(version=1, algorithm=algorithm, extra=b"")
vectors["aad_construction"] = {
    "version": 1,
    "algorithm": algorithm,
    "extra": "",
    "expected_aad": hx(built_aad),
}
built_aad_with_extra = Envelope._build_aad(version=1, algorithm=algorithm, extra=b"hello-aad")
vectors["aad_construction_with_extra"] = {
    "version": 1,
    "algorithm": algorithm,
    "extra": hx(b"hello-aad"),
    "expected_aad": hx(built_aad_with_extra),
}

# --- AES-256-GCM: fixed key/nonce/plaintext/aad ---
enc_key_fixed = bytes((i * 13) % 256 for i in range(32))
nonce = bytes((i * 17) % 256 for i in range(12))
plaintext = b"the quick brown fox jumps over the lazy dog"
aesgcm = AESGCM(enc_key_fixed)
ciphertext = aesgcm.encrypt(nonce, plaintext, built_aad)
vectors["aes_gcm"] = {
    "key": hx(enc_key_fixed),
    "nonce": hx(nonce),
    "plaintext": hx(plaintext),
    "aad": hx(built_aad),
    "expected_ciphertext_with_tag": hx(ciphertext),
}

out_path = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "glue_vectors.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(vectors, indent=2) + "\n")
print(f"Wrote {len(vectors)} vector sets to {out_path}")
