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

from quantum_safe import KEM, HybridKEM, HybridSign  # noqa: E402
from quantum_safe.signatures import Sign  # noqa: E402
from quantum_safe.protocols.jwt import JWTSigner  # noqa: E402
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
keypairs = []  # (label, KeyPair) reused for key-serialization vectors
for classical, pqc in HYBRID_SUITES:
    kem = HybridKEM(classical=classical, pqc=pqc)
    assert kem.backend_name == "liboqs", kem.backend_name
    kp = kem.generate_keypair()
    ct, ss = kem.encapsulate(kp.public)
    assert bytes(kem.decapsulate(kp.secret, ct)) == bytes(ss)
    keypairs.append(kp)
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
    keypairs.append(kp)
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

# ---- Key serialization: py's exact CBOR / PEM / JWK / fingerprint / bundle bytes ----
key_vectors = []
for kp in keypairs:
    key_vectors.append(
        {
            "algorithm": kp.public.algorithm,
            "migration_state": kp.public.migration_state.value,
            "public_raw": hx(kp.public.raw_bytes),
            "secret_raw": hx(kp.secret.raw_bytes),
            "public_cbor": hx(kp.public.to_cbor()),
            "secret_cbor": hx(kp.secret.to_cbor()),
            "public_pem": kp.public.to_pem(),
            "secret_pem": kp.secret.to_pem(),
            "public_jwk": kp.public.to_jwk(),
            "fingerprint": kp.public.fingerprint(),
            "fingerprint_colon": kp.public.fingerprint_colon(),
            "bundle": hx(kp.to_cbor_bundle()),
        }
    )
vectors["keys"] = key_vectors

# ---- Signatures: py signs, ts must verify (and sign with py keys, py verifies later) ----
PURE_SIGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256s"]
HYBRID_SIGS = [("Ed25519", "ML-DSA-44"), ("Ed25519", "ML-DSA-65"), ("Ed25519", "ML-DSA-87"), ("P-256", "ML-DSA-44"), ("P-256", "ML-DSA-65")]
sig_vectors = []


def add_sig(signer, kp, label, hedged):
    msg = f"py signed {label}".encode()
    ctx = b"vector-ctx"
    sm = signer.sign(msg, kp.secret, context=ctx)
    signer.verify(sm, kp.public)
    sig_vectors.append(
        {
            "algorithm": kp.public.algorithm,
            "hedged": hedged,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "message": hx(msg),
            "context": hx(ctx),
            "signed_message": hx(sm.to_cbor()),
            "signature_blob": hx(sm.signature),
        }
    )


for name in PURE_SIGS:
    signer = Sign(name)
    add_sig(signer, signer.generate_keypair(), name, True)
    signer = Sign(name, hedged=False)
    add_sig(signer, signer.generate_keypair(), name, False)
for classical, pqc in HYBRID_SIGS:
    signer = HybridSign(classical=classical, pqc=pqc)
    add_sig(signer, signer.generate_keypair(), f"{classical}+{pqc}", True)
    signer = HybridSign(classical=classical, pqc=pqc, hedged=False)
    add_sig(signer, signer.generate_keypair(), f"{classical}+{pqc}", False)
vectors["signatures"] = sig_vectors

# ---- JWT (quantum-safe-py mode): py signs, ts must verify ----
jwt_vectors = []
for algo in ["ML-DSA-65", "Ed25519+ML-DSA-65", "ML-DSA-44", "Ed25519+ML-DSA-87"]:
    signer = HybridSign(*algo.split("+")) if "+" in algo else Sign(algo)
    kp = signer.generate_keypair()
    token = JWTSigner(kp, issuer="https://issuer.example").sign(
        {"sub": "user-123", "role": "admin"}, expires_in=10**9
    )
    jwt_vectors.append(
        {
            "algorithm": algo,
            "public_key": hx(kp.public.raw_bytes),
            "token": token,
            "issuer": "https://issuer.example",
        }
    )
vectors["jwt"] = jwt_vectors

out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "suite_vectors.json"
out.write_text(json.dumps(vectors, indent=1) + "\n")
print(f"Wrote {len(kem_vectors)} KEM, {len(env_vectors)} envelope, {len(key_vectors)} key, {len(sig_vectors)} signature vectors to {out}")
