#!/usr/bin/env python3
"""Generate migration parity vectors with the real quantum-safe-py.

Classical keys are created with the `cryptography` package (not with py's own keygen) so the fixture proves that
py's and TypeScript's `Upgrader` accept the same independently produced X25519 / Ed25519 / P-256 key bytes.

Covers:
  * Upgrader.upgrade_kem_key / upgrade_signing_key (X25519, P-256, Ed25519) -> a ciphertext / signature made with the upgraded key
  * Upgrader.strip_classical_component
  * MigrationStateManager store layout (`<id>_current`, `<id>_history`, CBOR) with a multi-step history

Run from the repository root:  python scripts/generate_migrate_vectors.py
"""
import json
import pathlib
import warnings

warnings.filterwarnings("ignore")

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from quantum_safe import KEM, HybridKEM, HybridSign  # noqa: E402
from quantum_safe.migrate import MigrationStateManager, Upgrader  # noqa: E402
from quantum_safe.signatures import Sign  # noqa: E402
from quantum_safe.types import MigrationState  # noqa: E402

hx = bytes.hex
vectors: dict = {"_meta": {"generator": "scripts/generate_migrate_vectors.py", "quantum_safe_py": "0.3.0"}}


def x25519_pair():
    k = x25519.X25519PrivateKey.generate()
    return (
        k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def p256_kem_pair():
    k = ec.generate_private_key(ec.SECP256R1())
    return (
        k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        k.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
    )


def p256_sign_pair():
    k = ec.generate_private_key(ec.SECP256R1())
    nums = k.public_key().public_numbers()
    return (
        k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big"),
    )


def ed25519_pair():
    k = ed25519.Ed25519PrivateKey.generate()
    return (
        k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


# ---- KEM upgrades ----
kem_up = []
for classical, pqc, gen in [
    ("X25519", "ML-KEM-768", x25519_pair),
    ("X25519", "ML-KEM-1024", x25519_pair),
    ("P-256", "ML-KEM-768", p256_kem_pair),
]:
    csec, cpub = gen()
    res = Upgrader.upgrade_kem_key(csec, cpub, classical_algorithm=classical, target_pqc=pqc)
    kp = res.new_keypair
    assert res.migration_state == MigrationState.HYBRID_TRANSITION
    kem = HybridKEM(classical=classical, pqc=pqc)
    ct, ss = kem.encapsulate(kp.public)
    assert bytes(kem.decapsulate(kp.secret, ct)) == bytes(ss)
    kem_up.append(
        {
            "classical": classical,
            "pqc": pqc,
            "classical_secret": hx(csec),
            "classical_public": hx(cpub),
            "algorithm": res.new_algorithm,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "ciphertext": hx(ct.to_bytes()),
            "shared_secret": hx(bytes(ss)),
        }
    )
vectors["upgrade_kem"] = kem_up

# ---- signing upgrades ----
sig_up = []
for classical, pqc, gen in [
    ("Ed25519", "ML-DSA-65", ed25519_pair),
    ("Ed25519", "ML-DSA-87", ed25519_pair),
    ("P-256", "ML-DSA-65", p256_sign_pair),
]:
    csec, cpub = gen()
    res = Upgrader.upgrade_signing_key(csec, cpub, classical_algorithm=classical, target_pqc=pqc)
    kp = res.new_keypair
    signer = HybridSign(classical=classical, pqc=pqc)
    msg = f"py signs after upgrading {classical}".encode()
    sm = signer.sign(msg, kp.secret, context=b"upgrade")
    signer.verify(sm, kp.public)
    sig_up.append(
        {
            "classical": classical,
            "pqc": pqc,
            "classical_secret": hx(csec),
            "classical_public": hx(cpub),
            "algorithm": res.new_algorithm,
            "public_key": hx(kp.public.raw_bytes),
            "secret_key": hx(kp.secret.raw_bytes),
            "message": hx(msg),
            "context": hx(b"upgrade"),
            "signed_message": hx(sm.to_cbor()),
        }
    )
vectors["upgrade_sign"] = sig_up

# ---- strip_classical_component ----
strip = []
kem = HybridKEM(classical="X25519", pqc="ML-KEM-768")
kp = kem.generate_keypair()
stripped = Upgrader.strip_classical_component(kp)
assert stripped.public.migration_state == MigrationState.PQC_ONLY
pure = KEM("ML-KEM-768")
ct, ss = pure.encapsulate(stripped.public)
assert bytes(pure.decapsulate(stripped.secret, ct)) == bytes(ss)
strip.append(
    {
        "hybrid_public": hx(kp.public.raw_bytes),
        "hybrid_secret": hx(kp.secret.raw_bytes),
        "algorithm": stripped.public.algorithm,
        "public_key": hx(stripped.public.raw_bytes),
        "secret_key": hx(stripped.secret.raw_bytes),
        "ciphertext": hx(bytes(ct)),
        "shared_secret": hx(bytes(ss)),
    }
)
vectors["strip"] = strip

# ---- Sign (pure) strip as well, to be thorough ----
sgn = HybridSign(classical="Ed25519", pqc="ML-DSA-65")
skp = sgn.generate_keypair()
sstripped = Upgrader.strip_classical_component(skp)
psigner = Sign("ML-DSA-65")
psm = psigner.sign(b"stripped signer", sstripped.secret)
psigner.verify(psm, sstripped.public)
vectors["strip_sign"] = [
    {
        "hybrid_public": hx(skp.public.raw_bytes),
        "hybrid_secret": hx(skp.secret.raw_bytes),
        "algorithm": sstripped.public.algorithm,
        "public_key": hx(sstripped.public.raw_bytes),
        "signed_message": hx(psm.to_cbor()),
    }
]

# ---- MigrationStateManager store layout ----
store: dict = {}
mgr = MigrationStateManager(store)
mgr.transition("user-1", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "X25519+ML-KEM-768", actor="job-a", metadata={"batch": 7, "note": "first"})
mgr.transition("user-1", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "X25519+ML-KEM-768", actor="job-b")
mgr.transition(
    "user-1",
    MigrationState.PQC_PREFERRED,
    MigrationState.HYBRID_TRANSITION,
    "X25519+ML-KEM-768",
    actor="oncall",
    reason="rollback: interop bug",
    allow_backward=True,
)
mgr.transition("svc-ünï", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "Ed25519+ML-DSA-65")
mgr.transition("key/with/slashes", MigrationState.CLASSICAL_ONLY, MigrationState.HYBRID_TRANSITION, "P-256+ML-KEM-768")
mgr.transition("key/with/slashes", MigrationState.HYBRID_TRANSITION, MigrationState.PQC_PREFERRED, "P-256+ML-KEM-768")
mgr.transition("key/with/slashes", MigrationState.PQC_PREFERRED, MigrationState.PQC_ONLY, "ML-KEM-768")
vectors["store"] = {
    "entries": {k: hx(v) for k, v in sorted(store.items())},
    "progress": mgr.migration_progress(),
    "current_states": {k[: -len("_current")]: mgr.get_current_state(k[: -len("_current")]).value for k in sorted(store) if k.endswith("_current")},
    "histories": {
        kid: [r.to_dict() for r in mgr.get_history(kid)] for kid in sorted(k[: -len("_current")] for k in store if k.endswith("_current"))
    },
}

out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "migrate_vectors.json"
out.write_text(json.dumps(vectors, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"Wrote {len(kem_up)} KEM upgrades, {len(sig_up)} signing upgrades, strip, {len(store)} store entries to {out}")
