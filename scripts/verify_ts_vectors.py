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
from quantum_safe import HybridSign  # noqa: E402
from quantum_safe.signatures import Sign  # noqa: E402
from quantum_safe.types import PublicKey, SecretKey  # noqa: E402
from quantum_safe.types.signatures import SignedMessage  # noqa: E402
from quantum_safe.types.kem import CipherText, HybridCipherText  # noqa: E402

root = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors"
v = json.loads((root / "ts_vectors.json").read_text(encoding="utf-8"))
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

for k in v["keys"]:
    algo = k["algorithm"]
    try:
        pub = PublicKey.from_cbor(bytes.fromhex(k["public_cbor"]))
        sec = SecretKey.from_cbor(bytes.fromhex(k["secret_cbor"]))
        pub_pem = PublicKey.from_pem(k["public_pem"])
        sec_pem = SecretKey.from_pem(k["secret_pem"])
        pub_jwk = PublicKey.from_jwk(k["public_jwk"])
        ok = (
            pub.raw_bytes.hex() == k["public_raw"]
            and pub_pem.raw_bytes == pub.raw_bytes
            and sec_pem.raw_bytes == sec.raw_bytes
            and pub_jwk.raw_bytes == pub.raw_bytes
            and pub.fingerprint() == k["fingerprint"]
            and pub.algorithm == algo
        )
        check(f"keys {algo}", ok)
    except Exception as exc:  # noqa: BLE001
        check(f"keys {algo} ({type(exc).__name__}: {exc})", False)

for s in v["signatures"]:
    algo = s["algorithm"]
    label = f"signature {algo} hedged={s['hedged']}"
    try:
        sm = SignedMessage.from_cbor(bytes.fromhex(s["signed_message"]))
        pub = PublicKey(raw=bytes.fromhex(s["public_key"]), algorithm=algo)
        if "+" in algo:
            classical, pqc = algo.split("+", 1)
            HybridSign(classical=classical, pqc=pqc).verify(sm, pub)
        else:
            Sign(algo).verify(sm, pub)
        check(label, sm.message == b"ts signed message" and sm.context == b"ts-ctx")
    except Exception as exc:  # noqa: BLE001
        check(f"{label} ({type(exc).__name__}: {exc})", False)

# ---- Vectors produced by the TypeScript *facade* (built npm package) ----
js_path = root / "ts_js_vectors.json"
if js_path.exists():
    from quantum_safe.protocols.jwt import JWTVerifier

    jv = json.loads(js_path.read_text(encoding="utf-8"))
    for t in jv["jwt"]:
        algo = t["algorithm"]
        try:
            pub = PublicKey(raw=bytes.fromhex(t["public_key"]), algorithm=algo)
            claims = JWTVerifier(pub, issuer=t["issuer"]).verify(t["token"])
            check(f"jwt {algo}", claims.get("sub") == "ts-user" and claims.get("n") == 7)
        except Exception as exc:  # noqa: BLE001
            check(f"jwt {algo} ({type(exc).__name__}: {exc})", False)
    for e in jv["envelope"]:
        algo = e["algorithm"]
        try:
            sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm=algo)
            pt = Envelope.open(SealedMessage.from_hex(e["sealed"]), sk)
            check(f"facade envelope {algo}", pt.hex() == e["plaintext"])
        except Exception as exc:  # noqa: BLE001
            check(f"facade envelope {algo} ({type(exc).__name__}: {exc})", False)
    # Migration: py must accept TypeScript-upgraded keys and a TypeScript-written migration store.
    from quantum_safe.migrate import MigrationStateManager
    from quantum_safe.types import MigrationState
    from quantum_safe.types.kem import HybridCipherText as _HCT

    for u in jv.get("upgrade_kem", []):
        algo = u["algorithm"]
        try:
            classical, pqc = algo.split("+", 1)
            sk = SecretKey(raw=bytes.fromhex(u["secret_key"]), algorithm=algo)
            ct = _HCT.from_bytes(bytes.fromhex(u["ciphertext"]), algo)
            ss = bytes(HybridKEM(classical=classical, pqc=pqc).decapsulate(sk, ct))
            same_classical = bytes.fromhex(u["public_key"])[2 : 2 + len(bytes.fromhex(u["classical_public"]))] == bytes.fromhex(u["classical_public"])
            check(f"ts upgrade_kem {algo}", ss.hex() == u["shared_secret"] and same_classical)
        except Exception as exc:  # noqa: BLE001
            check(f"ts upgrade_kem {algo} ({type(exc).__name__}: {exc})", False)
    for u in jv.get("upgrade_sign", []):
        algo = u["algorithm"]
        try:
            classical, pqc = algo.split("+", 1)
            pub = PublicKey(raw=bytes.fromhex(u["public_key"]), algorithm=algo)
            sm = SignedMessage.from_cbor(bytes.fromhex(u["signed_message"]))
            HybridSign(classical=classical, pqc=pqc).verify(sm, pub)
            check(f"ts upgrade_sign {algo}", sm.message == b"ts signs after upgrade")
        except Exception as exc:  # noqa: BLE001
            check(f"ts upgrade_sign {algo} ({type(exc).__name__}: {exc})", False)
    if jv.get("migrate_store"):
        try:
            store = {k: bytes.fromhex(v) for k, v in jv["migrate_store"]["entries"].items()}
            mgr = MigrationStateManager(store)
            ok = (
                mgr.get_current_state("ts-user-1") == MigrationState.PQC_PREFERRED
                and mgr.get_current_state("ünï/slash") == MigrationState.HYBRID_TRANSITION
                and [r.to_state.value for r in mgr.get_history("ts-user-1")] == ["hybrid_transition", "pqc_preferred"]
                and mgr.get_history("ts-user-1")[0].metadata == {"batch": 3}
                and mgr.get_history("ts-user-1")[0].actor == "ts-job"
            )
            # py can continue a history that TypeScript wrote
            mgr.transition("ts-user-1", MigrationState.PQC_PREFERRED, MigrationState.PQC_ONLY, "ML-KEM-768", actor="py")
            ok = ok and mgr.get_current_state("ts-user-1") == MigrationState.PQC_ONLY and len(mgr.get_history("ts-user-1")) == 3
            check("ts migration store loads in py and py continues it", ok)
        except Exception as exc:  # noqa: BLE001
            check(f"ts migration store ({type(exc).__name__}: {exc})", False)
else:
    check("ts_js_vectors.json present (run scripts/gen_ts_js_vectors.mjs)", False)

# ---- Guards against vacuous passes ----
for label, items, minimum in [
    ("kem", v["kem"], 8),
    ("envelope", v["envelope"], 5),
    ("keys", v["keys"], 8),
    ("signatures", v["signatures"], 20),
]:
    check(f"{label}: at least {minimum} vectors were checked (got {len(items)})", len(items) >= minimum)
if js_path.exists():
    for label, key, minimum in [("jwt", "jwt", 6), ("facade envelope", "envelope", 3), ("upgrade_kem", "upgrade_kem", 3), ("upgrade_sign", "upgrade_sign", 2)]:
        check(f"{label}: at least {minimum} vectors were checked (got {len(jv.get(key, []))})", len(jv.get(key, [])) >= minimum)

# ---- Negative controls: the oracle must REJECT tampered data, or "ok" above means nothing ----
try:
    s0 = v["signatures"][0]
    algo0 = s0["algorithm"]
    sm0 = SignedMessage.from_cbor(bytes.fromhex(s0["signed_message"]))
    pub0 = PublicKey(raw=bytes.fromhex(s0["public_key"]), algorithm=algo0)
    verifier = HybridSign(*algo0.split("+", 1)) if "+" in algo0 else Sign(algo0)
    bad = SignedMessage(message=bytes([sm0.message[0] ^ 1]) + sm0.message[1:], signature=sm0.signature, algorithm=sm0.algorithm, context=sm0.context, signer_fingerprint=sm0.signer_fingerprint, signed_at=sm0.signed_at)
    try:
        verifier.verify(bad, pub0)
        check("negative control: py rejects a tampered signed message", False)
    except Exception:  # noqa: BLE001
        check("negative control: py rejects a tampered signed message", True)
except Exception as exc:  # noqa: BLE001
    check(f"negative control could not be built ({type(exc).__name__}: {exc})", False)

sys.exit(1 if fails else 0)
