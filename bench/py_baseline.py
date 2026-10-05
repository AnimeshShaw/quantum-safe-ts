"""Reference timings for liboqs (through liboqs-python) and quantum-safe-py on this machine.

Usage: python bench/py_baseline.py [seconds-per-operation]

This is the Python/C baseline that bench/bench.mjs results are compared with. Run it on the same machine,
with the same power settings, and pin it to one core for comparable numbers.
"""
import json
import platform
import sys
import time

SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0


def rate(fn):
    fn()  # warm-up
    n = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < SECONDS:
        fn()
        n += 1
    return n / (time.perf_counter() - t0)


import quantum_safe  # noqa: E402

out = {"quantum_safe_py": quantum_safe.__version__, "python": platform.python_version(), "machine": platform.processor(), "ops_per_second": {}}


def record(name, fn):
    out["ops_per_second"][name] = round(rate(fn), 1)
    print(f"{name:55s} {out['ops_per_second'][name]:>10.1f} ops/s", flush=True)


import oqs  # liboqs-python: C implementation (liboqs)

kem_name = "ML-KEM-768"
with oqs.KeyEncapsulation(kem_name) as kem:
    pk = kem.generate_keypair()
    ct, ss = kem.encap_secret(pk)
    # The decapsulation rows below must measure the real path: key and ciphertext have to belong together, or ML-KEM's implicit
    # rejection returns a pseudo-random secret with no error and the row would time the wrong thing.
    assert kem.decap_secret(ct) == ss, "benchmark setup error: decapsulation does not match encapsulation"

    def keygen():
        with oqs.KeyEncapsulation(kem_name) as k:
            k.generate_keypair()

    def encap():
        with oqs.KeyEncapsulation(kem_name) as k:
            k.encap_secret(pk)

    def decap():
        kem.decap_secret(ct)

    record("liboqs ML-KEM-768 keygen", keygen)
    record("liboqs ML-KEM-768 encapsulate", encap)
    record("liboqs ML-KEM-768 decapsulate", decap)

    # Like-for-like rows. The three rows above are not directly comparable: keygen and encapsulate build and free a liboqs context on every
    # call, while decapsulate reuses one. These rows add the missing combinations (the rows above are unchanged).
    sk = kem.export_secret_key()

    def decap_fresh():
        with oqs.KeyEncapsulation(kem_name, secret_key=sk) as k:
            k.decap_secret(ct)

    record("liboqs ML-KEM-768 encapsulate (reused context)", lambda: kem.encap_secret(pk))
    record("liboqs ML-KEM-768 decapsulate (fresh context per call)", decap_fresh)

sig_name = "ML-DSA-65"
msg = bytes(256)
with oqs.Signature(sig_name) as signer:
    spk = signer.generate_keypair()
    sg = signer.sign(msg)
    assert signer.verify(msg, sg, spk), "benchmark setup error: signature does not verify"

    def sig_keygen():
        with oqs.Signature(sig_name) as s:
            s.generate_keypair()

    def verify():
        with oqs.Signature(sig_name) as v:
            v.verify(msg, sg, spk)

    record("liboqs ML-DSA-65 keygen", sig_keygen)
    record("liboqs ML-DSA-65 sign (256 B)", lambda: signer.sign(msg))
    record("liboqs ML-DSA-65 verify", verify)

    ssk = signer.export_secret_key()

    def sign_fresh():
        with oqs.Signature(sig_name, secret_key=ssk) as s:
            s.sign(msg)

    record("liboqs ML-DSA-65 verify (reused context)", lambda: signer.verify(msg, sg, spk))
    record("liboqs ML-DSA-65 sign (fresh context per call)", sign_fresh)

try:
    import quantum_safe as qs

    kem = qs.HybridKEM()
    pair = kem.generate_keypair()
    ct2, ss2 = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.secret, ct2) == ss2, "benchmark setup error: quantum-safe-py decapsulation does not match encapsulation"
    record("quantum-safe-py HybridKEM keygen", kem.generate_keypair)
    record("quantum-safe-py HybridKEM encapsulate", lambda: kem.encapsulate(pair.public))
    record("quantum-safe-py HybridKEM decapsulate", lambda: kem.decapsulate(pair.secret, ct2))
    signer = qs.Sign()
    sp = signer.generate_keypair()
    signed = signer.sign(msg, sp.secret)
    signer.verify(signed, sp.public)  # raises if invalid
    record("quantum-safe-py Ed25519+ML-DSA-65 sign", lambda: signer.sign(msg, sp.secret))
    record("quantum-safe-py Ed25519+ML-DSA-65 verify", lambda: signer.verify(signed, sp.public))
except Exception as e:  # keep the liboqs numbers even if the py API differs
    print("quantum-safe-py benchmark skipped:", type(e).__name__, e)

json.dump(out, open("results/py_baseline.json", "w"), indent=2)
print("wrote results/py_baseline.json")
