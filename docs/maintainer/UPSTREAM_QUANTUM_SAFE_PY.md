# Proposed changes to quantum-safe-py (for you to apply in that repository)

This repository never modifies `quantum-safe-py`. Everything below is a **proposal** with exact locations and ready-to-use code, derived
from reading the 0.3.0 source and probing it against liboqs (`D:\quantum_safe`). Apply what you agree with.

## A. The reverse-direction parity test (ts → py)

quantum-safe-ts CI already proves "Python can read what TypeScript writes", but only inside this repository. Adding the same check to
quantum-safe-py makes the guarantee permanent and visible to its users.

1. Copy these fixtures from `quantum-safe-ts/tests/vectors/` into `quantum-safe-py/tests/interop/vectors/`:
   `ts_vectors.json` (Rust-core output) and `ts_js_vectors.json` (output of the built npm package).
2. Add `tests/interop/test_ts_interop.py`:

```python
"""Data produced by quantum-safe-ts (Rust core and the published npm package) must be accepted by quantum-safe-py."""
import json
import pathlib

import pytest

from quantum_safe import KEM, HybridKEM, HybridSign
from quantum_safe.protocols.envelope import Envelope, SealedMessage
from quantum_safe.protocols.jwt import JWTVerifier
from quantum_safe.signatures import Sign
from quantum_safe.types import PublicKey, SecretKey
from quantum_safe.types.kem import CipherText, HybridCipherText
from quantum_safe.types.signatures import SignedMessage

pytest.importorskip("oqs")  # needs the liboqs backend
VEC = pathlib.Path(__file__).parent / "vectors"
core = json.loads((VEC / "ts_vectors.json").read_text())
facade = json.loads((VEC / "ts_js_vectors.json").read_text())


@pytest.mark.parametrize("k", core["kem"], ids=lambda k: k["algorithm"])
def test_kem(k):
    algo = k["algorithm"]
    sk = SecretKey(raw=bytes.fromhex(k["secret_key"]), algorithm=algo)
    ct_bytes = bytes.fromhex(k["ciphertext"])
    if "+" in algo:
        classical, pqc = algo.split("+", 1)
        kem, ct = HybridKEM(classical=classical, pqc=pqc), HybridCipherText.from_bytes(ct_bytes, algo)
    else:
        kem, ct = KEM(algo), CipherText(ct_bytes, algo)
    assert bytes(kem.decapsulate(sk, ct)).hex() == k["shared_secret"]


@pytest.mark.parametrize("e", core["envelope"] + facade["envelope"], ids=lambda e: e["algorithm"])
def test_envelope(e):
    sk = SecretKey(raw=bytes.fromhex(e["secret_key"]), algorithm=e["algorithm"])
    sealed = SealedMessage.from_hex(e["sealed"])
    assert Envelope.open(sealed, sk).hex() == e["plaintext"]


@pytest.mark.parametrize("k", core["keys"], ids=lambda k: k["algorithm"])
def test_key_formats(k):
    pub = PublicKey.from_cbor(bytes.fromhex(k["public_cbor"]))
    assert pub.raw_bytes.hex() == k["public_raw"]
    assert PublicKey.from_pem(k["public_pem"]).raw_bytes == pub.raw_bytes
    assert PublicKey.from_jwk(k["public_jwk"]).raw_bytes == pub.raw_bytes
    assert SecretKey.from_pem(k["secret_pem"]).raw_bytes == SecretKey.from_cbor(bytes.fromhex(k["secret_cbor"])).raw_bytes
    assert pub.fingerprint() == k["fingerprint"]


@pytest.mark.parametrize("s", core["signatures"], ids=lambda s: f"{s['algorithm']}-hedged={s['hedged']}")
def test_signatures(s):
    algo = s["algorithm"]
    sm = SignedMessage.from_cbor(bytes.fromhex(s["signed_message"]))
    pub = PublicKey(raw=bytes.fromhex(s["public_key"]), algorithm=algo)
    if "+" in algo:
        classical, pqc = algo.split("+", 1)
        HybridSign(classical=classical, pqc=pqc).verify(sm, pub)
    else:
        Sign(algo).verify(sm, pub)


@pytest.mark.parametrize("t", facade["jwt"], ids=lambda t: t["algorithm"])
def test_jwt(t):
    pub = PublicKey(raw=bytes.fromhex(t["public_key"]), algorithm=t["algorithm"])
    claims = JWTVerifier(pub, issuer=t["issuer"]).verify(t["token"])
    assert claims["sub"] == "ts-user"
```

   (`scripts/verify_ts_vectors.py` in quantum-safe-ts is the reference implementation of these checks; it is run in CI there.)
3. Regenerate the fixtures when quantum-safe-ts changes a wire format (it must not): `cargo run -p quantum-safe-core --example gen_ts_vectors`
   and `node scripts/gen_ts_js_vectors.mjs` in quantum-safe-ts.

## B. Documentation and registry corrections found while building the TypeScript port

Each item was **verified by probing the real library**, not assumed.

| # | File | Finding | Suggested change |
|---|---|---|---|
| 1 | `src/quantum_safe/backends/liboqs.py` (`sign`/`verify` docstrings, ~lines 431-445) | Says the context prefix is "consistent with the HashML-DSA construction in FIPS 204 §5.4". The code signs plain FIPS 204 ML-DSA with an **empty** context over `len(ctx) ‖ ctx ‖ prefix ‖ message` (verified: the sub-signature verifies under plain ML-DSA with that input). | Reword: "domain separation by message prefix; not FIPS 204's native context and not HashML-DSA." Consider a future versioned suite that uses `sign_with_ctx_str`. |
| 2 | `src/quantum_safe/kem/hybrid.py` (module docstring, lines 5-8) | Says the construction "is exactly what TLS 1.3 hybrid key exchange uses (the X25519MLKEM768 group in RFC 9001 …)". The combiner is `HKDF(ikm = ss_c‖ss_pqc, salt = ct_c‖ct_pqc, info = "quantum-safe hybrid KEM v1"‖0‖algo)`, which differs from TLS's plain concatenation and from X-Wing. (RFC 9001 is QUIC-TLS; the hybrid group is specified by RFC 10024.) | Say it is a custom HKDF combiner "inspired by" the TLS design; add a note that envelopes are not readable by TLS/X-Wing implementations. |
| 3 | `src/quantum_safe/signatures/algorithms.py` (~lines 97-108) | `ML-DSA-87` lists `secret_key_bytes=4864` and `signature_bytes=4595` (round-3 Dilithium5 sizes). FIPS 204 / liboqs: **4896** and **4627**. (The keys themselves are correct because they come from liboqs; only the registry numbers are wrong. Verified: `len(sk) == 4896`.) | Correct the two constants. |
| 4 | `src/quantum_safe/compliance/cnsa2.py` (`check_kem`, `hybrid_kem`, `CNSA2_HYBRID_CLASSICAL`) | Reports `X25519+ML-KEM-1024` as compliant. The NSA CNSA 2.0 FAQ says hybrid is optional and the classical component of an NSS hybrid must be CNSA 1.0 (ECDH P-384); pure ML-KEM-1024 satisfies the requirement. Also `hybrid_kem(classical="P-384")` is allowed by the helper but `HybridKEM` rejects P-384 (not in `HYBRID_COMBINATIONS`). | Mark X25519 hybrids `PARTIAL`; make pure `ML-KEM-1024` the compliant example; drop `P-384` from `CNSA2_HYBRID_CLASSICAL` until implemented. Add a KDF-hash row (the combiner uses HKDF-SHA-256). |
| 5 | `src/quantum_safe/_internal/serialization.py` | If `cbor2` is missing the module silently emits a JSON+base64 envelope, which no CBOR reader can parse. `cbor2` is a hard dependency, so this is only reachable in a broken install. | Fail loudly instead of falling back, or tag the fallback format in every key/envelope version. |
| 6 | `src/quantum_safe/protocols/jwt.py` | JWTs include a hidden hedge prefix and a `jwt` context prefix in the signature blob: no other JOSE library can verify them. Documented, but surprising for a "JWT". | Offer an RFC 9964-compliant mode (ML-DSA, `AKP` JWK, empty context) alongside; quantum-safe-ts implements it as `StandardJwt`. |
| 7 | `README.md` / paper | "Conformance testing is not unique": `noble-post-quantum` also tests against ACVP; quantum-safe-ts now runs 1,317 NIST cases (vs 225). | Narrow the claim as `docs/production_readiness_rubric.md` already does; cite quantum-safe-ts' numbers if desired. |
| 8 | `src/quantum_safe/migrate/scanner.py` docstring | Says TypeScript scanning is "planned for v0.2". | Point to `quantum-safe-audit` (JS/TS scanner, SARIF + CycloneDX CBOM). |

## C. Optional additions that would close compatibility gaps from the Python side

- An **X-Wing / RFC 10024-style hybrid suite** so Python envelopes can be read by other ecosystems (the TypeScript library already has X-Wing).
- A matching **RFC 9964** JWT mode (item B6).
- Cross-check LMS: quantum-safe-ts verifies pyhsslms signatures (13 vectors in `tests/vectors/lms_pyhsslms.json`); the same vectors can be
  verified from `quantum_safe.signatures.stateful` as a smoke test of the `[lms]` extra.

## D. Suggested wording for the follow-up paper / README note

> A TypeScript/WebAssembly implementation, quantum-safe-ts, interoperates with quantum-safe-py byte-for-byte in both directions for hybrid
> envelopes, key serialisation (CBOR/PEM/JWK), hybrid signatures and JWTs, verified in continuous integration against the real library
> (liboqs backend). Building it surfaced a number of documentation and registry inaccuracies in 0.3.0, listed in
> `docs/maintainer/UPSTREAM_QUANTUM_SAFE_PY.md`, and a CNSA 2.0 interpretation question (hybrid classical component) that this work resolves
> against the NSA FAQ.
