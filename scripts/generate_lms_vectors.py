#!/usr/bin/env python3
"""Generate LMS/HSS cross-implementation vectors with pyhsslms (an independent implementation).

quantum-safe-ts verifies LMS/HSS signatures only (no signing: LMS is stateful). These vectors cover
parameter combinations the RFC 8554 Appendix F cases do not (LM-OTS W1/W2, other tree heights, one- and
two-level HSS, non-zero leaf indices). Requires:  pip install pyhsslms

    python scripts/generate_lms_vectors.py
"""
import json
import pathlib

import pyhsslms

LMS = {5: pyhsslms.lms_sha256_m32_h5, 10: pyhsslms.lms_sha256_m32_h10}
OTS = {1: pyhsslms.lmots_sha256_n32_w1, 2: pyhsslms.lmots_sha256_n32_w2, 4: pyhsslms.lmots_sha256_n32_w4, 8: pyhsslms.lmots_sha256_n32_w8}

cases = []


def add(levels: int, height: int, w: int, skip: int, msg: bytes) -> None:
    priv = pyhsslms.HssPrivateKey(levels=levels, lms_type=LMS[height], lmots_type=OTS[w])
    # Burn some signatures so the leaf index q is non-zero.
    for _ in range(skip):
        priv.sign(b"burn")
    sig = priv.sign(msg)
    pub = priv.publicKey()
    assert pub.verify(msg, sig)
    cases.append(
        {
            "levels": levels,
            "tree_height": height,
            "winternitz": w,
            "leaf_index_hint": skip,
            "hss_public_key": pub.serialize().hex(),
            "message": msg.hex(),
            "hss_signature": sig.hex() if isinstance(sig, (bytes, bytearray)) else sig.serialize().hex(),
        }
    )


for w in (1, 2, 4, 8):
    add(1, 5, w, 0, f"w={w} levels=1 q=0".encode())
    add(1, 5, w, 3, f"w={w} levels=1 q=3 with a longer message ".encode() * 5)
    add(2, 5, w, 1, f"w={w} levels=2".encode())
add(1, 10, 4, 7, b"height 10, w=4, q=7")

out = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "lms_pyhsslms.json"
out.write_text(json.dumps({"generator": "scripts/generate_lms_vectors.py (pyhsslms)", "cases": cases}, indent=1) + "\n")
print(f"wrote {len(cases)} cases to {out}")
