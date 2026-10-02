#!/usr/bin/env python3
"""Fetch NIST ACVP-Server known-answer vectors at a pinned commit.

Vectors are cached in tests/acvp/_vectors/ (git-ignored; they are large). The commit is the
same one quantum-safe-py pins, so results are directly comparable.

    python scripts/fetch_acvp.py
"""
import json
import pathlib
import sys
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
BASE = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{ACVP_COMMIT}/gen-val/json-files"
SUITES = [
    "ML-KEM-keyGen-FIPS203",
    "ML-KEM-encapDecap-FIPS203",
    "ML-DSA-keyGen-FIPS204",
    "ML-DSA-sigGen-FIPS204",
    "ML-DSA-sigVer-FIPS204",
    "SLH-DSA-keyGen-FIPS205",
    "SLH-DSA-sigGen-FIPS205",
    "SLH-DSA-sigVer-FIPS205",
]
FILES = ["prompt.json", "expectedResults.json"]
dest = pathlib.Path(__file__).resolve().parent.parent / "tests" / "acvp" / "_vectors"

for suite in SUITES:
    for name in FILES:
        out = dest / suite / name
        if out.exists():
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        url = f"{BASE}/{suite}/{name}"
        print("fetch", url)
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
        json.loads(data.decode("utf-8"))  # reject truncated bodies
        out.write_bytes(data)
print(f"ACVP-Server commit {ACVP_COMMIT[:12]}: vectors in {dest}")
