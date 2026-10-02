//! Writes tests/vectors/ts_vectors.json: data produced by quantum-safe-core that the
//! real quantum-safe-py must accept (verified by scripts/verify_ts_vectors.py).
//! Run: cargo run -p quantum-safe-core --example gen_ts_vectors
use quantum_safe_core::keys::{EncodedKey, KeyType, MigrationState};
use quantum_safe_core::sig::{self, SigSuite, SignOptions};
use quantum_safe_core::{envelope, kem, suite::KemSuite};
use serde_json::{json, Value};

fn main() {
    let mut kems: Vec<Value> = Vec::new();
    let mut envs: Vec<Value> = Vec::new();
    for s in KemSuite::all() {
        if s == KemSuite::XWing {
            continue; // not readable by quantum-safe-py by design
        }
        let name = s.name();
        let kp = kem::generate_keypair_for(&name).unwrap();
        let (ct, ss) = kem::encapsulate(&kp.public).unwrap();
        kems.push(json!({
            "algorithm": name,
            "public_key": hex::encode(&kp.public.raw),
            "secret_key": hex::encode(&*kp.secret.raw),
            "ciphertext": hex::encode(&ct),
            "shared_secret": hex::encode(*ss),
        }));
        if s.is_hybrid() {
            let pt = format!("ts envelope for {name}").into_bytes();
            let sealed = envelope::seal(&pt, &kp.public, b"ts-vector").unwrap();
            envs.push(json!({
                "algorithm": name,
                "secret_key": hex::encode(&*kp.secret.raw),
                "plaintext": hex::encode(&pt),
                "aad": hex::encode(b"ts-vector"),
                "sealed": hex::encode(sealed.to_cbor().unwrap()),
            }));
        }
    }
    // Key serialization of the KEM keys above (ts -> py parse).
    let mut keys: Vec<Value> = Vec::new();
    for k in &kems {
        let algo = k["algorithm"].as_str().unwrap().to_string();
        let ms = if algo.contains('+') {
            MigrationState::HybridTransition
        } else {
            MigrationState::PqcOnly
        };
        let public = EncodedKey::new(
            &algo,
            KeyType::Public,
            hex::decode(k["public_key"].as_str().unwrap()).unwrap(),
            ms,
        );
        let secret = EncodedKey::new(
            &algo,
            KeyType::Secret,
            hex::decode(k["secret_key"].as_str().unwrap()).unwrap(),
            ms,
        );
        keys.push(json!({
            "algorithm": algo,
            "public_raw": k["public_key"],
            "public_cbor": hex::encode(public.to_cbor()),
            "secret_cbor": hex::encode(secret.to_cbor()),
            "public_pem": public.to_pem(),
            "secret_pem": secret.to_pem(),
            "public_jwk": serde_json::from_str::<Value>(&public.to_jwk().unwrap()).unwrap(),
            "fingerprint": public.fingerprint(),
        }));
    }

    // Signatures for every suite quantum-safe-py's high-level API accepts.
    let mut sigs: Vec<Value> = Vec::new();
    for s in SigSuite::all() {
        if let SigSuite::Slh(p) = s {
            if !p.py_compatible() {
                continue;
            }
        }
        let name = s.name();
        let kp = sig::generate_keypair(&name).unwrap();
        for deterministic in [false, true] {
            let opts = SignOptions {
                deterministic,
                signer_fingerprint: String::new(),
                signed_at: 1_700_000_000.5,
            };
            let sm = sig::sign(&kp.secret, b"ts signed message", b"ts-ctx", &opts).unwrap();
            sigs.push(json!({
                "algorithm": name,
                "hedged": !deterministic,
                "public_key": hex::encode(&kp.public.raw),
                "signed_message": hex::encode(sm.to_cbor()),
            }));
        }
    }
    let out = json!({ "kem": kems, "envelope": envs, "keys": keys, "signatures": sigs });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/ts_vectors.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    println!("wrote {path}");
}
