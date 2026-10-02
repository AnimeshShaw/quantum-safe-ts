//! Writes tests/vectors/ts_vectors.json: data produced by quantum-safe-core that the
//! real quantum-safe-py must accept (verified by scripts/verify_ts_vectors.py).
//! Run: cargo run -p quantum-safe-core --example gen_ts_vectors
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
    let out = json!({ "kem": kems, "envelope": envs });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/ts_vectors.json");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    println!("wrote {path}");
}
