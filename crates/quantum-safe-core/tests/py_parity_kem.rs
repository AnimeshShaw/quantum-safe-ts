//! Parity tests: everything quantum-safe-py (real liboqs backend) produced must be
//! accepted by quantum-safe-core and yield identical results.
use quantum_safe_core::{envelope, kem};
use serde::Deserialize;

#[derive(Deserialize)]
struct KemVec {
    algorithm: String,
    public_key: String,
    secret_key: String,
    ciphertext: String,
    shared_secret: String,
}
#[derive(Deserialize)]
struct EnvVec {
    algorithm: String,
    secret_key: String,
    plaintext: String,
    aad: String,
    sealed: String,
}
#[derive(Deserialize)]
struct Vectors {
    kem: Vec<KemVec>,
    envelope: Vec<EnvVec>,
}

fn load() -> Vectors {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/suite_vectors.json"
    ))
    .expect("run scripts/generate_suite_vectors.py");
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn decapsulates_every_python_ciphertext_to_the_same_secret() {
    let v = load();
    assert_eq!(v.kem.len(), 8);
    for k in v.kem {
        let sk = kem::SecretKey::new(hex::decode(&k.secret_key).unwrap(), k.algorithm.clone());
        let ss = kem::decapsulate(&sk, &hex::decode(&k.ciphertext).unwrap()).unwrap();
        assert_eq!(hex::encode(*ss), k.shared_secret, "{}", k.algorithm);
        // Public key parses and we can encapsulate to it ourselves.
        let pk = kem::PublicKey {
            raw: hex::decode(&k.public_key).unwrap(),
            algorithm: k.algorithm.clone(),
        };
        assert!(kem::encapsulate(&pk).is_ok(), "{}", k.algorithm);
    }
}

#[test]
fn opens_every_python_sealed_envelope() {
    for e in load().envelope {
        let sk = kem::SecretKey::new(hex::decode(&e.secret_key).unwrap(), e.algorithm.clone());
        let sealed = envelope::SealedMessage::from_cbor(&hex::decode(&e.sealed).unwrap()).unwrap();
        assert_eq!(sealed.algorithm, e.algorithm);
        assert_eq!(sealed.aad, hex::decode(&e.aad).unwrap());
        let pt = envelope::open(&sealed, &sk).unwrap();
        assert_eq!(hex::encode(pt), e.plaintext, "{}", e.algorithm);
    }
}
