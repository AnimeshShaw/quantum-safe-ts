//! Parity tests: everything quantum-safe-py (real liboqs backend) produced must be
//! accepted by quantum-safe-core and yield identical results.
use quantum_safe_core::keys::{keypair_from_bundle, keypair_to_bundle, EncodedKey, KeyType};
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
struct KeyVec {
    algorithm: String,
    migration_state: String,
    public_raw: String,
    secret_raw: String,
    public_cbor: String,
    secret_cbor: String,
    public_pem: String,
    secret_pem: String,
    public_jwk: serde_json::Value,
    fingerprint: String,
    fingerprint_colon: String,
    bundle: String,
}
#[derive(Deserialize)]
struct Vectors {
    kem: Vec<KemVec>,
    envelope: Vec<EnvVec>,
    keys: Vec<KeyVec>,
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

#[test]
fn key_serialization_is_byte_identical_to_python() {
    for k in load().keys {
        let label = &k.algorithm;
        let public = EncodedKey::from_cbor(&hex::decode(&k.public_cbor).unwrap(), KeyType::Public).unwrap();
        let secret = EncodedKey::from_cbor(&hex::decode(&k.secret_cbor).unwrap(), KeyType::Secret).unwrap();
        assert_eq!(hex::encode(&*public.raw), k.public_raw, "{label}");
        assert_eq!(hex::encode(&*secret.raw), k.secret_raw, "{label}");
        assert_eq!(public.migration_state.as_str(), k.migration_state, "{label}");

        // Re-serializing must reproduce python's bytes exactly.
        assert_eq!(hex::encode(public.to_cbor()), k.public_cbor, "{label}");
        assert_eq!(hex::encode(secret.to_cbor()), k.secret_cbor, "{label}");
        assert_eq!(public.to_pem(), k.public_pem, "{label}");
        assert_eq!(secret.to_pem(), k.secret_pem, "{label}");
        let ours: serde_json::Value = serde_json::from_str(&public.to_jwk().unwrap()).unwrap();
        let theirs = k.public_jwk.clone();
        assert_eq!(ours, theirs, "{label}");
        assert_eq!(public.fingerprint(), k.fingerprint, "{label}");
        assert_eq!(public.fingerprint_colon(), k.fingerprint_colon, "{label}");

        // Python's PEM / JWK parse in Rust.
        assert_eq!(
            *EncodedKey::from_pem(&k.public_pem, KeyType::Public).unwrap().raw,
            *public.raw
        );
        assert_eq!(
            *EncodedKey::from_pem(&k.secret_pem, KeyType::Secret).unwrap().raw,
            *secret.raw
        );
        assert_eq!(
            *EncodedKey::from_jwk(&k.public_jwk.to_string()).unwrap().raw,
            *public.raw
        );

        let bundle = hex::decode(&k.bundle).unwrap();
        let (bp, bs) = keypair_from_bundle(&bundle).unwrap();
        assert_eq!(
            hex::encode(keypair_to_bundle(&bp, &bs).unwrap()),
            k.bundle,
            "{label}"
        );
    }
}
