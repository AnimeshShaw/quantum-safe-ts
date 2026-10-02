//! quantum-safe-py (liboqs) signatures must verify in quantum-safe-core, and py's secret keys
//! must be usable here to sign messages that verify against py's public keys.
use quantum_safe_core::kem::{PublicKey, SecretKey};
use quantum_safe_core::sig::{self, SignOptions, SignedMessage};
use serde::Deserialize;

#[derive(Deserialize)]
struct SigVec {
    algorithm: String,
    hedged: bool,
    public_key: String,
    secret_key: String,
    message: String,
    context: String,
    signed_message: String,
    signature_blob: String,
}
#[derive(Deserialize)]
struct Vectors {
    signatures: Vec<SigVec>,
}

fn load() -> Vec<SigVec> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/suite_vectors.json"
    ))
    .expect("run scripts/generate_suite_vectors.py");
    serde_json::from_str::<Vectors>(&raw).unwrap().signatures
}

#[test]
fn verifies_every_python_signature() {
    let vectors = load();
    assert_eq!(vectors.len(), 22);
    for v in vectors {
        let label = format!("{} (hedged={})", v.algorithm, v.hedged);
        let public = PublicKey {
            raw: hex::decode(&v.public_key).unwrap(),
            algorithm: v.algorithm.clone(),
        };
        let sm = SignedMessage::from_cbor(&hex::decode(&v.signed_message).unwrap()).unwrap();
        assert_eq!(hex::encode(&sm.message), v.message, "{label}");
        assert_eq!(hex::encode(&sm.context), v.context, "{label}");
        assert_eq!(hex::encode(&sm.signature), v.signature_blob, "{label}");
        assert_eq!(sm.signature[0] == 32, v.hedged, "{label}");
        sig::verify(&sm, &public).unwrap_or_else(|e| panic!("{label}: {e}"));

        // Negative control: a flipped message byte must not verify.
        let mut bad = sm.clone();
        bad.message[0] ^= 1;
        assert!(sig::verify(&bad, &public).is_err(), "{label}");
    }
}

#[test]
fn python_secret_keys_sign_messages_that_verify() {
    for v in load().into_iter().filter(|v| v.hedged) {
        let label = v.algorithm.clone();
        let secret = SecretKey::new(hex::decode(&v.secret_key).unwrap(), v.algorithm.clone());
        let public = PublicKey {
            raw: hex::decode(&v.public_key).unwrap(),
            algorithm: v.algorithm.clone(),
        };
        let sm = sig::sign(
            &secret,
            b"signed by ts with a py key",
            b"ctx",
            &SignOptions::default(),
        )
        .unwrap();
        sig::verify(&sm, &public).unwrap_or_else(|e| panic!("{label}: {e}"));
    }
}
