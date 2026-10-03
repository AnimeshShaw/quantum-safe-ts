#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::sig::{self, SignedMessage};
use std::sync::OnceLock;

static KP: OnceLock<sig::SigKeyPair> = OnceLock::new();
static KP_V2: OnceLock<[sig::SigKeyPair; 2]> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let kp = KP.get_or_init(|| sig::generate_keypair("Ed25519+ML-DSA-44").unwrap());
    if let Ok(sm) = SignedMessage::from_cbor(data) {
        let _ = sig::verify(&sm, &kp.public);
    }
    // Treat the raw bytes as a signature blob too.
    let _ = sig::verify_parts("Ed25519+ML-DSA-44", b"message", data, b"", &kp.public);
    // Signature format v2: the blob is the signature itself (fixed lengths); any other length or content must fail closed.
    let v2 = KP_V2.get_or_init(|| {
        [
            sig::generate_keypair("Ed25519+ML-DSA-44-v2").unwrap(),
            sig::generate_keypair("P-256+ML-DSA-44-v2").unwrap(),
        ]
    });
    for kp in v2 {
        let _ = sig::verify_parts(&kp.public.algorithm, b"message", data, b"", &kp.public);
    }
});
