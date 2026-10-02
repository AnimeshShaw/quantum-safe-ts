#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::{envelope, kem};
use std::sync::OnceLock;

static KP: OnceLock<kem::KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let kp = KP.get_or_init(kem::generate_keypair);
    if let Ok(msg) = envelope::SealedMessage::from_cbor(data) {
        let _ = envelope::open(&msg, &kp.secret);
    }
});
