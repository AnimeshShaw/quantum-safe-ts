#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::{kem, stream};
use std::sync::OnceLock;

static KP: OnceLock<kem::KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let kp = KP.get_or_init(kem::generate_keypair);
    // Attacker-controlled header bytes: parsing, key derivation and the first chunk must fail closed, never panic.
    let _ = stream::StreamHeader::from_cbor(data);
    if let Ok(mut c) = stream::StreamCipher::start_opening(&kp.secret, data, b"") {
        let _ = c.open_chunk(data, false);
        let _ = c.open_chunk(data, true);
    }
    // A valid header with attacker-controlled chunk bytes.
    if let Ok((header, _)) = stream::StreamCipher::start_sealing(&kp.public, b"", 1024) {
        if let Ok(mut c) = stream::StreamCipher::start_opening(&kp.secret, &header, b"") {
            let _ = c.open_chunk(data, data.len() % 2 == 0);
        }
    }
});
