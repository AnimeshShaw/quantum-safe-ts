#![no_main]
use libfuzzer_sys::fuzz_target;
use quantum_safe_core::keys::{keypair_from_bundle, EncodedKey, KeyType};

fuzz_target!(|data: &[u8]| {
    let _ = EncodedKey::from_cbor(data, KeyType::Public);
    let _ = EncodedKey::from_cbor(data, KeyType::Secret);
    let _ = keypair_from_bundle(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = EncodedKey::from_pem(text, KeyType::Public);
        let _ = EncodedKey::from_pem(text, KeyType::Secret);
        let _ = EncodedKey::from_jwk(text);
    }
});
