//! LMS/HSS signatures produced by an independent implementation (pyhsslms) must verify here, across
//! LM-OTS W1/W2/W4/W8, tree heights 5 and 10, one- and two-level HSS, and non-zero leaf indices.
use quantum_safe_core::lms::verify_hss;
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    levels: u32,
    tree_height: u32,
    winternitz: u32,
    hss_public_key: String,
    message: String,
    hss_signature: String,
}
#[derive(Deserialize)]
struct File {
    cases: Vec<Case>,
}

#[test]
fn every_pyhsslms_signature_verifies_and_every_corruption_does_not() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/lms_pyhsslms.json"
    ))
    .expect("run scripts/generate_lms_vectors.py");
    let file: File = serde_json::from_str(&raw).unwrap();
    assert_eq!(file.cases.len(), 13);
    for c in file.cases {
        let label = format!("levels={} h={} w={}", c.levels, c.tree_height, c.winternitz);
        let (pk, msg, sig) = (
            hex::decode(&c.hss_public_key).unwrap(),
            hex::decode(&c.message).unwrap(),
            hex::decode(&c.hss_signature).unwrap(),
        );
        assert_eq!(verify_hss(&pk, &msg, &sig), Ok(true), "{label}");
        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert_eq!(verify_hss(&pk, &bad_msg, &sig), Ok(false), "{label}: message");
        for i in (0..sig.len()).step_by(97) {
            let mut s = sig.clone();
            s[i] ^= 0x80;
            assert!(verify_hss(&pk, &msg, &s) != Ok(true), "{label}: sig byte {i}");
        }
    }
}
