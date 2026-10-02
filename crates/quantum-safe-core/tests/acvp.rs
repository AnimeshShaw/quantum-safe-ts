//! NIST ACVP known-answer tests (conformance *evidence*, not a CAVP/CMVP validation).
//!
//! Runs the vectors that `scripts/fetch_acvp.py` caches from usnistgov/ACVP-Server (pinned
//! commit, the same one quantum-safe-py pins) against ML-KEM, ML-DSA and SLH-DSA.
//! Reached directly: ML-KEM keyGen/encaps/decaps, ML-DSA keyGen/sigGen/sigVer, SLH-DSA
//! keyGen/sigGen/sigVer. Not run: pre-hash (HashML-DSA / HashSLH-DSA) groups and the ML-DSA
//! externalMu groups (this library exposes neither interface), and ML-KEM key-check groups.
//! Every skipped category is counted and printed.
//!
//! Skips (with a note) when the vectors are absent, unless `QS_REQUIRE_ACVP=1` (CI sets it).
//! `QS_ACVP_SAVE=<path>` writes a JSON summary. `QS_ACVP_SLH_SAMPLE=<n>` runs only every
//! n-th SLH-DSA sigGen/sigVer case (the SLH-DSA vector files are ~70 MB).

use ml_dsa::{ExpandedSigningKey, Signature as MlSig, VerifyingKey};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding as _;
use ml_kem::KeyExport as _;
use quantum_safe_core::kem;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/acvp/_vectors"))
}

fn load(suite: &str) -> Option<(Value, Value)> {
    let d = vectors_dir().join(suite);
    let p = std::fs::read_to_string(d.join("prompt.json")).ok()?;
    let e = std::fs::read_to_string(d.join("expectedResults.json")).ok()?;
    Some((
        serde_json::from_str(&p).unwrap(),
        serde_json::from_str(&e).unwrap(),
    ))
}

fn require_vectors(suite: &str) -> Option<(Value, Value)> {
    let v = load(suite);
    if v.is_none() {
        assert!(
            std::env::var("QS_REQUIRE_ACVP").is_err(),
            "ACVP vectors for {suite} missing; run `python scripts/fetch_acvp.py`"
        );
        eprintln!("SKIP {suite}: run `python scripts/fetch_acvp.py` to enable ACVP tests");
    }
    v
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing string field {k}"))
}
fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(v, k)).unwrap_or_else(|_| panic!("bad hex in {k}"))
}
fn hx_opt(v: &Value, k: &str) -> Option<Vec<u8>> {
    v.get(k).and_then(|x| x.as_str()).map(|x| hex::decode(x).unwrap())
}

#[derive(Default, Debug, serde::Serialize)]
struct Tally {
    run: usize,
    passed: usize,
    expected_accept: usize,
    expected_reject: usize,
    skipped: BTreeMap<String, usize>,
    failures: Vec<String>,
}

impl Tally {
    fn skip(&mut self, why: &str, n: usize) {
        *self.skipped.entry(why.to_string()).or_default() += n;
    }
    fn check(&mut self, ok: bool, label: String) {
        self.run += 1;
        if ok {
            self.passed += 1;
        } else if self.failures.len() < 20 {
            self.failures.push(label);
        }
    }
    fn report(&self, name: &str) {
        eprintln!(
            "ACVP {name}: {}/{} passed (accept-cases {}, reject-cases {}); skipped {:?}",
            self.passed, self.run, self.expected_accept, self.expected_reject, self.skipped
        );
        if let Ok(path) = std::env::var("QS_ACVP_SAVE") {
            // Tests run in parallel threads; serialize the read-modify-write of the shared file.
            static SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = SAVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(dir) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(dir).unwrap();
            }
            let mut all: serde_json::Map<String, Value> = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| serde_json::from_str(&t).ok())
                .unwrap_or_default();
            all.insert(name.to_string(), serde_json::to_value(self).unwrap());
            std::fs::write(&path, serde_json::to_string_pretty(&all).unwrap()).unwrap();
        }
        assert!(self.failures.is_empty(), "{name} failures: {:?}", self.failures);
        assert_eq!(self.passed, self.run, "{name}");
        assert!(self.run > 0, "{name}: no cases ran");
    }
}

fn expected_by_tc(expected: &Value, tg_id: u64, tc_id: u64) -> &Value {
    let g = expected["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["tgId"] == tg_id)
        .unwrap();
    g["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tcId"] == tc_id)
        .unwrap()
}

// ----------------------------------------------------------------------------- ML-KEM

macro_rules! with_mlkem {
    ($set:expr, $T:ident, $body:block) => {
        match $set {
            "ML-KEM-512" => {
                type $T = ml_kem::MlKem512;
                $body
            }
            "ML-KEM-768" => {
                type $T = ml_kem::MlKem768;
                $body
            }
            "ML-KEM-1024" => {
                type $T = ml_kem::MlKem1024;
                $body
            }
            other => panic!("unknown ML-KEM parameter set {other}"),
        }
    };
}

#[test]
fn acvp_ml_kem_keygen() {
    let Some((prompt, expected)) = require_vectors("ML-KEM-keyGen-FIPS203") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let mut seed = hx(tc, "d");
            seed.extend(hx(tc, "z"));
            let seed = ml_kem::Seed::try_from(seed.as_slice()).unwrap();
            let (ek, dk) = with_mlkem!(set, P, {
                let dk = ml_kem::DecapsulationKey::<P>::from_seed(seed);
                let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
                #[allow(deprecated)]
                let dk_bytes = dk.to_expanded_bytes().as_slice().to_vec();
                (ek, dk_bytes)
            });
            t.check(
                ek == hx(exp, "ek") && dk == hx(exp, "dk"),
                format!("{set} tc{}", tc["tcId"]),
            );
        }
    }
    t.report("ML-KEM-keyGen");
}

#[test]
fn acvp_ml_kem_encaps_decaps() {
    let Some((prompt, expected)) = require_vectors("ML-KEM-encapDecap-FIPS203") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        let function = s(g, "function");
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let label = format!("{set} {function} tc{}", tc["tcId"]);
            match function {
                "encapsulation" => {
                    let (c, k) = with_mlkem!(set, P, {
                        let key =
                            ml_kem::Key::<ml_kem::EncapsulationKey<P>>::try_from(hx(tc, "ek").as_slice())
                                .unwrap();
                        let ek = ml_kem::EncapsulationKey::<P>::new(&key).unwrap();
                        let m = ml_kem::B32::try_from(hx(tc, "m").as_slice()).unwrap();
                        let (c, k) = ek.encapsulate_deterministic(&m);
                        (c.as_slice().to_vec(), k.as_slice().to_vec())
                    });
                    t.check(c == hx(exp, "c") && k == hx(exp, "k"), label);
                }
                "decapsulation" => {
                    // Through this library's own decapsulation path (pure suite, expanded dk).
                    let sk = kem::SecretKey::new(hx(tc, "dk"), set);
                    let k = kem::decapsulate(&sk, &hx(tc, "c")).map(|k| k.to_vec());
                    t.check(k.as_ref().ok() == Some(&hx(exp, "k")), label);
                }
                other => t.skip(&format!("ML-KEM {other}"), 1),
            }
        }
    }
    t.report("ML-KEM-encapDecap");
}

// ----------------------------------------------------------------------------- ML-DSA

macro_rules! with_mldsa {
    ($set:expr, $T:ident, $body:block) => {
        match $set {
            "ML-DSA-44" => {
                type $T = ml_dsa::MlDsa44;
                $body
            }
            "ML-DSA-65" => {
                type $T = ml_dsa::MlDsa65;
                $body
            }
            "ML-DSA-87" => {
                type $T = ml_dsa::MlDsa87;
                $body
            }
            other => panic!("unknown ML-DSA parameter set {other}"),
        }
    };
}

#[test]
fn acvp_ml_dsa_keygen() {
    let Some((prompt, expected)) = require_vectors("ML-DSA-keyGen-FIPS204") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let seed = ml_dsa::Seed::try_from(hx(tc, "seed").as_slice()).unwrap();
            let (pk, sk) = with_mldsa!(set, P, {
                let esk = ExpandedSigningKey::<P>::from_seed(&seed);
                #[allow(deprecated)]
                let sk = esk.to_expanded().as_slice().to_vec();
                (esk.verifying_key().encode().as_slice().to_vec(), sk)
            });
            t.check(
                pk == hx(exp, "pk") && sk == hx(exp, "sk"),
                format!("{set} tc{}", tc["tcId"]),
            );
        }
    }
    t.report("ML-DSA-keyGen");
}

#[test]
fn acvp_ml_dsa_siggen() {
    let Some((prompt, expected)) = require_vectors("ML-DSA-sigGen-FIPS204") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        let internal = s(g, "signatureInterface") == "internal";
        let deterministic = g["deterministic"].as_bool().unwrap();
        let n = g["tests"].as_array().unwrap().len();
        if g["externalMu"].as_bool() == Some(true) {
            t.skip("ML-DSA externalMu", n);
            continue;
        }
        if !internal && s(g, "preHash") != "pure" {
            t.skip("ML-DSA HashML-DSA (preHash)", n);
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let rnd: [u8; 32] = if deterministic {
                [0u8; 32]
            } else {
                hx(tc, "rnd").try_into().unwrap()
            };
            let message = hx(tc, "message");
            let sig = with_mldsa!(set, P, {
                let enc = ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(hx(tc, "sk").as_slice()).unwrap();
                #[allow(deprecated)]
                let esk = ExpandedSigningKey::<P>::from_expanded(&enc);
                let sig = if internal {
                    esk.sign_internal(&[&message], &ml_dsa::B32::from(rnd))
                } else {
                    let ctx = hx(tc, "context");
                    // FIPS 204 Algorithm 2: M' = 0x00 || len(ctx) || ctx || M
                    let prefix: Vec<u8> = [&[0u8, ctx.len() as u8][..], &ctx].concat();
                    esk.sign_internal(&[&prefix, &message], &ml_dsa::B32::from(rnd))
                };
                sig.encode().as_slice().to_vec()
            });
            t.check(sig == hx(exp, "signature"), format!("{set} tc{}", tc["tcId"]));
        }
    }
    t.report("ML-DSA-sigGen");
}

#[test]
fn acvp_ml_dsa_sigver() {
    let Some((prompt, expected)) = require_vectors("ML-DSA-sigVer-FIPS204") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        let internal = s(g, "signatureInterface") == "internal";
        let n = g["tests"].as_array().unwrap().len();
        if g["externalMu"].as_bool() == Some(true) {
            t.skip("ML-DSA externalMu", n);
            continue;
        }
        if !internal && s(g, "preHash") != "pure" {
            t.skip("ML-DSA HashML-DSA (preHash)", n);
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let want = exp["testPassed"].as_bool().unwrap();
            if want {
                t.expected_accept += 1;
            } else {
                t.expected_reject += 1;
            }
            let message = hx(tc, "message");
            let got = with_mldsa!(set, P, {
                let pk = hx(tc, "pk");
                let enc = ml_dsa::EncodedVerifyingKey::<P>::try_from(pk.as_slice()).unwrap();
                let vk = VerifyingKey::<P>::decode(&enc);
                match MlSig::<P>::try_from(hx(tc, "signature").as_slice()) {
                    Err(_) => false,
                    Ok(sig) if internal => vk.verify_internal(&message, &sig),
                    Ok(sig) => vk.verify_with_context(&message, &hx(tc, "context"), &sig),
                }
            });
            t.check(got == want, format!("{set} tc{} want {want}", tc["tcId"]));
        }
    }
    assert!(
        t.expected_accept > 0 && t.expected_reject > 0,
        "need both accept and reject cases"
    );
    t.report("ML-DSA-sigVer");
}

// ----------------------------------------------------------------------------- SLH-DSA

macro_rules! with_slh {
    ($set:expr, $T:ident, $body:block) => {
        match $set {
            "SLH-DSA-SHAKE-128s" => {
                type $T = slh_dsa::Shake128s;
                $body
            }
            "SLH-DSA-SHAKE-128f" => {
                type $T = slh_dsa::Shake128f;
                $body
            }
            "SLH-DSA-SHAKE-192s" => {
                type $T = slh_dsa::Shake192s;
                $body
            }
            "SLH-DSA-SHAKE-192f" => {
                type $T = slh_dsa::Shake192f;
                $body
            }
            "SLH-DSA-SHAKE-256s" => {
                type $T = slh_dsa::Shake256s;
                $body
            }
            "SLH-DSA-SHAKE-256f" => {
                type $T = slh_dsa::Shake256f;
                $body
            }
            "SLH-DSA-SHA2-128s" => {
                type $T = slh_dsa::Sha2_128s;
                $body
            }
            "SLH-DSA-SHA2-128f" => {
                type $T = slh_dsa::Sha2_128f;
                $body
            }
            "SLH-DSA-SHA2-192s" => {
                type $T = slh_dsa::Sha2_192s;
                $body
            }
            "SLH-DSA-SHA2-192f" => {
                type $T = slh_dsa::Sha2_192f;
                $body
            }
            "SLH-DSA-SHA2-256s" => {
                type $T = slh_dsa::Sha2_256s;
                $body
            }
            "SLH-DSA-SHA2-256f" => {
                type $T = slh_dsa::Sha2_256f;
                $body
            }
            other => panic!("unknown SLH-DSA parameter set {other}"),
        }
    };
}

fn slh_sample() -> usize {
    std::env::var("QS_ACVP_SLH_SAMPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1)
}

#[test]
fn acvp_slh_dsa_keygen() {
    let Some((prompt, expected)) = require_vectors("SLH-DSA-keyGen-FIPS205") else {
        return;
    };
    let mut t = Tally::default();
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        for tc in g["tests"].as_array().unwrap() {
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let (sk, pk) = with_slh!(set, P, {
                use slh_dsa::signature::Keypair as _;
                let sk = slh_dsa::SigningKey::<P>::slh_keygen_internal(
                    &hx(tc, "skSeed"),
                    &hx(tc, "skPrf"),
                    &hx(tc, "pkSeed"),
                );
                (sk.to_vec(), sk.verifying_key().to_vec())
            });
            t.check(
                sk == hx(exp, "sk") && pk == hx(exp, "pk"),
                format!("{set} tc{}", tc["tcId"]),
            );
        }
    }
    t.report("SLH-DSA-keyGen");
}

#[test]
fn acvp_slh_dsa_siggen() {
    let Some((prompt, expected)) = require_vectors("SLH-DSA-sigGen-FIPS205") else {
        return;
    };
    let (mut t, step, mut i) = (Tally::default(), slh_sample(), 0usize);
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        let internal = s(g, "signatureInterface") == "internal";
        let deterministic = g["deterministic"].as_bool().unwrap();
        let n = g["tests"].as_array().unwrap().len();
        if !internal && s(g, "preHash") != "pure" {
            t.skip("SLH-DSA HashSLH-DSA (preHash)", n);
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            i += 1;
            if i % step != 0 {
                t.skip("sampled out (QS_ACVP_SLH_SAMPLE)", 1);
                continue;
            }
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let opt_rand = if deterministic {
                None
            } else {
                Some(hx(tc, "additionalRandomness"))
            };
            let message = hx(tc, "message");
            let sig = with_slh!(set, P, {
                let sk = slh_dsa::SigningKey::<P>::try_from(hx(tc, "sk").as_slice()).unwrap();
                if internal {
                    sk.slh_sign_internal(&message, opt_rand.as_deref()).to_vec()
                } else {
                    sk.try_sign_with_context(&message, &hx(tc, "context"), opt_rand.as_deref())
                        .unwrap()
                        .to_vec()
                }
            });
            t.check(sig == hx(exp, "signature"), format!("{set} tc{}", tc["tcId"]));
        }
    }
    t.report("SLH-DSA-sigGen");
}

#[test]
fn acvp_slh_dsa_sigver() {
    let Some((prompt, expected)) = require_vectors("SLH-DSA-sigVer-FIPS205") else {
        return;
    };
    let (mut t, step, mut i) = (Tally::default(), slh_sample(), 0usize);
    for g in prompt["testGroups"].as_array().unwrap() {
        let set = s(g, "parameterSet");
        let internal = s(g, "signatureInterface") == "internal";
        let n = g["tests"].as_array().unwrap().len();
        if !internal && s(g, "preHash") != "pure" {
            t.skip("SLH-DSA HashSLH-DSA (preHash)", n);
            continue;
        }
        for tc in g["tests"].as_array().unwrap() {
            i += 1;
            if i % step != 0 {
                t.skip("sampled out (QS_ACVP_SLH_SAMPLE)", 1);
                continue;
            }
            let exp = expected_by_tc(
                &expected,
                g["tgId"].as_u64().unwrap(),
                tc["tcId"].as_u64().unwrap(),
            );
            let want = exp["testPassed"].as_bool().unwrap();
            if want {
                t.expected_accept += 1;
            } else {
                t.expected_reject += 1;
            }
            let message = hx(tc, "message");
            let sig_bytes = hx(tc, "signature");
            let got = with_slh!(set, P, {
                let vk = slh_dsa::VerifyingKey::<P>::try_from(hx(tc, "pk").as_slice()).unwrap();
                match slh_dsa::Signature::<P>::try_from(sig_bytes.as_slice()) {
                    Err(_) => false,
                    Ok(sig) if internal => vk.slh_verify_internal(&message, &sig).is_ok(),
                    Ok(sig) => vk
                        .try_verify_with_context(&message, &hx_opt(tc, "context").unwrap(), &sig)
                        .is_ok(),
                }
            });
            t.check(got == want, format!("{set} tc{} want {want}", tc["tcId"]));
        }
    }
    assert!(
        t.expected_accept > 0 && t.expected_reject > 0,
        "need both accept and reject cases"
    );
    t.report("SLH-DSA-sigVer");
}
