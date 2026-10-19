//! Streaming envelope (format v3): authenticated public-key encryption of data that does not fit in memory, or arrives in pieces.
//! quantum-safe-py 1.0.0 (`quantum_safe.protocols.stream`) reads and writes the same bytes; 0.3.x cannot read it.
//!
//! One KEM encapsulation per stream. The data is cut into chunks of a fixed size (the last chunk may be shorter or empty), and each chunk is
//! sealed with AES-256-GCM under a key derived from the KEM shared secret and the stream header. This is the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizar 2015): the 96-bit nonce of chunk `i` is `prefix (7 random bytes) || i (u32, big endian) || last (1 byte, 0 or 1)`,
//! so chunks cannot be reordered, dropped from the middle, or duplicated, and truncating the stream fails because the final chunk present
//! was not sealed with `last = 1`.
//!
//! Header (CBOR map, exactly these five entries): `{"v": 3, "algo": <KEM suite>, "kct": <KEM ciphertext>, "np": <7-byte nonce prefix>, "cs": <chunk size>}`.
//! Key: `HKDF(shared secret, info = "qs-envelope-stream-v3" || 0x00 || H(header))`, with H and HKDF using SHA-256 for hybrid suites and SHA-384 for pure `ML-KEM-1024`
//! (the same suite rule as the single-message envelope). Every chunk's AAD is `u32(len(header)) || header || u32(len(caller aad)) || caller aad`.

use crate::aead::{self, AeadError};
use crate::cbor_guard;
use crate::kdf::{self, KdfError};
use crate::kem::{self, KemError};
use crate::suite::{KemSuite, Pqc};
use ciborium::value::Value;
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use zeroize::Zeroizing;

/// Stream format version written in the header (`v`).
pub const STREAM_VERSION: u8 = 3;
/// Length in bytes of the random per-stream nonce prefix.
pub const NONCE_PREFIX_LEN: usize = 7;
/// Length in bytes of the AES-GCM tag that ends every encrypted chunk.
pub const TAG_LEN: usize = 16;
/// Smallest chunk size in bytes a header may declare.
pub const MIN_CHUNK_SIZE: usize = 1024;
/// Largest chunk size in bytes a header may declare (16 MiB).
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// Chunk size in bytes that callers use when they have no reason to choose another (64 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
/// A header is a KEM ciphertext plus a few fixed fields; anything much larger is not a header.
pub const MAX_HEADER_LEN: usize = 64 * 1024;
/// HKDF `info` label; the header digest follows after a zero byte.
const KEY_INFO: &[u8] = b"qs-envelope-stream-v3";

/// Errors returned while sealing or opening a stream.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamError {
    /// The header is not a valid v3 header; the field says what is wrong (too large, not well-formed or
    /// decodable CBOR, not a map, not exactly five entries, bad version, a missing or mistyped entry, or a
    /// nonce prefix that is not 7 bytes).
    #[error("stream header is malformed: {0}")]
    Header(&'static str),
    /// The suite is neither a hybrid KEM suite (including X-Wing) nor pure ML-KEM-1024; the field is the
    /// algorithm string.
    #[error(
        "stream suite '{0}' is not supported (hybrid suites (including X-Wing) and pure ML-KEM-1024 only)"
    )]
    UnsupportedSuite(String),
    /// The header's algorithm differs from the secret key's.
    #[error("stream algorithm does not match the secret key algorithm")]
    AlgorithmMismatch,
    /// The chunk size is outside [`MIN_CHUNK_SIZE`]..=[`MAX_CHUNK_SIZE`].
    #[error("chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes")]
    BadChunkSize,
    /// A plaintext chunk is longer than the chunk size, or is shorter and not the last chunk.
    #[error("plaintext chunk has the wrong length: every chunk except the last must be exactly the chunk size, and none may exceed it")]
    BadPlaintextLength,
    /// An encrypted chunk is not `chunk_size + 16` bytes, or (for the last chunk) not between 16 and
    /// `chunk_size + 16` bytes. The stream is finished.
    #[error("encrypted chunk has the wrong length for its position in the stream")]
    BadChunkLength,
    /// The last chunk was already processed, or an earlier failure ended the stream.
    #[error("stream is finished or has failed; no further chunks are accepted")]
    Finished,
    /// The chunk counter (a `u32`) would overflow. The stream is finished.
    #[error("stream has too many chunks")]
    TooManyChunks,
    /// The KEM step failed (see [`KemError`]).
    #[error("KEM operation failed: {0}")]
    Kem(#[from] KemError),
    /// Deriving the stream key failed (see [`KdfError`]).
    #[error("key derivation failed: {0}")]
    Kdf(#[from] KdfError),
    /// A chunk's GCM tag did not verify. The stream is finished.
    #[error("chunk failed authentication: wrong key, wrong associated data, or a modified, reordered, dropped or truncated stream")]
    Authentication,
}

impl From<AeadError> for StreamError {
    fn from(_: AeadError) -> Self {
        StreamError::Authentication
    }
}

/// Which hash the key derivation uses for a suite, or an error for suites streams do not support.
fn uses_sha384(algorithm: &str) -> Result<bool, StreamError> {
    match KemSuite::parse(algorithm) {
        Some(s) if s.is_hybrid() => Ok(false),
        Some(KemSuite::Pure(Pqc::MlKem1024)) => Ok(true),
        _ => Err(StreamError::UnsupportedSuite(algorithm.to_string())),
    }
}

/// The parsed, validated header of a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    /// KEM suite name of the recipient key.
    pub algorithm: String,
    /// KEM ciphertext for the recipient.
    pub kem_ct: Vec<u8>,
    /// Random 7-byte prefix of every chunk nonce.
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// Plaintext bytes in every chunk except the last.
    pub chunk_size: usize,
}

impl StreamHeader {
    /// Encodes the header as the CBOR map `{v, algo, kct, np, cs}` with `v` = [`STREAM_VERSION`].
    ///
    /// The sealer encodes the header once and these exact bytes feed the key derivation and the chunk AAD.
    pub fn to_cbor(&self) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(STREAM_VERSION.into())),
            (Value::Text("algo".into()), Value::Text(self.algorithm.clone())),
            (Value::Text("kct".into()), Value::Bytes(self.kem_ct.clone())),
            (Value::Text("np".into()), Value::Bytes(self.nonce_prefix.to_vec())),
            (
                Value::Text("cs".into()),
                Value::Integer((self.chunk_size as u64).into()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("writing CBOR to a Vec cannot fail");
        out
    }

    /// Strict parser: exactly the five entries, correct types, a supported suite, a chunk size in range. Never panics.
    ///
    /// # Errors
    ///
    /// - [`StreamError::Header`] for a header over [`MAX_HEADER_LEN`] bytes, a shape the CBOR guard
    ///   refuses, undecodable CBOR, a top-level value that is not a map, a map without exactly five
    ///   entries, a version other than 3, a missing or mistyped `algo`, `kct`, `np` or `cs`, or a nonce
    ///   prefix that is not 7 bytes.
    /// - [`StreamError::UnsupportedSuite`] when `algo` is not a hybrid suite or ML-KEM-1024.
    /// - [`StreamError::BadChunkSize`] when `cs` is negative or outside the allowed range.
    pub fn from_cbor(data: &[u8]) -> Result<Self, StreamError> {
        if data.len() > MAX_HEADER_LEN {
            return Err(StreamError::Header("is too large"));
        }
        cbor_guard::validate_shape(data).map_err(|_| StreamError::Header("is not well-formed CBOR"))?;
        let value: Value =
            ciborium::from_reader(data).map_err(|_| StreamError::Header("is not decodable CBOR"))?;
        let Value::Map(entries) = value else {
            return Err(StreamError::Header("is not a map"));
        };
        if entries.len() != 5 {
            return Err(StreamError::Header("must have exactly five entries"));
        }
        let get = |k: &str| {
            entries.iter().find_map(|(key, v)| match key {
                Value::Text(t) if t == k => Some(v),
                _ => None,
            })
        };
        match get("v") {
            Some(Value::Integer(i)) if i128::from(*i) == i128::from(STREAM_VERSION) => {}
            _ => return Err(StreamError::Header("has an unsupported or missing version")),
        }
        let Some(Value::Text(algorithm)) = get("algo") else {
            return Err(StreamError::Header("is missing 'algo'"));
        };
        uses_sha384(algorithm)?;
        let Some(Value::Bytes(kem_ct)) = get("kct") else {
            return Err(StreamError::Header("is missing 'kct'"));
        };
        let Some(Value::Bytes(np)) = get("np") else {
            return Err(StreamError::Header("is missing 'np'"));
        };
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = np
            .as_slice()
            .try_into()
            .map_err(|_| StreamError::Header("has a nonce prefix of the wrong length"))?;
        let chunk_size = match get("cs") {
            Some(Value::Integer(i)) => {
                usize::try_from(i128::from(*i)).map_err(|_| StreamError::BadChunkSize)?
            }
            _ => return Err(StreamError::Header("is missing 'cs'")),
        };
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(StreamError::BadChunkSize);
        }
        Ok(Self {
            algorithm: algorithm.clone(),
            kem_ct: kem_ct.clone(),
            nonce_prefix,
            chunk_size,
        })
    }
}

/// Seals or opens the chunks of one stream, in order. It owns the key and the chunk counter, so a nonce can never be reused or skipped
/// by a caller. After the last chunk, or after any authentication failure, it refuses everything (fail closed).
pub struct StreamCipher {
    key: Zeroizing<[u8; 32]>,
    prefix: [u8; NONCE_PREFIX_LEN],
    aad: Vec<u8>,
    chunk_size: usize,
    counter: u32,
    finished: bool,
}

// Derives the 32-byte stream key from the KEM shared secret and the exact header bytes. `sha384` selects
// HKDF-SHA384 and SHA-384 for the header digest (pure ML-KEM-1024); otherwise SHA-256 is used for both.
fn derive_key(shared_secret: &[u8], header: &[u8], sha384: bool) -> Result<Zeroizing<[u8; 32]>, StreamError> {
    // info = label || 0x00 || H(header), with H = the KDF's own hash: binds the whole header (KEM ciphertext, nonce prefix, chunk size) to the key
    // while keeping the HKDF info short (some HKDF implementations cap it at 1,024 bytes; a KEM ciphertext alone can be longer).
    let digest: Vec<u8> = if sha384 {
        Sha384::digest(header).to_vec()
    } else {
        Sha256::digest(header).to_vec()
    };
    let mut info = Vec::with_capacity(KEY_INFO.len() + 1 + digest.len());
    info.extend_from_slice(KEY_INFO);
    info.push(0);
    info.extend_from_slice(&digest);
    let okm = Zeroizing::new(if sha384 {
        kdf::derive_key_sha384(shared_secret, &info, aead::KEY_LEN)?
    } else {
        kdf::derive_key(shared_secret, &info, aead::KEY_LEN)?
    });
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    Ok(key)
}

// The AAD of every chunk: `u32_be(len(header)) || header || u32_be(len(caller_aad)) || caller_aad`.
fn build_aad(header: &[u8], caller_aad: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + header.len() + caller_aad.len());
    v.extend_from_slice(&(header.len() as u32).to_be_bytes());
    v.extend_from_slice(header);
    v.extend_from_slice(&(caller_aad.len() as u32).to_be_bytes());
    v.extend_from_slice(caller_aad);
    v
}

impl StreamCipher {
    /// Starts a stream to `recipient`: encapsulates, writes the header, derives the key. Returns the header bytes to send first.
    ///
    /// `caller_aad` is authenticated with every chunk and not stored; the opener must supply the same bytes.
    ///
    /// # Errors
    ///
    /// - [`StreamError::BadChunkSize`] when `chunk_size` is outside [`MIN_CHUNK_SIZE`]..=[`MAX_CHUNK_SIZE`].
    /// - [`StreamError::UnsupportedSuite`] when the key's algorithm is not a hybrid suite or ML-KEM-1024.
    /// - [`StreamError::Kem`] when encapsulation fails, e.g. a malformed public key.
    /// - [`StreamError::Kdf`] if key derivation fails.
    ///
    /// # Panics
    ///
    /// Panics if the operating system RNG is unavailable.
    pub fn start_sealing(
        recipient: &kem::PublicKey,
        caller_aad: &[u8],
        chunk_size: usize,
    ) -> Result<(Vec<u8>, Self), StreamError> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(StreamError::BadChunkSize);
        }
        let sha384 = uses_sha384(&recipient.algorithm)?;
        let (kem_ct, shared_secret) = kem::encapsulate(recipient)?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        getrandom::fill(&mut nonce_prefix).expect("OS RNG must be available to generate a nonce prefix");
        let header = StreamHeader {
            algorithm: recipient.algorithm.clone(),
            kem_ct,
            nonce_prefix,
            chunk_size,
        }
        .to_cbor();
        let key = derive_key(&shared_secret[..], &header, sha384)?;
        let cipher = Self {
            key,
            prefix: nonce_prefix,
            aad: build_aad(&header, caller_aad),
            chunk_size,
            counter: 0,
            finished: false,
        };
        Ok((header, cipher))
    }

    /// Starts opening a stream: parses and validates the header, decapsulates, derives the key.
    ///
    /// `caller_aad` must equal the bytes given to [`StreamCipher::start_sealing`]; a difference shows up
    /// as [`StreamError::Authentication`] on the first chunk.
    ///
    /// # Errors
    ///
    /// - The errors of [`StreamHeader::from_cbor`].
    /// - [`StreamError::AlgorithmMismatch`] when the header's algorithm differs from the secret key's.
    /// - [`StreamError::Kem`] when decapsulation fails, e.g. a wrong-length KEM ciphertext.
    /// - [`StreamError::Kdf`] if key derivation fails.
    pub fn start_opening(
        recipient_secret: &kem::SecretKey,
        header_bytes: &[u8],
        caller_aad: &[u8],
    ) -> Result<Self, StreamError> {
        let header = StreamHeader::from_cbor(header_bytes)?;
        if header.algorithm != recipient_secret.algorithm {
            return Err(StreamError::AlgorithmMismatch);
        }
        let sha384 = uses_sha384(&header.algorithm)?;
        let shared_secret = kem::decapsulate(recipient_secret, &header.kem_ct)?;
        let key = derive_key(&shared_secret[..], header_bytes, sha384)?;
        Ok(Self {
            key,
            prefix: header.nonce_prefix,
            aad: build_aad(header_bytes, caller_aad),
            chunk_size: header.chunk_size,
            counter: 0,
            finished: false,
        })
    }

    /// The chunk size of this stream in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    // The 12-byte nonce of the current chunk: `prefix (7) || counter (u32 big-endian) || last (0 or 1)`.
    fn nonce(&self, last: bool) -> [u8; aead::NONCE_LEN] {
        let mut n = [0u8; aead::NONCE_LEN];
        n[..NONCE_PREFIX_LEN].copy_from_slice(&self.prefix);
        n[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&self.counter.to_be_bytes());
        n[aead::NONCE_LEN - 1] = u8::from(last);
        n
    }

    /// Seals the next chunk. Every chunk except the last must be exactly `chunk_size` bytes; the last may be 0..=`chunk_size`.
    ///
    /// The output is `plaintext.len() + 16` bytes. Passing `last = true` finishes the stream.
    ///
    /// # Errors
    ///
    /// - [`StreamError::Finished`] when the stream is already finished.
    /// - [`StreamError::BadPlaintextLength`] when the length is not allowed for this position.
    /// - [`StreamError::TooManyChunks`] when the chunk counter would overflow.
    pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>, StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        if plaintext.len() > self.chunk_size || (!last && plaintext.len() != self.chunk_size) {
            return Err(StreamError::BadPlaintextLength);
        }
        let out = aead::encrypt(&self.key, &self.nonce(last), plaintext, &self.aad);
        self.advance(last)?;
        Ok(out)
    }

    /// The key step of `seal_chunk` for a caller that runs AES-256-GCM itself: checks the stream is open and the
    /// chunk length is allowed and returns the chunk's nonce. Encrypt exactly `plaintext_len` bytes under
    /// [`StreamCipher::key`] with this nonce and [`StreamCipher::aad`] (the result equals `seal_chunk`'s), then call
    /// [`StreamCipher::commit`].
    ///
    /// Nothing advances until `commit`, so calling this twice without it returns the same nonce.
    ///
    /// # Errors
    ///
    /// [`StreamError::Finished`] when the stream is finished; [`StreamError::BadPlaintextLength`] when
    /// `plaintext_len` is not allowed for this position (the stream stays open).
    pub fn prepare_seal(
        &mut self,
        plaintext_len: usize,
        last: bool,
    ) -> Result<[u8; aead::NONCE_LEN], StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        if plaintext_len > self.chunk_size || (!last && plaintext_len != self.chunk_size) {
            return Err(StreamError::BadPlaintextLength);
        }
        Ok(self.nonce(last))
    }

    /// The key step of `open_chunk` for a caller that runs AES-256-GCM itself: checks the stream is open and the
    /// ciphertext length is allowed and returns the chunk's nonce. If the caller's decryption succeeds it calls
    /// [`StreamCipher::commit`]; if it fails it calls [`StreamCipher::abort`], which ends the stream exactly as a
    /// failure inside `open_chunk` does.
    ///
    /// # Errors
    ///
    /// [`StreamError::Finished`] when the stream is finished; [`StreamError::BadChunkLength`] when
    /// `ciphertext_len` is not allowed for this position, which also finishes the stream.
    pub fn prepare_open(
        &mut self,
        ciphertext_len: usize,
        last: bool,
    ) -> Result<[u8; aead::NONCE_LEN], StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        let ok_len = if last {
            (TAG_LEN..=self.chunk_size + TAG_LEN).contains(&ciphertext_len)
        } else {
            ciphertext_len == self.chunk_size + TAG_LEN
        };
        if !ok_len {
            self.finished = true;
            return Err(StreamError::BadChunkLength);
        }
        Ok(self.nonce(last))
    }

    /// Moves to the next chunk after the caller's AES-256-GCM step succeeded (the counter advances, or the stream
    /// finishes after the last chunk).
    ///
    /// # Errors
    ///
    /// [`StreamError::TooManyChunks`] when the chunk counter would overflow, which finishes the stream.
    pub fn commit(&mut self, last: bool) -> Result<(), StreamError> {
        self.advance(last)
    }

    /// Ends the stream: every later call is refused.
    pub fn abort(&mut self) {
        self.finished = true;
    }

    /// The one-time AES-256 key of this stream (for a caller that runs AES-256-GCM itself).
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The AAD that every chunk authenticates.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Opens the next chunk. `last` says whether the transport reached its end after this chunk. Any failure ends the stream.
    ///
    /// # Errors
    ///
    /// - [`StreamError::Finished`] when the stream is already finished.
    /// - [`StreamError::BadChunkLength`] when the ciphertext length is not allowed for this position.
    /// - [`StreamError::Authentication`] when the tag does not verify: a wrong key or AAD, or a modified,
    ///   reordered, dropped or truncated chunk.
    /// - [`StreamError::TooManyChunks`] when the chunk counter would overflow.
    pub fn open_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>, StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        let ok_len = if last {
            (TAG_LEN..=self.chunk_size + TAG_LEN).contains(&ciphertext.len())
        } else {
            ciphertext.len() == self.chunk_size + TAG_LEN
        };
        if !ok_len {
            self.finished = true;
            return Err(StreamError::BadChunkLength);
        }
        match aead::decrypt(&self.key, &self.nonce(last), ciphertext, &self.aad) {
            Ok(pt) => {
                self.advance(last)?;
                Ok(pt)
            }
            Err(_) => {
                self.finished = true;
                Err(StreamError::Authentication)
            }
        }
    }

    // Moves past the chunk just processed: the last chunk finishes the stream, any other increments the
    // counter, and an overflowing counter finishes the stream with `TooManyChunks`.
    fn advance(&mut self, last: bool) -> Result<(), StreamError> {
        if last {
            self.finished = true;
        } else {
            self.counter = self.counter.checked_add(1).ok_or_else(|| {
                self.finished = true;
                StreamError::TooManyChunks
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(algorithm: &str) -> kem::KeyPair {
        kem::generate_keypair_for(algorithm).unwrap()
    }

    fn seal_all(public: &kem::PublicKey, data: &[u8], aad: &[u8], cs: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let (header, mut c) = StreamCipher::start_sealing(public, aad, cs).unwrap();
        let mut frames = Vec::new();
        let mut chunks: Vec<&[u8]> = data.chunks(cs).collect();
        if chunks.is_empty() || chunks.last().unwrap().len() == cs {
            chunks.push(&[]); // a final (possibly empty) chunk is always sealed with last = 1
        }
        let n = chunks.len();
        for (i, ch) in chunks.into_iter().enumerate() {
            frames.push(c.seal_chunk(ch, i + 1 == n).unwrap());
        }
        (header, frames)
    }

    fn open_all(
        secret: &kem::SecretKey,
        header: &[u8],
        frames: &[Vec<u8>],
        aad: &[u8],
    ) -> Result<Vec<u8>, StreamError> {
        let mut c = StreamCipher::start_opening(secret, header, aad)?;
        let mut out = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            out.extend(c.open_chunk(f, i + 1 == frames.len())?);
        }
        Ok(out)
    }

    #[test]
    fn roundtrip_for_hybrid_and_cnsa_suites_with_various_lengths() {
        for algo in ["X25519+ML-KEM-768", "P-256+ML-KEM-512", "X-Wing", "ML-KEM-1024"] {
            let kp = pair(algo);
            for len in [0usize, 1, 1023, 1024, 1025, 3 * 1024, 5000] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
                let (h, frames) = seal_all(&kp.public, &data, b"aad", 1024);
                assert_eq!(
                    open_all(&kp.secret, &h, &frames, b"aad").unwrap(),
                    data,
                    "{algo} {len}"
                );
            }
        }
    }

    #[test]
    fn unsupported_suites_are_refused() {
        for algo in ["ML-KEM-512", "ML-KEM-768"] {
            let kp = pair(algo);
            let r = StreamCipher::start_sealing(&kp.public, b"", 1024);
            assert!(matches!(r, Err(StreamError::UnsupportedSuite(_))), "{algo}");
        }
    }

    #[test]
    fn truncation_reordering_duplication_extension_and_tampering_all_fail() {
        let kp = pair("X25519+ML-KEM-512");
        let data = vec![0x42u8; 4 * 1024 + 10];
        let (h, frames) = seal_all(&kp.public, &data, b"", 1024);
        assert_eq!(frames.len(), 5);
        // truncation: drop the last frame, or the last two
        assert!(open_all(&kp.secret, &h, &frames[..4], b"").is_err());
        assert!(open_all(&kp.secret, &h, &frames[..2], b"").is_err());
        // dropping from the middle
        let mut cut = frames.clone();
        cut.remove(1);
        assert!(open_all(&kp.secret, &h, &cut, b"").is_err());
        // reordering
        let mut swapped = frames.clone();
        swapped.swap(0, 1);
        assert!(open_all(&kp.secret, &h, &swapped, b"").is_err());
        // duplication
        let mut dup = frames.clone();
        dup.insert(1, frames[0].clone());
        assert!(open_all(&kp.secret, &h, &dup, b"").is_err());
        // extension: a copy of a middle frame appended after the real last frame
        let mut ext = frames.clone();
        ext.push(frames[0].clone());
        assert!(open_all(&kp.secret, &h, &ext, b"").is_err());
        // bit flips in every frame and in the header
        for i in 0..frames.len() {
            let mut bad = frames.clone();
            bad[i][0] ^= 1;
            assert!(open_all(&kp.secret, &h, &bad, b"").is_err());
        }
        let mut bad_header = h.clone();
        let at = bad_header.len() - 3;
        bad_header[at] ^= 1;
        assert!(open_all(&kp.secret, &bad_header, &frames, b"").is_err());
        // wrong associated data
        assert!(open_all(&kp.secret, &h, &frames, b"other").is_err());
        // the honest stream still opens
        assert_eq!(open_all(&kp.secret, &h, &frames, b"").unwrap(), data);
    }

    #[test]
    fn a_failure_ends_the_stream() {
        let kp = pair("X25519+ML-KEM-512");
        let (h, frames) = seal_all(&kp.public, &vec![1u8; 2048], b"", 1024);
        let mut c = StreamCipher::start_opening(&kp.secret, &h, b"").unwrap();
        let mut bad = frames[0].clone();
        bad[3] ^= 1;
        assert_eq!(c.open_chunk(&bad, false), Err(StreamError::Authentication));
        assert_eq!(c.open_chunk(&frames[0], false), Err(StreamError::Finished));
    }

    #[test]
    fn sealer_enforces_chunk_discipline() {
        let kp = pair("X25519+ML-KEM-512");
        let (_, mut c) = StreamCipher::start_sealing(&kp.public, b"", 1024).unwrap();
        assert_eq!(
            c.seal_chunk(&[0u8; 10], false),
            Err(StreamError::BadPlaintextLength)
        ); // short non-final chunk
        assert_eq!(
            c.seal_chunk(&[0u8; 2000], true),
            Err(StreamError::BadPlaintextLength)
        ); // too long
        c.seal_chunk(&[0u8; 1024], false).unwrap();
        c.seal_chunk(&[], true).unwrap();
        assert_eq!(c.seal_chunk(&[], true), Err(StreamError::Finished));
        assert_eq!(
            StreamCipher::start_sealing(&kp.public, b"", 10).err(),
            Some(StreamError::BadChunkSize)
        );
    }

    #[test]
    fn header_parser_is_strict_and_never_panics() {
        let kp = pair("X25519+ML-KEM-512");
        let (h, _) = StreamCipher::start_sealing(&kp.public, b"", 1024).unwrap();
        let parsed = StreamHeader::from_cbor(&h).unwrap();
        assert_eq!(parsed.to_cbor(), h);
        // every prefix and every single-byte mutation either parses to something sensible or is a typed error
        for n in 0..h.len() {
            let _ = StreamHeader::from_cbor(&h[..n]);
        }
        for i in 0..h.len() {
            let mut m = h.clone();
            m[i] ^= 0xff;
            let _ = StreamHeader::from_cbor(&m);
        }
        assert!(StreamHeader::from_cbor(&[]).is_err());
        assert!(StreamHeader::from_cbor(&vec![0u8; MAX_HEADER_LEN + 1]).is_err());
        let mut extra = h.clone();
        extra.push(0);
        assert!(StreamHeader::from_cbor(&extra).is_err()); // trailing bytes
    }

    #[test]
    fn algorithm_mismatch_is_refused() {
        let a = pair("X25519+ML-KEM-512");
        let b = pair("X25519+ML-KEM-768");
        let (h, _) = StreamCipher::start_sealing(&a.public, b"", 1024).unwrap();
        assert!(matches!(
            StreamCipher::start_opening(&b.secret, &h, b""),
            Err(StreamError::AlgorithmMismatch)
        ));
    }
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    /// Seals every chunk through `prepare_seal` + the caller's AES-GCM + `commit`, then opens the stream
    /// with the ordinary `open_chunk`, and the other way round.
    #[test]
    fn prepare_commit_path_matches_the_ordinary_chunk_path() {
        for algo in ["X25519+ML-KEM-768", "ML-KEM-1024"] {
            let pair = kem::generate_keypair_for(algo).unwrap();
            let cs = 1024usize;
            let chunks: Vec<Vec<u8>> = vec![vec![1u8; cs], vec![2u8; cs], vec![3u8; 17]];

            let (header, mut sealer) = StreamCipher::start_sealing(&pair.public, b"aad", cs).unwrap();
            let mut sealed = Vec::new();
            for (i, c) in chunks.iter().enumerate() {
                let last = i + 1 == chunks.len();
                let nonce = sealer.prepare_seal(c.len(), last).unwrap();
                sealed.push(aead::encrypt(sealer.key(), &nonce, c, sealer.aad()));
                sealer.commit(last).unwrap();
            }
            let mut opener = StreamCipher::start_opening(&pair.secret, &header, b"aad").unwrap();
            for (i, ct) in sealed.iter().enumerate() {
                let last = i + 1 == sealed.len();
                assert_eq!(opener.open_chunk(ct, last).unwrap(), chunks[i]);
            }

            // and open through the plan path what the ordinary path sealed
            let (header, mut sealer) = StreamCipher::start_sealing(&pair.public, b"aad", cs).unwrap();
            let ordinary: Vec<Vec<u8>> = chunks
                .iter()
                .enumerate()
                .map(|(i, c)| sealer.seal_chunk(c, i + 1 == chunks.len()).unwrap())
                .collect();
            let mut opener = StreamCipher::start_opening(&pair.secret, &header, b"aad").unwrap();
            for (i, ct) in ordinary.iter().enumerate() {
                let last = i + 1 == ordinary.len();
                let nonce = opener.prepare_open(ct.len(), last).unwrap();
                let plain = aead::decrypt(opener.key(), &nonce, ct, opener.aad()).unwrap();
                opener.commit(last).unwrap();
                assert_eq!(plain, chunks[i]);
            }
            assert!(matches!(
                opener.prepare_open(20, true),
                Err(StreamError::Finished)
            ));
        }
    }

    #[test]
    fn prepare_enforces_the_same_rules_and_abort_ends_the_stream() {
        let pair = kem::generate_keypair_for("X25519+ML-KEM-768").unwrap();
        let (header, mut sealer) = StreamCipher::start_sealing(&pair.public, b"", 1024).unwrap();
        assert!(matches!(
            sealer.prepare_seal(10, false),
            Err(StreamError::BadPlaintextLength)
        ));
        assert!(matches!(
            sealer.prepare_seal(1025, true),
            Err(StreamError::BadPlaintextLength)
        ));
        sealer.prepare_seal(0, true).unwrap();
        sealer.commit(true).unwrap();
        assert!(matches!(sealer.prepare_seal(0, true), Err(StreamError::Finished)));

        let mut opener = StreamCipher::start_opening(&pair.secret, &header, b"").unwrap();
        assert!(matches!(
            opener.prepare_open(5, false),
            Err(StreamError::BadChunkLength)
        ));
        assert!(
            matches!(opener.prepare_open(20, true), Err(StreamError::Finished)),
            "a length error ends the stream"
        );

        let mut opener = StreamCipher::start_opening(&pair.secret, &header, b"").unwrap();
        opener.prepare_open(20, true).unwrap();
        opener.abort();
        assert!(matches!(
            opener.prepare_open(20, true),
            Err(StreamError::Finished)
        ));
    }
}
