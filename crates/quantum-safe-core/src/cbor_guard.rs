//! A cheap structural check run on untrusted CBOR *before* it is decoded into a `ciborium::Value` tree.
//!
//! Decoding into `Value` allocates per item: a 10 MB array of one-byte items can become about 800 MB. The formats this crate reads (keys,
//! sealed messages, signed messages, hybrid signature payloads, key bundles) are tiny, flat maps of text keys to scalars and byte strings, so
//! this walk rejects anything outside that shape without allocating:
//!
//! * indefinite lengths, tags, and simple values other than false/true/null/floats;
//! * nesting deeper than [`MAX_DEPTH`], any array or map with more than [`MAX_CONTAINER_LEN`] entries, more than [`MAX_ITEMS`] items overall;
//! * maps whose keys are not text strings, and duplicate keys (a parser differential: Rust would take the first, quantum-safe-py the last);
//! * trailing bytes after the single top-level item.
//!
//! None of quantum-safe-py's own writers produce any of these, so valid data is unaffected.

const MAX_DEPTH: usize = 8;
const MAX_CONTAINER_LEN: u64 = 64;
const MAX_ITEMS: usize = 4096;

/// Returns `Err(reason)` if `data` is not a single, definite-length CBOR item of the allowed shape.
pub fn validate_shape(data: &[u8]) -> Result<(), &'static str> {
    let mut p = Parser {
        data,
        pos: 0,
        items: 0,
    };
    p.item(0)?;
    if p.pos != data.len() {
        return Err("trailing bytes after the CBOR item");
    }
    Ok(())
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    items: usize,
}

impl Parser<'_> {
    fn byte(&mut self) -> Result<u8, &'static str> {
        let b = *self.data.get(self.pos).ok_or("truncated CBOR")?;
        self.pos += 1;
        Ok(b)
    }

    /// The argument of a head byte (the "additional information"), definite lengths only.
    fn argument(&mut self, info: u8) -> Result<u64, &'static str> {
        let size = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err("indefinite or reserved CBOR length"),
        };
        let end = self.pos.checked_add(size).ok_or("truncated CBOR")?;
        let bytes = self.data.get(self.pos..end).ok_or("truncated CBOR")?;
        self.pos = end;
        let value = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        // Shortest form only (what cbor2 and ciborium write): a non-minimal encoding is a second spelling of the same data.
        let minimal = match info {
            24 => value >= 24,
            25 => value >= 0x100,
            26 => value >= 0x1_0000,
            _ => value >= 0x1_0000_0000,
        };
        if !minimal {
            return Err("non-minimal CBOR integer or length encoding");
        }
        Ok(value)
    }

    fn skip(&mut self, len: u64) -> Result<(), &'static str> {
        let len = usize::try_from(len).map_err(|_| "CBOR string longer than the input")?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or("CBOR string longer than the input")?;
        if end > self.data.len() {
            return Err("CBOR string longer than the input");
        }
        self.pos = end;
        Ok(())
    }

    fn item(&mut self, depth: usize) -> Result<(), &'static str> {
        if depth > MAX_DEPTH {
            return Err("CBOR nested too deeply");
        }
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err("CBOR has too many items");
        }
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 0x1f);
        match major {
            0 | 1 => {
                self.argument(info)?;
            }
            2 | 3 => {
                let len = self.argument(info)?;
                self.skip(len)?;
            }
            4 => {
                let len = self.argument(info)?;
                if len > MAX_CONTAINER_LEN {
                    return Err("CBOR array too long");
                }
                for _ in 0..len {
                    self.item(depth + 1)?;
                }
            }
            5 => {
                let len = self.argument(info)?;
                if len > MAX_CONTAINER_LEN {
                    return Err("CBOR map too large");
                }
                let mut keys: Vec<&[u8]> = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    // keys must be definite-length text strings
                    let key_head = self.byte()?;
                    if key_head >> 5 != 3 {
                        return Err("CBOR map key is not a text string");
                    }
                    let klen = self.argument(key_head & 0x1f)?;
                    let data = self.data;
                    let start = self.pos;
                    self.skip(klen)?;
                    let key = &data[start..self.pos];
                    if keys.contains(&key) {
                        return Err("duplicate CBOR map key");
                    }
                    keys.push(key);
                    self.items += 1;
                    self.item(depth + 1)?;
                }
            }
            6 => return Err("CBOR tags are not accepted"),
            _ => match info {
                20..=22 => {}
                25 => self.skip(2)?,
                26 => self.skip(4)?,
                27 => self.skip(8)?,
                _ => return Err("unsupported CBOR simple value"),
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_shapes_the_formats_use() {
        // {"v": 1, "key": h'0102', "ok": true, "t": 1.5}
        let mut d = vec![
            0xa4, 0x61, b'v', 0x01, 0x63, b'k', b'e', b'y', 0x42, 1, 2, 0x62, b'o', b'k', 0xf5, 0x61, b't',
        ];
        d.extend_from_slice(&[0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
        assert_eq!(validate_shape(&d), Ok(()));
    }

    #[test]
    fn rejects_non_minimal_integers_and_lengths() {
        assert!(validate_shape(&[0x18, 0x05]).is_err()); // 5 written in two bytes
        assert!(validate_shape(&[0x19, 0x00, 0x05]).is_err());
        assert!(validate_shape(&[0x42, 1, 2]).is_ok());
        assert!(validate_shape(&[0x58, 0x02, 1, 2]).is_err()); // length 2 written as 0x58 0x02
        assert!(validate_shape(&[0x18, 0x18]).is_ok()); // 24 needs the extra byte
    }

    #[test]
    fn rejects_trailing_bytes_duplicates_tags_indefinite_and_depth() {
        assert!(validate_shape(&[0xa0, 0x00]).is_err()); // trailing
        assert!(validate_shape(&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02]).is_err()); // duplicate key
        assert!(validate_shape(&[0xa1, 0x01, 0x01]).is_err()); // non-text key
        assert!(validate_shape(&[0xc0, 0x00]).is_err()); // tag
        assert!(validate_shape(&[0x9f, 0xff]).is_err()); // indefinite array
        assert!(validate_shape(&[0x5f, 0xff]).is_err()); // indefinite byte string
        assert!(validate_shape(&[0x81; 20]).is_err()); // deep nesting / truncated
        let mut deep = vec![0x81; 12];
        deep.push(0x00);
        assert!(validate_shape(&deep).is_err());
    }

    #[test]
    fn rejects_amplification_inputs_without_allocating_them() {
        // A huge array of tiny items: rejected at the length check, not decoded.
        let mut big = vec![0x9a, 0x00, 0xa0, 0x00, 0x00];
        big.extend(std::iter::repeat_n(0x00, 10_000_000));
        assert!(validate_shape(&big).is_err());
        // Many small entries just under the limit pass; just over fail.
        let mut ok = vec![0x98, 64];
        ok.extend(std::iter::repeat_n(0x00, 64));
        assert_eq!(validate_shape(&ok), Ok(()));
        let mut over = vec![0x98, 65];
        over.extend(std::iter::repeat_n(0x00, 65));
        assert!(validate_shape(&over).is_err());
    }

    #[test]
    fn truncated_and_overlong_strings_are_errors() {
        assert!(validate_shape(&[0x45, 1, 2]).is_err());
        assert!(validate_shape(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(validate_shape(&[]).is_err());
    }

    #[test]
    fn never_panics_on_arbitrary_prefixes() {
        for seed in 0u32..2000 {
            let mut x = seed.wrapping_mul(2654435761);
            let data: Vec<u8> = (0..(seed % 40))
                .map(|_| {
                    x = x.wrapping_mul(1103515245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = validate_shape(&data);
        }
    }
}
