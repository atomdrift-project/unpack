//! RFC 1924 base85: the alphabet of Python's `base64.b85encode`, which script
//! protectors and loaders use to carry payloads in a string literal.
//!
//! Distinct from Adobe ASCII85 (`!`–`u`, `<~ ~>` framing, `z` shorthand):
//! the same radix, a different alphabet, and no shorthand.

/// The RFC 1924 digits, in value order.
const ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

/// Each byte's digit value plus one; zero marks a byte outside the alphabet.
#[expect(
    clippy::indexing_slicing,
    reason = "compile-time table: i < 85 and every alphabet byte indexes 256 slots"
)]
const VALUE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        #[expect(clippy::cast_possible_truncation, reason = "i < 85")]
        {
            table[ALPHABET[i] as usize] = i as u8 + 1;
        }
        i += 1;
    }
    table
};

/// Decode RFC 1924 base85 `text` as Python's `base64.b85decode` does: groups
/// of five digits become four bytes, and a short final group is padded with
/// the highest digit and its padding dropped. `None` for a byte outside the
/// alphabet or a group above `u32::MAX`.
#[must_use]
pub fn decode_rfc1924(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 5 * 4 + 4);
    for chunk in text.chunks(5) {
        let mut acc: u64 = 0;
        for i in 0..5 {
            let digit = match chunk.get(i) {
                Some(&c) => VALUE.get(usize::from(c)).copied()?.checked_sub(1)?,
                None => 84,
            };
            acc = acc * 85 + u64::from(digit);
        }
        let word = u32::try_from(acc).ok()?.to_be_bytes();
        out.extend_from_slice(word.get(..chunk.len().saturating_sub(1))?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_python_b85encode_output() {
        // `base64.b85encode(b"hello world")` in CPython.
        assert_eq!(
            decode_rfc1924(b"Xk~0{Zy<MXa%^M").as_deref(),
            Some(&b"hello world"[..])
        );
        assert_eq!(decode_rfc1924(b"").as_deref(), Some(&b""[..]));
    }

    #[test]
    fn rejects_bytes_outside_the_alphabet() {
        assert_eq!(decode_rfc1924(b"Xk~0\"Zy<M"), None);
        assert_eq!(decode_rfc1924(b"Xk 0{"), None);
    }
}
