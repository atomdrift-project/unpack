//! Python modules shipped as a loader around an encrypted body: a string
//! literal decoded (RFC 1924 base85 or base64), XOR'd with a bytes key
//! written in the same file, zlib-decompressed, and handed to
//! `exec(compile(...))`.
//!
//! Commercial "protectors" and malware loaders both ship every module this
//! way, so a reader of the file sees only the loader. The key is in plain
//! sight, so the body is recovered by pairing the file's literals rather than
//! by guessing. Nothing is executed.

use std::io::Read;

/// Bytes literals tried as keys, and string literals tried as payloads.
const MAX_KEYS: usize = 8;
const MAX_PAYLOADS: usize = 8;
/// Most source one payload may decompress to.
const MAX_SOURCE: u64 = 4 * 1024 * 1024;

/// One recovered module body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// The decoded Python source.
    pub source: String,
    /// Byte offset, in the host source, of the literal it was decoded from.
    pub offset: usize,
}

/// Every module body `source` decodes to under this scheme.
///
/// Each payload literal is paired with each key literal, both bounded. zlib's
/// checksum makes a wrong pairing fail outright rather than yield noise, and a
/// body must be UTF-8. A file without a XOR operator or a decompress call is
/// skipped before any literal is read.
#[must_use]
pub fn decode(source: &str) -> Vec<Payload> {
    if !source.contains('^') || !source.contains("decompress") {
        return Vec::new();
    }
    // Keys: `b'…'` / `b"…"` of 4–256 printable characters, no escapes.
    // Payloads: a quoted literal of at least 64 characters.
    let (Some(key_re), Some(payload_re)) = (
        static_regex!(r#"b'([ -&(-\[\]-~]{4,256})'|b"([ !#-\[\]-~]{4,256})""#),
        static_regex!(r#"(?s)'''(.{64,}?)'''|"""(.{64,}?)"""|'([^'\\\n]{64,})'|"([^"\\\n]{64,})""#),
    ) else {
        return Vec::new();
    };
    let keys: Vec<&[u8]> = key_re
        .captures_iter(source)
        .filter_map(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().as_bytes())
        .take(MAX_KEYS)
        .collect();
    if keys.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for caps in payload_re.captures_iter(source).take(MAX_PAYLOADS) {
        let Some(literal) = (1..=4).find_map(|i| caps.get(i)) else {
            continue;
        };
        // A backslash-newline inside a literal is a line continuation, and the
        // loader strips any remaining newlines before decoding.
        let text: Vec<u8> = literal
            .as_str()
            .replace("\\\n", "")
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let decoded = [crate::base85::decode_rfc1924(&text), {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(&text).ok()
        }];
        if let Some(body) = decoded
            .into_iter()
            .flatten()
            .find_map(|raw| keys.iter().find_map(|key| unlock(&raw, key)))
        {
            out.push(Payload {
                source: body,
                offset: literal.start(),
            });
        }
    }
    out
}

/// `raw` XOR'd with `key` cyclically and zlib-decompressed, when that yields
/// non-empty UTF-8.
fn unlock(raw: &[u8], key: &[u8]) -> Option<String> {
    let xored: Vec<u8> = raw
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect();
    let mut body = String::new();
    flate2::read::ZlibDecoder::new(xored.as_slice())
        .take(MAX_SOURCE)
        .read_to_string(&mut body)
        .ok()?;
    (!body.trim().is_empty()).then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// RFC 1924 base85, the inverse of [`crate::base85::decode_rfc1924`].
    fn b85(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        let mut out = String::new();
        for chunk in data.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            let mut acc = u32::from_be_bytes(word);
            let mut digits = [0u8; 5];
            for d in digits.iter_mut().rev() {
                *d = ALPHABET[(acc % 85) as usize];
                acc /= 85;
            }
            out.push_str(std::str::from_utf8(&digits[..=chunk.len()]).unwrap());
        }
        out
    }

    /// A module armored the way the BoxLink protector ships one.
    fn armored(body: &str, key: &[u8]) -> String {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(body.as_bytes()).unwrap();
        let xored: Vec<u8> = z
            .finish()
            .unwrap()
            .iter()
            .zip(key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        let payload = b85(&xored);
        let wrapped: Vec<&str> = payload
            .as_bytes()
            .chunks(90)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "import base64 as _b, zlib as _z\n_K = b'{}'\n_P = '''{}'''\n\
             _D = _b.b85decode(_P.replace('\\n', ''))\n\
             _C = _z.decompress(bytes(_v ^ _K[_i % len(_K)] for _i, _v in enumerate(_D)))\n\
             exec(compile(_C, '<armor>', 'exec'), globals())\n",
            std::str::from_utf8(key).unwrap(),
            wrapped.join("\\\n")
        )
    }

    #[test]
    fn recovers_a_keyed_xor_zlib_module() {
        let body = "import subprocess\nsubprocess.run(['whoami'])\n".repeat(4);
        let host = armored(&body, b"FIXTURE_ARMOR_KEY_v1");
        let found = decode(&host);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].source, body);
        assert!(
            host[..found[0].offset].ends_with("_P = '''"),
            "the offset points at the payload literal"
        );
    }

    #[test]
    fn a_wrong_key_recovers_nothing() {
        let body = "print('hello')\n".repeat(8);
        let host = armored(&body, b"FIXTURE_ARMOR_KEY_v1")
            .replace("FIXTURE_ARMOR_KEY_v1", "SOME_OTHER_KEY_TEXT1");
        assert!(decode(&host).is_empty());
    }

    #[test]
    fn plain_source_is_skipped() {
        assert!(decode("x = b'abcdefgh'\nprint('a' * 100)\n").is_empty());
    }
}
