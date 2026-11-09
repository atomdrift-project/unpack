//! Bounded recovery of encoded and XOR-obfuscated inline scripts in Mach-O
//! string and constant sections. A static transform: it never executes the
//! input, and accepts a result only when it is a complete
//! `osascript -e '…'` invocation.

use crate::image;
use crate::macho_integer_tables::{Text, inline_applescript};
use crate::primitives::{rc4, unhex};

/// Largest section any recoverer reads.
const MAX_SECTION: usize = 4 * 1024 * 1024;
/// RC4 bytes produced per file, across every section, payload and key.
const RC4_BUDGET: usize = 64 * 1024 * 1024;
/// Largest input any recoverer reads.
const MAX_INPUT: usize = 32 * 1024 * 1024;

/// Each section's name, file offset and bytes, for sections of at most
/// [`MAX_SECTION`] bytes. A range is returned once even when several section
/// headers alias it, so a hostile header list cannot multiply the work.
fn sections(data: &[u8]) -> Vec<(String, usize, &[u8])> {
    if data.len() > MAX_INPUT {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    image::macho(data)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.size <= MAX_SECTION && seen.insert((s.offset, s.size)))
        .filter_map(|s| Some((s.name.clone(), s.offset, s.bytes(data)?)))
        .collect()
}

/// Each NUL-terminated string in `data` with its offset.
fn c_strings(data: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut pos = 0;
    data.split(|&c| c == 0).map(move |part| {
        let offset = pos;
        pos += part.len() + 1;
        (offset, part)
    })
}

fn recover_strings(data: &[u8], base: usize, budget: &mut usize) -> Vec<Text> {
    let mut keys = Vec::new();
    let mut payloads = Vec::new();
    for (offset, part) in c_strings(data) {
        if !part.iter().all(u8::is_ascii_hexdigit) || !part.len().is_multiple_of(2) {
            continue;
        }
        if (16..=128).contains(&part.len()) && keys.len() < 32 {
            keys.extend(unhex(part));
        } else if (1024..=2 * 1024 * 1024).contains(&part.len())
            && payloads.len() < 8
            && let Some(cipher) = unhex(part)
        {
            payloads.push((offset, cipher));
        }
    }
    let mut result = Vec::new();
    for (offset, cipher) in payloads {
        for key in &keys {
            let Some(left) = budget.checked_sub(cipher.len()) else {
                tracing::debug!(
                    offset = base + offset,
                    "Mach-O hex/RC4 search hit its work budget"
                );
                return result;
            };
            *budget = left;
            let plain = rc4(&cipher, key);
            if std::str::from_utf8(&plain).is_ok_and(|text| inline_applescript(text).is_some()) {
                result.push(Text {
                    data: plain,
                    offset: base + offset,
                });
                break;
            }
        }
    }
    result
}

/// Scripts stored as hex RC4 ciphertext in `__cstring`, with the hex key
/// stored beside them.
#[must_use]
pub fn recover(data: &[u8]) -> Vec<Text> {
    let mut budget = RC4_BUDGET;
    sections(data)
        .into_iter()
        .filter(|(name, _, _)| name.ends_with("__cstring"))
        .flat_map(|(_, start, bytes)| recover_strings(bytes, start, &mut budget))
        .collect()
}

/// Unpadded base64 over `alphabet` (64 distinct printable bytes).
#[expect(
    clippy::indexing_slicing,
    reason = "a 256-entry table indexed by a byte"
)]
fn custom_base64(data: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    if alphabet.len() != 64 {
        return None;
    }
    let mut map = [u8::MAX; 256];
    for (i, &b) in alphabet.iter().enumerate() {
        if !(33..=126).contains(&b) || map[usize::from(b)] != u8::MAX {
            return None;
        }
        map[usize::from(b)] = u8::try_from(i).ok()?;
    }
    let (mut acc, mut bits) = (0u32, 0u8);
    let mut out = Vec::new();
    for &b in data {
        let v = map[usize::from(b)];
        if v == u8::MAX {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
        }
    }
    Some(out)
}

/// The decoded script, when `encoded` decodes over one of `alphabets` to a
/// complete inline AppleScript invocation.
fn decode_script(encoded: &[u8], alphabets: &[&[u8]]) -> Option<Vec<u8>> {
    alphabets.iter().find_map(|alphabet| {
        let decoded = custom_base64(encoded, alphabet)?;
        std::str::from_utf8(&decoded)
            .ok()
            .and_then(inline_applescript)?;
        Some(decoded)
    })
}

fn recover_custom_strings(data: &[u8], base: usize) -> Vec<Text> {
    let mut alphabets: Vec<&[u8]> = Vec::new();
    let mut payloads = Vec::new();
    for (offset, part) in c_strings(data) {
        if part.len() == 64 && alphabets.len() < 16 && custom_base64(b"", part).is_some() {
            alphabets.push(part);
        } else if (1024..=2 * 1024 * 1024).contains(&part.len())
            && payloads.len() < 8
            && part.iter().all(u8::is_ascii_hexdigit)
            && let Some(bytes) = unhex(part)
        {
            payloads.push((offset, bytes));
        }
    }
    let mut out: Vec<Text> = payloads
        .into_iter()
        .filter_map(|(offset, encoded)| {
            Some(Text {
                data: decode_script(&encoded, &alphabets)?,
                offset: base + offset,
            })
        })
        .collect();
    // Some launchers store consecutive slices of the encoded text as
    // separate C strings. Reassemble a bounded run in file order; accept a
    // result only when the complete interpreter wrapper is recovered.
    let mut joined = Vec::new();
    let mut run_start = 0usize;
    let mut count = 0usize;
    for (offset, part) in c_strings(data) {
        if part.len() > 512
            || part.len() < 2
            || (part.len() < 128 && count == 0)
            || !part.iter().all(u8::is_ascii_hexdigit)
        {
            joined.clear();
            count = 0;
            continue;
        }
        if count == 0 {
            run_start = offset;
        }
        count += 1;
        if count > 512 || joined.len() + part.len() > 2 * 1024 * 1024 {
            break;
        }
        joined.extend_from_slice(part);
        if count < 4 || !joined.len().is_multiple_of(2) {
            continue;
        }
        let Some(encoded) = unhex(&joined) else {
            continue;
        };
        // Decode a short prefix before the whole run.
        let head = encoded.get(..encoded.len().min(32)).unwrap_or_default();
        let plausible: Vec<&[u8]> = alphabets
            .iter()
            .copied()
            .filter(|alphabet| {
                custom_base64(head, alphabet).is_some_and(|p| p.starts_with(b"osascript -e '"))
            })
            .collect();
        if let Some(decoded) = decode_script(&encoded, &plausible) {
            out.push(Text {
                data: decoded,
                offset: base + run_start,
            });
            return out;
        }
    }
    out
}

/// Scripts stored as hex text in a file-supplied base64 alphabet in
/// `__cstring`, whole or split across consecutive strings.
#[must_use]
pub fn recover_custom(data: &[u8]) -> Vec<Text> {
    sections(data)
        .into_iter()
        .filter(|(name, _, _)| name.ends_with("__cstring"))
        .flat_map(|(_, start, bytes)| recover_custom_strings(bytes, start))
        .collect()
}

fn decode_lcg(cipher: &[u8], seed: u32, multiplier: u32, modulus: u32) -> Option<Vec<u8>> {
    if modulus == 0 || cipher.len() > 1024 * 1024 {
        return None;
    }
    let mut state = seed;
    let mut out = Vec::with_capacity(cipher.len());
    for &b in cipher {
        let byte = b ^ state.to_le_bytes()[0];
        if byte == 0 {
            break;
        }
        out.push(byte);
        state = state.wrapping_mul(multiplier) % modulus;
    }
    std::str::from_utf8(&out)
        .ok()
        .and_then(inline_applescript)?;
    Some(out)
}

/// Most multiplier or modulus candidates tried.
const MAX_CANDIDATES: usize = 4;

/// Add `n` to `found` unless it is there already or `found` is full.
fn candidate(found: &mut Vec<u32>, n: u32) {
    if found.len() < MAX_CANDIDATES && !found.contains(&n) {
        found.push(n);
    }
}

/// x86 multiply-immediates followed by a store and a division: candidate
/// LCG multipliers.
fn multipliers(code: &[u8], found: &mut Vec<u32>) {
    for w in code.array_windows::<29>() {
        if found.len() == MAX_CANDIDATES {
            return;
        }
        if let [
            0x69,
            0x45,
            _,
            a,
            b,
            c,
            d,
            0x89,
            0x45,
            _,
            0xe8,
            _,
            _,
            _,
            _,
            0x89,
            0xc1,
            _,
            _,
            _,
            0x31,
            0xd2,
            0xf7,
            0xf1,
            ..,
        ] = *w
            && let n @ 2.. = u32::from_le_bytes([a, b, c, d])
        {
            candidate(found, n);
        }
    }
}

/// `HH:MM:SS` strings: candidate LCG moduli (seconds past midnight).
fn moduli(strings: &[u8], found: &mut Vec<u32>) {
    for w in strings.array_windows::<9>() {
        if found.len() == MAX_CANDIDATES {
            return;
        }
        let [h1, h2, b':', m1, m2, b':', s1, s2, 0] = *w else {
            continue;
        };
        let digits = [h1, h2, m1, m2, s1, s2];
        if !digits.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let [h1, h2, m1, m2, s1, s2] = digits.map(|d| u32::from(d - b'0'));
        let (hour, minute, second) = (h1 * 10 + h2, m1 * 10 + m2, s1 * 10 + s2);
        if hour < 24 && minute < 60 && second < 60 && hour + minute + second > 0 {
            candidate(found, hour * 3600 + minute * 60 + second);
        }
    }
}

/// A script XOR-ed with a multiplicative LCG stream in `__const`, seeded by
/// the section's first word; multiplier and modulus come from the code and
/// strings.
#[must_use]
pub fn recover_lcg(data: &[u8]) -> Vec<Text> {
    let sections = sections(data);
    let mut multiplier_candidates = Vec::new();
    let mut modulus_candidates = Vec::new();
    for (name, _, bytes) in &sections {
        if name.ends_with("__text") {
            multipliers(bytes, &mut multiplier_candidates);
        } else if name.ends_with("__cstring") {
            moduli(bytes, &mut modulus_candidates);
        }
    }
    for (name, start, bytes) in &sections {
        if !name.ends_with("__const") || !(1024..=1024 * 1024).contains(&bytes.len()) {
            continue;
        }
        let Some((seed, cipher)) = bytes.split_first_chunk::<4>() else {
            continue;
        };
        let seed = u32::from_le_bytes(*seed);
        for &m in &multiplier_candidates {
            for &n in &modulus_candidates {
                if let Some(plain) = decode_lcg(cipher, seed, m, n) {
                    return vec![Text {
                        data: plain,
                        offset: start + 4,
                    }];
                }
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho_integer_tables::tests::encode;

    #[test]
    fn custom_alphabet_recovery_and_controls() {
        let standard = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let alphabet: Vec<u8> = standard.iter().copied().rev().collect();
        let plain = format!("osascript -e '{}{}'", "x".repeat(600), "hello");
        let custom = encode(plain.as_bytes(), &alphabet);
        let hex = hex::encode(&custom);
        let input = [alphabet.as_slice(), b"\0", hex.as_bytes(), b"\0"].concat();
        let found = recover_custom_strings(&input, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, plain.as_bytes());
        assert!(custom_base64(&custom, &[b'A'; 64]).is_none());
        assert!(custom_base64(b"invalid?", standard).is_none());
        let mut split = Vec::new();
        for chunk in hex.as_bytes().chunks(137) {
            split.extend_from_slice(chunk);
            split.push(0);
        }
        split.extend_from_slice(&alphabet);
        split.push(0);
        let split_found = recover_custom_strings(&split, 0);
        assert_eq!(split_found.len(), 1);
        assert_eq!(split_found[0].data, plain.as_bytes());
        split[10] = b'Z';
        assert!(recover_custom_strings(&split, 0).is_empty());
    }

    #[test]
    fn lcg_stream_recovery_and_wrong_key() {
        let seed = 123_456u32;
        let multiplier = 14213u32;
        let modulus = 70129u32;
        let plain = format!("osascript -e '{}{}'", "x".repeat(600), "hello");
        let mut state = seed;
        let mut cipher = Vec::new();
        for byte in plain.bytes().chain(std::iter::once(0)) {
            cipher.push(byte ^ state as u8);
            state = state.wrapping_mul(multiplier) % modulus;
        }
        assert_eq!(
            decode_lcg(&cipher, seed, multiplier, modulus).unwrap(),
            plain.as_bytes()
        );
        assert!(decode_lcg(&cipher, seed + 1, multiplier, modulus).is_none());
        let mut found = Vec::new();
        moduli(b"x\x0019:28:49\0", &mut found);
        moduli(b"24:00:00\0", &mut found);
        assert_eq!(found, [70129]);
        let mut code = vec![0u8; 29];
        code[..2].copy_from_slice(&[0x69, 0x45]);
        code[3..7].copy_from_slice(&multiplier.to_le_bytes());
        code[7..9].copy_from_slice(&[0x89, 0x45]);
        code[10] = 0xe8;
        code[15..17].copy_from_slice(&[0x89, 0xc1]);
        code[20..24].copy_from_slice(&[0x31, 0xd2, 0xf7, 0xf1]);
        let mut found = Vec::new();
        multipliers(&code, &mut found);
        assert_eq!(found, [multiplier]);
    }

    #[test]
    fn recover_and_reject_near_misses() {
        let key = b"different-key-01";
        let plain = b"osascript -e 'display dialog \"hello\"'";
        let cipher = rc4(plain, key);
        let long_plain = format!("osascript -e '{}{}'", "x".repeat(512), "hello");
        let long_cipher = rc4(long_plain.as_bytes(), key);
        let input = format!("{}\0{}\0", hex::encode(key), hex::encode(&long_cipher));
        let found = recover_strings(input.as_bytes(), 0, &mut { RC4_BUDGET });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, long_plain.as_bytes());
        assert!(
            recover_strings(input.as_bytes(), 0, &mut 16).is_empty(),
            "an exhausted budget stops the search"
        );
        let wrong = format!(
            "{}\0{}\0",
            hex::encode(b"wrong-key-123456"),
            hex::encode(&long_cipher)
        );
        assert!(recover_strings(wrong.as_bytes(), 0, &mut { RC4_BUDGET }).is_empty());
        let short = format!("{}\0{}\0", hex::encode(key), hex::encode(&cipher));
        assert!(recover_strings(short.as_bytes(), 0, &mut { RC4_BUDGET }).is_empty());
        assert!(
            recover(b"").is_empty()
                && recover_custom(b"").is_empty()
                && recover_lcg(b"").is_empty()
        );
    }
}
