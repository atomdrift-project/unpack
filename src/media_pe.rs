//! PE images hidden in media files: as one contiguous Base64 run, or under
//! a single-byte XOR key. A candidate needs a structurally plausible DOS,
//! COFF and optional header before any larger body is decoded, and both
//! the work and the retained bytes are bounded.
//!
//! These searches assume an image, audio or similar carrier; the caller
//! chooses which files to run them on.

use base64::{Engine as _, engine::general_purpose};

/// A PE image recovered from a media file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Where its encoded form starts in the input.
    pub offset: usize,
    /// The decoded PE.
    pub data: Vec<u8>,
}

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_CANDIDATES: usize = 32;

/// Whether `data` opens with DOS, COFF and optional headers a loader would
/// accept, and holds the whole section table.
fn plausible_pe_header(data: &[u8]) -> bool {
    fn le16(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(*b.get(at..)?.first_chunk()?))
    }
    let check = || -> Option<bool> {
        if !data.starts_with(b"MZ") {
            return Some(false);
        }
        let offset = usize::try_from(u32::from_le_bytes(*data.get(60..)?.first_chunk()?)).ok()?;
        if !(64..=4096).contains(&offset) || data.get(offset..offset + 4)? != b"PE\0\0" {
            return Some(false);
        }
        let machine = le16(data, offset + 4)?;
        let sections = usize::from(le16(data, offset + 6)?);
        let optional_size = usize::from(le16(data, offset + 20)?);
        if !matches!(machine, 0x014c | 0x8664 | 0xaa64)
            || !(1..=96).contains(&sections)
            || optional_size < 96
        {
            return Some(false);
        }
        let optional = offset + 24;
        Some(
            matches!(le16(data, optional)?, 0x10b | 0x20b)
                && data.len() >= optional + optional_size + sections * 40,
        )
    };
    check().unwrap_or(false)
}

/// Contiguous Base64 PE images (`TV[o-r]…`) of 512 bytes to 16 MiB of text.
/// String decoders return text, so binary output would otherwise vanish
/// before analysis.
#[must_use]
pub fn base64_pes(data: &[u8]) -> Vec<Image> {
    const MAX_ENCODED: usize = 16 * 1024 * 1024;
    const MIN_ENCODED: usize = 512;
    if data.len() > MAX_INPUT {
        return Vec::new();
    }
    let is_base64 = |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/');
    let starts = memchr::memmem::find_iter(data, b"TV")
        .filter(|&offset| {
            !offset
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_some_and(is_base64)
                && data
                    .get(offset + 2)
                    .is_some_and(|b| matches!(b, b'o' | b'p' | b'q' | b'r'))
        })
        .take(MAX_CANDIDATES);
    let mut out = Vec::new();
    for offset in starts {
        let Some(tail) = data.get(offset..) else {
            continue;
        };
        // The run, then its padding, each bounded by the encoded limit.
        let limit = MAX_ENCODED + 1;
        let body = tail.iter().take(limit).take_while(|b| is_base64(b)).count();
        let padding = tail
            .iter()
            .skip(body)
            .take(limit.saturating_sub(body))
            .take_while(|&&b| b == b'=')
            .count();
        let Some(candidate) = tail.get(..body + padding) else {
            continue;
        };
        if !(MIN_ENCODED..=MAX_ENCODED).contains(&candidate.len()) {
            continue;
        }
        // Check a bounded prefix first, avoiding multi-megabyte allocations
        // for ordinary text that merely begins with a PE-like Base64 prefix.
        let prefix_len = candidate.len().min(8192) / 4 * 4;
        let Some(prefix) = candidate
            .get(..prefix_len)
            .and_then(|p| general_purpose::STANDARD.decode(p).ok())
        else {
            continue;
        };
        if !plausible_pe_header(&prefix) {
            continue;
        }
        let Ok(decoded) = general_purpose::STANDARD
            .decode(candidate)
            .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(candidate))
        else {
            continue;
        };
        if plausible_pe_header(&decoded) {
            out.push(Image {
                offset,
                data: decoded,
            });
        }
    }
    out
}

/// PE images under a single-byte XOR key, found by their DOS prefix and
/// decoded to the end of the input, at most 16 MiB each.
#[must_use]
pub fn xor_pes(data: &[u8]) -> Vec<Image> {
    const MAX_OUTPUT: usize = 16 * 1024 * 1024;
    if data.len() > MAX_INPUT {
        return Vec::new();
    }
    let candidates =
        data.array_windows::<4>()
            .enumerate()
            .filter_map(|(offset, &[m, z, third, fourth])| {
                let key = m ^ b'M';
                (key != 0
                    && z ^ key == b'Z'
                    && matches!(third ^ key, 0x90 | 0x00)
                    && fourth ^ key == 0)
                    .then_some((offset, key))
            });
    let mut out = Vec::new();
    for (offset, key) in candidates.take(MAX_CANDIDATES) {
        let Some(source) = data.get(offset..).filter(|s| s.len() <= MAX_OUTPUT) else {
            continue;
        };
        let prefix: Vec<u8> = source.iter().take(8192).map(|byte| byte ^ key).collect();
        if !plausible_pe_header(&prefix) {
            continue;
        }
        let decoded: Vec<u8> = source.iter().map(|byte| byte ^ key).collect();
        if plausible_pe_header(&decoded) {
            out.push(Image {
                offset,
                data: decoded,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest image `plausible_pe_header` accepts: one section.
    fn pe() -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        b[..4].copy_from_slice(b"MZ\x90\0");
        b[60..64].copy_from_slice(&128u32.to_le_bytes());
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        b[134..136].copy_from_slice(&1u16.to_le_bytes());
        b[148..150].copy_from_slice(&224u16.to_le_bytes());
        b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        b
    }

    #[test]
    fn base64_image_in_media_bytes() {
        let encoded = general_purpose::STANDARD.encode(pe());
        let media = [
            b"\x89PNG\r\n\x1a\n\0\0".as_slice(),
            encoded.as_bytes(),
            b"\0IEND",
        ]
        .concat();
        assert_eq!(
            base64_pes(&media),
            [Image {
                offset: 10,
                data: pe()
            }]
        );
        // Preceded by more Base64, the run is not a standalone image.
        let glued = [b"AAAA".as_slice(), encoded.as_bytes()].concat();
        assert!(base64_pes(&glued).is_empty());
        let mut broken = pe();
        broken[152] = 0;
        let broken = general_purpose::STANDARD.encode(broken);
        assert!(base64_pes(broken.as_bytes()).is_empty());
    }

    #[test]
    fn xor_image_in_media_bytes() {
        let key = 0x5a;
        let mut media = b"GIF89a....".to_vec();
        media.extend(pe().iter().map(|b| b ^ key));
        assert_eq!(
            xor_pes(&media),
            [Image {
                offset: 10,
                data: pe()
            }]
        );
        assert!(xor_pes(&pe()).is_empty(), "a zero key is not an encoding");
        media.truncate(300);
        assert!(xor_pes(&media).is_empty());
    }
}
