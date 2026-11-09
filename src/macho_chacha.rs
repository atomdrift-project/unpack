//! Authenticate and recover a code-integrity-bound Mach-O script envelope.
//!
//! Recognition uses the x86-64 nonce construction and three indexed pointer
//! tables, not file hashes, addresses, keys, domains, or plaintext signatures.
//! All variable inputs come from the file. Nothing from the file is executed.
//! Unsupported layouts and failed authentication produce no recovered payload.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};

use crate::image::{self, Section, file_offset};

/// One fully authenticated compiled script and its encrypted origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// The compiled AppleScript (`Fasd…`).
    pub data: Vec<u8>,
    /// Where the first encrypted segment starts in the input.
    pub offset: usize,
    /// How many AEAD segments it was split into.
    pub segments: usize,
    /// The PBKDF2 iteration count that derived its key.
    pub iterations: u32,
}

fn range(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(size)?)
}

fn address_offset(sections: &[Section], address: u64) -> Option<usize> {
    file_offset(sections, address, 1)
}

fn pointer(data: &[u8], sections: &[Section], offset: usize) -> Option<usize> {
    let address = u64::from_le_bytes(*range(data, offset, 8)?.first_chunk()?);
    address_offset(sections, address)
}

fn rip_target(code: &[u8], code_va: u64, pos: usize) -> Option<u64> {
    let displacement = i32::from_le_bytes(*range(code, pos.checked_add(3)?, 4)?.first_chunk()?);
    code_va
        .checked_add(u64::try_from(pos.checked_add(7)?).ok()?)?
        .checked_add_signed(i64::from(displacement))
}

/// HMAC-SHA256.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let hashed;
    let key = if key.len() > 64 {
        hashed = Sha256::digest(key);
        hashed.as_slice()
    } else {
        key
    };
    let mut padded = [0u8; 64];
    for (slot, &byte) in padded.iter_mut().zip(key) {
        *slot = byte;
    }
    let mut inner = Sha256::new();
    inner.update(padded.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(padded.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// One-block PBKDF2-HMAC-SHA256.
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut input = salt.to_vec();
    input.extend_from_slice(&1u32.to_be_bytes());
    let mut current = hmac(password, &input);
    let mut result = current;
    for _ in 1..iterations {
        current = hmac(password, &current);
        for (out, next) in result.iter_mut().zip(current) {
            *out ^= next;
        }
    }
    result
}

/// One-block HKDF-SHA256 with a zero salt, truncated to a nonce.
fn nonce(key: &[u8], info: &[u8]) -> [u8; 12] {
    let prk = hmac(&[0u8; 32], key);
    let mut input = info.to_vec();
    input.push(1);
    let expanded = hmac(&prk, &input);
    let mut result = [0; 12];
    for (slot, byte) in result.iter_mut().zip(expanded) {
        *slot = byte;
    }
    result
}

/// The instruction layout that stores a nonce and loads the three tables:
/// the segment count and the nonce's info bytes, read from operands.
fn nonce_site(window: &[u8; 180]) -> Option<(usize, [u8; 17])> {
    let matches = window.starts_with(&[0x48, 0xb8])
        && window.get(10..14) == Some(&[0x4c, 0x8d, 0x84, 0x24])
        && window.get(18..24) == Some(&[0x49, 0x89, 0x40, 0x05, 0x48, 0xb8])
        && window.get(32..35) == Some(&[0x49, 0x89, 0x00])
        && window.get(35..51)
            == Some(&[
                0x66, 0x41, 0xc7, 0x40, 0x0d, 0, 0, 0x41, 0xc6, 0x40, 0x0f, 0, 0x41, 0x88, 0x68,
                0x10,
            ])
        && window.get(107..110) == Some(&[0x48, 0x8d, 0x05])
        && window.get(119..122) == Some(&[0x48, 0x8d, 0x05])
        && window.get(131..134) == Some(&[0x48, 0x8d, 0x05])
        && window.get(171..174) == Some(&[0x48, 0x83, 0xfd]);
    if !matches {
        return None;
    }
    let count = usize::from(*window.get(174)?);
    if !(1..=32).contains(&count) {
        return None;
    }
    let mut info = [0u8; 17];
    info.get_mut(5..13)?.copy_from_slice(window.get(2..10)?);
    info.get_mut(..8)?.copy_from_slice(window.get(24..32)?);
    Some((count, info))
}

/// Recover only envelopes whose every AEAD tag validates, within fixed
/// bounds: a 32 MiB file, a 2 MiB `__text`, at most four scripts.
#[must_use]
pub fn recover(data: &[u8]) -> Vec<Script> {
    let mut recovered = Vec::new();
    if data.len() > 32 * 1024 * 1024 {
        return recovered;
    }
    let Some(sections) = image::macho(data) else {
        return recovered;
    };
    let Some(text) = sections.iter().find(|s| s.name.ends_with("__text")) else {
        return recovered;
    };
    let Some(code) = text
        .bytes(data)
        .filter(|code| code.len() <= 2 * 1024 * 1024)
    else {
        return recovered;
    };
    let digest = Sha256::digest(code);
    // The envelope stores the live text digest after its eight-byte root seed
    // and alignment padding. Require code references to both root and salt.
    let Some(digest_offset) = data.windows(32).position(|w| w == digest.as_slice()) else {
        return recovered;
    };
    let (Some(root_offset), Some(salt_offset)) =
        (digest_offset.checked_sub(32), digest_offset.checked_add(64))
    else {
        return recovered;
    };
    let (Some(root), Some(salt)) = (
        range(data, root_offset, 4)
            .and_then(<[u8]>::first_chunk)
            .map(|b| u32::from_le_bytes(*b)),
        range(data, salt_offset, 32),
    ) else {
        return recovered;
    };
    let mut has_root = false;
    let mut has_salt = false;
    let mut iteration_candidates = Vec::new();
    for pos in 0..code.len().saturating_sub(8) {
        let Some(head) = code.get(pos..pos + 8) else {
            break;
        };
        if head.starts_with(&[0x48, 0x8b, 0x15]) {
            has_root |= rip_target(code, text.vaddr, pos)
                .and_then(|va| address_offset(&sections, va))
                == Some(root_offset);
        }
        if head.starts_with(&[0x0f, 0x28, 0x05]) {
            has_salt |= rip_target(code, text.vaddr, pos)
                .and_then(|va| address_offset(&sections, va))
                == Some(salt_offset);
        }
        if let Some((&[0xff, 0xc5, 0x81, 0xfd], immediate)) = head.split_first_chunk::<4>()
            && let Some(bytes) = immediate.first_chunk::<4>()
        {
            let iterations = u32::from_le_bytes(*bytes);
            if (1..=250_000).contains(&iterations) && !iteration_candidates.contains(&iterations) {
                iteration_candidates.push(iterations);
            }
        }
    }
    if !has_root || !has_salt || iteration_candidates.is_empty() || iteration_candidates.len() > 4 {
        return recovered;
    }
    let mut password = [0u8; 36];
    for (slot, byte) in password.iter_mut().zip(root.to_be_bytes()) {
        *slot = byte;
    }
    let keys: Vec<_> = iteration_candidates
        .iter()
        .map(|&i| (i, derive_key(&password, salt, i)))
        .collect();
    // Literal nonce stores, followed by three RIP-relative indexed tables.
    // Layout offsets describe instruction operands, never sample file offsets.
    for (pos, window) in code.array_windows::<180>().enumerate() {
        let Some((count, mut info)) = nonce_site(window) else {
            continue;
        };
        let tables = [107, 119, 131].map(|offset| {
            rip_target(code, text.vaddr, pos + offset).and_then(|va| address_offset(&sections, va))
        });
        let [Some(cipher_table), Some(length_table), Some(tag_table)] = tables else {
            continue;
        };
        let tables = Tables {
            cipher: cipher_table,
            length: length_table,
            tag: tag_table,
            count,
        };
        for &(iterations, key) in &keys {
            let Some(payload) = decrypt_segments(data, &sections, &key, &mut info, &tables) else {
                continue;
            };
            if payload.starts_with(b"Fasd")
                && let Some(offset) = pointer(data, &sections, cipher_table)
            {
                recovered.push(Script {
                    data: payload,
                    offset,
                    segments: count,
                    iterations,
                });
            }
        }
        if recovered.len() >= 4 {
            break;
        }
    }
    tracing::debug!(
        scripts = recovered.len(),
        "Mach-O ChaCha20 envelope search done"
    );
    recovered
}

/// File offsets of the three indexed tables and how many entries each has.
struct Tables {
    cipher: usize,
    length: usize,
    tag: usize,
    count: usize,
}

fn decrypt_segments(
    data: &[u8],
    sections: &[Section],
    key: &[u8; 32],
    info: &mut [u8; 17],
    tables: &Tables,
) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut result = Vec::new();
    for index in 0..tables.count {
        let delta = index.checked_mul(8)?;
        let cp = pointer(data, sections, tables.cipher.checked_add(delta)?)?;
        let tp = pointer(data, sections, tables.tag.checked_add(delta)?)?;
        let size =
            u64::from_le_bytes(*range(data, tables.length.checked_add(delta)?, 8)?.first_chunk()?);
        let size = usize::try_from(size).ok()?;
        if size == 0 || result.len().checked_add(size)? > 8 * 1024 * 1024 {
            return None;
        }
        let mut chunk = range(data, cp, size)?.to_vec();
        chunk.extend_from_slice(range(data, tp, 16)?);
        *info.last_mut()? = u8::try_from(index).ok()?;
        let n = nonce(key, info);
        result.extend_from_slice(
            &cipher
                .decrypt(Nonce::from_slice(&n), chunk.as_slice())
                .ok()?,
        );
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdfs_match_published_vectors() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex::encode(hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 7914 §11: PBKDF2-HMAC-SHA256("passwd", "salt", 1), first block.
        assert_eq!(
            hex::encode(derive_key(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
    }

    #[test]
    fn non_images_and_unmatched_code_recover_nothing() {
        assert!(recover(b"").is_empty());
        assert!(recover(&[0u8; 4096]).is_empty());
        assert!(recover(&crate::image::tests::macho64()).is_empty());
    }
}
