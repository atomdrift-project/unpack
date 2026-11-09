//! Static decoding for encrypted Allaire ColdFusion templates.
//!
//! ColdFusion's historical template encoder wraps source in a fixed header,
//! then DES-ECB encrypts the template body with a public, built-in key. This
//! is obfuscation rather than a security boundary, so decode it only in
//! memory and pass the recovered source through the normal analysis pipeline.

use des::Des;
use des::cipher::{Block, BlockDecrypt, KeyInit};

const HEADER: &[u8] = b"Allaire Cold Fusion Template\nHeader Size: ";
const NEW_VERSION: &[u8] = b"New Version";
const NEW_VERSION_HEADER_SIZE: usize = 69;
const DES_KEY: [u8; 8] = [0x62, 0x31, 0xef, 0xba, 0x16, 0x31, 0xe0, 0x15];
const MAX_ENCRYPTED_TEMPLATE_SIZE: usize = 64 * 1024 * 1024;

/// Decrypt a recognized Allaire ColdFusion template without executing it.
///
/// Returns `None` for non-templates, malformed headers, oversized inputs, or
/// New Version templates missing their decrypted header terminator.
#[must_use]
pub fn decrypt_template(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > MAX_ENCRYPTED_TEMPLATE_SIZE || !bytes.starts_with(HEADER) {
        return None;
    }

    let (header_size, mut skip_template_header) =
        if bytes.get(HEADER.len()..)?.starts_with(NEW_VERSION) {
            (NEW_VERSION_HEADER_SIZE, true)
        } else {
            let remainder = bytes.get(HEADER.len()..)?;
            let digits = remainder
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 {
                return None;
            }
            let size = std::str::from_utf8(remainder.get(..digits)?)
                .ok()?
                .parse()
                .ok()?;
            (size, false)
        };

    if header_size < HEADER.len() + 1 || header_size >= bytes.len() {
        return None;
    }

    let encrypted = bytes.get(header_size..)?;
    let (blocks, tail) = encrypted.as_chunks::<8>();
    if blocks.is_empty() {
        return None;
    }
    let full_len = blocks.len() * 8;

    let cipher = Des::new_from_slice(&DES_KEY).ok()?;
    let mut decoded = Vec::with_capacity(encrypted.len());
    let mut found_template_header_end = !skip_template_header;

    for chunk in blocks {
        let mut block = Block::<Des>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for byte in block {
            if skip_template_header {
                if byte == 0x1a {
                    skip_template_header = false;
                    found_template_header_end = true;
                }
            } else {
                decoded.push(byte);
            }
        }
    }

    if !found_template_header_end {
        return None;
    }

    // The original encoder XORs a final partial block with its byte offset
    // instead of applying DES to it. Preserve that format behavior.
    for (index, byte) in tail.iter().enumerate() {
        decoded.push(byte ^ full_len.wrapping_add(index).to_le_bytes()[0]);
    }

    (!decoded.is_empty()).then_some(decoded)
}
