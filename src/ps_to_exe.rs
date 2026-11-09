//! Recover PowerShell-to-EXE converter resources without executing the stub.
//!
//! Recognize the converter's negated runtime vocabulary, derive candidate
//! RC4 keys from code-referenced eight-byte seeds, and inspect `RT_RCDATA`
//! only. Addresses, resource names, keys, and script contents are never
//! pinned.

use md5::{Digest, Md5};

use crate::image::{self, Section, file_offset};
use crate::primitives::rc4;

/// A PowerShell script recovered from a converter resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// The script text.
    pub data: Vec<u8>,
    /// Where its encrypted resource starts in the input.
    pub offset: usize,
}

fn range(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(size)?)
}

fn u16_at(data: &[u8], offset: usize) -> Option<usize> {
    Some(usize::from(u16::from_le_bytes(
        *range(data, offset, 2)?.first_chunk()?,
    )))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*range(data, offset, 4)?.first_chunk()?))
}

fn rva_offset(sections: &[Section], rva: u64) -> Option<usize> {
    file_offset(sections, rva, 1)
}

/// Whether `data` holds `plain` with every byte negated.
fn marker(data: &[u8], plain: &[u8]) -> bool {
    data.windows(plain.len())
        .any(|w| w.iter().zip(plain).all(|(&a, &b)| a == b.wrapping_neg()))
}

/// Walk the type/name/language hierarchy below `off`, collecting
/// `RT_RCDATA` leaves of 64 bytes to 4 MiB as (RVA, length).
fn walk(
    table: &[u8],
    off: usize,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(u32, usize)>,
) -> Option<()> {
    let count =
        u16_at(table, off.checked_add(12)?)?.checked_add(u16_at(table, off.checked_add(14)?)?)?;
    *budget = budget.checked_sub(count)?;
    let entries = off.checked_add(16)?;
    range(table, entries, count.checked_mul(8)?)?;
    for i in 0..count {
        let entry = entries.checked_add(i.checked_mul(8)?)?;
        let name = u32_at(table, entry)?;
        let target = u32_at(table, entry.checked_add(4)?)?;
        if depth == 0 && name != 10 {
            continue;
        }
        let rel = usize::try_from(target & 0x7fff_ffff).ok()?;
        let directory = target & 0x8000_0000 != 0;
        if depth < 2 && directory {
            walk(table, rel, depth + 1, budget, out)?;
        } else if depth == 2 && !directory {
            let rva = u32_at(table, rel)?;
            let len = usize::try_from(u32_at(table, rel.checked_add(4)?)?).ok()?;
            if (64..=4 * 1024 * 1024).contains(&len) {
                out.push((rva, len));
            }
        }
    }
    Some(())
}

/// The `RT_RCDATA` resources in the directory at file offset `root`, as
/// (file offset, length), within a shared entry and byte budget. Directory
/// offsets are relative to the root; data RVAs map through `sections`.
fn resources(data: &[u8], sections: &[Section], root: usize, size: usize) -> Vec<(usize, usize)> {
    let Some(table) = range(data, root, size) else {
        return vec![];
    };
    let mut entries = Vec::new();
    if walk(table, 0, 0, &mut 256, &mut entries).is_none() {
        return vec![];
    }
    let mut remaining: usize = 4 * 1024 * 1024;
    entries
        .into_iter()
        .filter_map(|(rva, len)| {
            let offset = rva_offset(sections, u64::from(rva))?;
            range(data, offset, len)?;
            remaining = remaining.checked_sub(len)?;
            Some((offset, len))
        })
        .collect()
}

fn script_prefix(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
        && data
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        && data.contains(&b'$')
        && data.iter().any(|b| b"=({|".contains(b))
}

/// RC4 keys: the upper-case hex MD5 of each eight-byte seed whose absolute
/// address an executable section loads (`mov rax, imm64; mov [rip+x], rax`).
fn keys(data: &[u8], pe: &image::Pe) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for section in pe
        .sections
        .iter()
        .filter(|s| s.executable && s.size <= 2 * 1024 * 1024)
    {
        let Some(code) = section.bytes(data) else {
            continue;
        };
        for w in code.array_windows::<17>() {
            let [0x48, 0xb8, a, b, c, d, e, f, g, h, 0x48, 0x89, 0x05, ..] = *w else {
                continue;
            };
            let va = u64::from_le_bytes([a, b, c, d, e, f, g, h]);
            let Some(seed) = va
                .checked_sub(pe.image_base)
                .and_then(|rva| rva_offset(&pe.sections, rva))
                .and_then(|at| range(data, at, 8))
            else {
                continue;
            };
            let key = hex::encode_upper(Md5::digest(seed)).into_bytes();
            if !keys.contains(&key) {
                keys.push(key);
            }
            if keys.len() >= 32 {
                return keys;
            }
        }
    }
    keys
}

/// Scripts in the RC4-encrypted `RT_RCDATA` resources of an x86-64
/// PowerShell-to-EXE converter stub of at most 32 MiB.
#[must_use]
pub fn recover(data: &[u8]) -> Vec<Script> {
    if data.len() > 32 * 1024 * 1024
        || !marker(data, b"p2eincfilepath")
        || !marker(data, b"powershell")
    {
        return vec![];
    }
    let Some(pe) = image::pe(data).filter(|pe| pe.machine == 0x8664) else {
        return vec![];
    };
    let Some((rva, size)) = pe.resources else {
        return vec![];
    };
    let Some(root) = rva_offset(&pe.sections, rva) else {
        return vec![];
    };
    let entries = resources(data, &pe.sections, root, size);
    if entries.is_empty() {
        return vec![];
    }
    let keys = keys(data, &pe);
    let mut recovered: Vec<Script> = Vec::new();
    for (offset, len) in entries {
        let Some(ciphertext) = range(data, offset, len) else {
            continue;
        };
        let head = ciphertext
            .get(..ciphertext.len().min(256))
            .unwrap_or_default();
        // The first key whose decryption starts like a script and is
        // UTF-8 throughout.
        let Some(plain) = keys.iter().find_map(|key| {
            if !script_prefix(&rc4(head, key)) {
                return None;
            }
            let mut plain = rc4(ciphertext, key);
            while plain.last() == Some(&0) {
                plain.pop();
            }
            std::str::from_utf8(&plain).is_ok().then_some(plain)
        }) else {
            continue;
        };
        if !recovered.iter().any(|p| p.data == plain) {
            recovered.push(Script {
                data: plain,
                offset,
            });
        }
    }
    tracing::debug!(
        scripts = recovered.len(),
        "PowerShell-to-EXE resource search done"
    );
    recovered
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_and_cyclic_resource_tables() {
        for size in 0..64 {
            let data = vec![0u8; size];
            assert!(resources(&data, &[], 0, size).is_empty());
        }
        let mut data = vec![0; 64];
        data[14] = 1;
        data[16] = 10;
        data[23] = 0x80;
        assert!(resources(&data, &[], 0, 64).is_empty());
    }

    #[test]
    fn randomized_plaintext_and_wrong_keys() {
        let script = b"$message = 'ordinary application'; Write-Output $message\r\n";
        let key = hex::encode_upper(Md5::digest(b"new seed")).into_bytes();
        let ciphertext = rc4(script, &key);
        assert_eq!(rc4(&ciphertext, &key), script);
        assert!(!script_prefix(&rc4(&ciphertext, b"wrong key")));
        assert!(script_prefix(script));
    }

    /// A PowerShell-to-EXE stub whose RCDATA resource at 0x680 holds an
    /// RC4-encrypted script keyed by `seed`.
    pub(crate) fn fixture(seed: [u8; 8], image_base: u64) -> Vec<u8> {
        fn put16(d: &mut [u8], o: usize, n: u16) {
            d[o..o + 2].copy_from_slice(&n.to_le_bytes());
        }
        fn put32(d: &mut [u8], o: usize, n: u32) {
            d[o..o + 4].copy_from_slice(&n.to_le_bytes());
        }
        let mut d = vec![0; 0xa00];
        d[..2].copy_from_slice(b"MZ");
        put32(&mut d, 0x3c, 0x80);
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut d, 0x84, 0x8664);
        put16(&mut d, 0x86, 3);
        put16(&mut d, 0x94, 0xf0);
        put16(&mut d, 0x96, 0x22);
        put16(&mut d, 0x98, 0x20b);
        put32(&mut d, 0xa8, 0x1000);
        d[0xb0..0xb8].copy_from_slice(&image_base.to_le_bytes());
        put32(&mut d, 0xb8, 0x1000);
        put32(&mut d, 0xbc, 0x200);
        put32(&mut d, 0xd0, 0x4000);
        put32(&mut d, 0xd4, 0x200);
        put16(&mut d, 0xdc, 2);
        put32(&mut d, 0x104, 16);
        put32(&mut d, 0x118, 0x3000);
        put32(&mut d, 0x11c, 0x400);
        for (i, (name, rva, offset, len, flags)) in [
            (b".renamed" as &[u8], 0x1000, 0x200, 0x200, 0x6000_0020),
            (b".values" as &[u8], 0x2000, 0x400, 0x200, 0xc000_0040),
            (b".assets" as &[u8], 0x3000, 0x600, 0x400, 0x4000_0040),
        ]
        .iter()
        .enumerate()
        {
            let o = 0x188 + i * 40;
            d[o..o + name.len()].copy_from_slice(name);
            put32(&mut d, o + 8, *len);
            put32(&mut d, o + 12, *rva);
            put32(&mut d, o + 16, *len);
            put32(&mut d, o + 20, *offset);
            put32(&mut d, o + 36, *flags);
        }
        d[0x200..0x202].copy_from_slice(&[0x48, 0xb8]);
        d[0x202..0x20a].copy_from_slice(&(image_base + 0x20a0).to_le_bytes());
        d[0x20a..0x211].copy_from_slice(&[0x48, 0x89, 0x05, 0, 0, 0, 0]);
        d[0x4a0..0x4a8].copy_from_slice(&seed);
        let vocabulary = b"p2eincfilepath powershell";
        for (i, c) in vocabulary.iter().enumerate() {
            d[0x400 + i] = c.wrapping_neg();
        }
        put16(&mut d, 0x60e, 1);
        put32(&mut d, 0x610, 10);
        put32(&mut d, 0x614, 0x8000_0020);
        put16(&mut d, 0x62e, 1);
        put32(&mut d, 0x630, 735);
        put32(&mut d, 0x634, 0x8000_0040);
        put16(&mut d, 0x64e, 1);
        put32(&mut d, 0x650, 0);
        put32(&mut d, 0x654, 0x60);
        let script = b"$message = 'ordinary application with no destructive behavior'; Write-Output $message\r\n";
        let encrypted = rc4(script, hex::encode_upper(Md5::digest(seed)).as_bytes());
        put32(&mut d, 0x660, 0x3080);
        put32(&mut d, 0x664, encrypted.len() as u32);
        d[0x680..0x680 + encrypted.len()].copy_from_slice(&encrypted);
        d
    }

    #[test]
    fn recovers_benign_scripts_with_changed_seed_base_sections_and_resource_name() {
        for (seed, base) in [(b"new seed", 0x1_8000_0000), (b"seed two", 0x2_4000_0000)] {
            let data = fixture(*seed, base);
            let recovered = recover(&data);
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].offset, 0x680);
            assert!(
                recovered[0]
                    .data
                    .starts_with(b"$message = 'ordinary application")
            );
        }
    }

    #[test]
    fn rejects_wrong_seed_missing_marker_and_truncated_ciphertext() {
        for variant in 0..3 {
            let mut data = fixture(*b"new seed", 0x1_8000_0000);
            match variant {
                0 => data[0x4a0] ^= 0x55,
                1 => data[0x400..0x420].fill(0),
                _ => data.truncate(0x690),
            }
            assert!(recover(&data).is_empty());
        }
    }
}
