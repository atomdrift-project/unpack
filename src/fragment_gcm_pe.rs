//! Recover PE members from a code-relative RC4 table envelope as inert data.
//! No specimen code or Windows APIs are executed.
use crate::primitives::{u16_le, u32_le};

/// A PE recovered from a fragmented, XOR-masked AES-GCM envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// Where the envelope's data starts in the host (its overlay).
    pub offset: usize,
    /// The recovered PE.
    pub data: Vec<u8>,
}
#[derive(Debug, Clone)]
struct Section {
    va: u32,
    off: usize,
    size: usize,
    exec: bool,
}
/// The section table of a PE, enough to map RVAs to file offsets.
#[derive(Debug, Clone)]
pub struct Layout {
    sections: Vec<Section>,
}
/// Read the section table of `b`, or `None` when `b` is not a PE whose
/// sections all lie inside it.
pub fn layout(b: &[u8]) -> Option<Layout> {
    if b.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_le(b, 60)? as usize;
    if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let n = usize::from(u16_le(b, pe.checked_add(6)?)?);
    if !(1..=96).contains(&n) {
        return None;
    }
    let opt = pe.checked_add(24)?;
    // PE32+ or PE32 optional header.
    if !matches!(u16_le(b, opt)?, 0x20b | 0x10b) {
        return None;
    }
    let first = opt.checked_add(usize::from(u16_le(b, pe.checked_add(20)?)?))?;
    let mut sections = Vec::new();
    for i in 0..n {
        let p = first.checked_add(i.checked_mul(40)?)?;
        let va = u32_le(b, p.checked_add(12)?)?;
        let size = u32_le(b, p.checked_add(16)?)? as usize;
        let off = u32_le(b, p.checked_add(20)?)? as usize;
        b.get(off..off.checked_add(size)?)?;
        sections.push(Section {
            va,
            off,
            size,
            exec: u32_le(b, p.checked_add(36)?)? & 0x20000000 != 0,
        });
    }
    Some(Layout { sections })
}
impl Layout {
    pub(super) fn offset(&self, rva: u64, n: usize) -> Option<usize> {
        for s in &self.sections {
            let delta = rva.checked_sub(u64::from(s.va));
            if let Some(delta) = delta.and_then(|d| usize::try_from(d).ok())
                && delta.checked_add(n)? <= s.size
            {
                return s.off.checked_add(delta);
            }
        }
        None
    }
}
/// Recover one fragmented, XOR-masked AES-GCM PE envelope, as inert bytes.
/// Offsets, fragment count, sizes and keys come from the decoder's code.
pub fn recover(data: &[u8]) -> Option<Member> {
    use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, KeyInit},
    };
    if data.len() > 512 * 1024 * 1024 {
        return None;
    }
    let image = layout(data)?;
    let overlay = image.sections.iter().map(|s| s.off + s.size).max()?;
    let source = data.get(overlay..)?;
    for section in image.sections.iter().filter(|s| s.exec) {
        let code = data.get(section.off..section.off + section.size.min(4 * 1024 * 1024))?;
        for at in 32..code.len().saturating_sub(24) {
            if code.get(at..at + 4) != Some(&[0x45, 0x8b, 0x8c, 0x0f])
                || code.get(at + 8..at + 12) != Some(&[0x45, 0x8b, 0x9c, 0x0f])
                || code.get(at + 16..at + 20) != Some(&[0x45, 0x8b, 0x94, 0x0f])
            {
                continue;
            }
            let candidate = (|| -> Option<Member> {
                let before = code.get(at.saturating_sub(96)..at)?;
                let lea = before.windows(3).rposition(|v| v == [0x48, 0x8d, 0x35])?
                    + at.saturating_sub(96);
                let next_rva = u64::from(section.va) + u64::try_from(lea + 7).ok()?;
                let disp = i32::from_le_bytes(code.get(lea + 3..lea + 7)?.try_into().ok()?);
                let masks_rva = next_rva.checked_add_signed(i64::from(disp))?;
                // The three tables are indexed against the image base, not a guessed address.
                let table_lea = before.windows(3).rposition(|v| v == [0x48, 0x8d, 0x0d])?
                    + at.saturating_sub(96);
                let table_disp =
                    i32::from_le_bytes(code.get(table_lea + 3..table_lea + 7)?.try_into().ok()?);
                let table_next = i64::try_from(table_lea + 7).ok()?;
                if i64::from(section.va) + table_next + i64::from(table_disp) != 0 {
                    return None;
                }
                let post = code.get(at + 24..(at + 4096).min(code.len()))?;
                let count_at = post
                    .windows(4)
                    .position(|v| v.starts_with(&[0x41, 0x83, 0xfd]))?;
                let count = usize::from(*post.get(count_at + 3)?);
                if !(1..=128).contains(&count) {
                    return None;
                }
                let key_at = post
                    .windows(4)
                    .position(|v| v == [0xc6, 0x44, 0x24, 0x30])?;
                let xor = *post.get(key_at + 4)?;
                let key_code = post.get(key_at..key_at + 64)?;
                let key_load = key_code
                    .windows(5)
                    .position(|v| v == [0x42, 0x0f, 0xb6, 0x8c, 0x2a])?;
                let key_rva = u32_le(key_code, key_load + 5)?;
                let key_off = image.offset(u64::from(key_rva), 32)?;
                let key: Vec<u8> = data
                    .get(key_off..key_off + 32)?
                    .iter()
                    .map(|v| v ^ xor)
                    .collect();
                let size_code = post.get(key_at + 64..)?;
                let size_at = size_code.windows(2).position(|v| v == [0x41, 0xb8])?;
                let size = u32_le(size_code, size_at + 2)? as usize;
                if !(64..=32 * 1024 * 1024).contains(&size) {
                    return None;
                }
                let [sources, destinations, lengths] = [4, 12, 20]
                    .map(|n| image.offset(u64::from(u32_le(code, at + n)?), count.checked_mul(4)?));
                let (sources, destinations, lengths) = (sources?, destinations?, lengths?);
                let masks_off = image.offset(masks_rva, count)?;
                let mut fragments = Vec::new();
                for i in 0..count {
                    let src = u32_le(data, sources + i * 4)? as usize;
                    let dst = u32_le(data, destinations + i * 4)? as usize;
                    let n = u32_le(data, lengths + i * 4)? as usize;
                    if n == 0 || dst.checked_add(n)? > size {
                        return None;
                    }
                    source.get(src..src.checked_add(n)?)?;
                    fragments.push((dst, src, n, *data.get(masks_off + i)?));
                }
                fragments.sort_unstable();
                let mut cipher = vec![0u8; size];
                let mut end = 0;
                for (dst, src, n, mask) in fragments {
                    if dst != end {
                        return None;
                    }
                    // Both ranges were bounds-checked when the fragment was read.
                    let out = cipher.get_mut(dst..dst + n)?;
                    let input = source.get(src..src + n)?;
                    for (o, i) in out.iter_mut().zip(input) {
                        *o = i ^ mask;
                    }
                    end = dst + n;
                }
                if end != size {
                    return None;
                }
                let aead = Aes256Gcm::new_from_slice(&key).ok()?;
                let plain = aead
                    .decrypt(cipher.get(..12)?.into(), cipher.get(12..)?)
                    .ok()?;
                layout(&plain)?;
                Some(Member {
                    offset: overlay,
                    data: plain,
                })
            })();
            if candidate.is_some() {
                return candidate;
            }
        }
    }
    None
}
/// [`recover`], then the SKC3 layer inside its result when there is one:
/// at most two known authenticated layers, never a recursive scan. Each
/// member comes with the encoding chain that produced it.
pub fn recover_chain(data: &[u8]) -> Vec<(Member, &'static str)> {
    let Some(member) = recover(data) else {
        return Vec::new();
    };
    let inner = crate::skc3_pe::recover(&member.data);
    let mut out = vec![(member, "fragment-gcm")];
    if let Some(data) = inner {
        out.push((Member { offset: 0, data }, "fragment-gcm/skc3"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_input_is_rejected() {
        for bytes in [b"".as_slice(), b"MZ", b"not a PE"] {
            assert!(recover(bytes).is_none());
        }
    }
    #[test]
    #[ignore = "needs a private sample: set CLEAVE_FRAGMENT_GCM_FIXTURE"]
    fn actual_envelope_and_integrity_controls() -> anyhow::Result<()> {
        let Ok(path) = std::env::var("CLEAVE_FRAGMENT_GCM_FIXTURE") else {
            return Ok(());
        };
        let bytes = std::fs::read(path)?;
        let plain =
            recover(&bytes).ok_or_else(|| anyhow::anyhow!("actual authenticated envelope"))?;
        assert_eq!(plain.data.len(), 44544);
        assert!(plain.data.windows(8).any(|v| v == b"SkLoader"));
        let truncated = &bytes[..bytes.len() / 2];
        assert!(recover(truncated).is_none());
        let mut damaged = bytes.clone();
        for byte in &mut damaged[plain.offset..] {
            *byte ^= 1;
        }
        assert!(recover(&damaged).is_none());
        if let Ok(path) = std::env::var("CLEAVE_FRAGMENT_GCM_REKEYED_FIXTURE") {
            let changed = std::fs::read(path)?;
            assert_eq!(
                recover(&changed)
                    .ok_or_else(|| anyhow::anyhow!("different authenticated key"))?
                    .data,
                plain.data
            );
        }
        Ok(())
    }
}
