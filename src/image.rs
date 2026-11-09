//! Section tables of PE and little-endian Mach-O images: just enough for a
//! decoder to map an address or RVA it read from code to a file offset.
//!
//! Every read is bounded and fails closed. Offsets index the whole input,
//! including a section of a universal binary's slice.

/// Most sections read from one image.
const MAX_SECTIONS: usize = 1024;
/// Most slices of a universal binary considered.
const MAX_SLICES: u32 = 16;

/// One section with bytes in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    /// `__TEXT,__text` in a Mach-O image, `.text` in a PE image.
    pub(crate) name: String,
    /// The section's virtual address (Mach-O) or RVA (PE).
    pub(crate) vaddr: u64,
    /// Where its bytes start in the input.
    pub(crate) offset: usize,
    /// How many of its bytes the file holds.
    pub(crate) size: usize,
    /// Whether its memory is executable.
    pub(crate) executable: bool,
}

impl Section {
    /// The section's bytes, when the file holds all of them.
    pub(crate) fn bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.offset..self.offset.checked_add(self.size)?)
    }
}

/// Where `len` bytes at `address` sit in the file, when one section holds
/// all of them.
pub(crate) fn file_offset(sections: &[Section], address: u64, len: usize) -> Option<usize> {
    let len = u64::try_from(len).ok()?;
    sections.iter().find_map(|section| {
        let delta = address.checked_sub(section.vaddr)?;
        if delta.checked_add(len)? > u64::try_from(section.size).ok()? {
            return None;
        }
        section.offset.checked_add(usize::try_from(delta).ok()?)
    })
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*b.get(at..)?.first_chunk()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*b.get(at..)?.first_chunk()?))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*b.get(at..)?.first_chunk()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

/// A fixed-width, NUL-padded name.
fn name(field: &[u8]) -> String {
    let end = memchr::memchr(0, field).unwrap_or(field.len());
    String::from_utf8_lossy(field.get(..end).unwrap_or_default()).into_owned()
}

/// What a PE image declares that the decoders use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pe {
    /// The COFF machine, e.g. `0x8664` for x86-64.
    pub(crate) machine: u16,
    /// The preferred load address.
    pub(crate) image_base: u64,
    /// The resource directory's RVA and size, when declared.
    pub(crate) resources: Option<(u64, usize)>,
    /// Sections with raw data, in header order.
    pub(crate) sections: Vec<Section>,
}

/// The headers of the PE image `data`, or `None` when it is not one.
pub(crate) fn pe(data: &[u8]) -> Option<Pe> {
    if data.get(..2)? != b"MZ" {
        return None;
    }
    let nt = usize::try_from(le32(data, 0x3c)?).ok()?;
    if data.get(nt..nt.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    // `nt` indexes the input, so adding a header's width cannot overflow.
    let coff = nt + 4;
    let machine = le16(data, coff)?;
    let count = usize::from(le16(data, coff + 2)?).min(MAX_SECTIONS);
    let optional_len = usize::from(le16(data, coff + 16)?);
    let optional = coff + 20;
    let (image_base, directories, directory_count) = match le16(data, optional)? {
        0x10b => (
            u64::from(le32(data, optional + 28)?),
            optional + 96,
            le32(data, optional + 92)?,
        ),
        0x20b => (
            le64(data, optional + 24)?,
            optional + 112,
            le32(data, optional + 108)?,
        ),
        _ => return None,
    };
    // The resource directory is entry 2, and only counts when the optional
    // header declares and holds it.
    let resource = directories + 16;
    let resources = (directory_count > 2 && resource + 8 <= optional + optional_len)
        .then(|| {
            let rva = le32(data, resource)?;
            let size = usize::try_from(le32(data, resource + 4)?).ok()?;
            (rva != 0).then_some((u64::from(rva), size))
        })
        .flatten();
    let table = optional + optional_len;
    let sections = (0..count)
        .map_while(|i| data.get(table + i * 40..table + i * 40 + 40))
        .filter_map(|header| {
            let size = usize::try_from(le32(header, 16)?).ok()?;
            (size > 0).then_some(())?;
            Some(Section {
                name: name(header.get(..8)?),
                vaddr: u64::from(le32(header, 12)?),
                offset: usize::try_from(le32(header, 20)?).ok()?,
                size,
                executable: le32(header, 36)? & 0x2000_0000 != 0,
            })
        })
        .collect();
    Some(Pe {
        machine,
        image_base,
        resources,
        sections,
    })
}

/// The sections of the Mach-O image `data`. For a universal binary, those
/// of the slice an x86-64 host would run, else Apple silicon's, else the
/// first that parses. `None` when no image parses.
pub(crate) fn macho(data: &[u8]) -> Option<Vec<Section>> {
    match data.first_chunk::<4>()? {
        [0xca, 0xfe, 0xba, 0xbe] => universal(data, false),
        [0xca, 0xfe, 0xba, 0xbf] => universal(data, true),
        _ => thin(data, 0),
    }
}

fn universal(data: &[u8], wide: bool) -> Option<Vec<Section>> {
    let count = be32(data, 4)?;
    // A Java class shares this magic; its version makes the count large.
    if count == 0 || count > MAX_SLICES {
        return None;
    }
    let width = if wide { 32 } else { 20 };
    let mut best: Option<(u8, Vec<Section>)> = None;
    for i in 0..usize::try_from(count).ok()? {
        let entry = 8 + i * width;
        let rank = match be32(data, entry)? {
            0x0100_0007 => 0,
            0x0100_000c => 1,
            _ => 2,
        };
        if best.as_ref().is_some_and(|&(held, _)| held <= rank) {
            continue;
        }
        let start = if wide {
            be64(data, entry + 8)?
        } else {
            u64::from(be32(data, entry + 8)?)
        };
        if let Some(sections) = usize::try_from(start).ok().and_then(|at| thin(data, at)) {
            best = Some((rank, sections));
        }
    }
    best.map(|(_, sections)| sections)
}

/// The sections of the Mach-O image starting `base` bytes into `data`.
fn thin(data: &[u8], base: usize) -> Option<Vec<Section>> {
    let image = data.get(base..)?;
    // (header, segment command, segment header, section header) widths.
    let (header, command, segment, entry): (usize, u32, usize, usize) =
        match image.first_chunk::<4>()? {
            [0xcf, 0xfa, 0xed, 0xfe] => (32, 0x19, 72, 80),
            [0xce, 0xfa, 0xed, 0xfe] => (28, 0x1, 56, 68),
            _ => return None,
        };
    let wide = command == 0x19;
    let commands_len = usize::try_from(le32(image, 20)?).ok()?;
    let commands = image.get(header..header.checked_add(commands_len)?)?;
    let mut sections = Vec::new();
    let mut at = 0;
    for _ in 0..le32(image, 16)? {
        let (Some(kind), Some(Ok(len))) = (
            le32(commands, at),
            le32(commands, at + 4).map(usize::try_from),
        ) else {
            break;
        };
        let Some(load) = commands.get(at..at + len).filter(|_| len >= 8) else {
            break;
        };
        at += len;
        if kind != command {
            continue;
        }
        let executable = le32(load, segment - 12).is_some_and(|prot| prot & 4 != 0);
        let count = le32(load, segment - 8).and_then(|n| usize::try_from(n).ok());
        for i in 0..count.unwrap_or(0) {
            if sections.len() == MAX_SECTIONS {
                return Some(sections);
            }
            let Some(header) = load.get(segment + i * entry..segment + (i + 1) * entry) else {
                break;
            };
            if let Some(section) = macho_section(header, wide, base, executable) {
                sections.push(section);
            }
        }
    }
    Some(sections)
}

/// One `section` or `section_64` header, or `None` for a zero-fill section
/// or one with no bytes in the file.
fn macho_section(header: &[u8], wide: bool, base: usize, executable: bool) -> Option<Section> {
    let (vaddr, size, offset, flags) = if wide {
        (
            le64(header, 32)?,
            le64(header, 40)?,
            le32(header, 48)?,
            le32(header, 64)?,
        )
    } else {
        (
            u64::from(le32(header, 32)?),
            u64::from(le32(header, 36)?),
            le32(header, 40)?,
            le32(header, 56)?,
        )
    };
    // S_ZEROFILL, S_GB_ZEROFILL and S_THREAD_LOCAL_ZEROFILL occupy no file bytes.
    if size == 0 || matches!(flags & 0xff, 0x1 | 0xc | 0x12) {
        return None;
    }
    Some(Section {
        name: format!("{},{}", name(header.get(16..32)?), name(header.get(..16)?)),
        vaddr,
        offset: base.checked_add(usize::try_from(offset).ok()?)?,
        size: usize::try_from(size).ok()?,
        executable,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A thin 64-bit Mach-O with one executable segment holding `__text`
    /// and `__cstring`, plus a zero-fill `__bss`.
    pub(crate) fn macho64() -> Vec<u8> {
        let mut d = vec![0u8; 0x400];
        d[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        d[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        d[16..20].copy_from_slice(&1u32.to_le_bytes());
        let len = 72 + 3 * 80;
        d[20..24].copy_from_slice(&(len as u32).to_le_bytes());
        let c = 32;
        d[c..c + 4].copy_from_slice(&0x19u32.to_le_bytes());
        d[c + 4..c + 8].copy_from_slice(&(len as u32).to_le_bytes());
        d[c + 8..c + 14].copy_from_slice(b"__TEXT");
        d[c + 60..c + 64].copy_from_slice(&5u32.to_le_bytes());
        d[c + 64..c + 68].copy_from_slice(&3u32.to_le_bytes());
        for (i, (sect, addr, offset, flags)) in [
            (&b"__text"[..], 0x1_0000_1000u64, 0x200u32, 0u32),
            (b"__cstring", 0x1_0000_1100, 0x300, 2),
            (b"__bss", 0x1_0000_2000, 0, 1),
        ]
        .into_iter()
        .enumerate()
        {
            let s = c + 72 + i * 80;
            d[s..s + sect.len()].copy_from_slice(sect);
            d[s + 16..s + 22].copy_from_slice(b"__TEXT");
            d[s + 32..s + 40].copy_from_slice(&addr.to_le_bytes());
            d[s + 40..s + 48].copy_from_slice(&0x100u64.to_le_bytes());
            d[s + 48..s + 52].copy_from_slice(&offset.to_le_bytes());
            d[s + 64..s + 68].copy_from_slice(&flags.to_le_bytes());
        }
        d
    }

    #[test]
    fn thin_and_universal_macho_sections() {
        let thin = macho64();
        let sections = macho(&thin).unwrap();
        let names: Vec<_> = sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["__TEXT,__text", "__TEXT,__cstring"]);
        assert!(sections.iter().all(|s| s.executable));
        assert_eq!(file_offset(&sections, 0x1_0000_1110, 4), Some(0x310));
        assert_eq!(file_offset(&sections, 0x1_0000_11fe, 4), None);

        // An arm64 slice first, then the x86-64 one: x86-64 is preferred
        // and its offsets index the universal file.
        let mut fat = vec![0u8; 0x1000];
        fat[..8].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]);
        fat[8..12].copy_from_slice(&0x0100_000cu32.to_be_bytes());
        fat[16..20].copy_from_slice(&0x400u32.to_be_bytes());
        fat[28..32].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        fat[36..40].copy_from_slice(&0x800u32.to_be_bytes());
        fat[0x400..0x800].copy_from_slice(&thin);
        fat[0x800..0xc00].copy_from_slice(&thin);
        fat[0x404..0x408].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        let sections = macho(&fat).unwrap();
        assert_eq!(sections[0].offset, 0xa00);
    }

    #[test]
    fn malformed_images_fail_closed() {
        let thin = macho64();
        for end in [0, 3, 31, 40, 100, 0x150] {
            let _ = macho(&thin[..end]);
            assert!(pe(&thin[..end]).is_none());
        }
        let mut java = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
        java.resize(64, 0);
        assert!(macho(&java).is_none());
        let mut huge = thin.clone();
        huge[32 + 4..32 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(macho(&huge), Some(Vec::new()));
        assert!(pe(b"MZ").is_none());
    }
}
