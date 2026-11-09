//! UPX: what `upx -d`'s refusals mean, and checksum repair for an analysis
//! copy of a PE32 NRV2B image. Running `upx` is the caller's: unpack never
//! starts a process.

/// Why `upx -d` refused an image, in a fixed vocabulary.
///
/// `upx` reports errors against the file it was handed, so its stderr
/// carries a path that differs on every run
/// (`upx: /tmp/.tmpJYEaZH: Exception: checksum error`); this text does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Fixed text, safe to compare across runs and machines.
    pub description: &'static str,
    /// The header checksum does not match the payload: evidence about the
    /// image, distinct from a tool limitation.
    pub checksum_mismatch: bool,
    /// The claimed UPX image is structurally invalid or not packed.
    pub invalid_image: bool,
}

/// What `upx -d`'s `stderr` says went wrong, matched on `upx`'s own
/// exception names, which are stable across releases.
#[must_use]
pub fn classify(stderr: &str) -> Refusal {
    let m = stderr.to_ascii_lowercase();
    let (description, checksum_mismatch, invalid_image) =
        if m.contains("checksum error") || m.contains("checksumexception") {
            ("UPX header checksum does not match payload", true, false)
        } else if m.contains("notpacked") || m.contains("not packed") {
            ("UPX markers present but image is not packed", false, true)
        } else if m.contains("corrupt")
            || m.contains("invalid header")
            || m.contains("invalid packed data")
            || m.contains("unexpected end of file")
        {
            ("UPX packed-image structure is invalid", false, true)
        } else if m.contains("cantunpack") || m.contains("cantpack") {
            ("UPX image refuses to unpack", false, false)
        } else if m.contains("ioexception") {
            ("UPX could not read the image", false, false)
        } else {
            ("UPX decompression failed", false, false)
        };
    Refusal {
        description,
        checksum_mismatch,
        invalid_image,
    }
}

/// Whether `data` carries UPX's `UPX!` magic, or a tampered `[A-Z]PX!`
/// copy of it, in its first 4 KiB, where UPX writes the header of the image
/// it packs: an image worth handing to `upx -d`. A packed PE can carry it
/// after its section table, around byte 1000.
#[must_use]
pub fn is_packed(data: &[u8]) -> bool {
    data.get(..data.len().min(4096))
        .unwrap_or(data)
        .array_windows::<4>()
        .any(|&[first, p, x, bang]| first.is_ascii_uppercase() && [p, x, bang] == *b"PX!")
}

/// Adler-32.
fn adler(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// The `p_info` header byte checksum: the sum of bytes 4..31 modulo 251.
fn header_sum(header: &[u8; 32]) -> u8 {
    let sum = header[4..31].iter().map(|&v| u32::from(v)).sum::<u32>() % 251;
    u8::try_from(sum).unwrap_or(0)
}

/// A copy of the PE32 NRV2B image `data` (at most 64 MiB) whose UPX header
/// checksums are recomputed from its decoded payload, so that standard
/// `upx -d` accepts it. `None` unless the header and stream are recognized
/// and the payload decodes to its declared length.
///
/// The repair changes evidence: the caller keeps the original integrity
/// finding, and analyzes the copy only if standard UPX then unpacks it.
#[must_use]
pub fn repair_checksums(data: &[u8]) -> Option<Vec<u8>> {
    const LIMIT: usize = 64 * 1024 * 1024;
    if data.len() > LIMIT || !data.starts_with(b"MZ") {
        return None;
    }
    let at = data
        .get(..data.len().min(4096))?
        .windows(4)
        .position(|v| v == b"UPX!")?;
    let header: &[u8; 32] = data.get(at..)?.first_chunk()?;
    if !(10..=13).contains(&header[4])
        || header[5] != 9
        || header[6] != 2
        || header[31] != header_sum(header)
    {
        return None;
    }
    let ulen = usize::try_from(u32::from_le_bytes([
        header[16], header[17], header[18], header[19],
    ]))
    .ok()?;
    let clen = usize::try_from(u32::from_le_bytes([
        header[20], header[21], header[22], header[23],
    ]))
    .ok()?;
    if ulen == 0 || ulen > LIMIT || clen == 0 || clen > LIMIT {
        return None;
    }
    let start = at.checked_add(32)?;
    let compressed = data.get(start..start.checked_add(clen)?)?;
    let decoded = crate::nrv32::decode(compressed, ulen).ok()?;
    if decoded.len() != ulen {
        return None;
    }
    let mut copy = data.to_vec();
    let repaired: &mut [u8; 32] = copy.get_mut(at..)?.first_chunk_mut()?;
    repaired[8..12].copy_from_slice(&adler(&decoded).to_le_bytes());
    repaired[12..16].copy_from_slice(&adler(compressed).to_le_bytes());
    repaired[31] = header_sum(repaired);
    Some(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_upx_packed_with_magic_after_elf_header() {
        // UPX! magic typically appears after ELF header
        let data_with_magic = b"\x7fELF\x00\x00\x00\x00UPX!\x00\x00";
        assert!(is_packed(data_with_magic));
    }

    #[test]
    fn test_is_upx_packed_without_magic() {
        // Regular ELF header without UPX magic
        let data_without_magic = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(!is_packed(data_without_magic));
    }

    #[test]
    fn test_is_upx_packed_empty() {
        let empty: &[u8] = &[];
        assert!(!is_packed(empty));
    }

    #[test]
    fn test_is_upx_packed_magic_at_start() {
        let data = b"UPX!\x00\x00\x00\x00";
        assert!(is_packed(data));
    }

    #[test]
    fn test_is_upx_packed_magic_at_end_of_search_range() {
        // Magic at byte 4088 (just within 4 KiB search range)
        let mut data = vec![0u8; 4096];
        data[4088..4092].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_pe_magic_after_section_table() {
        // Valid PE UPX samples can carry UPX! around byte 992, after the
        // section table, while still being unpackable by upx -d.
        let mut data = vec![0u8; 1200];
        data[0..2].copy_from_slice(b"MZ");
        data[992..996].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_at_exactly_512_boundary() {
        // Magic starting at byte 512 IS detected.
        let mut data = vec![0u8; 520];
        data[512..516].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_beyond_header_search() {
        // Magic starting beyond 4 KiB should not drive UPX unpacking.
        let mut data = vec![0u8; 4200];
        data[4097..4101].copy_from_slice(b"UPX!");
        assert!(!is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_partial_magic() {
        // Partial magic "UPX" without "!" should not match
        let data = b"\x7fELF\x00\x00\x00\x00UPX\x00\x00\x00";
        assert!(!is_packed(data));
    }

    #[test]
    fn test_is_upx_packed_similar_but_wrong_magic() {
        // Similar strings that are NOT UPX magic
        let data1 = b"\x7fELF\x00\x00\x00\x00upx!\x00\x00"; // lowercase
        assert!(!is_packed(data1));

        let data2 = b"\x7fELF\x00\x00\x00\x00UPX?\x00\x00"; // wrong char
        assert!(!is_packed(data2));

        let data3 = b"\x7fELF\x00\x00\x00\x00 UPX!\x00\x00"; // space before
        assert!(is_packed(data3)); // should still match
    }

    #[test]
    fn test_is_upx_packed_multiple_occurrences() {
        // Multiple UPX! strings - should still return true
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(b"UPX!");
        data[50..54].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_small_file() {
        // File smaller than 512 bytes with magic
        let data = b"UPX!";
        assert!(is_packed(data));
    }

    #[test]
    fn test_is_upx_packed_exactly_4_bytes() {
        // Exactly 4 bytes matching magic
        assert!(is_packed(b"UPX!"));
    }

    #[test]
    fn test_is_upx_packed_3_bytes() {
        // Only 3 bytes - cannot contain full magic
        assert!(!is_packed(b"UPX"));
    }

    #[test]
    fn test_is_upx_packed_binary_data_with_magic() {
        // Binary data with UPX magic embedded
        let mut data = vec![0xffu8; 256];
        data[100..104].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_real_elf_header_pattern() {
        // Realistic ELF header followed by UPX magic (typical UPX-packed ELF)
        let mut data = vec![0u8; 256];
        // ELF magic
        data[0..4].copy_from_slice(b"\x7fELF");
        // 64-bit, little-endian
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1; // ELF version
        // UPX magic typically appears in the packed data section
        data[100..104].copy_from_slice(b"UPX!");
        assert!(is_packed(&data));
    }

    #[test]
    fn refusals_are_stable_across_temp_paths() {
        let a = classify("upx: /tmp/.tmpJYEaZH: Exception: checksum error\n");
        let b = classify("upx: /tmp/.tmpQYT9GU: Exception: checksum error\n");
        assert_eq!(a, b);
        assert!(a.checksum_mismatch);
        assert_eq!(a.description, "UPX header checksum does not match payload");
        assert_eq!(
            classify("upx: something new").description,
            "UPX decompression failed"
        );
        for message in [
            "upx: /tmp/checksum.exe: NotPackedException: not packed",
            "upx: /tmp/test.exe: CantUnpackException: unsupported format",
        ] {
            assert!(!classify(message).checksum_mismatch, "{message}");
        }
        assert!(classify("upx: x: NotPackedException: not packed").invalid_image);
        assert!(!classify("upx: x: CantUnpackException: unsupported").invalid_image);
    }

    #[test]
    fn bounded_checksum_repair_recovers_literal_stream_without_touching_input() {
        // NRV2B literals "Hi", followed by the end marker.
        let stream = [0, 0, 0, 192, 72, 105, 0, 32, 1, 0, 255];
        let mut data = vec![0u8; 64 + 32];
        data[..2].copy_from_slice(b"MZ");
        data[64..72].copy_from_slice(&[b'U', b'P', b'X', b'!', 13, 9, 2, 1]);
        data[80..84].copy_from_slice(&2u32.to_le_bytes());
        data[84..88].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        data[95] = (data[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8;
        data.extend_from_slice(&stream);
        let original = data.clone();
        let fixed = repair_checksums(&data).unwrap();
        assert_eq!(data, original);
        assert_eq!(&fixed[96..], &stream);
        assert_eq!(
            u32::from_le_bytes(fixed[72..76].try_into().unwrap()),
            0x00fb00b2
        );
        assert_eq!(
            fixed[95],
            (fixed[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8
        );
        for len in 0..data.len() {
            assert!(repair_checksums(&data[..len]).is_none());
        }
        data[80..84].copy_from_slice(&u32::MAX.to_le_bytes());
        data[95] = (data[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8;
        assert!(repair_checksums(&data).is_none());
    }

    #[test]
    fn adler32_matches_the_reference() {
        assert_eq!(adler(b"Wikipedia"), 0x11E6_0398);
    }
}
