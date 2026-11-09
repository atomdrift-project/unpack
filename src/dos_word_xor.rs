//! Literal reconstruction of a bounded DOS COM word-XOR entry stub.
//!
//! These are recognizers for fixed instruction recipes, not an x86 emulator.
//! Its patch and XOR parameters are read as data; no sample code is run.
const MAX_COM: usize = 65536;

/// Which entry-stub recipe a COM file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipe {
    /// A word-XOR loop, entered through a patched or fall-through jump.
    WordXor,
    /// A byte-XOR loop that falls through into its payload.
    ByteXor,
    /// A byte-subtract loop.
    ByteSubtract,
    /// A `call`-anchored word subtract/XOR/rotate loop.
    WordSubXorRotate,
}

impl Recipe {
    /// The recipe's encoding name, e.g. `dos-word-xor`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WordXor => "dos-word-xor",
            Self::ByteXor => "dos-byte-xor",
            Self::ByteSubtract => "dos-byte-subtract",
            Self::WordSubXorRotate => "dos-word-sub-xor-rotate",
        }
    }
}

/// A COM image with its stub's encoding undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Where the stub_at stub starts.
    pub offset: usize,
    /// The recipe the stub uses.
    pub recipe: Recipe,
    /// The decoded image, the same length as the input.
    pub data: Vec<u8>,
}

/// The decoded image of a DOS COM file (at most 64 KiB) whose entry jump
/// leads to a recognized stub_at stub.
#[must_use]
pub fn decode(data: &[u8]) -> Option<Decoded> {
    if data.len() > MAX_COM {
        return None;
    }
    let tagged = |recipe| {
        move |(offset, data)| Decoded {
            offset,
            recipe,
            data,
        }
    };
    if data.first() == Some(&0xe8) {
        return decode_call_rotate_xor(data).map(tagged(Recipe::WordSubXorRotate));
    }
    if data.first() != Some(&0xe9) {
        return None;
    }
    let entry = near_target(0, i16::from_le_bytes([*data.get(1)?, *data.get(2)?]))?;
    decode_patched_entry(data, entry)
        .map(tagged(Recipe::WordXor))
        .or_else(|| decode_fallthrough(data, entry).map(tagged(Recipe::WordXor)))
        .or_else(|| decode_byte_fallthrough(data, entry).map(tagged(Recipe::ByteXor)))
        .or_else(|| decode_byte_subtract(data, entry).map(tagged(Recipe::ByteSubtract)))
}

/// The `N` bytes at `at`, when the input holds them all.
fn window<const N: usize>(data: &[u8], at: usize) -> Option<&[u8; N]> {
    data.get(at..)?.first_chunk()
}

/// `base + 3 + rel`: the target of a near `call`/`jmp` at `base`.
fn near_target(base: usize, rel: i16) -> Option<usize> {
    let target = isize::try_from(base)
        .ok()?
        .checked_add(3)?
        .checked_add(isize::from(rel))?;
    usize::try_from(target).ok()
}

/// Decode a literal byte-XOR loop that falls through into its payload.
fn decode_byte_fallthrough(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = window::<14>(data, entry)?;
    if stub[0] != 0xb2
        || stub[1] == 0
        || stub[2] != 0xbe
        || stub[5] != 0xb9
        || stub[8..14] != [0x2e, 0x30, 0x14, 0x46, 0xe2, 0xfa]
    {
        return None;
    }
    let start = usize::from(u16::from_le_bytes([stub[3], stub[4]])).checked_sub(0x100)?;
    let length = usize::from(u16::from_le_bytes([stub[6], stub[7]]));
    let body_end = start.checked_add(length)?;
    let after_stub = entry.checked_add(14)?;
    if length == 0
        || start < after_stub
        || start > after_stub.checked_add(4)?
        || body_end > data.len()
        || body_end > 0xff00
        || !data
            .get(after_stub..start)?
            .iter()
            .all(|byte| *byte == 0x90)
    {
        return None;
    }
    let mut decoded = data.to_vec();
    for byte in decoded.get_mut(start..body_end)? {
        *byte ^= stub[1];
    }
    Some((entry, decoded))
}

/// Recognize a forward subtract-byte recipe reached by a near CALL. This
/// reconstructs under the conventional DOS clear-direction-flag entry state.
fn decode_byte_subtract(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let limit = entry.checked_add(64)?.min(data.len());
    for stub in entry..limit {
        let Some(body) = window::<26>(data, stub) else {
            continue;
        };
        let end_stub = stub + 26;
        if body[..4] != [0xfa, 0x5f, 0x00, 0xfb]
            || body[4] != 0xb9
            || body[7..9] != [0xfa, 0xbe]
            || body[11..14] != [0x23, 0xff, 0xb2]
            || body[14] == 0
            || body[15..21] != [0x23, 0xff, 0x90, 0x2e, 0x28, 0x94]
            || body[23..26] != [0xa6, 0xe2, 0xf7]
        {
            continue;
        }
        let linked = (entry..stub.saturating_sub(2)).any(|at| {
            matches!(window::<3>(data, at), Some(&[0xe8, lo, hi])
                if near_target(at, i16::from_le_bytes([lo, hi])) == Some(stub))
        });
        if !linked {
            continue;
        }
        let si = u16::from_le_bytes([body[9], body[10]]);
        let disp = u16::from_le_bytes([body[21], body[22]]);
        let Some(start) = usize::from(si.wrapping_add(disp)).checked_sub(0x100) else {
            continue;
        };
        let count = usize::from(u16::from_le_bytes([body[5], body[6]]));
        let Some(end) = start.checked_add(count) else {
            continue;
        };
        if count == 0 || start != end_stub || end > data.len() || end > 0xff00 {
            continue;
        }
        let mut decoded = data.to_vec();
        for byte in decoded.get_mut(start..end)? {
            *byte = byte.wrapping_sub(body[14]);
        }
        return Some((stub, decoded));
    }
    None
}

/// Recognize a COM entry that calls a bounded subtract/XOR/rotate stub_at,
/// then jumps to the decoded block. This interprets a fixed recipe only.
fn decode_call_rotate_xor(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    let &[_, lo, hi, 0xeb, jump] = window::<5>(data, 0)? else {
        return None;
    };
    let stub_at = near_target(0, i16::from_le_bytes([lo, hi]))?;
    let target =
        usize::try_from(5isize.checked_add(isize::from(i8::from_le_bytes([jump])))?).ok()?;
    let body = window::<25>(data, stub_at)?;
    if body[0] != 0xe8
        || body[3..5] != [0x83, 0x3e]
        || body[7..12] != [0x00, 0x74, 0x0e, 0xad, 0x2b]
        || body[12..19] != [0xc1, 0x33, 0xc1, 0xd3, 0xc0, 0xab, 0xff]
        || body[19] != 0x0e
        || body[22..25] != [0xeb, 0xeb, 0xc3]
        || body[5..7] != body[20..22]
    {
        return None;
    }
    let setup = near_target(stub_at, i16::from_le_bytes([body[1], body[2]]))?;
    let setup_bytes = window::<16>(data, setup)?;
    if setup_bytes[..2] != [0xc7, 0x06]
        || setup_bytes[2..4] != body[5..7]
        || setup_bytes[6] != 0xbe
        || setup_bytes[9..11] != [0x8b, 0x0e]
        || setup_bytes[13..16] != [0x8b, 0xfe, 0xc3]
    {
        return None;
    }
    let start =
        usize::from(u16::from_le_bytes([setup_bytes[7], setup_bytes[8]])).checked_sub(0x100)?;
    let count = usize::from(u16::from_le_bytes([setup_bytes[4], setup_bytes[5]]));
    let end = start.checked_add(count.checked_mul(2)?)?;
    let key_at =
        usize::from(u16::from_le_bytes([setup_bytes[11], setup_bytes[12]])).checked_sub(0x100)?;
    let counter_at =
        usize::from(u16::from_le_bytes([setup_bytes[2], setup_bytes[3]])).checked_sub(0x100)?;
    let overlaps =
        |offset: usize, length: usize| offset < end && offset.saturating_add(length) > start;
    if start != target
        || count == 0
        || end > data.len()
        || end > 0xff00
        || overlaps(stub_at, 25)
        || overlaps(setup, 16)
        || overlaps(key_at, 2)
        || overlaps(counter_at, 2)
    {
        return None;
    }
    let key = u16::from_le_bytes(*window::<2>(data, key_at)?);
    let mut decoded = data.to_vec();
    for chunk in decoded.get_mut(start..end)?.as_chunks_mut::<2>().0 {
        let word = u16::from_le_bytes(*chunk).wrapping_sub(key) ^ key;
        *chunk = word.rotate_left(u32::from(key & 0xff)).to_le_bytes();
    }
    Some((stub_at, decoded))
}

fn decode_patched_entry(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = window::<28>(data, entry)?;
    if stub[..4] != [0xbe, 0x00, 0x01, 0x56]
        || stub[4] != 0xb9
        || stub[7..9] != [0xc7, 0x04]
        || stub[11..14] != [0xc6, 0x44, 0x02]
        || stub[15..17] != [0x81, 0x34]
        || stub[19..28] != [0x46, 0x46, 0xe2, 0xf8, 0x31, 0xf6, 0x31, 0xc9, 0xc3]
    {
        return None;
    }
    let words = usize::from(u16::from_le_bytes([stub[5], stub[6]]));
    let length = words.checked_mul(2)?;
    // The stub_at may not change its own instructions, and the patched bytes
    // must be within the decoded span. This also bounds the work to 64 KiB.
    if length < 4 || length > entry || length > data.len() {
        return None;
    }
    let mut decoded = data.to_vec();
    decoded
        .get_mut(..3)?
        .copy_from_slice(&[stub[9], stub[10], stub[14]]);
    let key = [stub[17], stub[18]];
    for chunk in decoded.get_mut(..length)?.as_chunks_mut::<2>().0 {
        chunk[0] ^= key[0];
        chunk[1] ^= key[1];
    }
    // A near jump back into the decoded span is an additional structural
    // guard; do not interpret arbitrary XOR-ed data as a program.
    let &[0xe9, lo, hi, ..] = decoded.as_slice() else {
        return None;
    };
    if near_target(0, i16::from_le_bytes([lo, hi]))? >= length {
        return None;
    }
    Some((entry, decoded))
}

/// A forward word-XOR loop decodes the bytes immediately after itself and
/// then falls through into them. The address is a DOS COM memory address.
fn decode_fallthrough(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = window::<19>(data, entry)?;
    if stub[0] != 0xbf
        || stub[3] != 0xfc
        || stub[4] != 0xb9
        || stub[7..9] != [0x81, 0x35]
        || stub[11..19] != [0x83, 0xc7, 0x03, 0x83, 0xef, 0x01, 0xe2, 0xf4]
    {
        return None;
    }
    let address = usize::from(u16::from_le_bytes([stub[1], stub[2]]));
    let start = address.checked_sub(0x100)?;
    let length = usize::from(u16::from_le_bytes([stub[5], stub[6]])).checked_mul(2)?;
    let end = start.checked_add(length)?;
    let key = [stub[9], stub[10]];
    if start != entry.checked_add(19)?
        || length == 0
        || end > data.len()
        || end.checked_add(0x100)? > 0x10000
        || key == [0, 0]
    {
        return None;
    }
    let mut decoded = data.to_vec();
    for chunk in decoded.get_mut(start..end)?.as_chunks_mut::<2>().0 {
        chunk[0] ^= key[0];
        chunk[1] ^= key[1];
    }
    Some((entry, decoded))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "invalid fixtures should fail the test")]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let key = [0x16, 0x44];
        let mut decoded = [0x90; 64];
        decoded[..3].copy_from_slice(&[0xe9, 0x0d, 0x00]);
        let patch = [
            decoded[0] ^ key[0],
            decoded[1] ^ key[1],
            decoded[2] ^ key[0],
        ];
        let mut encoded = decoded
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i & 1])
            .collect::<Vec<_>>();
        encoded[..3].copy_from_slice(&[0xe9, 61, 0]);
        encoded.extend_from_slice(&[
            0xbe, 0, 1, 0x56, 0xb9, 32, 0, 0xc7, 4, patch[0], patch[1], 0xc6, 0x44, 2, patch[2],
            0x81, 0x34, key[0], key[1], 0x46, 0x46, 0xe2, 0xf8, 0x31, 0xf6, 0x31, 0xc9, 0xc3,
        ]);
        encoded
    }
    #[test]
    fn restores_patched_entry_and_decodes_words() {
        let input = fixture();
        let Decoded {
            offset,
            data: result,
            ..
        } = decode(&input).expect("recognized recipe");
        assert_eq!(offset, 64);
        assert_eq!(&result[..3], &[0xe9, 0x0d, 0]);
        assert!(result[3..64].iter().all(|b| *b == 0x90));
    }
    #[test]
    fn decodes_forward_fallthrough_and_rejects_unsafe_variants() {
        let entry = 16usize;
        let mut input = vec![0x90; entry];
        input[..3].copy_from_slice(&[0xe9, 13, 0]);
        let address = (0x100u16 + entry as u16 + 19).to_le_bytes();
        input.extend_from_slice(&[
            0xbf, address[0], address[1], 0xfc, 0xb9, 8, 0, 0x81, 0x35, 0x85, 0xdb, 0x83, 0xc7, 3,
            0x83, 0xef, 1, 0xe2, 0xf4,
        ]);
        let plain = [
            0xe8, 0, 0, 0x5d, 0x81, 0xed, 1, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xcd, 0x20,
        ];
        input.extend(
            plain
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ [0x85, 0xdb][i & 1]),
        );
        let Decoded {
            offset: _,
            data: decoded,
            ..
        } = decode(&input).expect("forward recipe");
        assert_eq!(&decoded[entry + 19..], &plain);
        for (offset, value) in [
            (entry + 1, address[0].wrapping_add(1)),
            (entry + 5, 9),
            (entry + 11, 0x82),
            (entry + 18, 0xf3),
        ] {
            let mut altered = input.clone();
            altered[offset] = value;
            assert!(decode(&altered).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..input.len() - 1]).is_none());
    }
    #[test]
    fn decodes_call_linked_byte_subtract_and_rejects_bad_links() {
        let stub = 16usize;
        let start = stub + 26;
        let mut input = vec![0x90u8; 80];
        input[..3].copy_from_slice(&[0xe9, 0, 0]);
        input[5..8].copy_from_slice(&[0xe8, 8, 0]);
        let si = 0x2000u16;
        let displacement = (0x100u16 + start as u16).wrapping_sub(si).to_le_bytes();
        input[stub..stub + 26].copy_from_slice(&[
            0xfa,
            0x5f,
            0x00,
            0xfb,
            0xb9,
            12,
            0,
            0xfa,
            0xbe,
            0x00,
            0x20,
            0x23,
            0xff,
            0xb2,
            0x31,
            0x23,
            0xff,
            0x90,
            0x2e,
            0x28,
            0x94,
            displacement[0],
            displacement[1],
            0xa6,
            0xe2,
            0xf7,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0xcd, 0x20,
        ];
        for (dst, src) in input[start..start + plain.len()].iter_mut().zip(plain) {
            *dst = src.wrapping_add(0x31);
        }
        let Decoded {
            offset,
            data: decoded,
            ..
        } = decode(&input).expect("byte subtract recipe");
        assert_eq!(offset, stub);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (5, 0x90),
            (stub + 5, 60),
            (stub + 14, 0),
            (stub + 21, displacement[0].wrapping_add(1)),
            (stub + 25, 0xf6),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..stub + 25]).is_none());
    }

    #[test]
    fn decodes_byte_xor_fallthrough_and_rejects_bad_bounds() {
        let entry = 16usize;
        let start = entry + 15;
        let mut input = vec![0x90; 64];
        input[..3].copy_from_slice(&[0xe9, 13, 0]);
        let address = (0x100u16 + start as u16).to_le_bytes();
        input[entry..entry + 14].copy_from_slice(&[
            0xb2, 0x0e, 0xbe, address[0], address[1], 0xb9, 16, 0, 0x2e, 0x30, 0x14, 0x46, 0xe2,
            0xfa,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0x90, 0x90, 0x90, 0x90,
            0xcd, 0x20,
        ];
        for (dst, src) in input[start..start + plain.len()].iter_mut().zip(plain) {
            *dst = src ^ 0x0e;
        }
        let Decoded {
            offset,
            data: decoded,
            ..
        } = decode(&input).expect("byte XOR recipe");
        assert_eq!(offset, entry);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (entry + 1, 0),
            (entry + 3, 0),
            (entry + 6, 80),
            (entry + 13, 0xf9),
            (entry + 14, 0xcc),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..entry + 13]).is_none());
    }

    #[test]
    fn call_rotate_xor_recovers_bounded_words_and_rejects_invalid_stubs() {
        let mut input = vec![0x90; 128];
        let start = 16usize;
        let setup = 64usize;
        let stub_at = 80usize;
        let key = 0x304eu16;
        input[0] = 0xe8;
        input[1..3].copy_from_slice(&((stub_at as i16) - 3).to_le_bytes());
        input[3..5].copy_from_slice(&[0xeb, (start - 5) as u8]);
        input[40..42].copy_from_slice(&key.to_le_bytes());
        input[setup..setup + 16].copy_from_slice(&[
            0xc7, 0x06, 0x2a, 0x01, 0x08, 0x00, 0xbe, 0x10, 0x01, 0x8b, 0x0e, 0x28, 0x01, 0x8b,
            0xfe, 0xc3,
        ]);
        let displacement = ((setup as i16) - (stub_at as i16) - 3).to_le_bytes();
        input[stub_at..stub_at + 25].copy_from_slice(&[
            0xe8,
            displacement[0],
            displacement[1],
            0x83,
            0x3e,
            0x2a,
            0x01,
            0x00,
            0x74,
            0x0e,
            0xad,
            0x2b,
            0xc1,
            0x33,
            0xc1,
            0xd3,
            0xc0,
            0xab,
            0xff,
            0x0e,
            0x2a,
            0x01,
            0xeb,
            0xeb,
            0xc3,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0x90, 0x90, 0x90, 0x90,
            0xcd, 0x20,
        ];
        for (i, bytes) in plain.as_chunks::<2>().0.iter().enumerate() {
            let word = u16::from_le_bytes([bytes[0], bytes[1]]);
            let encoded = (word.rotate_right(u32::from(key & 0xff)) ^ key).wrapping_add(key);
            input[start + i * 2..start + i * 2 + 2].copy_from_slice(&encoded.to_le_bytes());
        }
        let Decoded {
            offset,
            data: decoded,
            ..
        } = decode(&input).expect("recognized rotate recipe");
        assert_eq!(offset, stub_at);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (3, 0x90),
            (setup + 4, 40),
            (setup + 11, 0x1f),
            (stub_at + 14, 0x90),
            (stub_at + 20, 0x20),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..100]).is_none());
    }

    #[test]
    fn rejects_changed_code_bounds_and_invalid_entry() {
        let input = fixture();
        for (offset, value) in [(64, 0xbf), (68, 0xba), (85, 0xe1), (69, 33), (73, 0)] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..70]).is_none());
    }
}
