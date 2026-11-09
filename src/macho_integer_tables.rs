//! Recover data encoded by x86-64 indexed subtract/XOR integer tables.
//!
//! Only recognized instruction forms and file-backed operands are read. No
//! specimen instructions are executed. A recovered alphabet is derived from
//! the file, and decoded text is returned without inferring intent.

use crate::image::{self, Section, file_offset};
use crate::primitives::{u32_le, unhex};

/// Text recovered from a Mach-O image, and where its encoded form starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    /// The decoded text.
    pub data: Vec<u8>,
    /// Where its encoded form starts in the input.
    pub offset: usize,
}

const MAX_TEXT: usize = 1024 * 1024;
const MAX_TABLES: usize = 32;

fn bytes(b: &[u8], p: usize, n: usize) -> Option<&[u8]> {
    b.get(p..p.checked_add(n)?)
}

fn rip(code: &[u8], va: u64, pos: usize) -> Option<u64> {
    let disp = i32::from_le_bytes(*bytes(code, pos.checked_add(3)?, 4)?.first_chunk()?);
    va.checked_add(u64::try_from(pos.checked_add(7)?).ok()?)?
        .checked_add_signed(i64::from(disp))
}

/// The byte table `arr - sub ^ xor`, each operand `count` little-endian
/// words, read as hex.
fn table(
    data: &[u8],
    sections: &[Section],
    arr: u64,
    sub: u64,
    xor: u64,
    count: usize,
) -> Option<Text> {
    if !(16..=MAX_TEXT).contains(&count) {
        return None;
    }
    let len = count.checked_mul(4)?;
    let [a, s, x] = [arr, sub, xor].map(|v| file_offset(sections, v, len));
    let (a, s, x) = (a?, s?, x?);
    let mut text = Vec::with_capacity(count);
    for i in 0..count {
        let j = i.checked_mul(4)?;
        let value = u32_le(data, a.checked_add(j)?)?.wrapping_sub(u32_le(data, s.checked_add(j)?)?)
            ^ u32_le(data, x.checked_add(j)?)?;
        text.push(value.to_le_bytes()[0]);
    }
    Some(Text {
        data: unhex(&text)?,
        offset: a,
    })
}

/// Base64 over a file-supplied alphabet of 64 distinct printable bytes,
/// accepted only when it decodes to mostly printable UTF-8.
#[expect(
    clippy::indexing_slicing,
    reason = "a 256-entry table indexed by a byte"
)]
fn base64_custom(data: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    if alphabet.len() != 64 {
        return None;
    }
    let mut lookup = [u8::MAX; 256];
    for (i, &ch) in alphabet.iter().enumerate() {
        if !(33..=126).contains(&ch) || lookup[usize::from(ch)] != u8::MAX {
            return None;
        }
        lookup[usize::from(ch)] = u8::try_from(i).ok()?;
    }
    let mut bits = 0u32;
    let mut count = 0u8;
    let mut out = Vec::new();
    for &ch in data {
        let n = lookup[usize::from(ch)];
        // Discarding unknown bytes could manufacture apparent code. Reject
        // unsupported padding rather than guessing an alphabet position.
        if n == u8::MAX {
            return None;
        }
        bits = (bits << 6) | u32::from(n);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count).to_le_bytes()[0]);
        }
    }
    if out.is_empty() || out.len() > MAX_TEXT || std::str::from_utf8(&out).is_err() {
        return None;
    }
    let printable = out
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    (printable * 100 >= out.len() * 95).then_some(out)
}

/// Text from at most 32 tables of at most 1 MiB each, in the Mach-O image
/// `data` (for a universal binary, its preferred slice). Unsupported
/// instruction layouts recover nothing.
#[must_use]
pub fn recover(data: &[u8]) -> Vec<Text> {
    if data.len() > 32 * 1024 * 1024 {
        return Vec::new();
    }
    image::macho(data).map_or_else(Vec::new, |sections| recover_sections(data, &sections))
}

/// The sequential loop: sub and xor table addresses are loaded into
/// r15/r13 and the data table into rax; the same r12 index is used in all
/// three operations, and the result goes to `push_back`.
fn sequential(data: &[u8], sections: &[Section], code: &[u8], va: u64, pos: usize) -> Option<Text> {
    if bytes(code, pos, 3)? != [0x4c, 0x8d, 0x3d] || bytes(code, pos + 7, 3)? != [0x4c, 0x8d, 0x2d]
    {
        return None;
    }
    let sub = rip(code, va, pos)?;
    let xor = rip(code, va, pos + 7)?;
    // The data-table load directly precedes the indexed sub/xor/sign-extend.
    let q = (pos + 14..(pos + 100).min(code.len())).find(|&q| {
        bytes(code, q, 3) == Some(&[0x48, 0x8d, 0x05])
            && bytes(code, q + 7, 17)
                == Some(&[
                    0x42, 0x8b, 0x04, 0xa0, 0x43, 0x2b, 0x04, 0xa7, 0x43, 0x33, 0x44, 0xa5, 0x00,
                    0x0f, 0xbe, 0xf0, 0x48,
                ])
    })?;
    let mut count = None;
    for k in pos + 14..q {
        match bytes(code, k, 3) {
            Some([0x41, 0x83, 0xfc]) => {
                count = code.get(k + 3).map(|&b| usize::from(b) + 1);
            }
            Some([0x41, 0x81, 0xfc]) => {
                count = u32_le(code, k + 3)
                    .and_then(|n| usize::try_from(n).ok())
                    .and_then(|n| n.checked_add(1));
            }
            _ => {}
        }
    }
    table(data, sections, rip(code, va, q)?, sub, xor, count?)
}

/// The permuted loop: rcx is an index permutation; rdx/rsi/rdi hold the
/// three operand tables; each decoded byte is stored at its index.
fn permuted(data: &[u8], sections: &[Section], code: &[u8], va: u64, pos: usize) -> Option<Text> {
    let loads = [
        (pos, [0x48, 0x8d, 0x0d]),
        (pos + 7, [0x48, 0x8d, 0x15]),
        (pos + 14, [0x48, 0x8d, 0x35]),
        (pos + 21, [0x48, 0x8d, 0x3d]),
    ];
    if !loads
        .iter()
        .all(|&(at, op)| bytes(code, at, 3) == Some(&op))
    {
        return None;
    }
    let [order, arr, sub, xor] = loads.map(|(at, _)| rip(code, va, at));
    let (order, arr, sub, xor) = (order?, arr?, sub?, xor?);
    let n = usize::try_from(xor.checked_sub(arr)? / 4).ok()?;
    if !(16..=MAX_TEXT).contains(&n) || sub.checked_sub(xor) != u64::try_from(n * 4).ok() {
        return None;
    }
    let order_offset = file_offset(sections, order, n * 4)?;
    let mut seen = vec![false; n];
    for i in 0..n {
        let idx = usize::try_from(u32_le(data, order_offset + i * 4)?).ok()?;
        match seen.get_mut(idx) {
            Some(slot) if !*slot => *slot = true,
            _ => return None,
        }
    }
    let window = code.get(pos..(pos + 160).min(code.len()))?;
    if !window.windows(12).any(|w| {
        w == [
            0x46, 0x8b, 0x0c, 0x82, 0x46, 0x2b, 0x0c, 0x86, 0x46, 0x33, 0x0c, 0x87,
        ]
    }) {
        return None;
    }
    table(data, sections, arr, sub, xor, n)
}

fn recover_sections(data: &[u8], sections: &[Section]) -> Vec<Text> {
    let Some(text) = sections.iter().find(|s| s.name.ends_with("__text")) else {
        return Vec::new();
    };
    let Some(code) = text
        .bytes(data)
        .filter(|code| code.len() <= 2 * 1024 * 1024)
    else {
        return Vec::new();
    };
    let mut tables = Vec::new();
    for pos in 0..code.len() {
        if tables.len() == MAX_TABLES {
            break;
        }
        tables.extend(sequential(data, sections, code, text.vaddr, pos));
        tables.extend(permuted(data, sections, code, text.vaddr, pos));
    }
    // A 64-byte table is an alphabet; every other table may be text in it.
    let mut result: Vec<Text> = Vec::new();
    for alphabet in tables.iter().filter(|t| t.data.len() == 64) {
        for t in tables.iter().filter(|t| t.data.len() != 64) {
            if let Some(data) = base64_custom(&t.data, &alphabet.data)
                && !result.iter().any(|r| r.data == data)
            {
                result.push(Text {
                    data,
                    offset: t.offset,
                });
            }
        }
    }
    result
}

/// The script inside a complete single-quoted `osascript -e '…'`
/// invocation, optionally backgrounded. Shell tails and incomplete
/// wrappers are never taken for script source.
#[must_use]
pub fn inline_applescript(command: &str) -> Option<&str> {
    let body = command.strip_prefix("osascript -e '")?;
    body.strip_suffix("'&")
        .or_else(|| body.strip_suffix("' &"))
        .or_else(|| body.strip_suffix('\''))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Unpadded base64 over `alphabet`.
    pub(crate) fn encode(input: &[u8], alphabet: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in input.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                out.push(alphabet[(n >> (18 - 6 * i)) as usize & 63]);
            }
        }
        out
    }

    fn fixture(command: &[u8], permuted: bool) -> (Vec<u8>, Vec<Section>) {
        let encoded = encode(command, STANDARD);
        let inputs = [STANDARD.as_slice(), &encoded];
        let mut data = vec![0x90; 512];
        for (i, input) in inputs.iter().enumerate() {
            let hex = hex::encode(input);
            let n = hex.len();
            let a = data.len();
            for b in hex.bytes() {
                data.extend_from_slice(&((u32::from(b) ^ 0x39) + 11).to_le_bytes());
            }
            let first = data.len();
            for _ in 0..n {
                data.extend_from_slice(&(if permuted { 0x39u32 } else { 11u32 }).to_le_bytes());
            }
            let second = data.len();
            for _ in 0..n {
                data.extend_from_slice(&(if permuted { 11u32 } else { 0x39u32 }).to_le_bytes());
            }
            let (sub, xor) = if permuted {
                (second, first)
            } else {
                (first, second)
            };
            let order = data.len();
            if permuted {
                for idx in (0..n).rev() {
                    data.extend_from_slice(&(idx as u32).to_le_bytes());
                }
            }
            let p = i * 100;
            let loads = if permuted {
                vec![
                    (p, [0x48, 0x8d, 0x0d], order),
                    (p + 7, [0x48, 0x8d, 0x15], a),
                    (p + 14, [0x48, 0x8d, 0x35], sub),
                    (p + 21, [0x48, 0x8d, 0x3d], xor),
                ]
            } else {
                vec![
                    (p, [0x4c, 0x8d, 0x3d], sub),
                    (p + 7, [0x4c, 0x8d, 0x2d], xor),
                    (p + 32, [0x48, 0x8d, 0x05], a),
                ]
            };
            for (at, op, target) in loads {
                data[at..at + 3].copy_from_slice(&op);
                data[at + 3..at + 7]
                    .copy_from_slice(&((target as i32) - (at as i32) - 7).to_le_bytes());
            }
            if permuted {
                data[p + 32..p + 44].copy_from_slice(&[
                    0x46, 0x8b, 0x0c, 0x82, 0x46, 0x2b, 0x0c, 0x86, 0x46, 0x33, 0x0c, 0x87,
                ]);
                continue;
            }
            data[p + 16..p + 19].copy_from_slice(&[0x41, 0x81, 0xfc]);
            data[p + 19..p + 23].copy_from_slice(&((n - 1) as u32).to_le_bytes());
            data[p + 39..p + 56].copy_from_slice(&[
                0x42, 0x8b, 0x04, 0xa0, 0x43, 0x2b, 0x04, 0xa7, 0x43, 0x33, 0x44, 0xa5, 0x00, 0x0f,
                0xbe, 0xf0, 0x48,
            ]);
        }
        let section = |name: &str, offset: usize, size: usize| Section {
            name: name.to_string(),
            vaddr: 4096 + offset as u64,
            offset,
            size,
            executable: false,
        };
        let sections = vec![
            section("__TEXT,__text", 0, 512),
            section("__TEXT,__const", 512, data.len() - 512),
        ];
        (data, sections)
    }

    #[test]
    fn table_recovery_and_malformed_operands() {
        let command = b"osascript -e 'display dialog \"inert fixture\"'&";
        let (data, sections) = fixture(command, false);
        let recovered = recover_sections(&data, &sections);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].data, command);
        assert_eq!(
            inline_applescript(std::str::from_utf8(command).unwrap()),
            Some("display dialog \"inert fixture\"")
        );
        assert_eq!(
            inline_applescript("osascript -e 'x'; touch /tmp/wrong"),
            None
        );
        let mut corrupted = data.clone();
        corrupted[100 + 39 + 5] = 0x03; // ADD is not the recognized SUB instruction.
        assert!(recover_sections(&corrupted, &sections).is_empty());
        for end in [0, 16, 200, 512, data.len() - 4] {
            assert!(recover_sections(&data[..end], &sections).is_empty());
        }
    }

    #[test]
    fn permuted_table_recovery_and_bad_index() {
        let command = b"osascript -e 'display dialog \"permuted fixture\"'&";
        let (data, sections) = fixture(command, true);
        let recovered = recover_sections(&data, &sections);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].data, command);
        let mut corrupted = data.clone();
        // The first loop's permutation address is a RIP-relative operand.
        let target = 7 + i32::from_le_bytes(data[3..7].try_into().unwrap()) as usize;
        corrupted[target..target + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(recover_sections(&corrupted, &sections).is_empty());
        corrupted = data.clone();
        corrupted[100 + 32 + 5] = 0x03;
        assert!(recover_sections(&corrupted, &sections).is_empty());
    }

    #[test]
    fn custom_alphabet_and_invalid_inputs() {
        assert_eq!(
            base64_custom(b"ZWNobyBvaw", STANDARD).as_deref(),
            Some(b"echo ok".as_slice())
        );
        assert!(base64_custom(b"ZWNobyBvaw!", STANDARD).is_none());
        assert!(base64_custom(b"ZWNobyBvaw", &[b'A'; 64]).is_none());
        assert!(base64_custom(b"////", STANDARD).is_none());
        assert_eq!(encode(b"echo ok", STANDARD), b"ZWNobyBvaw");
        assert!(recover(b"not a mach-o").is_empty());
    }
}
