//! Members of a Nuitka onefile payload: one Zstandard frame after a
//! three-byte marker, streamed to writers the caller opens.
//!
//! Two record layouts are read:
//!
//! - Windows: NUL-terminated UTF-16LE name, `u64` little-endian size, bytes.
//! - Cached POSIX (Mach-O hosts): NUL-terminated UTF-8 name, a flags byte,
//!   `u64` size, CRC-32, bytes. Links are rejected rather than created.
//!
//! An empty name ends the list. Uncached and newer table-of-contents
//! layouts are rejected: a failed extraction must not pass for complete
//! coverage. Names are validated before the caller sees them, and output
//! is bounded per member and in total, even when the frame omits its size.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Most bytes all members may hold.
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
/// Most bytes one member may hold; a larger member fails extraction.
pub const MAX_MEMBER: u64 = 512 * 1024 * 1024;
/// Most members read.
const MAX_MEMBERS: usize = 4096;
/// Longest member name, in units.
const MAX_NAME: usize = 4096;

/// A relative path for member `name` that cannot leave the output
/// directory: no root, drive, empty, `.` or `..` component.
fn member_path(name: &str) -> io::Result<PathBuf> {
    let name = name.replace('\\', "/");
    if name.starts_with('/')
        || name.contains(':')
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(io::Error::other("unsafe Nuitka member name"));
    }
    Ok(PathBuf::from(name))
}

fn utf16_name(reader: &mut impl Read) -> io::Result<String> {
    let mut units = Vec::new();
    for _ in 0..MAX_NAME {
        let mut pair = [0u8; 2];
        reader.read_exact(&mut pair)?;
        let unit = u16::from_le_bytes(pair);
        if unit == 0 {
            return String::from_utf16(&units)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err));
        }
        units.push(unit);
    }
    Err(io::Error::other("Nuitka member name too long"))
}

fn utf8_name(reader: &mut impl Read) -> io::Result<String> {
    let mut name = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        if byte == [0] {
            break;
        }
        if name.len() >= MAX_NAME {
            return Err(io::Error::other("Nuitka member name too long"));
        }
        name.extend_from_slice(&byte);
    }
    String::from_utf8(name).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn u64_le(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// One member's bytes as the visitor reads them, with their CRC-32.
struct Member<R> {
    inner: io::Take<R>,
    crc: crc32fast::Hasher,
}

impl<R: Read> Read for Member<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.crc.update(buf.get(..read).unwrap_or_default());
        Ok(read)
    }
}

/// The marker a Nuitka payload's Zstandard frame follows.
pub const PAYLOAD_MARKER: &[u8] = b"KAY\x28\xb5\x2f\xfd";

/// Where the Nuitka payload of `data` starts: the first [`PAYLOAD_MARKER`]
/// in a file that carries Nuitka's one-file runtime. A caller that knows
/// which markers lie inside embedded images (filefacts does) should pass
/// its own offset to [`extract`] instead.
#[must_use]
pub fn payload_offset(data: &[u8]) -> Option<usize> {
    memchr::memmem::find(data, b"NUITKA_ONEFILE_")?;
    memchr::memmem::find(data, PAYLOAD_MARKER)
}

/// Stream the members of the Nuitka payload whose marker starts `offset`
/// bytes into `data` (a Nuitka host executable), handing each to
/// `visit(relative path, bytes)`. Returns how many members were visited.
/// Whatever the visitor leaves unread is skipped.
///
/// The cached POSIX layout is read when `data` is a Mach-O image, the
/// Windows one otherwise.
///
/// # Errors
///
/// Any malformed, truncated, unsafe, duplicate or oversized record, a
/// failed CRC, a stream with no members, bytes after the terminator, and
/// whatever `visit` returns. Members already visited stay visited.
pub fn extract(
    data: &[u8],
    offset: usize,
    mut visit: impl FnMut(&Path, &mut dyn Read) -> io::Result<()>,
) -> io::Result<usize> {
    let frame = offset
        .checked_add(3)
        .and_then(|start| data.get(start..))
        .ok_or_else(|| io::Error::other("invalid Nuitka frame offset"))?;
    let posix = matches!(
        data.first_chunk::<4>(),
        Some([0xcf | 0xce, 0xfa, 0xed, 0xfe])
    );
    let decoder = zstd::stream::read::Decoder::new(frame)?.single_frame();
    let mut reader = decoder.take(MAX_TOTAL + 1);
    let mut total = 0u64;
    let mut names = HashSet::new();
    for count in 0..MAX_MEMBERS {
        let name = if posix {
            utf8_name(&mut reader)?
        } else {
            utf16_name(&mut reader)?
        };
        if name.is_empty() {
            let mut trailing = [0u8; 1];
            if count == 0 || reader.read(&mut trailing)? != 0 {
                return Err(io::Error::other("invalid Nuitka record terminator"));
            }
            tracing::debug!(members = count, bytes = total, "extracted Nuitka payload");
            return Ok(count);
        }
        let relative = member_path(&name)?;
        if !names.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(io::Error::other("duplicate Nuitka member"));
        }
        if posix {
            let mut flags = [0u8; 1];
            reader.read_exact(&mut flags)?;
            if flags[0] & !1 != 0 {
                return Err(io::Error::other("unsupported Nuitka member flags"));
            }
        }
        let size = u64_le(&mut reader)?;
        let expected_crc = if posix {
            let mut crc = [0u8; 4];
            reader.read_exact(&mut crc)?;
            Some(u32::from_le_bytes(crc))
        } else {
            None
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| io::Error::other("Nuitka member size overflow"))?;
        if size > MAX_MEMBER || total > MAX_TOTAL {
            return Err(io::Error::other("Nuitka extraction byte limit"));
        }
        let mut member = Member {
            inner: (&mut reader).take(size),
            crc: crc32fast::Hasher::new(),
        };
        visit(&relative, &mut member)?;
        io::copy(&mut member, &mut io::sink())?;
        if member.inner.limit() != 0 {
            return Err(io::Error::other("truncated Nuitka member"));
        }
        let actual = member.crc.finalize();
        // Nuitka stores a zero CRC as one.
        if expected_crc.is_some_and(|expected| expected != actual.max(1)) {
            return Err(io::Error::other("Nuitka member CRC mismatch"));
        }
    }
    Err(io::Error::other("Nuitka member count limit"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(name: &str) -> Vec<u8> {
        name.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn payload(records: &[u8]) -> Vec<u8> {
        let mut data = b"MZ host....KA\x19".to_vec();
        data.extend(zstd::encode_all(records, 1).unwrap());
        data
    }

    fn collect(data: &[u8], offset: usize) -> io::Result<Vec<(PathBuf, Vec<u8>)>> {
        let mut out = Vec::new();
        extract(data, offset, |path, member| {
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes)?;
            out.push((path.to_path_buf(), bytes));
            Ok(())
        })?;
        Ok(out)
    }

    #[test]
    fn windows_records_reach_the_visitor() {
        let mut records = utf16("lib/app.py");
        records.extend(5u64.to_le_bytes());
        records.extend(b"print");
        records.extend(utf16(""));
        let data = payload(&records);
        let members = collect(&data, 11).unwrap();
        assert_eq!(members, [(PathBuf::from("lib/app.py"), b"print".to_vec())]);
        // A visitor that reads nothing still leaves the stream aligned.
        assert_eq!(extract(&data, 11, |_, _| Ok(())).unwrap(), 1);
    }

    #[test]
    fn unsafe_duplicate_and_trailing_records_are_rejected() {
        for name in ["../escape", "/abs", "c:/x", "a//b"] {
            let mut records = utf16(name);
            records.extend(1u64.to_le_bytes());
            records.push(b'x');
            records.extend(utf16(""));
            assert!(collect(&payload(&records), 11).is_err(), "{name}");
        }
        let mut records = Vec::new();
        for _ in 0..2 {
            records.extend(utf16("same"));
            records.extend(1u64.to_le_bytes());
            records.push(b'x');
        }
        records.extend(utf16(""));
        assert!(collect(&payload(&records), 11).is_err(), "duplicate");
        assert!(collect(&payload(&utf16("")), 11).is_err(), "no members");
        assert!(collect(b"short", 11).is_err(), "offset past the end");
    }
}
