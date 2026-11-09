//! Attachments of a multipart MIME message, decoded by their declared
//! Base64 transfer encoding. Only ZIP, PE and ELF bodies are kept; at most
//! 16 parts of a message of at most 10 MiB are read.

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// What an attachment's body is, by its magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A ZIP archive.
    Zip,
    /// A PE executable.
    Pe,
    /// An ELF executable.
    Elf,
}

/// One decoded attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Where its encoded body starts in the input.
    pub offset: usize,
    /// What the body is.
    pub format: Format,
    /// The decoded body.
    pub data: Vec<u8>,
}

/// The ZIP, PE and ELF attachments of the MIME message `data`.
#[must_use]
pub fn attachments(data: &[u8]) -> Vec<Attachment> {
    if data.len() > 10 * 1024 * 1024 {
        return Vec::new();
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let lower = source.to_ascii_lowercase();
    if !lower.contains("mime-version:") || !lower.contains("multipart/") {
        return Vec::new();
    }
    let Some(parts) = static_regex!(
        r"(?im)content-transfer-encoding:[ \t]*base64[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([A-Za-z0-9+/=\r\n]+)"
    ) else {
        return Vec::new();
    };
    parts
        .captures_iter(source)
        .take(16)
        .filter_map(|caps| {
            let body = caps.get(1)?;
            let compact: String = body
                .as_str()
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            let data = STANDARD.decode(compact).ok()?;
            let format = if data.starts_with(b"PK\x03\x04") {
                Format::Zip
            } else if data.starts_with(b"MZ") {
                Format::Pe
            } else if data.starts_with(b"\x7fELF") {
                Format::Elf
            } else {
                return None;
            };
            Some(Attachment {
                offset: body.start(),
                format,
                data,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_supported_attachments_only() {
        let zip = STANDARD.encode(b"PK\x03\x04 archive bytes");
        let text = STANDARD.encode(b"hello");
        let message = format!(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
             Content-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\n\r\n{zip}\r\n--b\r\n\
             Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n{text}\r\n--b--\r\n"
        );
        let found = attachments(message.as_bytes());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].format, Format::Zip);
        assert_eq!(found[0].data, b"PK\x03\x04 archive bytes");
        assert_eq!(&message[found[0].offset..found[0].offset + 4], &zip[..4]);
        assert!(attachments(message.replace("multipart/", "single/").as_bytes()).is_empty());
    }
}
