//! Shared support for the script reconstructors: parsing a source the
//! caller has no syntax tree for, and decoding string-literal escapes.

use tree_sitter::{Language, Parser, Tree};

/// Largest source any reconstructor parses itself.
pub(crate) const MAX_SOURCE: usize = 4 * 1024 * 1024;

fn parse(source: &str, language: &Language) -> Option<Tree> {
    if source.len() > MAX_SOURCE {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(language).ok()?;
    parser.parse(source, None)
}

/// A JavaScript syntax tree for `source`, at most [`MAX_SOURCE`] bytes.
pub(crate) fn javascript(source: &str) -> Option<Tree> {
    parse(source, &tree_sitter_javascript::LANGUAGE.into())
}

/// A Python syntax tree for `source`, at most [`MAX_SOURCE`] bytes.
pub(crate) fn python(source: &str) -> Option<Tree> {
    parse(source, &tree_sitter_python::LANGUAGE.into())
}

/// Decode the escape sequences a parsed JavaScript or Python string body
/// carries, to the text the program uses. An unrecognized escape keeps its
/// backslash, and a doubled backslash stays one literal backslash.
///
/// This mirrors filefacts' `decode_source_escapes_for_type` for every
/// language but Lua, so a value recovered here equals the literal filefacts
/// reports; change both together.
pub(crate) fn decode_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(esc) = chars.next() else {
            out.push('\\');
            break;
        };
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '\\' | '\'' | '"' | '`' | '/' | '$' => out.push(esc),
            // A line continuation: neither character is part of the value.
            '\n' => {}
            'x' => match take_hex(&mut chars, 2).and_then(char::from_u32) {
                Some(decoded) => out.push(decoded),
                None => out.push_str("\\x"),
            },
            'u' => {
                let mut probe = chars.clone();
                match unicode_escape(&mut probe) {
                    Some(decoded) => {
                        chars = probe;
                        out.push(decoded);
                    }
                    None => out.push_str("\\u"),
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Exactly `n` hex digits, consumed only when all are present.
fn take_hex(chars: &mut Chars<'_>, n: usize) -> Option<u32> {
    let mut lookahead = chars.clone();
    let mut value = 0;
    for _ in 0..n {
        value = value * 16 + lookahead.next()?.to_digit(16)?;
    }
    *chars = lookahead;
    Some(value)
}

/// The body of a `\u` escape: `\uNNNN`, `\u{…}`, or a surrogate pair
/// written as two consecutive `\uNNNN` escapes.
fn unicode_escape(chars: &mut Chars<'_>) -> Option<char> {
    if chars.next_if_eq(&'{').is_some() {
        let mut value = 0;
        for (digits, d) in chars.by_ref().enumerate() {
            if d == '}' {
                return (digits > 0).then_some(value).and_then(char::from_u32);
            }
            if digits == 6 {
                return None;
            }
            value = value * 16 + d.to_digit(16)?;
        }
        return None;
    }
    let first = take_hex(chars, 4)?;
    if let Some(decoded) = char::from_u32(first) {
        return Some(decoded);
    }
    if !(0xD800..=0xDBFF).contains(&first) {
        return None;
    }
    let mut lookahead = chars.clone();
    if lookahead.next() != Some('\\') || lookahead.next() != Some('u') {
        return None;
    }
    let low = take_hex(&mut lookahead, 4)?;
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let decoded = char::from_u32(0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00))?;
    *chars = lookahead;
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_decode_like_filefacts() {
        assert_eq!(
            decode_escapes(r"powershell\x20-c\x20\x22irm\x22"),
            "powershell -c \"irm\""
        );
        assert_eq!(decode_escapes(r"\u0041\u{1F600}\ud83d\ude00"), "A😀😀");
        assert_eq!(decode_escapes(r"C:\\x41\d"), r"C:\x41\d");
        assert_eq!(decode_escapes(r"\u12"), r"\u12");
        assert_eq!(decode_escapes("a\\\nb"), "ab");
    }

    #[test]
    fn parsers_build_trees_within_bounds() {
        assert!(javascript("var a = 1;").is_some_and(|t| !t.root_node().has_error()));
        assert!(python("a = 1\n").is_some_and(|t| !t.root_node().has_error()));
        assert!(javascript(&" ".repeat(MAX_SOURCE + 1)).is_none());
    }
}
