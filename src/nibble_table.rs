//! Reconstruct literal low/high nibble tables a script interpreter rebuilds
//! into its next stage. Only decimal literals are evaluated, never the
//! surrounding program. The reconstruction formula must be present, every
//! nibble must be 0–15, and the input is at most 1 MiB, which keeps
//! ordinary CSV data out.

use crate::Language;

/// The bytes a nibble table rebuilds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    /// Where the table starts in the input.
    pub offset: usize,
    /// The script that holds the table.
    pub language: Language,
    /// The rebuilt bytes, at least 24 of them.
    pub data: Vec<u8>,
}

/// Shortest rebuilt payload worth returning.
const MIN_PAYLOAD: usize = 24;

/// `hi * 16 + lo`, or `None` when either is not a nibble.
fn byte(lo: &str, hi: &str) -> Option<u8> {
    let (lo, hi) = (lo.parse::<u8>().ok()?, hi.parse::<u8>().ok()?);
    (lo <= 15 && hi <= 15).then(|| hi * 16 + lo)
}

/// PowerShell: `[int]… * 16 + [int]…` over `index,lo,hi` CSV rows.
fn powershell(source: &str) -> Option<(usize, Vec<u8>)> {
    let formula = static_regex!(r"(?i)\[int\].{0,40}\*\s*16\s*\+\s*\[int\]")?;
    if !formula.is_match(source) {
        return None;
    }
    let row = static_regex!(r"(?m)^\d{1,8},(\d{1,2}),(\d{1,2})\r?$")?;
    let offset = row.find(source).map_or(0, |m| m.start());
    let data = row
        .captures_iter(source)
        .map(|caps| byte(caps.get(1)?.as_str(), caps.get(2)?.as_str()))
        .collect::<Option<Vec<u8>>>()?;
    Some((offset, data))
}

/// VBScript: `Chr(CLng(…)*16+CLng…)` over `"lo.hi,lo.hi"` string chunks.
fn vbscript(source: &str) -> Option<(usize, Vec<u8>)> {
    let formula = static_regex!(r"(?i)Chr\(CLng\([^\r\n]{1,60}\)\*16\+CLng")?;
    if !formula.is_match(source) {
        return None;
    }
    let chunks = static_regex!(r#""([0-9.,]+)""#)?;
    let offset = chunks.find(source).map_or(0, |m| m.start());
    let is_pair = |pair: &str| {
        pair.split_once('.').is_some_and(|(lo, hi)| {
            !lo.is_empty()
                && !hi.is_empty()
                && lo.bytes().all(|b| b.is_ascii_digit())
                && hi.bytes().all(|b| b.is_ascii_digit())
        })
    };
    let joined: String = chunks
        .captures_iter(source)
        .filter_map(|c| {
            let chunk = c.get(1)?.as_str();
            (chunk == "," || chunk.split(',').filter(|s| !s.is_empty()).all(is_pair))
                .then_some(chunk)
        })
        .collect();
    let data = joined
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (lo, hi) = pair.split_once('.')?;
            byte(lo, hi)
        })
        .collect::<Option<Vec<u8>>>()?;
    Some((offset, data))
}

/// The payload a PowerShell or VBScript nibble table rebuilds.
#[must_use]
pub fn recover(data: &[u8]) -> Option<Table> {
    if data.len() > 1024 * 1024 {
        return None;
    }
    let source = std::str::from_utf8(data).ok()?;
    let lower = source.to_ascii_lowercase();
    let (language, (offset, data)) = if lower.contains("addscript") && lower.contains("[int]") {
        (Language::PowerShell, powershell(source)?)
    } else if lower.contains("chr(clng(") && lower.contains("\nexecute ") {
        (Language::VbScript, vbscript(source)?)
    } else {
        return None;
    };
    (data.len() >= MIN_PAYLOAD).then_some(Table {
        offset,
        language,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"Write-Output 'rebuilt from a nibble table'";

    #[test]
    fn powershell_rows() {
        let rows: String = PAYLOAD
            .iter()
            .enumerate()
            .map(|(i, b)| format!("{i},{},{}\n", b & 15, b >> 4))
            .collect();
        let script =
            format!("$ps.AddScript($s)\n$b = [int]$r.Hi * 16 + [int]$r.Lo\n$csv = @'\n{rows}'@\n");
        let table = recover(script.as_bytes()).unwrap();
        assert_eq!(table.language, Language::PowerShell);
        assert_eq!(table.data, PAYLOAD);
        assert!(recover(script.replace("* 16", "* 8").as_bytes()).is_none());
        assert!(recover(script.replacen(",4,", ",16,", 1).as_bytes()).is_none());
    }

    #[test]
    fn vbscript_chunks() {
        let pairs: Vec<String> = PAYLOAD
            .iter()
            .map(|b| format!("{}.{}", b & 15, b >> 4))
            .collect();
        let (a, b) = pairs.split_at(pairs.len() / 2);
        let script = format!(
            "s = \"{}\" & \",\" & \"{}\"\nx = Chr(CLng(Split(p,\".\")(1))*16+CLng(Split(p,\".\")(0)))\nExecute x\n",
            a.join(","),
            b.join(",")
        );
        let table = recover(script.as_bytes()).unwrap();
        assert_eq!(table.language, Language::VbScript);
        assert_eq!(table.data, PAYLOAD);
        assert!(recover(b"short").is_none());
    }
}
