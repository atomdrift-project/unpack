//! Bounded reconstruction of literal-only script recipes. No interpreter
//! is invoked. Unknown writes, expressions, keys, or mismatched variables stop
//! reconstruction; callers analyze recovered text as a separate source layer.
use regex::Regex;
use std::{collections::HashMap, sync::LazyLock};

use crate::Language;

/// One reconstructed source layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Where its recipe starts in the input.
    pub offset: usize,
    /// The reconstructed text.
    pub text: String,
    /// Its language, when the recipe determines it. A string a Python
    /// recipe writes out has none; the caller identifies it.
    pub language: Option<Language>,
}

const MAX_SOURCE: usize = 4 * 1024 * 1024;
const MAX_PARTS: usize = 8192;
const MAX_OUTPUT: usize = 1024 * 1024;

static JS_START: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
    r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+Array\s*\(\s*\)|\[\s*\]|\{\s*\})\s*;"
).ok()
});
static JS_WRITE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
    r#"^\s*([A-Za-z_$][\w$]*)\s*\[\s*("(?:\\.|[^"\\\r\n])*")\s*\]\s*=\s*("(?:\\.|[^"\\\r\n])*")\s*;"#
).ok()
});
static JS_EVAL: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"^\s*eval\s*\(\s*").ok());
static JS_READ: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"^\s*([A-Za-z_$][\w$]*)\s*\[\s*("(?:\\.|[^"\\\r\n])*")\s*\]\s*"#).ok()
});

static PS_RECIPE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(concat!(
    r"(?i)\$(\w+)\s*=\s*(-?\d{1,12})\s*;\s*",
    r"\$(\w+)\s*=\s*@\(\s*((?:-?\d{1,12}\s*,\s*){16,}-?\d{1,12})\s*\)\s*;\s*",
    r#"\$(\w+)\s*=\s*(?:''|"")\s*;\s*"#,
    r"for\s*\(\s*\$(\w+)\s*=\s*0\s*;\s*\$(\w+)\s*-lt\s*\$(\w+)\.Length\s*;\s*\$(\w+)\+\+\s*\)\s*\{\s*",
    r"\$(\w+)\s*\+=\s*\[char\]\s*\(\s*(?:\[(?:long|u?int\d*)\]\s*)?\$(\w+)\s*\[\s*\$(\w+)\s*\]\s*([+-])\s*\$(\w+)\s*\)\s*;?\s*\}\s*;?\s*",
    r"\[scriptblock\]\s*::\s*Create\s*\(\s*\$(\w+)\s*\)\s*\.\s*Invoke\s*\(\s*\)"
)).ok()
});

/// The layers literal-only recipes in `source` (at most 4 MiB) rebuild, at
/// most 1 MiB in all: Python character arrays and the strings they write,
/// JavaScript permutation and Packer layers and string-table `eval`s, and
/// PowerShell offset-`[char]` loops.
#[must_use]
pub fn decode(source: &str) -> Vec<Layer> {
    if source.len() > MAX_SOURCE {
        return Vec::new();
    }
    let mut results = Vec::new();
    let mut budget = MAX_OUTPUT;
    let mut push = |budget: &mut usize, offset, text: String, language| {
        if let Some(left) = budget.checked_sub(text.len()) {
            *budget = left;
            results.push(Layer {
                offset,
                text,
                language,
            });
        }
    };
    if let Some((decoded, scripts)) = crate::python_char_array::decode(source) {
        push(&mut budget, 0, decoded, Some(Language::Python));
        for (offset, script) in scripts {
            push(&mut budget, offset, script, None);
        }
    }
    for (offset, decoded) in crate::js_permutation::decode(source) {
        push(&mut budget, offset, decoded, Some(Language::JavaScript));
    }
    if let Some(decoded) = crate::js_decimal_packer::decode(source) {
        push(&mut budget, 0, decoded, Some(Language::JavaScript));
    }
    if source.contains("eval")
        && let Some(js_start) = JS_START.as_ref()
    {
        for start in js_start.captures_iter(source).take(64) {
            let (Some(whole), Some(name)) = (start.get(0), start.get(1)) else {
                continue;
            };
            let tail = source.get(whole.end()..).unwrap_or_default();
            if let Some(decoded) = js_table(tail, name.as_str(), budget) {
                push(
                    &mut budget,
                    whole.start(),
                    decoded,
                    Some(Language::JavaScript),
                );
            }
        }
    }
    if (source.contains("[char]") || source.to_ascii_lowercase().contains("[char]"))
        && let Some(ps_recipe) = PS_RECIPE.as_ref()
    {
        for cap in ps_recipe.captures_iter(source).take(64) {
            if let (Some(decoded), Some(whole)) = (ps_offset(&cap, budget), cap.get(0)) {
                push(
                    &mut budget,
                    whole.start(),
                    decoded,
                    Some(Language::PowerShell),
                );
            }
        }
    }
    results
}

fn js_table(mut tail: &str, name: &str, budget: usize) -> Option<String> {
    let mut table = HashMap::<String, String>::new();
    let mut stored = 0usize;
    for _ in 0..MAX_PARTS {
        let Some(cap) = JS_WRITE.as_ref()?.captures(tail) else {
            break;
        };
        if cap.get(1)?.as_str() != name {
            return None;
        }
        let key: String = serde_json::from_str(cap.get(2)?.as_str()).ok()?;
        let value: String = serde_json::from_str(cap.get(3)?.as_str()).ok()?;
        stored = stored.checked_add(key.len())?.checked_add(value.len())?;
        if stored > MAX_OUTPUT {
            return None;
        }
        table.insert(key, value);
        tail = tail.get(cap.get(0)?.end()..)?;
    }
    if table.len() < 4 {
        return None;
    }
    tail = tail.get(JS_EVAL.as_ref()?.find(tail)?.end()..)?;
    let mut decoded = String::new();
    for _ in 0..MAX_PARTS {
        let cap = JS_READ.as_ref()?.captures(tail)?;
        if cap.get(1)?.as_str() != name {
            return None;
        }
        let key: String = serde_json::from_str(cap.get(2)?.as_str()).ok()?;
        let value = table.get(&key)?;
        if decoded.len().checked_add(value.len())? > budget {
            return None;
        }
        decoded.push_str(value);
        tail = tail.get(cap.get(0)?.end()..)?;
        if tail.starts_with(')') {
            return Some(decoded);
        }
        tail = tail.strip_prefix('+')?;
    }
    None
}

fn ps_offset(cap: &regex::Captures<'_>, budget: usize) -> Option<String> {
    let equal = |a, b| {
        cap.get(a)
            .zip(cap.get(b))
            .is_some_and(|(x, y)| x.as_str().eq_ignore_ascii_case(y.as_str()))
    };
    if !equal(6, 7)
        || !equal(6, 9)
        || !equal(6, 12)
        || !equal(3, 8)
        || !equal(3, 11)
        || !equal(5, 10)
        || !equal(5, 15)
        || !equal(1, 14)
    {
        return None;
    }
    // Distinct bindings avoid changing the key/array while the decoder runs.
    for a in [1, 3, 5, 6] {
        for b in [1, 3, 5, 6] {
            if a < b && equal(a, b) {
                return None;
            }
        }
    }
    let key: i64 = cap.get(2)?.as_str().parse().ok()?;
    let subtract = cap.get(13)?.as_str() == "-";
    let mut units = Vec::new();
    for number in cap.get(4)?.as_str().split(',') {
        if units.len() >= MAX_PARTS {
            return None;
        }
        let n: i64 = number.trim().parse().ok()?;
        let n = if subtract {
            n.checked_sub(key)?
        } else {
            n.checked_add(key)?
        };
        units.push(u16::try_from(n).ok()?);
    }
    let decoded = String::from_utf16(&units).ok()?;
    (decoded.len() <= budget).then_some(decoded)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    fn js() -> String {
        r#"var tab = new Array(); tab["a"]="var ";tab["b"]="x = ";tab["c"]="1; ";tab["d"]="alert(x);";eval(tab["a"]+tab["b"]+tab["c"]+tab["d"]);"#.to_owned()
    }
    fn ps(key: i64, subtract: bool) -> String {
        let body = "Write-Output 'harmless decoder control'";
        let values = body
            .encode_utf16()
            .map(|n| {
                if subtract {
                    i64::from(n) + key
                } else {
                    i64::from(n) - key
                }
            })
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let op = if subtract { '-' } else { '+' };
        format!(
            "$offset={key};$parts=@({values});$text='';for($j=0;$j -lt $parts.Length;$j++){{$text += [char]([long] $parts[$j] {op} $offset)}};[scriptblock]::Create($text).Invoke()"
        )
    }
    #[test]
    fn table_and_renamed_table() {
        for s in [js(), js().replace("tab", "renamed_thing")] {
            assert_eq!(decode(&s)[0].text, "var x = 1; alert(x);");
        }
    }
    #[test]
    fn table_rejects_dynamic_unresolved_and_mutated_inputs() {
        for s in [
            js().replace("tab[\"b\"]+", "tab[dynamic]+"),
            js().replace("tab[\"a\"]+", "other[\"a\"]+"),
            js().replace("eval(", "tab=fetch();eval("),
            js().replace("tab[\"d\"]);", "tab[\"missing\"]);"),
            js().replace("eval(", "console.log("),
        ] {
            assert!(decode(&s).is_empty(), "{s}");
        }
    }
    #[test]
    fn offset_add_subtract_case_and_carrier() {
        for s in [
            ps(1520498, false),
            ps(73321, true),
            ps(45, false).to_ascii_uppercase(),
            format!("import subprocess\nstage=r\"\"\"{}\"\"\"", ps(85412, false)),
        ] {
            assert_eq!(
                decode(&s)[0].text,
                "Write-Output 'harmless decoder control'"
            );
        }
    }
    #[test]
    fn offset_rejects_binding_changes_and_bad_characters() {
        for s in [
            ps(50231, false).replace("Create($text)", "Create($other)"),
            ps(50231, false).replace("$parts[$j]", "$other[$j]"),
            ps(50231, false).replace("$j++", "$k++"),
            ps(50231, false).replace("+ $offset", "+ $dynamic"),
            ps(50231, false).replace("$offset=50231", "$offset=-999999999999"),
        ] {
            assert!(decode(&s).is_empty(), "{s}");
        }
    }
    #[test]
    fn bounded_and_decoding_does_not_assign_hostility() {
        assert!(decode(&"x".repeat(MAX_SOURCE + 1)).is_empty());
        assert!(js_table(js().split_once(';').expect("fixture separator").1, "tab", 2).is_none());
        assert!(decode(&ps(500, false))[0].text.starts_with("Write-Output"));
    }
}
