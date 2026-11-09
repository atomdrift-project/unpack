//! # unpack
//!
//! Recovers the bytes a file hides: the image inside a packed executable,
//! resources compressed into a loader, scripts bundled into a native host.
//! Every method decodes data; none executes a sample, resolves an import or
//! runs an external program.
//!
//! Each method is bounded, recognizes its own container, validates its
//! output, and returns either the files it recovered or why it could not.
//! A method handed bytes it does not recognize recovers nothing, so
//! [`try_all`] needs no file identification; a caller that already knows
//! the type (from [filefacts], say) can call one method directly. Nothing
//! here judges whether a result is malicious: the caller analyzes the
//! recovered files and decides.
//!
//! The library depends on neither filefacts nor stng, so either can use it.
//!
//! ```no_run
//! let data = std::fs::read("sample.exe")?;
//! let outcome = unpack::try_all(&data, &unpack::Options::default());
//! for file in &outcome.unpacked {
//!     println!("{} via {} ({} bytes)", file.name, file.method, file.data.len());
//! }
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [filefacts]: https://github.com/atomdrift-project/filefacts
#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        reason = "test fixtures build binary layouts from literals; the non-test \
                  lib target lints production code"
    )
)]

/// A regex compiled once, on first use; `None` if the pattern is invalid.
macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new($pattern).ok()).as_ref()
    }};
}

pub mod aes_payload;
pub mod batch_self_hex;
pub mod cfml;
pub mod dos_word_xor;
pub mod fragment_gcm_pe;
pub mod hex_rc4_nextbyte;
mod image;
#[cfg(feature = "script")]
pub mod js_decimal_packer;
#[cfg(feature = "script")]
pub mod js_joined_module;
#[cfg(feature = "script")]
pub mod js_permutation;
#[cfg(feature = "script")]
pub mod js_string_table;
#[cfg(feature = "script")]
pub mod js_xor_command;
#[cfg(feature = "script")]
pub mod literal_program;
pub mod macho_chacha;
pub mod macho_hex_scripts;
pub mod macho_integer_tables;
pub mod media_pe;
pub mod metamorphic_graft;
pub mod mime;
pub mod mpress;
pub mod nibble_table;
pub mod node_sea;
pub mod nrv32;
pub mod nrv8;
pub mod nuitka;
pub mod powershell_literals;
pub mod powershell_payloads;
mod primitives;
pub mod ps_to_exe;
pub mod pyinstaller;
#[cfg(feature = "script")]
pub mod python_char_array;
#[cfg(feature = "script")]
pub mod python_encoded_command;
pub mod rc4_pe_table;
#[cfg(feature = "script")]
mod script;
pub mod skc3_pe;
pub mod upx;

/// Every method [`try_all`] runs: its name in [`Unpacked::method`] and what
/// it recovers from.
pub const METHODS: &[(&str, &str)] = &[
    (
        "mpress-lzma",
        "resources in an MPRESS 2.x x86 LZMA-packed PE",
    ),
    (
        "node-sea-resource",
        "sources and assets of a Node.js single-executable application",
    ),
    (
        "nrv2b-memory-image",
        "the memory image an x86 NRV2B (UPX-style) stub rebuilds",
    ),
    (
        "feedback-stream-rc4",
        "a DLL grafted behind an x86 feedback-stream/RC4 decoder",
    ),
    ("rc4-table", "PE files in an x86-64 code-relative RC4 table"),
    (
        "fragment-gcm",
        "a PE in a fragmented, XOR-masked AES-GCM envelope",
    ),
    (
        "fragment-gcm/skc3",
        "the SKC3-encrypted PE inside a fragment-gcm member",
    ),
    (
        "hex-rc4-nextbyte",
        "a PE in a hex/RC4/forward-feedback envelope",
    ),
    (
        "ps-to-exe-rc4",
        "PowerShell in the RC4 resources of a PowerShell-to-EXE stub",
    ),
    (
        "integer-sub-xor",
        "text in x86-64 Mach-O subtract/XOR integer tables",
    ),
    ("hex-rc4", "an inline AppleScript as hex RC4 Mach-O strings"),
    (
        "hex-custom-base64",
        "an inline AppleScript as hex custom-alphabet base64 Mach-O strings",
    ),
    (
        "lcg-xor",
        "an inline AppleScript under an LCG XOR stream in Mach-O constants",
    ),
    (
        "chacha20-poly1305",
        "a compiled AppleScript in a code-bound Mach-O ChaCha20 envelope",
    ),
    (
        "certutil-hex",
        "a PE a batch script writes from its own hex text via certutil",
    ),
    (
        "aes-128-cbc",
        "a payload a script decrypts with AES-128-CBC",
    ),
    (
        "aes-256-cbc",
        "a payload a script decrypts with AES-256-CBC",
    ),
    ("media-base64-pe", "a PE stored as one Base64 run"),
    ("media-xor-pe", "a PE under a single-byte XOR key"),
    (
        "mime-base64",
        "ZIP, PE and ELF attachments of a MIME message",
    ),
    (
        "nibble-table",
        "the next stage a PowerShell or VBScript nibble table rebuilds",
    ),
    (
        "character-table",
        "a PowerShell script with its character tables rebuilt",
    ),
    (
        "decimal-byte-array",
        "a PE in a PowerShell typed decimal byte array",
    ),
    (
        "base64/aes-cbc",
        "a payload PowerShell decrypts from Base64 with AES-CBC",
    ),
    (
        "base64/xor",
        "a PE PowerShell decodes from Base64 with a repeating XOR key",
    ),
    (
        "base64/xor/base64",
        "a PE PowerShell decodes from Base64, XOR, then Base64",
    ),
    (
        "cfml-des",
        "the source of an Allaire DES-encrypted ColdFusion template",
    ),
    ("pyinstaller", "modules and files of a PyInstaller bundle"),
    ("nuitka", "files of a Nuitka one-file bundle"),
    ("dos-word-xor", "a DOS COM image behind a word-XOR stub"),
    ("dos-byte-xor", "a DOS COM image behind a byte-XOR stub"),
    (
        "dos-byte-subtract",
        "a DOS COM image behind a byte-subtract stub",
    ),
    (
        "dos-word-sub-xor-rotate",
        "a DOS COM image behind a subtract/XOR/rotate stub",
    ),
    #[cfg(feature = "script")]
    (
        "javascript-literal-program",
        "JavaScript a permutation, Packer or string-table recipe rebuilds",
    ),
    #[cfg(feature = "script")]
    (
        "python-literal-program",
        "Python with its built-in character-array recipes rebuilt",
    ),
    #[cfg(feature = "script")]
    (
        "python-written-string",
        "a string a Python character-array recipe writes out",
    ),
    #[cfg(feature = "script")]
    (
        "powershell-literal-program",
        "PowerShell an offset-[char] loop rebuilds",
    ),
    #[cfg(feature = "script")]
    (
        "js-constant-string-table",
        "JavaScript with checksum-rotated string-table reads resolved",
    ),
    #[cfg(feature = "script")]
    (
        "hex/xor",
        "a command line JavaScript decodes from hex and XOR and executes",
    ),
    #[cfg(feature = "script")]
    (
        "js-joined-base64-module",
        "a JavaScript module imported as a joined base64 data URL",
    ),
    #[cfg(feature = "script")]
    (
        "scrypt/aes-256-cbc",
        "JavaScript an imported module decrypts with scrypt and AES-256-CBC",
    ),
    #[cfg(feature = "script")]
    (
        "python-encoded-command",
        "a shell command Python decodes from constants and runs",
    ),
];

/// The script language a recovered text is written in, when a method
/// knows it: a hint for the caller's analyzer, not file identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// JavaScript or TypeScript.
    JavaScript,
    /// Python.
    Python,
    /// A POSIX shell script.
    Shell,
    /// PowerShell.
    PowerShell,
    /// VBScript.
    VbScript,
    /// A Windows command line or batch file.
    Batch,
}

impl Language {
    /// The language's lower-case name, e.g. `javascript`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Shell => "shell",
            Self::PowerShell => "powershell",
            Self::VbScript => "vbscript",
            Self::Batch => "batch",
        }
    }

    /// The file extension its sources conventionally use.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::JavaScript => "js",
            Self::Python => "py",
            Self::Shell => "sh",
            Self::PowerShell => "ps1",
            Self::VbScript => "vbs",
            Self::Batch => "bat",
        }
    }
}

/// One file recovered from inside another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpacked {
    /// The file's path inside its parent, e.g. `mpress/resource-1a0.exe`.
    pub name: String,
    /// How it was recovered, as one step of an encoding chain
    /// (`mpress-lzma`, `node-sea-resource`, …).
    pub method: &'static str,
    /// The recovered bytes.
    pub data: Vec<u8>,
}

/// A method recognized its container but could not recover from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The method that gave up, e.g. `mpress`.
    pub method: &'static str,
    /// Why, in the method's words.
    pub reason: String,
}

/// What [`try_all`] recovered from one file, and what it could not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Recovered files, in the order the methods ran.
    pub unpacked: Vec<Unpacked>,
    /// Methods that recognized their container and failed.
    pub failures: Vec<Failure>,
}

impl Outcome {
    /// Record a file recovered by `method`, which [`METHODS`] lists.
    fn push(&mut self, name: String, method: &'static str, data: Vec<u8>) {
        debug_assert!(
            METHODS.iter().any(|&(listed, _)| listed == method),
            "method {method} is missing from METHODS"
        );
        self.unpacked.push(Unpacked { name, method, data });
    }
}

/// Which methods [`try_all`] may apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Rebuild the memory image an x86 NRV2B (UPX-style) stub would produce.
    /// The image has unresolved imports and is for analysis only.
    pub nrv_memory_image: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            nrv_memory_image: true,
        }
    }
}

/// Every method, run in turn; each recovers only from a container it
/// recognizes.
pub fn try_all(data: &[u8], options: &Options) -> Outcome {
    let mut outcome = Outcome::default();
    pe(data, *options, &mut outcome);
    macho(data, &mut outcome);
    script(data, &mut outcome);
    #[cfg(feature = "script")]
    scripts(data, &mut outcome);
    legacy(data, &mut outcome);
    installers(data, &mut outcome);
    outcome
}

/// The PE methods: MPRESS resources, Node single-executable members, the
/// NRV2B memory image, the RC4 and AES-GCM payload envelopes, and
/// PowerShell-to-EXE resources.
fn pe(data: &[u8], options: Options, outcome: &mut Outcome) {
    match mpress::recover(data) {
        Ok(resources) => {
            for resource in resources {
                let suffix = if resource.executable { "exe" } else { "txt" };
                outcome.push(
                    format!("mpress/resource-{:x}.{suffix}", resource.rva),
                    "mpress-lzma",
                    resource.data,
                );
            }
        }
        Err(reason) => outcome.failures.push(Failure {
            method: "mpress",
            reason: reason.to_string(),
        }),
    }

    for member in node_sea::recover(data).unwrap_or_default() {
        outcome.push(
            format!("node-sea/{}", member.name),
            "node-sea-resource",
            member.data,
        );
    }

    if options.nrv_memory_image {
        match nrv32::recover(data) {
            Ok(Some(image)) => outcome.push(
                "nrv2b/memory-image.dll".to_string(),
                "nrv2b-memory-image",
                image,
            ),
            Ok(None) => {}
            Err(reason) => outcome.failures.push(Failure {
                method: "nrv2b",
                reason: reason.to_string(),
            }),
        }
    }

    if let Some(graft) = metamorphic_graft::recover(data) {
        outcome.push(
            format!("feedback-rc4/payload-{}.dll", graft.offset),
            "feedback-stream-rc4",
            graft.data,
        );
    }

    for member in rc4_pe_table::recover(data) {
        outcome.push(
            format!("rc4-table/payload-{}.exe", member.offset),
            "rc4-table",
            member.data,
        );
    }

    let mut sealed = fragment_gcm_pe::recover_chain(data);
    if let Some(member) = hex_rc4_nextbyte::recover(data) {
        sealed.push((
            fragment_gcm_pe::Member {
                offset: member.offset,
                data: member.data,
            },
            "hex-rc4-nextbyte",
        ));
    }
    for (member, method) in sealed {
        outcome.push(
            format!("{method}/payload-{}.exe", member.offset),
            method,
            member.data,
        );
    }

    for script in ps_to_exe::recover(data) {
        outcome.push(
            format!("ps-to-exe/resource-{}.ps1", script.offset),
            "ps-to-exe-rc4",
            script.data,
        );
    }
}

/// The script reconstructors. Those that walk a syntax tree get one parse
/// of the input, made only when the markers they need are present.
#[cfg(feature = "script")]
fn scripts(data: &[u8], outcome: &mut Outcome) {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let javascript = ["parseInt", "Buffer", "data:text/javascript;base64,"];
    if javascript.iter().any(|marker| source.contains(marker))
        && let Some(tree) = script::javascript(source)
    {
        javascript_trees(source, &tree, outcome);
    }
    if source.contains("b32decode")
        && let Some(tree) = script::python(source)
    {
        for command in python_encoded_command::decode(source, &tree) {
            outcome.push(
                format!("python-encoded-command/command-{}.sh", command.offset),
                "python-encoded-command",
                command.text.into_bytes(),
            );
        }
    }
    for layer in literal_program::decode(source) {
        let (method, suffix) = match layer.language {
            Some(Language::Python) => ("python-literal-program", "py"),
            Some(Language::PowerShell) => ("powershell-literal-program", "ps1"),
            Some(_) => ("javascript-literal-program", "js"),
            None => ("python-written-string", "txt"),
        };
        outcome.push(
            format!("{method}/layer-{}.{suffix}", layer.offset),
            method,
            layer.text.into_bytes(),
        );
    }
}

/// The reconstructors over a JavaScript syntax tree.
#[cfg(feature = "script")]
fn javascript_trees(source: &str, tree: &tree_sitter::Tree, outcome: &mut Outcome) {
    if let Some(reduced) = js_string_table::decode(source, tree) {
        outcome.push(
            "js-constant-string-table/source.js".to_string(),
            "js-constant-string-table",
            reduced.into_bytes(),
        );
    }
    for command in js_xor_command::decode(source, tree) {
        let suffix = command.language.extension();
        outcome.push(
            format!("hex-xor/command-{}.{suffix}", command.offset),
            "hex/xor",
            command.text.into_bytes(),
        );
    }
    for (offset, module) in js_joined_module::decode(source, tree) {
        let layers = js_joined_module::encrypted_layers(source, tree, &module, offset);
        for (index, (layer, _)) in layers.into_iter().enumerate() {
            outcome.push(
                format!("scrypt-aes/module-{offset}-{index}.js"),
                "scrypt/aes-256-cbc",
                layer.into_bytes(),
            );
        }
        outcome.push(
            format!("js-joined-base64-module/module-{offset}.js"),
            "js-joined-base64-module",
            module.into_bytes(),
        );
    }
}

/// The installer bundles: PyInstaller archives and Nuitka one-file payloads.
fn installers(data: &[u8], outcome: &mut Outcome) {
    if pyinstaller::is_pyinstaller(data) {
        match pyinstaller::extract_to_memory(data) {
            Ok(bundle) => {
                for entry in bundle.entries {
                    outcome.push(
                        format!("pyinstaller/{}", entry.name),
                        "pyinstaller",
                        entry.data,
                    );
                }
            }
            Err(err) => outcome.failures.push(Failure {
                method: "pyinstaller",
                reason: err.to_string(),
            }),
        }
    }
    if let Some(offset) = nuitka::payload_offset(data) {
        let mut members = Vec::new();
        let read = nuitka::extract(data, offset, |path, member| {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(member, &mut bytes)?;
            members.push((path.to_string_lossy().into_owned(), bytes));
            Ok(())
        });
        if let Err(err) = read {
            outcome.failures.push(Failure {
                method: "nuitka",
                reason: err.to_string(),
            });
        }
        for (name, bytes) in members {
            outcome.push(format!("nuitka/{name}"), "nuitka", bytes);
        }
    }
}

/// The DOS and template methods: COM decoder stubs and encrypted ColdFusion
/// templates.
fn legacy(data: &[u8], outcome: &mut Outcome) {
    if let Some(decoded) = dos_word_xor::decode(data) {
        let method = decoded.recipe.name();
        outcome.push(
            format!("{method}/payload-{}.com", decoded.offset),
            method,
            decoded.data,
        );
    }
    if let Some(source) = cfml::decrypt_template(data) {
        outcome.push("cfml-des/template.cfm".to_string(), "cfml-des", source);
    }
}

/// The Mach-O methods: scripts in integer tables, hex/RC4, custom base64
/// and LCG-XOR strings, and the ChaCha20 script envelope.
fn macho(data: &[u8], outcome: &mut Outcome) {
    let texts = [
        ("integer-sub-xor", macho_integer_tables::recover(data)),
        ("hex-rc4", macho_hex_scripts::recover(data)),
        ("hex-custom-base64", macho_hex_scripts::recover_custom(data)),
        ("lcg-xor", macho_hex_scripts::recover_lcg(data)),
    ];
    for (method, found) in texts {
        for text in found {
            outcome.push(
                format!("{method}/text-{}.txt", text.offset),
                method,
                text.data,
            );
        }
    }
    for script in macho_chacha::recover(data) {
        outcome.push(
            format!("chacha20-poly1305/script-{}.scpt", script.offset),
            "chacha20-poly1305",
            script.data,
        );
    }
}

/// The script and carrier methods: a batch file's certutil hex payload,
/// AES-CBC payloads, PowerShell literal payloads and character tables,
/// nibble tables, MIME attachments, and Base64 or XOR-encoded PE images.
fn script(data: &[u8], outcome: &mut Outcome) {
    if let Some(payload) = batch_self_hex::recover(data) {
        outcome.push(
            format!("certutil-hex/payload-{}.exe", payload.offset),
            "certutil-hex",
            payload.data,
        );
    }
    for payload in aes_payload::extract_aes_payloads(data) {
        // Only the two CBC key sizes are ever decrypted.
        let method = if payload.algorithm.contains("128") {
            "aes-128-cbc"
        } else {
            "aes-256-cbc"
        };
        let suffix = match payload.detected_type {
            Some(language) => language.extension(),
            None => "bin",
        };
        outcome.push(
            format!("{method}/payload-{}.{suffix}", payload.original_offset),
            method,
            payload.data,
        );
    }
    for payload in powershell_payloads::extract(data) {
        let suffix = match payload.kind {
            powershell_payloads::Kind::Pe => "exe",
            powershell_payloads::Kind::Text => "txt",
        };
        outcome.push(
            format!("{}/payload-{}.{suffix}", payload.encoding, payload.offset),
            payload.encoding,
            payload.data,
        );
    }
    if let Some(script) = powershell_literals::recover(data) {
        outcome.push(
            "character-table/script.ps1".to_string(),
            "character-table",
            script.into_bytes(),
        );
    }
    if let Some(table) = nibble_table::recover(data) {
        outcome.push(
            format!(
                "nibble-table/payload-{}.{}",
                table.offset,
                table.language.extension()
            ),
            "nibble-table",
            table.data,
        );
    }
    for attachment in mime::attachments(data) {
        let suffix = match attachment.format {
            mime::Format::Zip => "zip",
            mime::Format::Pe => "exe",
            mime::Format::Elf => "elf",
        };
        outcome.push(
            format!("mime/attachment-{}.{suffix}", attachment.offset),
            "mime-base64",
            attachment.data,
        );
    }
    let images = [
        ("media-base64-pe", media_pe::base64_pes(data)),
        ("media-xor-pe", media_pe::xor_pes(data)),
    ];
    for (method, found) in images {
        for image in found {
            outcome.push(
                format!("{method}/payload-{}.exe", image.offset),
                method,
                image.data,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_files_carry_their_method_and_path() {
        let stub = ps_to_exe::tests::fixture(*b"new seed", 0x1_8000_0000);
        let outcome = try_all(&stub, &Options::default());
        assert_eq!(outcome.failures, []);
        let [file] = outcome.unpacked.as_slice() else {
            panic!("expected one file, got {:?}", outcome.unpacked);
        };
        assert_eq!(file.name, "ps-to-exe/resource-1664.ps1");
        assert_eq!(file.method, "ps-to-exe-rc4");
        assert!(file.data.starts_with(b"$message"));
        assert!(METHODS.iter().any(|&(name, _)| name == file.method));
    }

    /// Each input recovers at least one file through the method named, and
    /// every method `try_all` reports is listed.
    #[cfg(feature = "script")]
    #[test]
    fn script_methods_recover_and_are_listed() {
        let table = r#"var tab = new Array(); tab["a"]="var ";tab["b"]="x = ";tab["c"]="1; ";tab["d"]="alert(x);";eval(tab["a"]+tab["b"]+tab["c"]+tab["d"]);"#;
        let inputs: [(&[u8], &str); 3] = [
            (table.as_bytes(), "javascript-literal-program"),
            (
                include_bytes!("testdata/vsix-string-table/base64-proxies.js"),
                "js-constant-string-table",
            ),
            (
                include_bytes!("testdata/javascript-permutation/loader.js"),
                "javascript-literal-program",
            ),
        ];
        for (input, method) in inputs {
            let outcome = try_all(input, &Options::default());
            assert!(
                outcome.unpacked.iter().any(|file| file.method == method),
                "{method}: {:?}",
                outcome
                    .unpacked
                    .iter()
                    .map(|f| f.method)
                    .collect::<Vec<_>>()
            );
            for file in &outcome.unpacked {
                assert!(METHODS.iter().any(|&(name, _)| name == file.method));
            }
        }
    }

    #[test]
    fn unrecognized_bytes_recover_nothing() {
        for data in [&b"plain text"[..], b"MZ", b""] {
            assert_eq!(try_all(data, &Options::default()), Outcome::default());
        }
    }
}
