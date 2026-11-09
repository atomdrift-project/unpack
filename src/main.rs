//! `unpack`: recover the files hidden inside other files.
//!
//! Runs every method on each input, writes what it recovers, and unpacks
//! the recovered files in turn up to `--depth` layers. Nothing is executed.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: unpack [options] <file>...

Recovers the files hidden inside each <file>: unpacked executables,
decrypted payloads, bundled sources. Recovered files are unpacked again, up
to --depth layers. No sample code is ever run.

options:
  -o, --out <dir>      write recovered files here (default: <file>.unpacked/)
  -d, --depth <n>      layers to unpack (default 3)
      --max-bytes <n>  stop after writing this many bytes in total (default 512 MiB)
      --no-nrv-image   skip rebuilding NRV2B (UPX-style) memory images
      --json           print the manifest as JSON on stdout
      --list           list the methods and what each recovers
  -h, --help           show this help

exit status: 0 when something was recovered, 1 when nothing was, 2 on error.";

/// Parsed command line.
#[derive(Debug)]
struct Args {
    files: Vec<PathBuf>,
    out: Option<PathBuf>,
    depth: usize,
    max_bytes: u64,
    options: unpack::Options,
    json: bool,
}

/// What the command should do.
#[derive(Debug)]
enum Command {
    Unpack(Args),
    List,
    Help,
}

fn parse(mut words: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut args = Args {
        files: Vec::new(),
        out: None,
        depth: 3,
        max_bytes: 512 << 20,
        options: unpack::Options::default(),
        json: false,
    };
    while let Some(arg) = words.next() {
        let mut value = |name: &str| words.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--list" => return Ok(Command::List),
            "--json" => args.json = true,
            "--no-nrv-image" => args.options.nrv_memory_image = false,
            "-o" | "--out" => args.out = Some(PathBuf::from(value(&arg)?)),
            "-d" | "--depth" => {
                args.depth = value(&arg)?.parse().map_err(|e| format!("--depth: {e}"))?;
            }
            "--max-bytes" => {
                args.max_bytes = value(&arg)?
                    .parse()
                    .map_err(|e| format!("--max-bytes: {e}"))?;
            }
            flag if flag.starts_with('-') && flag.len() > 1 => {
                return Err(format!("unknown option {flag}"));
            }
            file => args.files.push(PathBuf::from(file)),
        }
    }
    if args.files.is_empty() {
        return Err("no input files".to_string());
    }
    Ok(Command::Unpack(args))
}

/// Writes recovered files and records them in the manifest.
#[derive(Debug)]
struct Writer {
    written: u64,
    max_bytes: u64,
    seen: BTreeSet<[u8; 32]>,
    recovered: usize,
}

impl Writer {
    /// Unpack `data` (called `name`, `depth` layers below an input) into
    /// `dir`, appending manifest entries to `entries`.
    fn unpack(
        &mut self,
        data: &[u8],
        name: &str,
        dir: &Path,
        depth: usize,
        args: &Args,
        entries: &mut Vec<Value>,
    ) -> Result<(), String> {
        if depth >= args.depth {
            return Ok(());
        }
        let outcome = unpack::try_all(data, &args.options);
        for failure in &outcome.failures {
            entries.push(json!({
                "source": name,
                "method": failure.method,
                "failed": failure.reason,
            }));
        }
        for file in outcome.unpacked {
            let digest: [u8; 32] = Sha256::digest(&file.data).into();
            // A layer that recovers itself (or a sibling's bytes) once is
            // enough; repeating it would loop.
            if !self.seen.insert(digest) {
                continue;
            }
            let size = u64::try_from(file.data.len()).unwrap_or(u64::MAX);
            if self.written.saturating_add(size) > self.max_bytes {
                entries.push(json!({
                    "source": name,
                    "method": file.method,
                    "skipped": format!("--max-bytes {} reached", self.max_bytes),
                }));
                continue;
            }
            let child = format!("{name}!{}", file.name);
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
            let path = dir.join(sanitize(&child));
            std::fs::write(&path, &file.data)
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
            self.written = self.written.saturating_add(size);
            self.recovered += 1;
            entries.push(json!({
                "source": name,
                "method": file.method,
                "name": child,
                "path": path.display().to_string(),
                "size": size,
                "sha256": hex::encode(digest),
            }));
            self.unpack(&file.data, &child, dir, depth + 1, args, entries)?;
        }
        Ok(())
    }
}

/// A file name for `name` that cannot leave the output directory.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '\0' => '_',
            c => c,
        })
        .collect::<String>()
        .trim_start_matches('.')
        .to_string()
}

fn run(args: &Args) -> Result<ExitCode, String> {
    let mut writer = Writer {
        written: 0,
        max_bytes: args.max_bytes,
        seen: BTreeSet::new(),
        recovered: 0,
    };
    for input in &args.files {
        let data = std::fs::read(input).map_err(|e| format!("reading {}: {e}", input.display()))?;
        let dir = args.out.clone().unwrap_or_else(|| {
            let mut dir = input.clone().into_os_string();
            dir.push(".unpacked");
            PathBuf::from(dir)
        });
        let name = input.file_name().map_or_else(
            || input.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let mut entries = Vec::new();
        writer.unpack(&data, &name, &dir, 0, args, &mut entries)?;
        let doc = json!({"input": input.display().to_string(), "recovered": entries});
        let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
        // The directory exists only when something was written to it.
        if dir.is_dir() {
            let path = dir.join("manifest.json");
            std::fs::write(&path, &text).map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
        if args.json {
            println!("{text}");
        } else {
            let mut summary = String::new();
            for entry in &entries {
                if let Some(path) = entry.get("path").and_then(Value::as_str) {
                    let _ = writeln!(summary, "{path}  ({})", entry["method"]);
                } else if let Some(reason) = entry.get("failed").and_then(Value::as_str) {
                    let _ = writeln!(
                        summary,
                        "{}: {} failed: {reason}",
                        entry["source"], entry["method"]
                    );
                }
            }
            print!("{summary}");
        }
    }
    Ok(if writer.recovered > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::List) => {
            for (method, what) in unpack::METHODS {
                println!("{method:<22} {what}");
            }
            ExitCode::SUCCESS
        }
        Ok(Command::Unpack(args)) => run(&args).unwrap_or_else(|error| {
            eprintln!("unpack: {error}");
            ExitCode::from(2)
        }),
        Err(error) => {
            eprintln!("unpack: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Command, String> {
        parse(list.iter().map(ToString::to_string))
    }

    #[test]
    fn parses_flags_and_files() {
        let Ok(Command::Unpack(a)) = args(&["-d", "2", "--json", "--no-nrv-image", "a.exe"]) else {
            panic!("expected an unpack command");
        };
        assert_eq!(a.depth, 2);
        assert!(a.json);
        assert!(!a.options.nrv_memory_image);
        assert_eq!(a.files, [PathBuf::from("a.exe")]);
        assert!(matches!(args(&["--list"]), Ok(Command::List)));
        assert!(args(&[]).is_err());
        assert!(args(&["--bogus", "a"]).is_err());
        assert!(args(&["--depth"]).is_err());
    }

    #[test]
    fn recovered_names_stay_in_the_output_directory() {
        assert_eq!(
            sanitize("a.exe!mpress/resource-1.exe"),
            "a.exe!mpress_resource-1.exe"
        );
        assert_eq!(sanitize("../../etc/passwd"), "_.._etc_passwd");
        assert!(!sanitize("..\\x").contains('\\'));
    }
}
