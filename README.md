# unpack

Recovers the files other files hide: the image inside a packed executable,
resources compressed into a loader, the payload of an installer
(PyInstaller, Nuitka), the next stage an obfuscated script rebuilds. It
decodes data only; no sample code, import or external program ever runs.

```
$ unpack sample.exe
sample.exe.unpacked/sample.exe!mpress_resource-1a0.exe  ("mpress-lzma")
$ unpack --list
```

Recovered files are unpacked again, up to `--depth` layers (default 3), and
each output directory gets a `manifest.json` recording the source, method,
size and SHA-256 of every file. Exit status is 0 when something was
recovered, 1 when nothing was, 2 on error.

## As a library

```rust
let outcome = unpack::try_all(&data, &unpack::Options::default());
for file in outcome.unpacked { /* file.name, file.method, file.data */ }
```

Every method recognizes its own container, so `try_all` needs no file
identification; a caller that knows the type can call one method directly.
Nothing here decides whether a result is malicious.

The JavaScript and Python reconstructors sit behind the `script` feature
(on by default), which adds tree-sitter. They take the caller's syntax tree,
so a caller that already parsed the file does not parse it again:

```toml
unpack = { git = "https://github.com/atomdrift-project/unpack.git", default-features = false, features = ["script"] }
```

tree-sitter comes from a fork; a consuming workspace carries the same
`[patch.crates-io]` entries as this crate's `Cargo.toml`.

## Where it fits

unpack depends on neither [filefacts] nor [stng], so either can use it.
filefacts identifies files and says where a payload sits; unpack turns bytes
into the bytes they hide; [cleave] decides what to unpack, analyzes the
results and judges them. See cleave's [ARCHITECTURE.md] for the full split.

[filefacts]: https://github.com/atomdrift-project/filefacts
[stng]: https://github.com/atomdrift-project/stng
[cleave]: https://github.com/atomdrift-project/cleave
[ARCHITECTURE.md]: https://github.com/atomdrift-project/cleave/blob/main/docs/ARCHITECTURE.md
