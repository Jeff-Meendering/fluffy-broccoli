# Building and packaging

## Requirements

Use the pinned Rust 1.99.1 toolchain, Cargo and a native compiler/linker. `rustup` installs the toolchain from `rust-toolchain.toml` when available; Homebrew Rust also works when its version matches. On Windows, use the MSVC toolchain and Visual Studio C++ build tools. On macOS, install Xcode Command Line Tools. For the Linux desktop app, provide the X11/Wayland/OpenGL development libraries required by winit/glutin and a desktop session. On Debian/Ubuntu, the CI build installs `libxkbcommon-dev libx11-dev libxi-dev libgl1-mesa-dev`.

Apple targets use `-fapple-link-rtlib` in `.cargo/config.toml` so optimized ONNX/CoreML links include Clang's availability helpers. See the [upstream integration note](https://docs.rs/crate/yolo-rs/0.3.0).

The default CLI and desktop builds enable ONNX Runtime. The `ort` build dependency downloads its platform runtime during compilation unless a compatible local build is configured. Cargo dependencies are locked in `Cargo.lock`. Scanning does not download assets.

Tesseract is optional and separate from the Rust executable. On macOS use `brew install tesseract`; on Debian/Ubuntu use the distribution's `tesseract-ocr` and English language packages. On Windows install a trusted Tesseract distribution and add its directory to PATH. The scanner also checks standard Homebrew installation paths on macOS, so Finder-launched apps can find local OCR. Packages created here include pinned English/orientation language data but do not bundle Tesseract or its native libraries. OCR failures become attention items and preserve earlier text findings.

## Developer checks

```sh
cargo fetch --locked
cargo xtask assets
cargo xtask test
cargo build --workspace
```

Optional Python scorer tests require a prepared Python 3.12 environment with `tools/accuracy/scorer-requirements.lock` installed using `pip --require-hashes`. See [the accuracy setup](../tools/accuracy/README.md); Python and NumPy are not needed to build or run PII Explorer.

`cargo xtask test` runs formatting, all-target/all-feature clippy with warnings denied, workspace tests, minimal-core tests and minimal-CLI tests. Model-backed tests use locally installed assets; OCR integration tests run when Tesseract is installed. Tests do not download models. GitHub CI is configured for Linux, macOS and Windows; successful remote runs, native rendering/signing and clean-machine installation are separate release checks. Build the workspace before launching the desktop app so its extraction helper exists beside it. Building the CLI package builds both CLI and helper executables.

## CLI feature selection

The CLI defaults to `full`. Features are independently selectable:

| Feature | Capability |
| --- | --- |
| none | Pattern/custom detection, labelled names, text/markup/CSV, metadata and binary recovery |
| `formats` | Spreadsheet, MIME, PDF text/forms and OneNote parsers |
| `archives` | Compressed/archive extraction; combine with formats for OOXML/ODF/EPUB |
| `ocr` | Image preprocessing and Rust PDF rasterization for local Tesseract |
| `ner` | ONNX person-name inference |
| `report` | PDF report creation |
| `full` | All of the above |

```sh
cargo build --release --locked -p pii-explorer-cli --no-default-features
cargo build --release --locked -p pii-explorer-cli --no-default-features --features formats,archives,report
```

Feature-limited CLI builds disable unavailable model/pixel features by default; unsupported document content still produces coverage diagnostics. Build the CLI independently when testing its reduced dependency graph: workspace builds include the desktop app's full core features through Cargo feature unification.

## Packages

```sh
cargo xtask assets
cargo xtask package
cargo xtask verify
```

Build on the target platform. `--target TRIPLE` selects a Rust target installed on the machine; cross-compilation may require platform linkers and a compatible ONNX distribution. The command stages CLI, desktop app, extraction helper, runtime support, pinned models/language data, documentation, a frozen smoke corpus, license files and `Cargo.lock` under `dist/<target-triple>`. macOS produces `PII Explorer.app` with all three executables in `Contents/MacOS`; its assets are in `Contents/assets`.

`BUILD-PROVENANCE.json` records the compiler/Cargo versions, target, build arguments and SHA-256 map of enumerated Rust inputs. `build-source` contains those exact sources/manifests/schema/embedded font and asset pins. Packaging checks the map before and after compilation and staging, failing if inputs changed. This snapshot supports release compilation independently of an uncommitted checkout base; external test fixtures remain outside the build-source snapshot. It is unsigned local provenance, not a byte-for-byte reproducibility or publisher-authentication claim. Host libraries and dependency build scripts can affect output.

A fresh staging directory prevents stale files from surviving a rebuild. `SHA256SUMS` covers every packaged file. `cargo xtask verify [PACKAGE_DIR]` rejects missing, extra, changed or linked files and unsafe manifest paths. Checksums establish consistency with a manifest, not publisher authenticity. Packaging does not sign, notarize, publish or upload anything.

The package also records the resolved target dependency graph in `licenses/rust/inventory.json` and copies available upstream license/notice files, top-level READMEs and nested font attribution text. This conservative inventory includes build/development dependencies and is not a complete license determination for nested assets or native runtimes. Review redistributed assets and notices before a public release.

Smoke-test the package outside the checkout, with explicit package assets, to avoid development assets masking a packaging defect:

```sh
/path/to/package/pii-explorer evaluate /path/to/package/tests/fixtures/accuracy-smoke.jsonl /tmp/fresh-evaluation.json --assets /path/to/package/assets
```

For macOS, replace `/path/to/package` with the app's `Contents` and invoke `Contents/MacOS/pii-explorer`. Run `scan` over the mixed fixture corpus as well, inspect all expected attention items, then test on a clean machine. Unsigned local packages should not be represented as signed or portable OCR distributions.

The old .NET/Java implementation, scripts and workflow are retained only as migration reference under `legacy/dotnet`; they are outside the Rust build and active CI.
