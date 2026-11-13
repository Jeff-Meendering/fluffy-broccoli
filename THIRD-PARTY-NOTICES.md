# Third-party components — Rust 0.4.0

PII Explorer source is Apache-2.0 licensed; see LICENSE and NOTICE. Preserve upstream notices when redistributing dependencies or assets. `Cargo.lock` is the exact Rust dependency inventory; per-crate license expressions and upstream links are recorded by the package task in `licenses/rust/inventory.json`, alongside available license/notice files, top-level READMEs and nested font attribution text from the resolved graph.

This generated inventory includes build/development dependencies and is not a determination of everything linked into a particular executable. Some published crates omit full license texts or contain additional nested assets; review those and native runtime notices before distribution. The inventory does not establish a completed legal/security review.

| Component | Source of version and attribution |
| --- | --- |
| Rust libraries, egui/eframe desktop UI, native document/archive parsers, PDF renderer/reporter | Cargo.lock and generated target dependency inventory |
| ONNX Runtime and ort bindings | Locked `ort`/`ort-sys` versions; downloaded native distribution's own notices must be reviewed with a release |
| English person model | onnx-community/distilbert-NER-ONNX revision `3a19fe9404a4469d91aa3d551558a97f68872f67`; `licenses/model-card.md` and the pinned upstream model README |
| Tesseract | Optional system installation, not bundled by `cargo xtask package`; preserve its distribution's licenses if separately bundling it |
| OCR language data | tessdata_fast 4.1.0 English/orientation data; SHA-256 pins in `scripts/assets.json`, Apache-2.0 upstream data |
| Noto Sans report font | `crates/core/assets/NotoSans-Regular.ttf`, `crates/core/assets/OFL.txt`, `licenses/noto-sans/LICENSE` |
| egui built-in fonts | `epaint_default_fonts` license expression in the inventory; includes OFL/Ubuntu font obligations requiring asset-notice review |

The Rust application does not depend on or package .NET, Avalonia, Tika or Java. Their original source/notices are historical reference under `legacy/dotnet` and `docs/history/THIRD-PARTY-NOTICES-0.3.md`.

Optional independent benchmark Python dependencies, competitor tools and dataset provenance are separately pinned under `tools/accuracy`; their retained notices are under `licenses/accuracy`. They are not application runtime dependencies. Dataset records and local benchmark environments are not redistributed by the application package.

The OneNote parser fixture's upstream source is documented in `tests/fixtures/README.md`. Development tests contain only synthetic/example identifiers and public checksum vectors.

Checksums detect changes relative to a trusted manifest. They are not publisher signatures. Local packages are unsigned and are not a substitute for release signing, asset review and clean-machine validation.
