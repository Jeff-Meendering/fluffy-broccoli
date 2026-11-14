# Rust 0.4.0 validation and release status

The Rust workspace is now the active implementation. The .NET/Java source, tests, license inventory and scripts are retained under `legacy/dotnet` for reference. The earlier assessment is preserved in `docs/history/REVIEW-0.3.md`; its accuracy and performance numbers do not describe this rewrite.

## Architecture and completed migration work

The shared Rust core serves a headless CLI and a native egui application. The CLI supports piped input, machine-readable exports, saved-scan triage/comparison, source verification and offline PDF reporting. Its document/archive/report features can be built without ONNX or page rasterization. The desktop application remains available for interactive occurrence review. There is no Java or .NET runtime dependency.

This pass restored pre-OCR deskew/upscaling, including a tilted whiteboard case where sparse OCR returned confidently fragmented text, and completed scanned/mixed PDF page OCR using the Rust renderer and local Tesseract. It renders all pages, including pages that also contain extractable text, so images inside PDF forms and inline image content do not depend on a shallow resource inventory. OCR has separate per-page provenance, dimension/work budgets and explicit failure diagnostics; earlier text is retained when rendering or OCR fails.

Fixed Brazilian CPF grouping being accepted incidentally as a phone number, missing system-Tesseract fallback when selecting a model asset directory or launching from Finder, and evaluation suppressing labelled Person predictions when ONNX inference was disabled. SARIF now omits absent fingerprints and keeps extracted-stream offsets separate from container-file positions. Apple optimized builds explicitly link the compiler runtime required by native ONNX/CoreML availability checks.

Packaging verifies pinned assets, excludes unlisted local assets, records the resolved Rust dependency graph and available upstream/font notices, stages fresh output and hashes every distribution file. Asset setup rejects linked destination parents, bounds downloads and never promotes a checksum mismatch. Updated setup wrappers and cross-platform CI use Cargo; legacy Java/.NET workflows are no longer active.

## Reproduction

```sh
cargo xtask assets
cargo xtask test
cargo check --locked -p pii-explorer-cli --no-default-features --features formats,archives,report
cargo xtask package
cargo xtask verify
```

`cargo xtask test` includes formatting, all-target/all-feature clippy with warnings denied, workspace tests, minimal-core tests and minimal-CLI command contracts. OCR integration tests run when Tesseract is installed; model tests use pinned local assets. The frozen 57-case text corpus is exercised with and without ONNX inference. It is a developer regression set, not independent accuracy evidence.

Local validation on 9 November 2026 used macOS 26.6.2 on Apple Silicon, Rust/Cargo 1.99.1 and Tesseract 5.5.3. `cargo xtask test` passed: **192 workspace tests**, plus **99 minimal-core tests** and **13 minimal-CLI tests**, with no failures. Formatting and all-target/all-feature clippy passed with warnings denied; the CLI also passed a separate minimal-build clippy run. The document/archive/report CLI configuration passed `cargo check` without ONNX or the page renderer.

The frozen text corpus matched all 57 cases with 38 true positives, zero false positives and zero false negatives, including installed-model inference. The tilted-image and scanned-PDF OCR integration regressions passed. These are developer-authored regression fixtures and do not estimate real-world precision or recall.

The optimized macOS package was exercised outside the checkout with an explicit packaged asset path and `PATH=/usr/bin:/bin`. It passed the same 57-case evaluator, completed all 50 mixed fixtures with 320 occurrences and eight explicit attention items, and retained expected email coverage across 17 selected resource/format groups, including tilted images, scanned PDFs and nested archives. All 50 root-file hashes matched on subsequent verification; a self-comparison retained all 320 observations with no changes. The eight attention items cover handwriting uncertainty, a notebook index, malformed OneNote/Office/PDF/ZIP files, binary-control content and an encrypted archive member. Findings in separate streams can repeat the same underlying value; this count is not an accuracy or affected-person metric.

Package verification matched 1,184 files to `SHA256SUMS`. The package is an unsigned local build, not a clean-machine or notarization result.

The optional Python scorer's 13 contract tests passed using the available Python 3.12 / NumPy 2.3.5 environment. The checked-in scorer lock specifies NumPy 2.5.3 for CI/reproduction; this local run was not a reproduction of that exact environment. No new held-out 5,000-document Rust accuracy benchmark or competitor run was performed.

Logs and generated assessment outputs live in ignored `test-results/` and are not source artifacts. GitHub-hosted matrix CI has been configured but has not run in this local session.

## Practical limits before a public release

The parser pipeline is in-process. Its checks and cooperative deadlines are not an OS sandbox or a hard bound on parser allocations/latency. Encrypted inputs and unsupported formats require analyst review. Legacy `.doc`, Outlook `.msg`, HEIC and arbitrary binaries may receive only a bounded strings view; that is reduced coverage, not full native format support. Local model-backed names are English-focused; international/language coverage remains uneven.

Source hashes establish equality to the recorded bytes, not authenticity, immutable acquisition or chain of custody. Saved scans are not signed or encrypted. Output masking does not remove identifying resource names or every diagnostic. Retest comparison reports observations and coverage rather than a remediation certification.

Clean-machine Windows/Linux installation, signed/notarized releases, native dependency/asset notice review, independent representative extraction/OCR evaluation, held-out Rust accuracy measurements and total-process memory/latency benchmarks remain release work. Historical competitor results are not Rust benchmark results. A generated dependency inventory and configured advisory CI are not a claim that the entire native supply chain is audited or vulnerability-free.
