# PII Explorer

Local PII and credential discovery for authorized security assessments. Rust 0.5.0 development release, Apache-2.0 licensed.

Scan an evidence directory or pipe text into the CLI; review occurrences in the native desktop app; export JSON, JSONL, CSV, SARIF, or PDF. Each finding retains its resource, extracted stream, coordinate system, detector and context. Root files receive SHA-256 hashes so you can verify the bytes later.

## Build and run

Install the toolchain in `rust-toolchain.toml` (Rust 1.99.1). From the checkout:

```sh
cargo build --release --locked -p pii-explorer-cli
./target/release/pii-explorer scan /path/to/evidence --no-names --no-ocr -o /path/to/results.jsonl
```

Use `target/release/pii-explorer.exe` on Windows. The output path must be outside the evidence directory for streaming scans. No assets are needed for patterns, labelled names, text, document and archive extraction.

For local model-backed names and OCR, install Tesseract on your system and fetch the checksum-pinned model and English language data:

```sh
cargo xtask assets
cargo run --release --locked -p pii-explorer-cli -- scan /path/to/evidence -o /path/to/results.jsonl
cargo run --release --locked -p pii-explorer-app
```

Tesseract is the only external extraction process. The Rust application needs no Java, .NET or Python runtime. Dependency builds and the explicit asset command download files; scanning and inference run locally.

For a smaller server/assessment build that omits ONNX and page rendering:

```sh
cargo build --release --locked -p pii-explorer-cli --no-default-features --features formats,archives,report
```

See [setup and packaging](docs/BUILD.md) for platform prerequisites and distribution limits.

## Assessment workflow

```sh
# Save all observations, source hashes and coverage warnings.
pii-explorer scan ./evidence -o ../assessment.jsonl

# Find the resources with the most occurrences, without printing captured values.
pii-explorer triage ../assessment.jsonl --top 20

# Capture a retest and compare exact values while allowing offsets to move.
pii-explorer scan ./evidence -o ../retest.jsonl
pii-explorer compare ../assessment.jsonl ../retest.jsonl --fail-on-new

# Check that evidence still matches the recorded root-file hashes.
pii-explorer verify ../assessment.jsonl ./evidence

# Generate a new report without reopening the evidence files.
pii-explorer report ../assessment.jsonl ../report.pdf --hide-file-names
```

The CLI is the primary interface for repeatable assessments and pipelines. [Durable cases](docs/CASES.md) add resumable checkpoints, unchanged-source caching, paged findings and persistent review decisions. The desktop app provides interactive folder scanning, filtering, evidence context and export. Default filesystem scans use a separate [extraction helper](docs/ISOLATION.md). The shared core is usable as a Rust library. See the [command reference](docs/CLI.md), [analyst guide](PILOT-GUIDE.md), and [example custom rules](rules.example.json).

## Coverage

Detects person names, email, phone, SSN, payment cards, street addresses, dates of birth, IP/MAC addresses, UK National Insurance, IBAN, selected national IDs, labelled identifiers, credentials and crypto wallets. Checksums and country-aware validation reduce noise; scores are heuristics, not calibrated probabilities.

Extracts text/encodings, CSV/TSV, HTML/XML, Office Open XML, XLS/XLSB/ODS, ODT/ODP/EPUB, PDF text/forms/metadata, OneNote sections, MIME email and attachments, images and nested ZIP/RAR/7z/TAR/GZIP/BZIP2/XZ archives. With OCR enabled, PDF pages are rendered in Rust and passed to local Tesseract, including pages with both text and images. Unsupported binaries receive a bounded strings view and an attention item.

## Limits and trust

Detection is not exhaustive. An empty finding list does not establish absence of PII. Always review attention items, interrupted scans and skipped formats. Extraction runs in separate helper processes by default, with bounded IPC and enforced deadlines. These controls are not an OS sandbox; platform resource limits vary. Use an isolated analysis environment for hostile documents.

Exports can contain PII, credentials and identifying filenames. `--redact mask` removes captured values and context, but retains resource names and diagnostics. Hashes permit correlation and do not anonymize predictable identifiers. Keep cases and exports outside source control.

The [Rust validation record](REVIEW.md) distinguishes regression evidence from independent accuracy claims. Historical .NET/Java source is isolated in [legacy/dotnet](legacy/dotnet/README.md) and is not used by Cargo or current CI.

## Contributing and license

[Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [Third-party notices](THIRD-PARTY-NOTICES.md) · [Apache-2.0 license](LICENSE)
