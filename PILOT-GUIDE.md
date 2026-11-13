# Analyst guide — Rust 0.5.0

Use PII Explorer on evidence you are authorized to inspect. Keep an original copy and work in an isolated environment for untrusted documents. The tool reads local files; it does not fetch cloud notebooks, decrypt password-protected evidence with supplied credentials, or send findings to an external service.

## Choose an interface

Use the CLI for repeatable assessments, remote shells, pipelines and retests. [Durable cases](docs/CASES.md) provide resource checkpoints, content/configuration-based reuse, paged queries and persistent review decisions. Save a full, unredacted JSON/JSONL export in controlled storage for comparison or existing report consumers. Create masked presentation exports separately. The native desktop app supports folder scanning, cancellation, search/type filters, source context and JSON/PDF export. It keeps results in memory until export; only its theme preference is saved automatically.

Start with `pii-explorer scan ./evidence -o ../case.jsonl`. Use `--no-names --no-ocr` for a quick pattern/text pass, then run a full assessment with pinned assets and Tesseract. A quick pass has reduced coverage. Export paths should be outside evidence to prevent results being re-ingested.

## Review coverage before conclusions

A completed traversal and an empty finding list do not prove a clean dataset. Review every attention item: unsupported files, partial binary recovery, encryption, size/expansion limits, unreadable files, OCR uncertainty, missing models and timeouts all indicate review work. Default dependency/VCS/system exclusions are explicit and can be overridden with `--include-excluded` or extended with `--exclude-dir`.

Defaults are 100 MiB per root file/member, 400 MiB cumulative archive expansion, 2,000 archive members, four nesting levels, 16 million extracted UTF-16 units per root, 500,000 findings and 10,000 attention items. A root file has a 180-second deadline; individual OCR calls are bounded to 60 seconds. PDF OCR renders every page at 200 DPI, with 40 megapixels per page and 80 megapixels per document. Limits and partial coverage produce attention; global finding/attention caps cancel a regular scan. Durable cases apply the finding cap per root resource.

Document parsers run in separate helpers by default, with bounded IPC, deadlines and worker replacement. Unix termination includes the helper process group; Linux also enforces a worker address-space limit. Parent detection remains cooperative. This is not an OS security sandbox, and macOS/Windows resource controls remain incomplete. See [the exact isolation boundaries](docs/ISOLATION.md). Large spreadsheets/PDFs may still require substantial memory even when input bytes fit the file-size limit.

## Interpret findings

Open occurrence context and inspect the detector, source stream, representation, offsets and source hash. Person recognition is English-focused and imperfect. Phone regions affect domestic matching. Many labels and addresses are language-specific. A valid check digit does not establish that an identifier was issued or belongs to a real person. IPs, MACs and wallet addresses are potential identifiers, not always personal data.

The same value can occur in decoded body text, generated table labels, metadata, OCR and filenames. These are separate evidence streams, not distinct people. Byte offsets refer to recovered binary strings; UTF-16 offsets refer to a particular extracted stream. OCR is a best-effort reading of rendered pixels and can miss or misread content.

`triage` ranks resources and gives exact distinct captured strings by type without printing captured values. This is a review aid, not risk scoring or subject counting. Protected resource names can themselves contain PII.

## Retest and verify

Run a second scan with the same evidence scope, build, models, features and options. `compare baseline.jsonl retest.jsonl` matches exact values per entity/resource/stream and preserves repeated counts while ignoring shifted offsets. Inspect current-only observations. Investigate baseline-only observations against coverage warnings and changed sources; absence is not proof of remediation.

`verify case.jsonl ./evidence` compares the root-file bytes with saved SHA-256 values. Container hashes cover archive members and attachments indirectly. This verifies equality to a saved record, not authenticity, immutable acquisition or chain of custody. Files can change while being scanned; such cases generate attention.

## Exports and storage

JSON/JSONL can be loaded into CLI triage, comparison, verification and PDF reporting. Imports are bounded; a missing stream summary remains incomplete. CSV and SARIF are integration/presentation outputs. CSV neutralizes formula prefixes. PDF reports exclude context by default and can alias resource names. Every export may still disclose sensitive data.

Masking removes captured values/context but keeps resource names and diagnostics. Hashing supports correlation and is vulnerable to guessing on predictable values. Do not publish raw scans, reports, hashes of sensitive identifiers, or screenshots from real assessments. Unix exports start with owner-only file permissions; Windows inherits its destination ACL. Data is not encrypted by the application.

## Release status

This is a development rewrite with regression checks, not a forensic certification or an exhaustive detector. See [REVIEW.md](REVIEW.md) for measured validation and known release limits. The earlier .NET implementation's benchmark results are historical and do not describe Rust performance or accuracy.
