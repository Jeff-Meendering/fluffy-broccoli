# rollcall

Open-source breach-response data mining. Point it at a folder of files taken in a breach and it builds the list that has to exist before anyone can be notified: **who was affected, and which of their data was exposed**.

> **Status: early development (Milestone 1).** Spreadsheets only. Not ready for a real incident. `rollcall` is a working name.

## Who it is for

Incident responders, and the security staff of organisations that cannot pay for commercial data-mining platforms, who need a notification list they can defend: every entry traceable to a file, sheet and row, and every file that was not understood called out.

## What it does today

- Reads CSV, TSV and XLSX/XLSM files with its own parsers.
- Recognises columns by header and, where there is none, by strict checks on the values: names, SSNs and ITINs, dates of birth, email, phone, postal address, payment cards, bank account and routing numbers, driver's licence, passport, medical record and insurance IDs.
- Turns each row into a person record. Columns about someone else (`Spouse SSN`, `Emergency Contact Phone`) become that person's own record.
- Repairs what spreadsheets damage: leading zeros dropped from SSNs, ZIP codes and routing numbers; dates stored as serial numbers.
- Keeps a case file (SQLite) with a SHA-256 for every evidence file. Ingest can be repeated; unchanged files are not read again.
- Reports every coverage gap: unsupported or unreadable files, tables it could not interpret, size limits reached, files that have gone missing.
- Exports the list as CSV, with sensitive identifiers masked to their last four characters unless you ask for full values.

## What it does not do yet

- Merge the same person across files (Milestone 2). The list currently has one row per person per source row.
- Read documents, PDFs, email, archives, images or legacy `.xls` files. These are reported as gaps, not skipped silently.
- Decide whether a person must be notified under any law. That is a legal judgement.

## Try it

Requires the Rust toolchain in `rust-toolchain.toml`.

```sh
cargo build --release
cargo xtask synth --seed 1 --out /tmp/breach
./target/release/rollcall ingest /tmp/breach/evidence --case /tmp/breach.rollcall
./target/release/rollcall people --case /tmp/breach.rollcall
./target/release/rollcall gaps --case /tmp/breach.rollcall
./target/release/rollcall export --case /tmp/breach.rollcall --out /tmp/list.csv
```

`cargo xtask synth` writes an invented breach dataset with a ground-truth file. `cargo xtask score` compares an exported list (`--values full`) with that truth: people found, rows that belong to nobody, values credited to the wrong person.

## Handle with care

A case file and every export contain personal data. Keep them outside the evidence folder and outside source control. Both are created readable by their owner only on Unix; neither is encrypted. Use the tool only on data you are authorized to inspect.

A passing score on synthetic data shows the pipeline is consistent with its own test generator. It is not evidence of accuracy on real breach data.

## Layout

| Crate | Purpose |
| --- | --- |
| `crates/model` | Shared types: elements, tables, person records, coverage gaps |
| `crates/extract` | File bytes to tables with coordinates (own CSV, XML and XLSX readers) |
| `crates/detect` | Header and value recognition, validation, canonical forms |
| `crates/link` | Row to person records |
| `crates/case` | Case database, ingest, export |
| `crates/cli` | The `rollcall` command |
| `crates/xtask` | Tooling: synthetic data and list scoring |

All first-party code is Rust. Third-party crates are limited to plumbing: SQLite (`rusqlite`), SHA-256 (`sha2`), the zip container (`zip`), argument parsing (`clap`), JSON (`serde`), error context (`anyhow`).

The previous project, PII Explorer, is preserved on the `archive/pii-explorer-0.5` branch.

## License

Apache-2.0. See [LICENSE](LICENSE).
