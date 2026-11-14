# rollcall

Open-source breach-response data mining. Point it at a folder of files taken in a breach and it builds the list that has to exist before anyone can be notified: **who was affected, and which of their data was exposed**.

> **Status: early development (Milestone 2).** Spreadsheets only. Not ready for a real incident. `rollcall` is a working name.

## Who it is for

Incident responders, and the security staff of organisations that cannot pay for commercial data-mining platforms, who need a notification list they can defend: every entry traceable to a file, sheet and row, every merge explained, and every file that was not understood called out.

## What it does today

- **Reads** CSV, TSV and XLSX/XLSM files with its own parsers.
- **Recognises** columns by header and, where there is none, by strict checks on the values: names, SSNs and ITINs, dates of birth, email, phone, postal address, payment cards, bank account and routing numbers, driver's licence, passport, medical record and insurance IDs. It repairs what spreadsheets damage, such as leading zeros dropped from SSNs and ZIP codes.
- **Links** each row to the person it describes. Columns about someone else (`Spouse SSN`, `Emergency Contact Phone`) become that person's own record.
- **Merges** records of the same person across files, and says why. It merges without asking only on strong evidence: an identifier issued to one person, or a matching name together with a shared date of birth, email, phone or address. It knows short forms of names (`Bob`, `Robert`) and never puts two SSNs or two dates of birth into one person.
- **Asks** about everything weaker. `rollcall review list` shows pairs of records that may be one person; a reviewer accepts or rejects each, and can merge or split any two records by hand. Rulings survive re-ingest.
- **Keeps a case** (one SQLite file) with a SHA-256 for every evidence file, and an audit log in which each entry is chained to the one before.
- **Reports every coverage gap:** unsupported or unreadable files, tables it could not interpret, size limits reached, files that have gone missing.
- **Exports** the notification list as CSV, one row per person, with sensitive identifiers masked to their last four characters unless you ask for full values. A second export lists the source records behind it.

## What it does not do yet

- Read documents, PDFs, email, archives, images or legacy `.xls` files. These are reported as gaps, not skipped silently.
- Join records that share nothing: a row with only a name and date of birth and a row with only an email and SSN stay two entries, because nothing in the data connects them.
- Suggest matches on a name alone when more than eight unmerged groups share it. Common names need other evidence.
- Decide whether a person must be notified under any law. That is a legal judgement.

## Try it

Requires the Rust toolchain in `rust-toolchain.toml`.

```sh
cargo build --release
cargo xtask synth --seed 1 --out /tmp/breach
alias rollcall=./target/release/rollcall

rollcall ingest /tmp/breach/evidence --case /tmp/breach.rollcall
rollcall people --case /tmp/breach.rollcall
rollcall review list --case /tmp/breach.rollcall
rollcall review accept 1 --case /tmp/breach.rollcall --note "same person, checked the source"
rollcall person 1 --case /tmp/breach.rollcall
rollcall gaps --case /tmp/breach.rollcall
rollcall export --case /tmp/breach.rollcall --out /tmp/list.csv
rollcall audit --case /tmp/breach.rollcall
```

`cargo xtask synth` writes an invented breach dataset with a ground-truth file: people spread over several files under short forms and misspellings of their names, strangers who share a name, and housemates who share a phone and address. `cargo xtask score` compares an exported list (`--values full`) with that truth: people found, people listed twice, values credited to the wrong person.

## Handle with care

A case file and every export contain personal data. Keep them outside the evidence folder and outside source control. Both are created readable by their owner only on Unix; neither is encrypted. Use the tool only on data you are authorized to inspect.

The audit log detects an entry that was changed or removed from the middle. It cannot prove the log is authentic: someone able to rewrite the case file can rebuild the chain. `rollcall audit` prints the hash of the latest entry so it can be recorded somewhere else.

A passing score on synthetic data shows the pipeline is consistent with its own test generator. It is not evidence of accuracy on real breach data.

## Layout

| Crate | Purpose |
| --- | --- |
| `crates/model` | Shared types: elements, tables, person records, coverage gaps |
| `crates/extract` | File bytes to tables with coordinates (own CSV, XML and XLSX readers) |
| `crates/detect` | Header and value recognition, validation, canonical forms |
| `crates/link` | Row to person records |
| `crates/resolve` | Records to persons: name parsing, nicknames, string similarity, merge policy |
| `crates/case` | Case database, ingest, rulings, audit log, export |
| `crates/cli` | The `rollcall` command |
| `crates/xtask` | Tooling: synthetic data and list scoring |

All first-party code is Rust. Third-party crates are limited to plumbing: SQLite (`rusqlite`), SHA-256 (`sha2`), the zip container (`zip`), argument parsing (`clap`), JSON (`serde`), error context (`anyhow`).

The previous project, PII Explorer, is preserved on the `archive/pii-explorer-0.5` branch.

## License

Apache-2.0. See [LICENSE](LICENSE).
