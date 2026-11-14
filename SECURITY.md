# Security

rollcall reads files that an attacker has had in their hands, and stores the personal data it finds. Both facts shape what it defends against.

## Reporting a vulnerability

Please report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue for a suspected vulnerability, and never attach real breach data to a report; a file made with `cargo xtask synth`, or a minimal hand-made one, is enough.

There is no stable release yet. Fixes are made on the main branch.

## What the tool defends against

Evidence is treated as hostile input.

| Threat | Defence |
| --- | --- |
| A crafted file crashes the tool or exhausts memory | Parsers are written in safe Rust (`unsafe` is forbidden in the workspace) and report what they cannot read as a coverage gap. Every reader is bounded: bytes per file, bytes per decompressed workbook part, rows per table, cells per file. |
| XML entity expansion or external entities | The XML reader never interprets a document type declaration. Entities other than the five predefined ones stay as literal text. |
| Compression bombs in workbooks | Each part is decompressed through a size limit and dropped if it exceeds it. |
| File or sheet names that forge lines of output or drive the terminal | Control characters in names are stored as visible escapes. All terminal output passes through a filter that does the same for values. |
| Cell values that run as formulas when the list is opened in a spreadsheet | Exported cells that begin with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with an apostrophe. |
| Symbolic links pointing out of, or back into, the evidence | Links are reported and never followed. |
| Two files whose names are displayed identically | Each keeps its own entry; the later one is marked as a name collision. |
| A wrong merge hiding an affected person | Automatic merging requires strong evidence and never joins two SSNs or two dates of birth. Everything weaker goes to a reviewer. |

These properties are checked by tests that feed the readers random and deliberately damaged input (`crates/*/tests/hostile.rs`, `crates/resolve/tests/properties.rs`).

## What it does not defend against

- **It is not a sandbox.** Parsing runs in the same process as everything else, with your permissions. Analyse untrusted evidence on an isolated machine.
- **Cases and exports are not encrypted.** They are created readable by their owner only on Unix and inherit the folder's permissions on Windows. Keep them on encrypted storage.
- **The audit log is not tamper-proof.** It detects an entry changed or removed from the middle. Someone who can rewrite the case file can rebuild the chain; record the head hash from `rollcall audit` somewhere else.
- **Detection is not exhaustive.** An empty list does not show that no personal data is present. Coverage gaps list what was not read; data in a form the tool does not recognise is not listed anywhere.
- **Dependencies** (SQLite via `rusqlite`, `zip`, `sha2`, `clap`, `serde`, `anyhow`) are trusted as published.
