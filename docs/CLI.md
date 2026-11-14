# Command reference

Run `pii-explorer --help` or `pii-explorer <command> --help` for the complete argument list. Examples assume the executable is on PATH.

## Scanning and detection

```sh
pii-explorer scan ./evidence -o ../scan.jsonl
pii-explorer scan ./single-file.zip --format json -o ../scan.json
printf 'Contact: analyst@example.com' | pii-explorer scan - --no-names --no-ocr
pii-explorer detect 'Contact: analyst@example.com' --no-names --no-ocr --format text
```

Prefer stdin for sensitive text; literal arguments can enter shell history and process listings. `scan` accepts a file, directory or UTF-8 stdin. `detect` bypasses extraction. Non-UTF-8 files are decoded through file extraction.

Common engine options:

| Option | Meaning |
| --- | --- |
| `--assets DIR` | Directory containing `models/` and `ocr/tessdata/`; uses a bundled `ocr/tesseract[.exe]` if present, otherwise system Tesseract |
| `--no-names` | Disable ONNX inference; explicit labelled-name rules continue |
| `--no-ocr` | Skip pixel OCR; image metadata remains checked and missing pixel coverage is reported |
| `--phone-regions US,GB,DE` | Countries for domestic numbers; international `+` numbers are also checked |
| `--jobs 2` | File workers, 1–8 |
| `--max-file-mib 100` | Root-file and archive-member size limit, 1–2048 MiB |
| `--timeout-secs 180` | Per-file deadline; the extraction helper is terminated when it expires. Parent detection observes the same deadline cooperatively |
| `--in-process` | Explicitly run parsers in the coordinator for trusted inputs; removes process fault isolation |
| `--rules rules.example.json` | Add declarative, bounded Rust regex rules; repeatable |
| `--no-context` | Omit captured surrounding text |
| `--exclude-dir NAME` | Skip exact directory basenames; repeatable |
| `--include-excluded` | Include default-excluded VCS, dependency and system directories |

Symlinks inside a scanned tree are not followed. Default exclusions are recorded as attention items. A file too large to read can still have findings in its filename. A root SHA-256 identifies the bytes read; archive members and attachments are identified through logical resource paths and covered by their root container hash.

## Output contracts

`--format jsonl` is the default. Records contain `kind` and one payload: `settings`, `finding`, `attention`, `source` or `summary`. Settings are first, summary is last. Findings, attention and source records stream during the scan without retaining a second whole-scan collection. Live order can vary with worker timing. Use `--no-stream` for sorted output after completion. Keep streaming output outside the scanned directory. A broken pipe or failed write stops the scan with an error.

`--format json` produces one saved document. JSON and JSONL are supported by `triage`, `compare`, `verify` and `report`, along with the desktop app's versioned JSON exports. Import is bounded to 256 MiB, 8 MiB per JSONL record and one million total records. A missing JSONL summary is marked incomplete. Very large scans may need lower capture limits or partitioned evidence to fit the import ceiling.

`--format csv` produces finding, attention and source records, with formula-like field prefixes neutralized for spreadsheet use. It is a presentation export; use JSON/JSONL to preserve exact values and full provenance. `--format sarif` emits SARIF 2.1.0 with occurrence fingerprints, provenance and coverage diagnostics. Extracted-stream offsets are not necessarily offsets in the original container file; consult stream/representation properties when consuming SARIF.

`--type email,ssn` filters emitted findings only. Detection totals and exit policies still cover all types. `--redact mask` replaces values and clears context. `--redact hash` replaces values with SHA-256 fingerprints and clears context. Neither hides filenames, resource IDs, stream names, custom-rule definitions or attention diagnostics. These exports still need controlled storage.

`-o PATH` creates a new file and refuses replacement. On Unix, exports are created with mode 0600. Windows permissions inherit from the destination directory. No result is encrypted automatically. `-o -` selects stdout.

Text-stream and parsed-document offsets use UTF-16 code units. Binary strings use byte offsets and record their byte stride. Metadata, OCR, filename and synthesized table streams are distinct coordinate spaces. Separate streams may contain the same value; occurrences are not a count of affected people.

## Triage and retests

For large or repeated assessments, use [durable cases](CASES.md). A case keeps checkpoints and review decisions in SQLite and supports paged queries without the JSON import ceiling. The desktop scan/review interface still uses an in-memory result collection.

```sh
pii-explorer triage scan.jsonl --top 30 -o triage.json
pii-explorer compare baseline.jsonl current.jsonl --fail-on-new -o changes.json
```

Triage ranks logical resources by occurrence count, breaking ties by resource name, and reports exact distinct strings per entity type. It never prints captured values. Distinct counts become `null` when recognized masked/hashed values prevent reliable counting.

Comparison requires unfiltered, unredacted scans. Matching uses entity type, exact value, resource ID and stream ID with occurrence multiplicity. Offsets are ignored, so inserting unrelated text does not produce false changes. Changing a value or moving it to another resource produces a change. Reports include value fingerprints rather than captured values; protect fingerprints and resource names as sensitive data.

`current_only` and `baseline_only` describe observations, not a remediation verdict. Interrupted or partial extraction, different exclusions, missing models, different builds and changed scope can all make observations disappear. Compare coverage and attention in the original scans. `same_recorded_settings` compares serialized settings; it does not verify model bytes or engine identity. CLI output filters are detected through retained-versus-summary counts; do not hand-edit the saved files or their summary counters.

## Verification and reports

```sh
pii-explorer verify scan.jsonl ./original-evidence -o verification.json
pii-explorer report scan.jsonl findings.pdf --hide-file-names --include-context
```

`verify` requires the directory originally scanned, or the parent of a single scanned file. It rejects unsafe relative paths and linked components, and reports changed, missing, unreadable, unsafe and unhashed sources. Hash equality does not authenticate a scan record or establish chain of custody. `stdin` has no file to verify automatically.

PDF reports are created from saved observations without rereading evidence. Context is excluded unless requested. `--hide-file-names` replaces resource/stream names with stable report aliases. Captured values remain in the PDF. The `report` command requires the `report` Cargo feature.

## Evaluation

```sh
pii-explorer evaluate tests/fixtures/accuracy-smoke.jsonl evaluation.json
pii-explorer predict inputs.jsonl predictions.jsonl
```

Evaluation scores exact type and UTF-16 spans in labelled JSONL, with asset/configuration hashes. With names enabled, a missing model is an error. `predict` consumes only `Id`/`Text`, returns `Id`/`TextSha256`/`Entities`, and prints configuration provenance; gold annotations never enter that process. See [accuracy benchmarking](../tools/accuracy/README.md). The developer smoke corpus is not independent accuracy evidence.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed under the selected policies; inspect coverage diagnostics |
| 1 | Configuration, input, import or output error |
| 2 | Scan cancelled or global finding/attention cap reached |
| 3 | Attention exists and `--fail-on-attention` was selected |
| 4 | Findings exist with `--fail-on-findings`, or new occurrences exist with `compare --fail-on-new` |
| 5 | `verify` could not establish all recorded root-file hashes as matching |

For scans, cancellation takes precedence, then attention policy, then finding policy. A per-file extraction warning does not change the exit code unless `--fail-on-attention` is enabled.
