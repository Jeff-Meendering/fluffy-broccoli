# Durable assessment cases

Use a case for large local assessments, interrupted scans, repeated scans of the same scope, or persistent analyst review. Place the case outside the evidence tree. No remote collection or cloud credentials are required.

```sh
pii-explorer case scan ./evidence --case ../assessment.piicase
pii-explorer case scan ./evidence --case ../assessment.piicase --resume
pii-explorer case show ../assessment.piicase --limit 100 --type email
pii-explorer case review ../assessment.piicase 42 --status confirmed --note 'Reviewed in source' --reviewer analyst
pii-explorer case show ../assessment.piicase --status confirmed --after 42
pii-explorer case runs ../assessment.piicase
pii-explorer case export ../assessment.piicase ../assessment.jsonl
pii-explorer case integrity ../assessment.piicase
```

`show` returns a keyset page (1–1,000 rows) with finding IDs, review decisions and `next_after`. Pass that cursor as `--after` for the next page. Optional `--run ID` selects historical runs; the latest run is the default. Decisions are `unreviewed`, `confirmed`, `false-positive` and `needs-review`; notes and reviewer names persist. False positives remain captured evidence, with the decision stored alongside them. Export includes additive review metadata and remains readable by the existing JSONL consumers. Those consumers do not yet display case review decisions.

Each `--resume` creates a new run and inventories the current scope. Completed resources are reused only when their logical path, SHA-256 bytes and engine/configuration fingerprint all match, with no extraction warnings or cancellation. Matching size and modification time alone is insufficient. The fingerprint includes CLI/helper executables, selected model/OCR assets, build features and scan options. Unfinished resources and resources with extraction warnings are retried. `--refresh` bypasses reuse. Removed resources stay in history and disappear from the new run. A different evidence root requires a new case.

Review decisions follow reused snapshots. Changing the source or engine creates new finding IDs with unreviewed decisions; previous decisions remain in history. Interrupted runs are marked interrupted on the next capture. Checkpoints are per root resource; an unfinished root is scanned again, including its nested members. Partial captured observations remain available in the earlier incomplete run. Captures use a bounded work queue and stream batches into the database; only per-file extraction/detection buffers remain in memory. The configured finding cap applies to each root resource in case capture, rather than to the whole case. Streaming exports use disk-backed rows without a whole-case collection. JSON imports elsewhere still have their documented limits.

An OS file lock permits one capture writer per case, while SQLite transactions protect checkpoints and review writes. Process crashes release the lock. Retain the `.scan-lock` sidecar while a capture is running. The database and its directory contain plaintext PII; Unix creation requires owner-only file permissions, and Windows permissions inherit from the destination directory. Use protected storage. Cases are not encrypted, signed, authenticated or automatically backed up.

`integrity` checks SQLite structure/references, finding payload hashes, audit-chain hashes and review consistency. These checks detect accidental corruption and inconsistent edits. An actor able to rewrite the database can recompute unsigned hashes. Integrity success does not establish acquisition authenticity or chain of custody. Source hashing identifies bytes actually read; acquire a stable evidence snapshot when sources could change concurrently.

Case capture is currently a CLI workflow. The desktop app has not yet gained a paged case browser or persistent case-review controls.
