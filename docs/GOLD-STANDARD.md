# Professional quality acceptance target

This is the working acceptance record for the requested 9/10 target. A self-assigned score is not a certification. A release earns a category only through reproducible evidence; missing external evidence remains unearned. Scope is local PII discovery and evidence review for authorized assessments.

| Category | Weight | Required evidence |
| --- | ---: | --- |
| Detection accuracy | 3.0 | Frozen, versioned development/holdout separation; current Rust per-type precision/recall, uncertainty and clean-document false positives; representative independently adjudicated labels before general accuracy claims; no gold-label or holdout tuning |
| Extraction and coverage | 1.5 | Labelled end-to-end fixtures for every advertised format, nested/embedded content and OCR; unsupported/encrypted/truncated content is explicit; coordinates and root-container hashes survive export |
| Scale and recovery | 2.0 | Bounded-retention scanning, durable per-resource checkpoints, cancellation/crash recovery, unchanged-file caching keyed by content and full engine configuration; measured large-file/file-count/unique-finding memory and throughput |
| Reliability and isolation | 1.5 | Crashed/stuck parsers cannot stop the coordinator; enforceable worker deadlines, bounded IPC, resource controls, adversarial regression/fuzz tests; precise distinction between process isolation and OS sandboxing |
| Analyst workflow and evidence | 1.0 | Persistent review decisions/notes/suppressions, traceable findings, exact retest semantics, versioned provenance and honest partial-coverage reporting |
| Release and reproducibility | 1.0 | Clean-machine Windows/Linux/macOS checks, verified packaged assets, complete dependency/asset notice review, vulnerability checks and documented support; authentic release signatures for a public stable release |

Target: at least 9/10, with no critical failure in provenance, data loss, parser containment, or advertised coverage. Numerical accuracy thresholds must be fixed on a separate development corpus before observing a fresh acceptance holdout; they must not be chosen retrospectively to award points. Individual categories may be delivered incrementally, but completing a feature does not automatically earn its entire weight.

## Work sequence

1. Record a current Rust baseline on the frozen external text corpus; retain benchmark limitations. Prepare development data independently of held-out predictions.
2. Add bounded result delivery and resource-level scanning as the foundation for large cases.
3. Add a durable, indexed case store, recoverable scan runs, content/configuration-based caching, and persistent analyst review decisions.
4. Add a separate extraction worker with enforceable deadlines, bounded protocol and explicit resource/sandbox controls.
5. Expand native extraction where useful and validate representative mixed-document/hostile corpora.
6. Improve detectors against separate development data, freeze candidates, and run acceptance comparisons without inspecting held-out errors for tuning.
7. Complete platform/package/performance checks and document external validation still required.

## Starting evidence

Rust 0.4.0 has 192 workspace tests plus minimal-build tests, a 57-case developer smoke corpus, and a 50-file mixed-format package check. These are regression evidence. The existing 5,000-document competitor reports were produced by the earlier .NET engine and do not count as current Rust accuracy or throughput evidence. Large-case recovery, process isolation, persistent review state, independent human adjudication and signed/clean-machine releases were not established at the start of this work.

Current measurements and acceptance progress will be added as work is verified. Raw assessment data and benchmark texts remain outside tracked source files.

## Verified 0.5 development checkpoint

On 9 November 2026, the local macOS/Apple Silicon build passed formatting and all-feature/all-target clippy with warnings denied, 219 workspace tests, 101 minimal-core tests and 22 minimal-CLI tests. The optimized package passed checksums for 1,278 files and the 57-case regression evaluator. A packaged scan outside the checkout retained exactly the prior 320 findings and 50 source records across the mixed fixtures; all source hashes verified. Eleven coverage warnings now include explicit partial-representation warnings for legacy DOC, Outlook MSG and HEIC, which previously lacked those warnings.

Implemented and tested:

- Streaming JSONL with exact totals and no second whole-scan finding/source collection.
- SQLite cases with per-resource checkpoints, bounded discovery queues, content/configuration reuse, historical runs, paged queries, persistent review notes/decisions and streaming export. Interrupted captures recover without duplicating completed root snapshots. Sources with extraction warnings are retried instead of cached. Review decisions remain tied to exact reused snapshots.
- Separate extraction processes with bounded framing/text budgets, mandatory completion, provenance validation, crash recovery and enforced extraction deadlines. Local tests cover crashes, malformed/oversize responses, blocked input pipes, cancellation, worker retirement, Unix descendant cleanup and parity with native extraction across all 50 fixtures. Platform limitations remain documented in [ISOLATION.md](ISOLATION.md).
- Packaged source snapshots and before/after source hashing, compiler/target/build arguments and executable/asset checksums. This is unsigned provenance, not authenticated or bit-reproducible release evidence.

The current Rust text baseline is [recorded separately](../tools/accuracy/baselines/rust-0.4/README.md): 77.67% precision, 72.74% recall and 75.13% F1 on 5,000 projected-label synthetic documents. Presidio in the frozen comparison configuration scored 61.46% precision and 75.02% recall. Timing was uncontrolled; no speedup is claimed. Detector work now has separate 10,000-document train and 2,000-document validation samples prepared without opening test errors.

A first 1,000-file/100,000-unique-email scale run validated all expected findings/sources, unchanged reuse, equal-size/equal-mtime invalidation, streaming export and forced coordinator-crash recovery. Sampled process-tree RSS during capture was about 66 MiB. The harness and measurement limitations are in [tools/performance](../tools/performance/README.md); more dimensions/repetitions are still being measured. This synthetic text result does not establish large mixed-document/model/OCR bounds.

The refreshed RustSec database at commit `d9cb059f3217db87aeccd190b81eaffe8cc29cb9` reported zero known vulnerabilities in the locked graph and two unmaintained-package warnings (`atomic-polyfill` through phone metadata serialization and `ttf-parser` through PDF extraction). This is an advisory check with disclosed warnings, not a complete native supply-chain audit.

The 9/10 target is **not yet achieved**. Remaining evidence includes substantial accuracy improvement, independent representative adjudication, broader end-to-end format/OCR gold labels, larger/repeated memory measurements, OS sandbox/Windows job controls, and actual clean-machine matrix/release-signing results. A paged desktop case browser is an optional workflow extension; the CLI is the primary assessment interface. The implemented features do not automatically award category points.
