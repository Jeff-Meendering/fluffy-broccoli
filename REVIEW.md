# Rust 0.5 development validation

The active implementation is Rust: a shared detection/extraction core, native desktop app, headless CLI, durable SQLite cases and separate extraction workers. The [0.4 validation record](docs/history/REVIEW-RUST-0.4.md) and [.NET assessment](docs/history/REVIEW-0.3.md) are historical. The requested [9/10 acceptance target](docs/GOLD-STANDARD.md) remains active and unachieved.

## Verified engineering

Local macOS/Apple Silicon checks on 9 November 2026 passed formatting and all-target/all-feature clippy with warnings denied, **219 workspace tests**, **101 minimal-core tests** and **22 minimal-CLI tests**. The 13 Python scoring-contract tests passed in the hash-locked accuracy environment. Rust/Cargo are 1.99.1; local OCR is Tesseract 5.5.3.

The durable case workflow covers per-resource checkpoints, interruption recovery, SHA-256/configuration reuse, historical runs, paged queries, persistent review notes/decisions, streaming export and internal integrity checks. Equal-size edits with restored modification times invalidate the cache. Unfinished or warning-bearing resources are retried. Reviews follow exact reused snapshots; changed source/engine snapshots start unreviewed. Discovery commits bounded batches before dispatch; completed roots retain individual atomic durability checkpoints. See [CASES.md](docs/CASES.md).

Default CLI/desktop filesystem extraction runs in helpers with bounded IPC, required completion records, root budgets, deadlines, crash replacement and explicit partial coverage. Tests include malformed/oversize responses, blocked input, cancellation, worker retirement, Unix descendant cleanup and native-versus-worker equality across all 50 mixed fixtures. Unix pipes use readiness polling rather than a fixed per-response delay. Process isolation is not an OS sandbox; [ISOLATION.md](docs/ISOLATION.md) records Linux/macOS/Windows boundaries.

The optimized package includes CLI, desktop and worker executables, pinned assets, notices, source snapshots and build provenance. Source hashes are checked before/after compilation and staging. Checksums verified 1,278 files at this checkpoint. This is an unsigned local build, not a clean-machine, authenticated or byte-reproducible release result.

Outside the checkout, the packaged evaluator passed all 57 developer smoke cases (38 TP, zero FP/FN). The full packaged mixed-format scan retained exactly the previous 320 findings and all 50 source records, with every root hash verified. Eleven attention items include three newly explicit partial-representation warnings for legacy DOC, Outlook MSG and HEIC. Those formats still use reduced strings views. The other eight warnings cover handwriting uncertainty, the OneNote index, malformed documents/archives, binary-control content and an encrypted member. Occurrence totals are not affected-person or general accuracy metrics.

## Accuracy and scale evidence

The [frozen Rust 0.4 artifact baseline](tools/accuracy/baselines/rust-0.4/README.md) measured 77.67% precision, 72.74% recall and 75.13% F1 on 5,000 synthetic text documents with projected labels. Presidio in the frozen configuration measured 61.46% precision and 75.02% recall. These are current Rust measurements, separate from historical .NET results. Timings were uncontrolled and do not support a speedup claim. Independent adjudication and a fresh acceptance holdout remain required for general claims.

Separate 10,000-document train and 2,000-document validation samples now support detector development without inspecting held-out errors. No detector changes have yet been accepted from this work. Upstream model/corpus training overlap must be disclosed for candidate selection.

The [scale harness](tools/performance/README.md) validates distinct-email capture, reuse, paging, streaming output, same-size/same-mtime invalidation and forced coordinator-crash recovery while sampling coordinator/process-tree RSS. A first 1,000-file/100,000-finding run used about 66 MiB observed tree RSS. A 10,000-file run exposed avoidable IPC/discovery overhead, which is being measured again after readiness-polling and bounded-transaction changes. These are synthetic text workloads with names/OCR disabled, warm filesystem caches and sampled rather than exact peak memory. Larger per-file, mixed-document and model/OCR bounds remain unproven.

The refreshed RustSec database (`d9cb059f3217db87aeccd190b81eaffe8cc29cb9`, 9 November 2026) reported zero known vulnerabilities and two unmaintained-package warnings: `atomic-polyfill` through phone metadata serialization and `ttf-parser` through PDF extraction. This is not a native supply-chain audit. Generated dependency/asset notices still need redistribution review.

## Remaining acceptance work

Accuracy improvement and independent representative labels, broader end-to-end OCR/format gold data, repeated large-case measurements, OS sandbox/Windows Job Object controls, actual clean-machine Windows/Linux/macOS runs and authenticated release signing remain incomplete. A desktop case browser is an optional extension to the primary CLI workflow. GitHub matrix CI is configured; it has not run in this local session. Case/export records are plaintext and unsigned; internal consistency and source equality do not establish authenticity or chain of custody.

Reproduce with `cargo xtask assets`, `cargo xtask test`, `cargo xtask package` and `cargo xtask verify`. Logs, benchmark corpora, generated cases and measurements remain in ignored local directories. Completing engineering features does not itself award the 9/10 target.
