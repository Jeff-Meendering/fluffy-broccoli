# Initial Rust artifact baseline — 9 November 2026

Both engines processed the same frozen 5,000-document Gretel text corpus: 7,499 projected gold entities across Email, IP, payment card, Person, Phone and SSN. The Rust artifact is the previously built 0.4.0 macOS package, before durable-case/streaming improvements. Its exact executable, model and vocabulary hashes are in `piiexplorer.report.json`; the executable is retained locally under ignored `.build-tools/baseline-bin`.

| Engine | Precision | Recall | F1 | False positives / scope-clean document |
| --- | ---: | ---: | ---: | ---: |
| PII Explorer Rust 0.4.0 | 77.67% | 72.74% | 75.13% | 0.207 |
| Presidio 2.2.362 / spaCy large | 61.46% | 75.02% | 67.57% | 0.516 |

These are diagnostic baseline measurements, not a gold-standard acceptance result. Rules, model thresholds, mappings and gold labels were not changed to obtain the outcome. The source labels are projected from annotation values rather than independently adjudicated spans. Corpus preparation checked exact normalized document overlap with source train/validation and the local smoke set; it does not exclude template or pretrained-model contamination. See the parent benchmark README for full conventions and limitations.

The environment was the hash-locked Python benchmark installation, including NumPy 2.5.3, PyArrow 23.0.1, Presidio 2.2.362, spaCy 3.8.11 and en_core_web_lg 3.8.0. Python networking was disabled during Presidio prediction. Rust used only local pinned assets. No assessment or benchmark text is checked in here.

Recorded startup-inclusive timings were 170.2 seconds for the Rust artifact and 356.0 seconds for Presidio on this Apple Silicon host. Other development compilation occurred during the session, and the runs were not repeated under controlled idle-machine conditions. These timings must not be presented as a general speedup or release performance benchmark. Peak process-tree memory was not measured in this run.

The report's `source_commit` is the checkout base, not a clean Rust release commit: the original Rust migration was still uncommitted. The executable hash identifies the tested artifact. This limitation must be corrected for a reproducible public release through a frozen source/build manifest and authenticated release artifacts.
