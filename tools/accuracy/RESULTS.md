# Initial independent baseline — 11–12 September 2026

Both detectors processed the same 5,000 Gretel test documents, with 7,499 projected gold entities in the six-type scope. There were 990 documents without gold entities in that scope. Dataset revision, label projection, configurations and limitations are specified in [README.md](README.md); machine-readable aggregate reports are in [baselines](baselines).

| Engine/configuration | TP | FP | FN | Precision | Recall | F1 (95% document-bootstrap interval) | FN/gold | FP/clean document |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PII Explorer, patterns + local names | 5,414 | 1,453 | 2,085 | 78.84% | 72.20% | 75.37% (74.46–76.26%) | 27.80% | 0.170 |
| Presidio 2.2.362, spaCy large, threshold 0 | 5,626 | 3,528 | 1,873 | 61.46% | 75.02% | 67.57% (66.70–68.38%) | 24.98% | 0.516 |

| Type | PII Explorer precision / recall / F1 | Presidio precision / recall / F1 |
| --- | --- | --- |
| Email | 94.1% / 95.6% / 94.8% | 97.8% / 99.6% / 98.7% |
| IP address | 96.4% / 74.4% / 84.0% | 96.7% / 99.4% / 98.0% |
| Payment card | 99.0% / 60.9% / 75.4% | 97.0% / 54.4% / 69.8% |
| Person | 58.7% / 81.0% / 68.0% | 40.8% / 68.8% / 51.2% |
| Phone | 91.1% / 49.6% / 64.2% | 44.2% / 77.8% / 56.4% |
| Social Security number | 97.5% / 61.0% / 75.0% | 76.1% / 60.5% / 67.4% |

These results expose substantial misses and false positives that the development smoke corpus did not show. They describe a synthetic corpus, projected labels, and fixed configurations. They do not establish superiority across domains, languages, extraction paths, tuned competitors, or real-world documents. In particular, literal source annotation projection and synthetic identifier validity can affect both engines' measured errors. No detector rules, model weights, confidence thresholds, or label mappings were tuned against these outcomes.

Normalized full-document leakage checks against all source train/validation records and the local smoke corpus found zero overlaps; duplicate and unalignable test-document counts were also zero. Template-level overlap and pretrained-model contamination remain unknown. No independent human annotation agreement result is available; the audit command and prospective agreement gates are provided for that work.

## Five shared identifier types, all local

The following comparison excludes Person consistently across all four engines. It contains 5,239 projected gold entities and 1,735 scope-clean documents. PII Explorer/Presidio use the same predictions as above, projected to this scope. Philter/Phinder use the frozen five-identifier policy with names disabled. Their name models are not evaluated.

| Engine | TP | FP | FN | Precision | Recall | F1 (95% interval) | FN/gold | FP/clean document |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PII Explorer | 3,584 | 164 | 1,655 | 95.62% | 68.41% | 79.76% (78.82–80.66%) | 31.59% | 0.025 |
| Presidio | 4,070 | 1,270 | 1,169 | 76.22% | 77.69% | 76.94% (76.01–77.82%) | 22.31% | 0.171 |
| Philter 3.4.2 / Phileas 3.3.0 | 3,896 | 2,343 | 1,343 | 62.45% | 74.37% | 67.89% (66.84–68.86%) | 25.63% | 0.499 |
| Phinder pinned snapshot / Phileas 4.2.0 | 3,896 | 2,343 | 1,343 | 62.45% | 74.37% | 67.89% (66.84–68.86%) | 25.63% | 0.499 |

Philter and Phinder were executed independently and returned identical aggregate counts under this policy. Both ran locally with Docker networking disabled. Philter's client and server communicated only over loopback inside one container; Phinder used a direct Java method. Presidio was also verified with Python network operations blocked and a bundled suffix snapshot. No outside requests are needed during testing; pinned dependency/corpus downloads are a separate preparation step.

The complete per-type counts, rates and intervals for each configuration are in the `*-identifiers.report.json` baseline files. These results do not evaluate Philter/Phinder's optional name models or any file extraction path. Source annotations remain projected, not independently human-adjudicated.

The report schema is version 1 for this standalone benchmark. The older application `--evaluate` report advances to schema 2 for additive miss-rate and clean-document metrics. Its small synthetic corpus remains a smoke check and does not replace this benchmark.
