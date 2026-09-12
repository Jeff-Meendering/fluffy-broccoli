# PII Explorer 0.3.0 assessment

Reviewed 11 September 2026. This is a useful development checkpoint and a candidate for a controlled professional pilot. It is not yet supported by evidence sufficient to claim best-in-class detection, exhaustive discovery, or forensic-grade reliability.

I02 follow-up: a separate [independent text benchmark](tools/accuracy/RESULTS.md) now measures 5,000 externally authored synthetic documents against PII Explorer, Presidio, and local Philter/Phinder identifier configurations. The original assessment below predates those runs. They do not replace extraction/OCR evaluation, independent human adjudication, or evaluation of the competitors' optional name models.

## Continue or use Presidio?

Continue if the product you want is a portable, local folder-scanning and evidence-review application for analysts. If your only requirement is a general-purpose PII detection API, start by evaluating Presidio instead of maintaining a competing library from scratch. Keeping this application and reusing a stronger detector are compatible decisions.

| Area | PII Explorer now | Presidio |
| --- | --- | --- |
| Analyst workflow | Native Windows UI, folder discovery, nested source locations, attention items, filtering, PDF reports and portable packaging | Developer framework with APIs, integrations and samples; adapting it to this workflow still requires application work |
| Detection architecture | Custom rules/checksums, libphonenumber, explicit table context, Unicode normalization and a local English DistilBERT name model | Extensible recognizers combining patterns, validation, context and configurable NLP engines |
| Coverage | Selected identifiers across several countries, credentials, wallets and some address forms; uneven coverage with substantial custom maintenance | Broader documented country/entity inventory and model integrations; configuration and evaluation are still necessary |
| File handling | Tika document extraction, selected metadata, archives, OCR and limited binary-string recovery | Text, structured-data, image/redaction capabilities and integration examples; compare the specific pipeline you would deploy |
| Proven accuracy/speed | Local regression checks and synthetic workload timings below | No head-to-head run was performed here, so neither superiority nor a performance disadvantage is established |

Sources: [Presidio Analyzer architecture](https://presidio.dataprivacystack.org/analyzer/), [supported entities](https://presidio.dataprivacystack.org/supported_entities/), and [official project](https://github.com/data-privacy-stack/presidio). The old Microsoft repository redirects to the current project location. Presidio itself does not promise to discover all sensitive information.

The next engine decision should use the same held-out, consented or synthetic corpus for both systems. Freeze versions, NLP models, languages, country configuration and thresholds. Map entity labels and span conventions before scoring: this app uses UTF-16 offsets and includes labels in some spans, whereas Python string indexing counts Unicode code points. Measure per-type precision/recall, missed files, false positives per clean document, source attribution, cold startup, p50/p95 latency and total peak memory including subprocesses. Keep extraction/OCR evaluation separate from text-detector evaluation.

Use Presidio as a baseline first; integrate it locally only if the measured benefit justifies the Python/runtime and packaging cost. PII-specific models, including the GLiNER integration documented by Presidio, are reasonable experiments on that evaluation branch. Experimental models are not automatic reliability improvements. No Presidio runtime, remote inference service or replacement model was added in this pass.

## Review of the new changes

Kept libphonenumber, the expanded identifier/credential/wallet rules, configurable workers/phone regions, name-token handling, markup extraction and binary recovery. The international rules add useful coverage but their scores are heuristics, not calibrated probabilities. Check digits establish format consistency, not issuance or identity. Some legitimate national variants and lower-case/unlabelled names or addresses remain outside these rules.

Corrected these concrete defects:

- One broad path-removal regex was applied to findings, context, metadata and errors alike. It replaced legitimate detected values that begin with `/`, including a reproduced email and a connection-string credential, and because a match ran to the end of the line it also removed the parser failure reason that followed a path. Reports now redact only unambiguous host paths from a detected value, keep each value verbatim inside its surrounding context, and stop a path match at the end of the path.
- Fast gates skipped valid IPv6 addresses with few decimal digits, letter-heavy IBANs, POB addresses and supported medical/member/patient labels. IDNA-encoded email suffixes also work again.
- Invalid year values could throw during national-ID validation, interrupting extraction of unrelated evidence. Zero-filled NHS/TFN placeholders are rejected.
- Wallet validation now checks witness version, program length, padding and the appropriate Bech32/Bech32m checksum. Generic checksum validity alone was insufficient; short valid witness addresses were also missed. See [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
- Overlap resolution handles non-monotonic span ends and preserves earlier findings before reporting a later regex timeout. An explicit ID label prevents incidental phone classification without excluding helpline labels.
- Binary recovery has bounded chunks, nearby word-boundary splitting, overlap, strict output limits, correct ASCII/UTF-16LE starting byte offsets and separate contiguous runs. Unrelated byte ranges no longer acquire invented shared label context. It remains a partial strings view, not a packet, memory or database parser; other encodings/compression/encryption are not decoded.
- Package evaluation now reads the current corpus annotations and enables names. The previous package assertion expected 37 cases, while the updated corpus has 57, including a Person annotation.
- Refreshed normal/benchmark/publish dependency locks and license inventory. Every model/tokenizer/config input is checksum-pinned, and incomplete downloads cannot become cached assets.
- Added a repeatable validation script, pinned Windows CI actions, editor settings, contributor guidance and exclusions for local cases, exports and credentials. Previous review notes are retained locally in the ignored build directory rather than presented as current release evidence.

## Validation and performance

`./scripts/Test.ps1` passed on 11 September 2026: **397 tests, zero failures or skips**, with warnings treated as errors. Normal, benchmark and Windows publish dependency locks were refreshed/checked. NuGet audit reported no known vulnerabilities in the restored NuGet graph at that time. Java was rebuilt from the current worker source; pinned existing download files were hash-checked. PowerShell scripts passed syntax parsing. Hosted GitHub CI has not run yet; native desktop rendering and a clean VM install have not been verified in this pass.

Final engine benchmarks use Windows 11, Ryzen 9 7900X (24 logical processors), approximately 64 GB RAM, .NET 10.0.9 and two scan workers. These are three sequential repetitions with a new scanner each time; OS/JIT caches may be warm. The desktop UI defaults to 2–4 workers depending on CPU count, so its timings can differ.

| Workload | Median seconds | Range (seconds) | Findings | Attention items | .NET allocated MB (median) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2000 small text files, patterns | 0.613 | 0.606–0.751 | 2000 | 0 | 60.9 |
| 200000 emails, patterns | 0.601 | 0.543–0.666 | 200000 | 0 | 314.1 |
| 25000 spreadsheet rows, names on | 3.160 | 3.089–3.706 | 44892 | 0 | 631.1 |
| mixed corpus, OCR and names on | 4.111 | 4.086–4.303 | 246 | 18 | 120.8 |
All three repetitions returned identical finding/attention counts within each workload. The mixed corpus intentionally contains unreadable, encrypted and malformed inputs; its 18 attention items are expected. These measurements exclude GUI rendering, report export and fixture creation. Allocation figures are cumulative managed allocations, not peak RAM, and exclude Java/OCR/native model memory.

The expanded detector costs more on the large email list than the earlier narrower implementation (earlier local measurements were around 0.3–0.4 seconds). Spreadsheet and mixed-document timings are encouraging, but environment/cache effects and changed coverage make a universal speedup claim unjustified. More findings also do not establish greater accuracy. Test representative laptops, large numbers of unique results and adverse inputs before setting throughput expectations. Reproduce with `tools/PiiExplorer.Benchmarks`; the final local measurements are in `test-results/final-0.3.0-benchmarks.json`.

The rebuilt 0.3.0 Windows executable passed the isolated-PATH package check across all 50 mixed fixtures, including OCR, local names, PDF, Office and nested archives. Its evaluator passed all 57 smoke cases with 38 true positives, zero false positives and zero false negatives, with names enabled. This is a same-host deployment smoke test, not a clean-machine or Sandbox test.

The smoke corpus is a developer-authored regression set, now 57 short cases with 38 annotated entities and 19 negative controls. Its results do not estimate real-world accuracy. With `--no-names`, its Person annotation intentionally remains a false negative; use names enabled for the package acceptance check.

## Release limits

The parser and OCR processes are not an OS sandbox. File limits, cancellation, archive limits and attention items reduce failure impact but do not contain a parser exploit. The optional Windows Sandbox configuration has not been exercised in a live guest during this review. Use a disposable, isolated analysis environment for untrusted files.

Clean-machine and representative laptop performance, Windows signing, total-process memory measurement, independent accuracy evaluation, broader international coverage, case persistence/resume, cryptographic source hashing and an evidence audit trail remain unfinished. Source length/timestamp checking does not establish an unchanged file hash. Findings and temporary data can contain PII; crash cleanup is not guaranteed. NuGet audit results do not cover all Java/native components. The retained Linux build has not been revalidated for 0.3.0.

Before broad professional rollout, define acceptance thresholds with testers, validate realistic corpora and isolated clean-machine installs, review all bundled dependencies, and establish a signed release/update process. Until then, describe this as a pilot with explicit limitations. See [PILOT-GUIDE.md](PILOT-GUIDE.md) and [CONTRIBUTING.md](CONTRIBUTING.md).
