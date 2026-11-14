# Independent text accuracy benchmark

This workflow evaluates frozen detectors against independently authored labels. All detector testing runs on this computer; no outside inference requests are permitted. The existing 57-case `evaluate` corpus remains a development smoke test. Neither corpus evaluates extraction, OCR, file discovery, UI behavior, or real-world prevalence. See [RESULTS.md](RESULTS.md) for the measured baselines and annotation limitations.

Historical reports in `baselines` and `RESULTS.md` describe the earlier .NET engine. New runs use the Rust CLI and must be labelled as a separate engine/build; do not reuse historical results as Rust accuracy claims.

## Reproduce

Use Python 3.12, the pinned Rust toolchain and pinned assets. From the repository root, in PowerShell:

```powershell
py -3.12 -m venv .build-tools/accuracy-venv
$accuracyPython = '.build-tools/accuracy-venv/Scripts/python.exe'
& $accuracyPython -m pip install --require-hashes -r tools/accuracy/requirements.lock
cargo xtask assets
cargo build --release --locked -p pii-explorer-cli
& $accuracyPython -m unittest discover -s tools/accuracy -v
& $accuracyPython tools/accuracy/benchmark.py prepare .build-tools/accuracy-heldout
& $accuracyPython tools/accuracy/benchmark.py run .build-tools/accuracy-heldout test-results/accuracy-new
```

Preparation downloads approximately 24 MB of dataset Parquet files. Environment installation also downloads the large local spaCy model. These are explicit setup steps, separate from testing. Once prepared, repeat the tests without downloading anything: the PII Explorer adapter invokes the built local Rust CLI; Presidio's Python network operations are blocked and its email validator uses the bundled suffix snapshot without cache or online refresh. The Java competitors run with Docker networking disabled and `--pull never`. No outside requests or hosted inference are used during these runs. Use a **new directory** for each prepare/run; existing files are never overwritten. On POSIX, create the environment with `python3.12` and use `.build-tools/accuracy-venv/bin/python`. Alternatively, `uv venv --python 3.12 .build-tools/accuracy-venv` provisions an isolated Python when it is not installed system-wide. The measured environment is Windows/Python 3.12.14; other platforms have not been verified.

The `run` command requires already-built Release binaries. It runs PII Explorer and Presidio sequentially, then scores their predictions. Use `--engines piiexplorer` or `--engines presidio` for one engine. A failed engine aborts the command; any earlier engine's complete report survives. There is no report for an incomplete engine, and missing predictions are never interpreted as clean documents. Partial output directories must not be used as successful full comparison runs.

For fast scorer tests alone, install `scorer-requirements.lock` with `--require-hashes` and run the unittest command. The separate `accuracy-scorer.yml` workflow does this without downloading labels or running detectors. Hosted execution of that new workflow remains to be verified.

## Corpus and frozen projection

The source is [Gretel AI's synthetic English PII corpus](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1/blob/5a7552a2a4d5782845015f18dc3e96826df14506/README.md), revision `5a7552a2a4d5782845015f18dc3e96826df14506`, under Apache 2.0. Its published test split has 5,000 documents. `dataset.json` pins the revision and SHA-256 of every downloaded split. No source documents or labels are committed or shipped in application packages. Only aggregate baseline reports are checked in.

The source annotations contain values and types rather than offsets. Projection v1 finds **all literal occurrences** of each annotated value and converts code-point positions to UTF-16 code units. Overlapping or whitespace-adjacent Person parts merge into a full Person span. Original text is never normalized for detection/scoring. Empty/unmatched source annotations quarantine the entire document before any predictions are inspected. Projection is reproducible, but can propagate source omissions, mislabel repeated values, or merge adjacent distinct people; these are label uncertainties, not evidence of detector errors. No human-adjudicated offset gold or inter-annotator agreement score is claimed for this initial run.

The predeclared common comparison scope is:

| Benchmark type | Gretel labels | Presidio labels |
| --- | --- | --- |
| Person | name, first_name, last_name | PERSON |
| Email | email | EMAIL_ADDRESS |
| Phone | phone_number | PHONE_NUMBER |
| IP address | ipv4, ipv6 | IP_ADDRESS |
| Payment card | credit_card_number | CREDIT_CARD |
| Social Security number | ssn | US_SSN |

DOB versus general dates, partial versus full addresses, and ambiguous identifier subtypes are excluded because their taxonomies differ. The manifest counts every excluded source type; reports count excluded prediction types. This is a six-type comparison, not an accuracy claim for all advertised entities. Synthetic identifiers are scored according to source labels even when a checksum/issuance validator rejects them; this measures source-labelled entity discovery, not identifier validity.

## Leakage and annotation checks

Preparation compares NFKC-normalized, casefolded, whitespace-collapsed document fingerprints against all source train/validation records and the local smoke corpus. Overlaps and repeated test documents/IDs are quarantined deterministically in ID order and counted in the manifest. Test texts are not selected according to predictions. The first run found no overlaps, duplicates, or unalignable annotations. This check does not establish absence of template/near-duplicate overlap or contamination in pretrained models; it also cannot inspect private tuning corpora.

`inputs.jsonl` contains only `Id` and `Text`. The predictor process receives this file, not `gold.jsonl`. Scoring checks corpus hashes, prediction text hashes, exact document coverage, label scope, duplicates, and valid UTF-16 boundaries. Duplicate predictions count once; duplicate gold spans are errors. A predicted type or boundary mismatch counts as both FP and FN.

For a human annotation audit, have two reviewers independently label the same text-only sample under the frozen scope and span policy, without viewing detector output or each other's annotations. Store separate JSONL files with `Id`, `Text`, and `Entities` (`Type`, `Start`, `Length` in UTF-16). Then run:

```powershell
& $accuracyPython tools/accuracy/benchmark.py agreement cases/reviewer-a.jsonl cases/reviewer-b.jsonl reports/agreement-new.json
```

This reports symmetric exact-entity agreement F1 and per-type disagreement accounting, with file fingerprints. It is not chance-adjusted kappa and cannot verify reviewer independence. Require F1 >= 0.95 overall and >= 0.90 for each type with at least 20 annotations; adjudicate all disagreements before designating a human-reviewed gold release. These are prospective annotation-quality gates, not measured results. Use at least 200 randomly selected documents, including at least 50 scope-clean controls. Reviewer output and adjudicated labels stay outside the repository.

Do not inspect held-out errors to change recognizers, label mappings, thresholds, or test selection. Develop changes against separate development data; run the frozen benchmark as a release checkpoint. If a label defect requires correction, version the corpus/projection, document the reason independently of engine rankings, and establish a new baseline for **every** engine. Repeated release use eventually makes this a regression corpus; obtain a fresh independent holdout for subsequent generalization claims.

Prepare independent development samples from the already checksum-pinned source train/validation files:

```sh
.build-tools/accuracy-venv/bin/python tools/accuracy/prepare_development.py .build-tools/accuracy-heldout/source .build-tools/accuracy-development
```

This creates separate 10,000-document train and 2,000-document validation corpora by stable SHA-256(uid) order, applying the same label projection and exact normalized development deduplication. The script never opens test Parquet or held-out predictions/errors. Validation is checked against the entire source train split, including unsampled documents. These are development sets with synthetic projected labels, suitable for candidate selection and diagnostics. They are not fresh acceptance holdouts or independent human ground truth. Models may already have seen related source templates during upstream training; record that limitation when selecting models.

## Metrics, uncertainty, and regression gates

Reports include per-type and micro TP/FP/FN, gold support, precision, recall, F1, FN/gold, scope-clean document counts, and FP per scope-clean document. For a per-type metric, clean means no gold of that type; for micro it means no gold of any of the six types. A document may still contain excluded PII. Macro metrics average only defined type metrics and report the number of defined types. Zero denominators produce `null`, never a perfect score.

Per-type and micro rates have 95% percentile intervals from 2,000 deterministic document bootstrap resamples (seed 20260911). This preserves within-document entity dependence; related documents/templates and label uncertainty are not modeled. Resamples with undefined denominators are omitted and their count is reported. All-correct samples yield degenerate bootstrap intervals, which do not establish zero population error. The displayed macro averages have no interval. Elapsed time includes startup and is descriptive, not a controlled performance comparison.

The initial **prospective engineering budgets**, fixed before inspecting results, are a maximum absolute drop of 0.02 in precision, recall, or F1 for micro and each type with at least 50 gold entities, and a maximum increase of 0.05 FP per clean document with at least 50 clean documents. Unsupported sample sizes are explicitly unassessed. These are change-control budgets, not calibrated statistical significance or product acceptance thresholds. Review the uncertainty intervals and annotate any configuration changes alongside a gate result.

```powershell
& $accuracyPython tools/accuracy/benchmark.py compare test-results/accuracy-rust-baseline/piiexplorer.report.json test-results/accuracy-new/piiexplorer.report.json
```

Create a fresh Rust baseline in `test-results/accuracy-rust-baseline` before using that comparison. Checked-in .NET baselines intentionally have a different engine identity.

The command fails on budget violations or incompatible engine, corpus, scope, or matching conventions. A passing comparison does not establish sufficient absolute accuracy. Product thresholds and representative independent human-reviewed corpora are still required before making professional accuracy claims. Do not change budgets to make a held-out candidate pass.

## Competitor contracts

Presidio is pinned to `2.2.362`, spaCy `3.8.11`, `en_core_web_lg` `3.8.0`, English, six requested entities and threshold `0.0`; the complete Python dependency graph and model wheel hashes are locked. This is a documented stock configuration, not a threshold-optimized competitor. PII Explorer uses patterns plus its pinned local name model, default US/GB phone regions, and the scanner's occurrence spans. The comparison does not implement the future scanner evidence-fusion policy in I17. All supported detector spans are scored without confidence trimming or boundary repair.

### Local Philter and Phinder

The additional comparison covers five shared identifier types: Email, IP address, Payment card, Phone, and Social Security number. `identifier-policy.json` enables those recognizers only. Person is excluded from gold and predictions, with excluded counts reported. PII Explorer and Presidio's existing full-detector predictions are also scored on exactly this five-type scope. Do not compare a five-type score directly with the six-type score above.

[Philter](https://github.com/philterd/philter/tree/88181923f078f888615fac100b7bd9d9f1808b96) 3.4.2 uses Phileas 3.3.0. `PhilterAccuracy.java` and the Philter server run **inside the same network-disabled container**. The client uses only its hardcoded `127.0.0.1` endpoint; there is no published host port, proxy, redirect, or selectable external endpoint. Only effective `appliedSpans` are scored, after checking they refer to original input text. No Ph-eye name service or remote model is enabled. The harness stops and removes its own server container on completion or failure.

[Phinder](https://github.com/philterd/phinder/tree/ab074151c4a4699dd1efff866f8c190af17490ca) is pinned to revision `ab074151c4a4699dd1efff866f8c190af17490ca`, version `1.0.0-SNAPSHOT`, Phileas 4.2.0. Its ordinary CLI report discards spans, so `PhinderAccuracy.java` calls its existing `findPii(text, policy)` Java method directly, in one local process with networking disabled. No upstream source changes or remote service are required. This tests the text detector, excluding file routing and filename evidence. Both adapters receive only the text input file; gold labels are not mounted into their containers.

One-time setup below downloads pinned build dependencies. Skip setup when they are already available; the test commands following it make no outside requests. Use a local Docker engine.

```powershell
$accuracyJavaImage = 'maven@sha256:31618505df21177d2baa3dc574be2d0b0b32614c8539baca1f23a9136b766eb0'
docker pull $accuracyJavaImage
docker pull philterd/philter@sha256:3ad701da32966af04db6e019997f1fb7d3ebb3f2931a4b737274318c83e70380
git clone --no-checkout https://github.com/philterd/phinder.git .build-tools/accuracy-phinder
git -C .build-tools/accuracy-phinder checkout --detach ab074151c4a4699dd1efff866f8c190af17490ca
$accuracyPhinderRoot = (Resolve-Path .build-tools/accuracy-phinder).Path
docker run --rm --memory 3g --cpus 4 --mount "type=bind,source=$accuracyPhinderRoot,target=/work" -w /work $accuracyJavaImage mvn -B -q '-DskipTests' '-Dmaven.javadoc.skip=true' package
```

Run local tests after setup:

```powershell
& $accuracyPython tools/accuracy/benchmark.py phinder .build-tools/accuracy-heldout test-results/phinder-new .build-tools/accuracy-phinder
& $accuracyPython tools/accuracy/benchmark.py philter .build-tools/accuracy-heldout test-results/philter-new .build-tools/accuracy-phinder
```

The Phinder checkout must have the pinned revision and no tracked modifications. Reports record source revision, jar/adapter/policy hashes, immutable container images, scope and memory/CPU settings. Philter's small client uses Gson from the already built Phinder jar; Philter's detector still runs the separately pinned Philter image. The recorded jar fingerprint identifies the tested build; byte-identical Maven rebuilds are not claimed.

The generic `score` command accepts complete prediction JSONL files from another local tool, with `Id`, `TextSha256`, and `Entities` in the same schema. It never contacts that tool. Provide a JSON configuration with `engine`, `version`, build/model/policy hashes, mapping and settings. An optional `scope` array can select a nonempty subset of the six frozen types; excluded gold and predictions are counted explicitly:

```powershell
& $accuracyPython tools/accuracy/benchmark.py score .build-tools/accuracy-heldout cases/external.predictions.jsonl cases/external-config.json reports/external-new.json
```

For the five-type comparison, supply `scope: ["Email", "IP address", "Payment card", "Phone", "Social Security number"]` and retain the original prediction configuration and report fingerprint. The checked-in `*-identifiers.report.json` files demonstrate this rescore. All four engines have been run on the 5,000-document corpus. Philter/Phinder name-model comparisons and an independent human annotation audit remain outside these measured baselines.

Reports carry no source text. Their input/prediction hashes, engine settings, local asset hashes, executable hashes, dependency versions, and harness file fingerprints support replay. Local report directories and all corpus/annotation files remain ignored. Independent human adjudication remains necessary before treating projected source annotations as validated offset gold.
