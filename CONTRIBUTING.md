# Contributing

PII Explorer is an Apache-2.0 Rust workspace for local, authorized PII discovery. Changes should improve analyst evidence, coverage, accuracy or reproducibility. Keep reports and source data out of commits.

## Development

Read [build instructions](docs/BUILD.md), then run:

```sh
cargo xtask assets
cargo xtask test
```

For the optional Python scorer checks, prepare the locked environment in [tools/accuracy](tools/accuracy/README.md) before running its unittest command.

Use synthetic fixtures only. Put local cases and reports in ignored directories. Run `git diff --check` before submitting. Do not include working secrets or personal records in issues, test snapshots, screenshots or PRs. Follow [SECURITY.md](SECURITY.md) for vulnerabilities.

## Workspace

- `crates/core`: detection, extraction, provenance, source verification, saved-scan import, evaluation and reports.
- `crates/cli`: pipeline/assessment interface and saved-scan review commands.
- `crates/app`: native egui folder scanning and evidence review.
- `crates/xtask`: pinned asset verification, repeatable checks and local package staging.
- `tests/fixtures`: frozen synthetic regression and adversarial extraction inputs.
- `tools/accuracy`: independent text benchmark and scorer contracts; optional Python tooling, not an application dependency.
- `legacy/dotnet`: historical source/tests for migration reference; not an active implementation.

## Changes to detection and extraction

Preserve exact occurrence coordinates, separate decoded/synthesized/OCR/metadata streams, and root-container provenance. Do not merge repeated occurrences simply because values are equal. Keep filename and embedded-content coverage visible. Unsupported, malformed, encrypted or truncated content must produce attention rather than a clean result.

Include a positive example and a meaningful negative or adversarial example for detector changes. Check Unicode, boundaries and label context. Preserve existing gold labels unless independent review establishes a label error. A checksum proves format consistency, not issuance. Scores are heuristics; do not present them as calibrated identity probabilities.

Keep archive expansion, extracted text, image dimensions, regex configuration and subprocess output bounded. Cancellation/deadlines must not discard earlier findings or block the UI. An in-process parser cannot be forcibly stopped by a cooperative timeout; do not describe this as a sandbox.

## Measuring improvements

Run the 57-case smoke corpus as a regression check and the held-out text benchmark when changing coverage or models. Record versions, settings, asset hashes, extraction settings and environment. Text-only benchmarks do not validate OCR or document extraction. Report per-type precision/recall and clean-document false positives rather than a single marketing score. Historical .NET baselines cannot be attributed to the Rust engine.

Dependency updates must update `Cargo.lock` and preserve license notices. Packages include a generated dependency inventory; maintainers still need to review native components and nested third-party assets. CI should pass on all supported platforms before tagging a release. Signing, notarization and clean-machine validation are release work, not effects of `cargo xtask package`.
