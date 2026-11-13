# Scale and recovery measurements

This harness generates only synthetic, distinct ASCII emails in plain text. It exercises durable capture, unchanged-source reuse, bounded paging, streaming export, regular JSONL streaming, equal-size/equal-mtime edits and optional coordinator crash recovery. It checks actual finding/source counts and case integrity instead of timing commands without validating their output.

```sh
python3 -m venv .build-tools/performance-venv
.build-tools/performance-venv/bin/python -m pip install --require-hashes -r tools/performance/requirements.lock
cargo xtask package
.build-tools/performance-venv/bin/python tools/performance/benchmark.py /path/to/package/pii-explorer test-results/scale-1000x100 --files 1000 --per-file 100 --crash
```

On macOS use `dist/aarch64-apple-darwin/PII Explorer.app/Contents/MacOS/pii-explorer` (or the matching host target). Give each run a new output directory. Keep all outputs outside the evidence tree; the harness uses a newly generated subdirectory with known synthetic content. `--crash` deliberately kills its own live CLI process after at least three resource checkpoints and verifies recovery in a new run. Use at least 100 files for that check.

Compare different dimensions with the same release binaries: for example 1,000×100 and 10,000×10 distinguish findings from file-count overhead; 1×100,000 exercises per-file buffers. Run multiple repetitions on an otherwise idle host with identical options, and report warm file-cache effects. The regular stream check retains its default 500,000-finding cap. Names and OCR are disabled to isolate coordination and case storage. These results do not measure model inference, OCR, mixed-format extraction, general detection accuracy or network-source performance.

`python tools/performance/suite.py /path/to/pii-explorer test-results/scale-suite --repetitions 3` runs all three dimensions serially, checks unchanged artifact hashes and produces a compact `summary.json` with observed ranges/medians and peak sampled RSS. Keep compilers, other scans and competing workloads idle during measurement. Repeated warm-cache runs are not independent cold-cache trials.

The pinned [psutil](https://psutil.io/) monitor samples coordinator and recursive child RSS every 20 ms. Summed RSS can double-count shared pages and miss short peaks; it is not a precise private-memory or working-set bound. Permission failures are errors rather than reported zero memory. Run in an environment that permits inspecting the benchmark processes. Process exit races are expected. Reports include sample counts, observed peak coordinator/tree RSS, process counts, elapsed time, artifact/harness hashes and validated summaries. CLI output and measurements stay on disk, so the harness does not retain the finding collection.

The corpus and case database are deliberately not tracked. A successful run is regression and scale evidence for that exact workload and machine. It does not establish an overall product score.
