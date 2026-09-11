# PII Explorer

Choose a folder, click **Scan folder**, and select a finding to see its source and context. Search or filter the results; review **Needs attention** for incomplete files.

**0.3.0 professional pilot:** see [PILOT-GUIDE.md](PILOT-GUIDE.md) for portable installation, package verification, optional Windows Sandbox configuration, and offline accuracy evaluation. This is an evaluation build, not a claim of exhaustive detection.

Use the **Theme** selector in the header to choose **System**, **Light**, or **Dark**. The choice is remembered locally; only the theme preference is saved. The folder settings scroll independently, while the heading and scan controls stay visible. Search, filter, and PDF export controls use a consistent compact height.

- **Windows x64:** open `PiiExplorer.exe`.
- **Linux x64:** run `./PiiExplorer`. This package targets Ubuntu 26.04 with a desktop; older distributions need a rebuild.
- Copy the whole package, including `assets`. No Python, Java, Office or .NET installation is needed.

Scanning is local. Results and the bounded analysis cache stay in memory. Source files are unchanged. Reports are created only when you choose **Save PDF report**. Extraction and OCR use unique `PiiExplorer-*` directories in the user's temporary directory (owner-only on Unix). Normal completion and cancellation clean them up, but a crash can leave sensitive temporary files. Older builds used a `PiiExplorer` subfolder. Cleanup is not secure erasure.

Supports text/Markdown, CSV/TSV, Office documents, PDF, OneNote `.one`, email, common images (including JPEG) and archives including ZIP/RAR/7z. Archive signatures are checked even when extensions are missing or incorrect. Findings identify the original file, nested member, extraction location and surrounding text. Names in archive entries and PII in source metadata are checked too. OneNote `.onetoc2` is an index; scan the local `.one` section files for content. Cloud notebooks are not downloaded. Unrecognized formats receive a limited ASCII/UTF-16LE strings scan with an explicit incomplete-coverage notice.

OCR and name recognition are English-focused. Phone validation uses libphonenumber with configurable domestic regions (default US,GB); international + numbers use their country code. Rules also cover selected national IDs, MAC addresses, credentials, Bitcoin/Ethereum wallets and several address forms. Country and entity coverage remains incomplete. Encrypted content, handwriting, HEIC and unusual layouts can be unreadable. Only the first frame of animated images is OCR checked, with an attention item for remaining frames. Audio/video speech is not transcribed. No findings does not guarantee no PII. The supported parser and bundled OCR versions are recorded in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

The desktop defaults to 2–4 workers based on CPU count (adjustable from 1 to 8); diagnostics and benchmarks default to two. Limits: 100 MiB per file (adjustable), three minutes per file, four archive layers, 2,000 members (including directory entries), 400 MiB expanded archive data, 500,000 findings, and 10,000 attention items. Finding/attention limits stop the scan and mark remaining coverage incomplete. Repeated values within the same file/member and evidence category appear once; filename, body and metadata evidence remain distinct. A location points to representative evidence, not every occurrence. Disable names or image reading for faster, narrower scans. Limits, timeouts and incomplete extraction appear under **Needs attention**; a processed file is not necessarily fully readable.

Files are checked as they are discovered, with at most 256 waiting in the discovery queue. The discovered count grows during scanning. If stopped early, it is the number discovered so far, not the total folder size. Structured findings appear before name recognition finishes. Valid earlier CSV/TSV rows remain available if a later row is malformed.

CSV/TSV and parsed document tables use explicit headers for names, dates of birth, SSNs, passports, account numbers, and tax IDs. Complex/merged layouts still need review. Unicode width, decimal-digit, separator, and selected invisible-format variants are normalized for pattern matching; findings preserve the original value and offsets and identify normalized matches. This does not repair arbitrary OCR substitutions or recognize all obfuscation. IBANs use a country-length snapshot and MOD-97 validation, not proof that a bank account exists. Source length/timestamp changes during a scan produce attention items; unchanged metadata does not prove unchanged bytes.

After scanning, choose **Save PDF report…** above the results and select a new filename. The report includes **all** findings and attention items, regardless of search/type filters, and marks stopped scans as partial. The **Stop** button also cancels report creation. Existing files are never overwritten.

- The PDF metadata dictionary is empty: no author, creator, producer, creation/modification dates, XMP, document IDs, source attachments or computer name. A fixed embedded font avoids dependence on installed fonts.
- Source paths are relative to the scanned folder; absolute paths in extracted fields and error messages are replaced with an omission marker. This can shorten the displayed evidence, so use the app to review original values.
- **Use file IDs instead of names** hides source filenames and nested names. Search for a report's `File 00001` or `Part 00001` in the app to find the original. The mapping exists only for the current scan/export and is lost when the app closes or another scan starts.
- **Include surrounding context** is off by default. The PDF still contains the detected PII; file IDs and empty metadata do not anonymize the findings themselves. Characters unavailable in the report font are shown reversibly as `[U+XXXX]`.
- This applies to the PDF's embedded metadata. The operating system still maintains filesystem timestamps/ownership, and sharing services may add their own information.

Assessment, measured performance, and the comparison with Presidio: [REVIEW.md](REVIEW.md). Development and GitHub checkpoint instructions: [CONTRIBUTING.md](CONTRIBUTING.md).

For professional evaluation, start with a controlled pilot. Accuracy on the included synthetic examples does not establish production recall, and the parser processes are not an OS security sandbox. See the review for the remaining release requirements and measured performance.

Build on Windows with .NET SDK 10.0.301, PowerShell 7 and 7-Zip. Java, the model, and the pinned OCR distribution are downloaded by the asset script; no system-wide Tesseract installation is used:

```powershell
./scripts/Get-Assets.ps1
./scripts/Build-Worker.ps1
./scripts/Prepare-WindowsRuntime.ps1
./scripts/Test.ps1
./scripts/Collect-Licenses.ps1
./scripts/Publish.ps1 -Runtime win-x64
./scripts/Test-WindowsPackage.ps1
./scripts/Make-Archives.ps1 -Runtime win-x64
```

For Linux, publish with `-Runtime linux-x64`, then run `scripts/prepare-linux.sh "/path/to/PII Explorer"` on Ubuntu. `scripts/Make-Archives.ps1 -Runtime win-x64` creates a fresh Windows ZIP; omit the option to package both platforms after separately rebuilding Linux. Test fixtures are included in `tests/fixtures`; downloaded runtimes, build outputs and packages are excluded from Git. Diagnostic mode: `PiiExplorer --scan-test /folder` (exit 0: completed; 2: stopped/limited; 3: attention items; 1: error).

Dependencies and licenses: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Reproduce engine benchmarks (synthetic inputs; aggregate metrics only):

```powershell
dotnet run --project tools/PiiExplorer.Benchmarks -c Release -- "$PWD" "$PWD/test-results/benchmarks.json" 3
```
