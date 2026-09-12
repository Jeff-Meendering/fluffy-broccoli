# PII Explorer 0.3.0 pilot

Extract the entire Windows ZIP into a new folder and open **PiiExplorer.exe**. Keep the `assets` and `licenses` directories alongside it. No administrator rights, Office, Java, Python, or .NET installation is needed. Windows x64 only; this release has not been tested on Windows ARM or a clean virtual machine. The executable is not publisher-signed.

Choose a controlled test folder, scan it, and review **Needs attention** as carefully as the findings. A completed file count includes files that could only be partially checked. Stopped scans and limits leave incomplete coverage. Names and OCR focus on English; numeric identifiers and addresses have limited country coverage.

## Finding locations

Repeated values at different offsets appear as separate findings. Overlapping extraction chunks collapse only when the resource, text stream, entity type, offset and length match. Filename, metadata, parsed body and raw markup evidence remain separate; counts can therefore include multiple representations of the same source content.

Selected findings and PDF reports identify the resource, text stream, representation, zero-based offset and length. Archive resource IDs use entry positions (including directory entries), so members with identical names remain distinguishable. IDs are local to the outer file and stable for unchanged inputs and extraction settings; changing container entries can change their IDs.

Text offsets count UTF-16 code units in the identified representation; an emoji can occupy two units. Binary-string offsets and lengths count original bytes. Parsed documents and OCR use extracted-text coordinates, not PDF page positions, image boxes or file byte offsets. Table labels, separators and filename substitutions are explicitly marked as synthesized context. They do not establish an original-source range for redaction. Context retains the extraction text's line breaks. Detailed cell mappings are not yet available.

## Verify the download

Compare the ZIP's SHA-256 with the `.zip.sha256` file received through a trusted channel. From the extracted folder, run the following with PowerShell:

```powershell
./Verify-Package.ps1
```

The verifier checks every listed file and rejects missing, modified, extra, and linked files. These hashes detect changes; they do not replace publisher signing or authenticate a manifest obtained from an untrusted source. Generate evaluation reports outside the package directory so they do not become unlisted package files.

## Isolated testing of untrusted documents

On a supported Windows installation with Windows Sandbox already enabled:

```powershell
./New-SandboxConfig.ps1 -PackageFolder "$PWD" -InputFolder 'C:\PII-Test-Data' -OutputFile "$env:TEMP\PII-Pilot.wsb"
```

Open the generated `.wsb`, then select **C:\Input** in the app inside Sandbox. The configuration shares only the package and the chosen input directory, both read-only. Networking, clipboard, printer, microphone, camera, and GPU sharing are disabled; protected client mode is requested. It allocates 8 GiB to the guest. Do not map a broad home directory when a small test folder suffices.

The generator does not install or launch Sandbox. Its XML and path handling are checked, but a live Sandbox guest has not been validated in this review. If Sandbox is unavailable, use an isolated analysis VM configured by your team. The ordinary desktop app's parser processes are **not** an OS security boundary. Reports created inside this configuration disappear when the guest closes because no writable host output directory is shared. For persistent reports, use your team's approved VM export procedure.

Configuration reference: [Microsoft Windows Sandbox settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file).

## Measure accuracy on your own cases

The package includes an offline evaluator and `accuracy-smoke.jsonl`. Run from the extracted folder:

```powershell
# The pipeline waits for the Windows GUI executable's diagnostic mode to finish.
./PiiExplorer.exe --evaluate ./accuracy-smoke.jsonl "$env:TEMP\pii-accuracy-new.json" | Out-Null
Get-Content "$env:TEMP\pii-accuracy-new.json"
```

Use a new report filename each time. Existing reports are never overwritten. Exit 0 means the evaluation completed, **not** that it passed an accuracy threshold. The smoke corpus contains 57 small, synthetic cases with 38 annotated entities and 19 negative controls. It is a developer-authored regression check, not an independent accuracy benchmark.

Your JSONL corpus must have one case per line:

```json
{"text":"Contact alice@example.com","entities":[{"type":"Email","start":8,"length":17}]}
{"text":"No personal information here.","entities":[]}
```

Annotate every target entity, including duplicates at different locations. Offsets and lengths use **UTF-16 code units**, as .NET does; an emoji can occupy two units. Labels must use the app's exact type names: `Person`, `Email`, `Phone`, `Social Security number`, `Payment card`, `Street address`, `Date of birth`, `IP address`, `MAC address`, `UK National Insurance`, `IBAN`, `National ID`, `Labelled identifier`, `Credential`, or `Crypto wallet`. Existing DOB/labelled-identifier findings include their contextual label in the span. Each text is limited to 100,000 characters, 10,000 annotations, and a 512,000-character JSONL record.

Names are enabled in the command above. Add `--no-names` to disable both pattern-based and model-based Person findings; the bundled corpus then intentionally records its Person annotation as a miss. Gold Person annotations still count as misses if names are disabled. The report includes exact-span precision, recall, and F1 by type and overall; duplicate predictions at the same span count once. Incorrect boundaries count as both a miss and a false positive. Undefined metrics are `null`, not 100%. Reports contain aggregate metrics, settings, engine version, and corpus/model hashes; no input text, source paths, or case IDs are copied. Hashes are fingerprints, not anonymization guarantees.

This evaluator measures detection on supplied text. Independently check document parsing, archive completeness, OCR, and source attribution on files. Include clean negative documents, difficult scans, tables, languages used by your team, and deliberately damaged input. Keep a held-out set that is not used to tune rules or select models. Select precision/recall requirements with your analysts before comparing candidates.

## Useful tester feedback

- Windows version, CPU/RAM, scan settings, total files/bytes, and elapsed time.
- Whether the app remains responsive while scanning, stopping, filtering, and exporting.
- False negatives and false positives by PII type, plus incomplete-file messages.
- A minimal synthetic reproducer for failures when possible. Do not send real PII through ordinary bug reports.

No automatic telemetry or feedback upload is performed by the application. Normal scans retain findings in memory; explicitly exported PDFs contain detected PII. Extractors use temporary files which can remain after a crash. Source length/timestamp changes raise attention items, but this is not cryptographic source verification or forensic chain of custody.
