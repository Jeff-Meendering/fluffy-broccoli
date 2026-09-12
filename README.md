# PII Explorer

Scan folders for personally identifiable information. Open a folder, select findings to see source context, search, filter, or generate PDF reports.

Professional pilot 0.3.0. Not exhaustive detection. See [PILOT-GUIDE.md](PILOT-GUIDE.md).

## Install

**macOS:**
```bash
./scripts/setup-macos.sh
./scripts/publish-macos.sh
open "dist/osx-arm64/PII Explorer.app"
```
Use `dist/osx-x64` on Intel.

**Windows:**
```powershell
./scripts/Get-Assets.ps1
./scripts/Build-Worker.ps1
./scripts/Prepare-WindowsRuntime.ps1
./scripts/Test.ps1
./scripts/Publish.ps1 -Runtime win-x64
```

**Linux:**
```bash
./scripts/prepare-linux.sh "/path/to/PII Explorer"
```

## Develop

```bash
dotnet run --project src/PiiExplorer.App -- --assets "$PWD/assets"
```

Needs the [.NET 10.0 SDK](global.json); macOS also needs Homebrew OpenJDK 21 and Tesseract. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Detects

Person, email, phone, SSN, payment card, street address, date of birth, IP and MAC address, UK National Insurance, IBAN, national IDs, credentials, crypto wallets.

Reads text, markdown, CSV/TSV, DOCX/XLSX/PPTX, PDF, OneNote, email, web pages, JPEG/PNG/HEIC and ZIP/RAR/7-Zip archives.

## Limits

- Local processing only; OCR and extraction use temporary directories
- 100 MiB per file (adjustable), 3 minutes per file
- 500,000 findings and 10,000 attention items
- Paths relative to the scanned folder, empty PDF metadata

## License

[Apache License 2.0](LICENSE) — see [NOTICE](NOTICE). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

[PILOT-GUIDE](PILOT-GUIDE.md) · [REVIEW](REVIEW.md) · [CONTRIBUTING](CONTRIBUTING.md) · [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md)
