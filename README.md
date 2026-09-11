# PII Explorer

Scan folders for personally identifiable information. Open a folder, select findings to see source context, search, filter, or generate PDF reports.

## Installation

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

## Development
```bash
dotnet run --project src/PiiExplorer.App -- --assets "$PWD/assets"
```

## Features

- **Local processing**: All scans happen on your machine. No data leaves your system.
- **Multiple formats**: Text, Markdown, CSV, TSV, Office documents, PDF, OneNote, email, images, archives.
- **Pattern detection**: SSNs, credit cards, addresses, emails, phone numbers, crypto wallets.
- **Name recognition**: Uses ML models for English names.
- **Report generation**: Export findings to PDF with file ID privacy.

## Note

Professional pilot 0.3.0. Not exhaustive detection. See [PILOT-GUIDE.md](PILOT-GUIDE.md) for details.

## Technical Details

### Supported Formats

- Text: text, markdown, CSV, TSV
- Office: DOCX, XLSX, PPTX
- Images: JPEG, PNG, HEIC
- Archives: ZIP, RAR, 7-Zip
- Others: PDF, OneNote, email, web pages

### PII Types Detected

Person, email, phone, Social Security number, payment card, street address, date of birth, IP address, MAC address, UK National Insurance, IBAN, national IDs, credentials, crypto wallets

### Limits

- File size: 100 MiB (adjustable)
- Timeout: 3 minutes per file
- Maximum findings: 500,000
- Maximum attention items: 10,000

### Privacy

- File paths relative to scanned folder (can use file IDs)
- Empty PDF metadata
- Local processing only
- OCR/Extraction in temporary directories

### Dependencies

- [.NET 10.0 SDK](global.json)
- Homebrew OpenJDK 21 (macOS)
- Tesseract OCR
- Apache Tika (for document parsing)
- ONNX Runtime (for name recognition)
- libphonenumber (for phone validation)

## Links

- [PILOT-GUIDE.md](PILOT-GUIDE.md) - Installation and usage guide
- [REVIEW.md](REVIEW.md) - Performance and accuracy evaluation
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development instructions
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) - Third-party licenses