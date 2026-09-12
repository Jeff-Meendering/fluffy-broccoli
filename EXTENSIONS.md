# Extending scanning

`IRecognizer` and `IExtractor` are public contracts in `PiiExplorer.Core`. Register caller-owned, thread-safe instances with `ScanEngine`; the engine snapshots registration order and does not dispose your instances. Built-in patterns and names implement `IRecognizer`. Custom recognizers run after enabled built-ins, including when built-ins are disabled. Entity types are open strings and do not require editing `PiiTypes.All` (the built-in catalog).

```csharp
var engine = new ScanEngine(new RuntimePaths(),
    recognizers: [new CustomerRecognizer()], extractors: [new CustomTextParser()]);
var options = new ScanOptions(Ocr: false, Names: false, Patterns: false);
await engine.ScanAsync(folder, options, progress, cancellationToken);

sealed class CustomerRecognizer : IRecognizer
{
    public string Id => "customer-id";
    public IEnumerable<EntitySpan> Detect(string text, CancellationToken cancellationToken)
    {
        for (int offset = 0; offset < text.Length;)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int start = text.IndexOf("ACME-42", offset, StringComparison.Ordinal);
            if (start < 0) yield break;
            yield return new("Customer ID", start, 7, 1, Id);
            offset = start + 7;
        }
    }
}

sealed class CustomTextParser : IExtractor
{
    public bool CanExtract(ExtractionRequest request) =>
        request.ResourceName.EndsWith(".custom", StringComparison.OrdinalIgnoreCase);

    public async IAsyncEnumerable<ExtractedPart> ExtractAsync(ExtractionRequest request,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Example format: a small UTF-8 text file with a .custom extension.
        string text = await File.ReadAllTextAsync(request.FilePath, cancellationToken);
        yield return new(request.Source, "body", text, "text/plain")
        {
            Origin = new(request.ResourceId, "body", EvidenceKind.Body,
                TextRepresentation.DecodedText)
        };
    }
}
```

The first matching custom extractor handles the input before built-in routing. This also applies to staged archive members: use `ResourceName` for selection and `FilePath` for reading, since staging changes filenames. Preserve `Source` and `ResourceId`. Successful parts require evidence origins with stable stream IDs and offsets; descendant resources must remain below the request resource ID. Emit typed issues for partial extraction. Do not emit scanner completion markers. Production parsers should stream bounded chunks with absolute stream offsets and honor cancellation while parsing; the example reads a small file in full.

Recognizer spans use UTF-16 offsets within the supplied text, positive lengths, nonempty types/methods, and finite confidence from 0 to 1. Invalid spans or exceptions produce `RecognizerFailure` coverage and do not suppress other recognizers or findings already emitted. Identical typed occurrences are deduplicated. Parser exceptions and invalid provenance produce extraction failures at the resource boundary. Extensions run in process and must cooperate with cancellation; this interface does not sandbox untrusted extension code.

`ScanOptions.Validate()` rejects invalid limits, worker counts outside 1–8, and unsupported or empty phone region entries. Region case and duplicates are normalized; invalid entries never disappear or fall back to US. The scan validates settings before discovery. The UI reports validation errors, including blank regions.

Text-only scanning uses `new ScanOptions(Ocr: false, Names: false)` and needs no Java, OCR executable or model files. Selecting names or OCR requires their assets at preflight. Java/Tika requirements are checked only when the built-in document parser is used; missing parser assets produce `MissingDependency` coverage while other inputs continue. HTML raw text remains readable even if its parsed representation is unavailable. `Patterns: false` disables built-in pattern recognition, allowing a custom-only policy.

Executable examples and negative contract cases live in `tests/PiiExplorer.Tests/ExtensionContractTests.cs`.
