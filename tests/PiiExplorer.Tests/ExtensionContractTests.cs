using System.Runtime.CompilerServices;
using System.IO.Compression;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class ExtensionContractTests : IDisposable
{
    private readonly string root = Directory.CreateTempSubdirectory("PiiContracts-").FullName;
    private RuntimePaths MissingAssets => new(Path.Combine(root, "absent-assets"));
    public void Dispose() => Directory.Delete(root, true);
    private sealed class Progress(Action<ScanUpdate> action) : IProgress<ScanUpdate>
    { public void Report(ScanUpdate update) => action(update); }
    private async Task<(ScanSummary Summary, List<Finding> Findings)> Scan(IRecognizer[]? recognizers = null,
        IExtractor[]? extractors = null, ScanOptions? options = null)
    {
        var findings = new List<Finding>();
        var summary = await new ScanEngine(MissingAssets, recognizers, extractors).ScanAsync(root,
            options ?? new(Ocr: false, Names: false, Workers: 1),
            new Progress(u => { if (u.Findings is not null) findings.AddRange(u.Findings); }), default);
        return (summary, findings);
    }

    [Fact] public async Task TextAndArchiveTextNeedNoOptionalAssets()
    {
        File.WriteAllText(Path.Combine(root, "test.txt"), "test@example.com");
        using (var zip = ZipFile.Open(Path.Combine(root, "test.zip"), ZipArchiveMode.Create))
        using (var writer = new StreamWriter(zip.CreateEntry("nested.txt").Open())) writer.Write("test@example.com");
        var result = await Scan();
        Assert.Equal(CoverageStatus.Success, result.Summary.Status);
        Assert.Equal(2, result.Findings.Count(f => f.Type == "Email"));
    }

    [Fact] public async Task MissingParserDoesNotPreventTextSiblingScan()
    {
        File.WriteAllText(Path.Combine(root, "test.txt"), "test@example.com");
        File.WriteAllText(Path.Combine(root, "test.pdf"), "not a pdf");
        var result = await Scan();
        Assert.Contains(result.Summary.Outcomes, o => o.Reasons.Contains(CoverageReason.MissingDependency));
        Assert.Single(result.Findings, f => f.Type == "Email");
        Assert.Equal(1, result.Summary.SuccessfulFiles);
    }

    [Theory] [InlineData("")] [InlineData("US,nope")] [InlineData("US,")]
    public void InvalidRegionsAreExplicit(string regions) =>
        Assert.Throws<ArgumentException>(() => new ScanOptions(PhoneRegions: regions).Validate());

    [Fact] public void WorkerLimitIsValidated() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScanOptions(Workers: 9).Validate());

    [Theory] [InlineData(true, false)] [InlineData(false, true)]
    public async Task SelectedMissingAssetsAreExplicit(bool names, bool ocr) =>
        await Assert.ThrowsAsync<InvalidOperationException>(() => Scan(options: new(Names: names, Ocr: ocr)));

    private sealed class Recognizer(bool fail = false, bool invalid = false) : IRecognizer
    {
        public string Id => "example";
        public IEnumerable<EntitySpan> Detect(string text, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int start = text.IndexOf("ACME-42", StringComparison.Ordinal);
            if (start < 0) yield break;
            yield return new("Customer ID", invalid ? text.Length : start, 7, 1, Id);
            if (fail) throw new InvalidOperationException("synthetic failure after first result");
        }
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task RecognizerFailuresKeepOtherRecognizersAndEarlierFindings(bool invalid)
    {
        File.WriteAllText(Path.Combine(root, "test.txt"), "ACME-42 test@example.com");
        var result = await Scan([new Recognizer(fail: true, invalid: invalid), new Recognizer()]);
        Assert.Single(result.Findings, f => f.Type == "Customer ID");
        Assert.Single(result.Findings, f => f.Type == "Email");
        Assert.Contains(CoverageReason.RecognizerFailure, Assert.Single(result.Summary.Outcomes).Reasons);
        Assert.Equal(CoverageStatus.Partial, result.Summary.Status);
    }

    private sealed class Parser(bool invalid = false) : IExtractor
    {
        public bool CanExtract(ExtractionRequest request) => request.ResourceName.EndsWith(".custom", StringComparison.Ordinal);
        public async IAsyncEnumerable<ExtractedPart> ExtractAsync(ExtractionRequest request,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            string text = await File.ReadAllTextAsync(request.FilePath, cancellationToken);
            yield return new(request.Source, "custom body", text, "text/plain")
            { Origin = invalid ? null : new(request.ResourceId, "custom", EvidenceKind.Body, TextRepresentation.DecodedText) };
        }
    }

    [Fact] public async Task CustomParserWorksInsideArchiveWithCustomEntityAndNoBuiltins()
    {
        using (var zip = ZipFile.Open(Path.Combine(root, "test.zip"), ZipArchiveMode.Create))
        using (var writer = new StreamWriter(zip.CreateEntry("nested.custom").Open())) writer.Write("ACME-42");
        var result = await Scan([new Recognizer()], [new Parser()], new(Ocr: false, Names: false, Patterns: false));
        var finding = Assert.Single(result.Findings);
        Assert.Equal("Customer ID", finding.Type);
        Assert.Equal("root/archive:1", finding.Evidence!.Origin.ResourceId);
        Assert.Equal(CoverageStatus.Success, result.Summary.Status);
        Assert.False(result.Summary.Configuration!.Patterns);
    }

    [Fact] public async Task InvalidParserEvidenceIsReported()
    {
        File.WriteAllText(Path.Combine(root, "test.custom"), "ACME-42");
        var result = await Scan([new Recognizer()], [new Parser(invalid: true)]);
        Assert.Empty(result.Findings);
        Assert.Contains(CoverageReason.ExtractionFailure, Assert.Single(result.Summary.Outcomes).Reasons);
    }

    [Fact] public void BuiltinRecognizerHonorsCancellation()
    {
        IRecognizer recognizer = new PatternDetector();
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => recognizer.Detect("test@example.com", cancelled.Token).ToArray());
    }
}
