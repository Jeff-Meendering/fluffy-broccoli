using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class OccurrenceEvidenceTests : IDisposable
{
    private const string Email = "repeat@example.net";
    private readonly string _temp = Directory.CreateTempSubdirectory("PiiExplorerEvidenceTests-").FullName;
    public void Dispose() => Directory.Delete(_temp, true);

    private async Task<Finding[]> Scan(int workers = 1, bool names = false)
    {
        var findings = new ConcurrentBag<Finding>();
        var issues = new ConcurrentBag<ScanIssue>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp,
            new(Ocr: false, Names: names, Workers: workers), new InlineProgress<ScanUpdate>(u =>
            {
                foreach (var f in u.Findings ?? []) findings.Add(f);
                foreach (var i in u.Issues ?? []) issues.Add(i);
            }), default);
        Assert.False(summary.Cancelled);
        Assert.Empty(issues);
        Assert.Equal(findings.Count, summary.Findings);
        Assert.All(findings, f => Assert.NotNull(f.Evidence));
        return findings.ToArray();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RepeatedUnicodeValuesKeepExactDecodedOffsetsAcrossOverlappingChunks(bool utf16)
    {
        const string email = "re\u200bpeat@example.net";
        string text = "\U0001f642 e\u0301 " + email + "\r\n";
        text = text.PadRight(23800) + email + "\n" + new string(' ', 400) + email + "\n";
        File.WriteAllText(Path.Combine(_temp, "unicode.txt"), text, utf16 ? Encoding.Unicode : new UTF8Encoding(false));
        var found = (await Scan()).Where(f => f.Type == "Email").OrderBy(f => f.Evidence!.Start).ToArray();
        Assert.Equal(3, found.Length);
        Assert.Equal(Positions(text, email), found.Select(f => f.Evidence!.Start));
        foreach (var f in found)
        {
            var e = f.Evidence!;
            Assert.Equal(OffsetUnit.Utf16CodeUnit, e.Origin.Unit);
            Assert.Equal(TextRepresentation.DecodedText, e.Origin.Representation);
            Assert.Equal(email, f.Value);
            Assert.Equal(email, text.Substring((int)e.Start, (int)e.Length));
            Assert.Equal(f.Context, text.Substring((int)e.ContextStart, f.Context.Length));
            Assert.Equal(e.Start, e.Origin.Start + e.DetectorStart);
            Assert.Equal(email.Length, e.DetectorLength);
        }
    }

    [Fact]
    public async Task DuplicateNestedArchiveNamesHaveDistinctStableResourceIdentities()
    {
        using var innerBytes = new MemoryStream();
        using (var inner = new ZipArchive(innerBytes, ZipArchiveMode.Create, true))
            for (int i = 0; i < 2; i++)
            {
                using var writer = new StreamWriter(inner.CreateEntry("same.txt").Open());
                writer.Write(Email);
            }
        using (var outer = ZipFile.Open(Path.Combine(_temp, "outer.zip"), ZipArchiveMode.Create))
            for (int i = 0; i < 2; i++)
            {
                using var stream = outer.CreateEntry("same.zip").Open();
                stream.Write(innerBytes.ToArray());
            }
        var findings = (await Scan()).Where(f => f.Type == "Email").ToArray();
        Assert.Equal(4, findings.Length);
        Assert.All(findings, f => Assert.Equal("same.zip > same.txt", f.Source));
        Assert.Equal(new[] { "root/archive:1/archive:1", "root/archive:1/archive:2", "root/archive:2/archive:1", "root/archive:2/archive:2" },
            findings.Select(f => f.Evidence!.Origin.ResourceId).Order());
        Assert.Equal(4, findings.Select(f => f.DisplayLocation).Distinct().Count());
        Assert.Equal(Snapshot(findings), Snapshot((await Scan(4)).Where(f => f.Type == "Email")));
    }

    [Fact]
    public async Task ParserChunksMetadataAndRawMarkupRetainSeparateCoordinateSystems()
    {
        string body = Email + "\n" + new string(' ', 23700) + Email + "\n" + new string(' ', 500) + Email;
        string path = Path.Combine(_temp, "page.html");
        File.WriteAllText(path, $"<html><head><meta name=\"author\" content=\"{Email}\"></head><body><pre>{body}</pre></body></html>");
        var parts = new List<ExtractedPart>();
        using (var client = new ExtractionClient(TestPaths.Assets))
            await foreach (var part in client.ReadAsync(path, false, default)) parts.Add(part);
        var bodyParts = parts.Where(p => p.Origin?.Kind == EvidenceKind.Body).ToArray();
        Assert.True(bodyParts.Length > 1);
        Assert.All(bodyParts, p => Assert.Equal("body", p.Origin!.StreamId));
        var expected = bodyParts.SelectMany(p => Positions(p.Text, Email).Select(at => p.Origin!.Start + at)).Distinct().Order().ToArray();
        Assert.Equal(3, expected.Length);
        var findings = (await Scan()).Where(f => f.Type == "Email").ToArray();
        var parsed = findings.Where(f => f.Evidence!.Origin.StreamId == "body").ToArray();
        Assert.Equal(expected, parsed.Select(f => f.Evidence!.Start).Order());
        Assert.Equal(4, findings.Count(f => f.Evidence!.Origin.StreamId == "decoded-text"));
        Assert.Contains(findings, f => f.Evidence!.Origin.Kind == EvidenceKind.Metadata && f.Value == Email);
        foreach (var f in parsed)
        {
            var p = Assert.Single(bodyParts, p => p.Origin!.Start == f.Evidence!.Origin.Start);
            Assert.Equal(f.Value, p.Text.Substring(f.Evidence!.DetectorStart, f.Evidence.DetectorLength));
        }
    }

    [Theory]
    [InlineData("csv")]
    [InlineData("html")]
    public async Task GeneratedTableLabelsAreExplicitlySynthesizedEvidence(string extension)
    {
        string contents = extension == "csv" ? "dob,email\n1991-07-24," + Email + "\n1991-07-24," + Email + "\n" :
            "<html><body><table><tr><th>dob</th><th>email</th></tr>" +
            $"<tr><td>1991-07-24</td><td>{Email}</td></tr><tr><td>1991-07-24</td><td>{Email}</td></tr></table></body></html>";
        File.WriteAllText(Path.Combine(_temp, "table." + extension), contents);
        var dates = (await Scan()).Where(f => f.Type == "Date of birth").ToArray();
        Assert.Equal(2, dates.Length);
        Assert.All(dates, f =>
        {
            Assert.Equal(TextRepresentation.SynthesizedText, f.Evidence!.Origin.Representation);
            Assert.Contains("Synthesized", f.DisplayContext);
            Assert.Contains("synthesized text", f.DisplayLocation);
            Assert.Contains("DOB:", f.Value);
            Assert.DoesNotContain(f.Value, contents);
        });
        Assert.Equal(2, dates.Select(f => f.Evidence!.Start).Distinct().Count());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WorkerCountAndWorkerReuseDoNotChangeEvidence(bool names)
    {
        for (int i = 0; i < 6; i++)
            File.WriteAllText(Path.Combine(_temp, $"page-{i}.html"),
                $"<html><head><meta name=\"author\" content=\"{Email}\"></head><body>Maria Hernandez spoke with David Okonkwo. {Email} {Email}</body></html>");
        Assert.Equal(Snapshot(await Scan(names: names)), Snapshot(await Scan(4, names)));
    }

    [Fact]
    public async Task CsvChunkOffsetsDoNotRestartOrCollapseRepeatedRows()
    {
        File.WriteAllText(Path.Combine(_temp, "rows.csv"), "dob,email\n" +
            string.Concat(Enumerable.Repeat("1991-07-24," + Email + "\n", 800)));
        string extracted = "dob | email\n" + string.Concat(Enumerable.Repeat("DOB: 1991-07-24 | " + Email + " | " + Environment.NewLine, 800));
        var findings = (await Scan()).Where(f => f.Type == "Email").ToArray();
        Assert.Equal(Positions(extracted, Email), findings.Select(f => f.Evidence!.Start).Order());
        Assert.True(findings.Select(f => f.Evidence!.Origin.Start).Distinct().Count() > 1);
        Assert.All(findings, f => Assert.Equal(f.Context, extracted.Substring((int)f.Evidence!.ContextStart, f.Context.Length)));
    }

    [Fact]
    public async Task BinaryStringOccurrencesMapToTheirOriginalByteRanges()
    {
        byte[] bytes = [0, 1, 0, .. Encoding.ASCII.GetBytes(Email), 0, 1, 0,
            .. Encoding.Unicode.GetBytes(Email), 0, 0, 1, 0, .. Encoding.ASCII.GetBytes(Email), 0];
        string path = Path.Combine(_temp, "strings.bin");
        File.WriteAllBytes(path, bytes);
        var parts = new List<ExtractedPart>();
        await foreach (var p in BinaryStrings.ReadAsync(path, "", 1_000_000, default)) parts.Add(p);
        var occurrences = parts.SelectMany(p => new PatternDetector().Detect(p.Text)
            .Where(s => s.Type == "Email").Select(s => (Part: p, Span: s))).ToArray();
        Assert.Equal(3, occurrences.Length);
        foreach (var (part, span) in occurrences)
        {
            var origin = part.Origin!;
            Assert.Equal(OffsetUnit.Byte, origin.Unit);
            long start = origin.Start + span.Start * origin.Stride;
            var encoding = origin.Stride == 1 ? Encoding.ASCII : Encoding.Unicode;
            Assert.Equal(Email, encoding.GetString(bytes, (int)start, span.Length * origin.Stride));
        }
    }

    private static IEnumerable<long> Positions(string text, string value)
    {
        for (int start = 0; (start = text.IndexOf(value, start, StringComparison.Ordinal)) >= 0; start += value.Length)
            yield return start;
    }

    private static string[] Snapshot(IEnumerable<Finding> findings) => findings.Select(f => JsonSerializer.Serialize(f)).Order().ToArray();
}
