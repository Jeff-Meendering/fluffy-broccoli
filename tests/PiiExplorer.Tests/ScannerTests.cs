using System.Collections.Concurrent;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public static class TestPaths
{
    public static string Root { get; } = FindRoot();
    public static RuntimePaths Assets => new(Environment.GetEnvironmentVariable("PII_TEST_ASSETS") ?? Path.Combine(Root, "assets"));
    private static string FindRoot() {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "PiiExplorer.slnx"))) return dir.FullName;
        throw new DirectoryNotFoundException("Test project root");
    }
}

public sealed class ScannerTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "PiiExplorerTests", Guid.NewGuid().ToString("N"));
    public ScannerTests() => Directory.CreateDirectory(_temp);
    public void Dispose() => Directory.Delete(_temp, true);
    private async Task<(ScanSummary Summary, Finding[] Findings, ScanIssue[] Issues)> Scan(ScanOptions? options = null, CancellationToken token = default) {
        var findings = new ConcurrentBag<Finding>(); var issues = new ConcurrentBag<ScanIssue>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, options ?? new(Names: false), new InlineProgress<ScanUpdate>(u => {
            foreach (var f in u.Findings ?? []) findings.Add(f);
            foreach (var i in u.Issues ?? []) issues.Add(i);
        }), token);
        return (summary, findings.ToArray(), issues.ToArray());
    }
    [Theory]
    [InlineData("maria.hernandez@example.com", "Email")]
    [InlineData("+1 (415) 555-0142", "Phone")]
    [InlineData("+44 20 7946 0958", "Phone")]
    [InlineData("123-45-6789", "Social Security number")]
    [InlineData("4111 1111 1111 1111", "Payment card")]
    [InlineData("DOB: 1984-03-11", "Date of birth")]
    [InlineData("1600 Pennsylvania Avenue", "Street address")]
    [InlineData("GB82 WEST 1234 5698 7654 32", "IBAN")]
    [InlineData("AB123456C", "UK National Insurance")]
    public void StructuredIdentifiers(string text, string type) => Assert.Contains(new PatternDetector().Detect(text), s => s.Type == type);

    [Theory]
    [InlineData("4111 1111 1111 1112")]
    [InlineData("0000000000000000")]
    [InlineData("999.999.999.999")]
    [InlineData("The release is version 12.34.56 and contains 125 files.")]
    public void NegativeControls(string text) => Assert.Empty(new PatternDetector().Detect(text));

    [Fact] public void LocalNamesAndOffsets() {
        using var detector = new NameDetector(TestPaths.Assets);
        const string input = "Maria Hernandez spoke with David Okonkwo about the delivery.";
        var values = detector.Detect(input, default).Select(s => input.Substring(s.Start, s.Length)).ToArray();
        Assert.Contains("Maria Hernandez", values); Assert.Contains("David Okonkwo", values);
        Assert.DoesNotContain(detector.Detect("user=d.okonkwo@example.org", default), s => s.Length == 1);
    }
    [Fact] public async Task RepeatedLongTextRetainsSeparateSources() {
        string text = string.Concat(Enumerable.Repeat("Maria Hernandez works with David Okonkwo. Contact maria@example.com. ", 40));
        File.WriteAllText(Path.Combine(_temp, "first.txt"), text);
        File.WriteAllText(Path.Combine(_temp, "second.txt"), text);
        var result = await Scan(new(Ocr: false, Workers: 1));
        Assert.Empty(result.Issues);
        foreach (string file in new[] { "first.txt", "second.txt" }) {
            Assert.Contains(result.Findings, f => f.FileName == file && f.Type == "Person" && f.Value == "Maria Hernandez");
            Assert.Contains(result.Findings, f => f.FileName == file && f.Value == "maria@example.com");
        }
        using var detector = new NameDetector(TestPaths.Assets);
        detector.Detect(text, default);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => detector.Detect(text, cancelled.Token));
    }
    [Fact] public async Task EncodingsChunkBoundaryAndNoSourceChanges() {
        File.WriteAllText(Path.Combine(_temp, "utf16.txt"), "Maria Hernandez maria@example.com", Encoding.Unicode);
        File.WriteAllBytes(Path.Combine(_temp, "legacy.txt"), Encoding.Latin1.GetBytes("Mémo pour José. Email: jose@example.com"));
        File.WriteAllText(Path.Combine(_temp, "boundary.md"), new string(' ', 23993) + "edge@example.net" + new string(' ', 25000));
        var before = Directory.GetFiles(_temp).ToDictionary(f => f, f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));
        var result = await Scan();
        Assert.Empty(result.Issues); Assert.Equal(3, result.Summary.Completed);
        foreach (string email in new[] { "maria@example.com", "jose@example.com", "edge@example.net" }) Assert.Single(result.Findings, f => f.Value == email);
        foreach (var pair in before) Assert.Equal(pair.Value, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pair.Key))));
    }
    [Fact] public async Task ArchiveMemberSourcesAndTraversalIsolation() {
        string escaped = "escaped-" + Guid.NewGuid().ToString("N") + ".txt";
        string zip = Path.Combine(_temp, "backup.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create)) {
            using var writer = new StreamWriter(archive.CreateEntry("../../" + escaped).Open()); writer.Write("archive@example.com");
        }
        var result = await Scan();
        Assert.Empty(result.Issues);
        var finding = Assert.Single(result.Findings, f => f.Type == "Email");
        Assert.Equal(zip, finding.FilePath); Assert.Contains(escaped, finding.Source);
        Assert.False(File.Exists(Path.Combine(Path.GetTempPath(), escaped)));
        Assert.Single(Directory.GetFiles(_temp));
    }
    [Fact] public async Task ExpandedArchiveLimitIsVisible() {
        using (var archive = ZipFile.Open(Path.Combine(_temp, "large.zip"), ZipArchiveMode.Create)) {
            using var writer = new StreamWriter(archive.CreateEntry("large.txt").Open()); writer.Write(new string('x', 30000));
        }
        var result = await Scan(new(Names: false, MaxFileBytes: 10000));
        Assert.Contains(result.Issues, i => i.Message.Contains("expanded size"));
    }
    [Fact] public async Task FindingLimitStopsWithPartialResults() {
        File.WriteAllText(Path.Combine(_temp, "list.txt"), "a@example.com b@example.net c@example.org");
        var result = await Scan(new(Names: false, MaxFindings: 2));
        Assert.True(result.Summary.Cancelled); Assert.Equal(2, result.Findings.Length);
        Assert.Contains(result.Issues, i => i.Message.Contains("Finding limit"));
    }
    [Fact] public async Task CancellationIsResponsive() {
        for (int i = 0; i < 30; i++) File.WriteAllText(Path.Combine(_temp, i + ".txt"), new string('a', 200000));
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Scan(token: cts.Token));
    }
    [Fact] public async Task RealOneNoteTextIsExtracted() {
        using var client = new ExtractionClient(TestPaths.Assets);
        var parts = new List<ExtractedPart>();
        await foreach (var part in client.ReadAsync(Path.Combine(TestPaths.Root, "tests", "fixtures", "testOneNote2016.one"), true, default)) parts.Add(part);
        Assert.DoesNotContain(parts, p => p.Issue is not null);
        Assert.Contains(parts, p => p.Location.StartsWith("document text") && p.Text.Length > 30);
    }
    [Fact] public async Task PlantedEmailInsideRealOneNoteIsFound() {
        byte[] bytes = File.ReadAllBytes(Path.Combine(TestPaths.Root, "tests", "fixtures", "testOneNote2016.one"));
        const string original = "This is one note 2016";
        string replacement = "one.test@example.com".PadRight(original.Length);
        int changed = 0;
        foreach (var encoding in new[] { Encoding.Unicode, Encoding.UTF8 }) {
            byte[] search = encoding.GetBytes(original), insert = encoding.GetBytes(replacement);
            for (int start = 0; start < bytes.Length;) {
                int offset = bytes.AsSpan(start).IndexOf(search); if (offset < 0) break;
                insert.CopyTo(bytes, start + offset); changed++; start += offset + search.Length;
            }
        }
        Assert.True(changed > 0, "Expected OneNote test text was not present");
        File.WriteAllBytes(Path.Combine(_temp, "contact.one"), bytes);
        var result = await Scan(new(Ocr: false, Names: false));
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Value == "one.test@example.com" && f.FileName == "contact.one");
    }
    [Fact] public async Task JpegOcrFindsPrintedEmail() {
        string png = Path.Combine(TestPaths.Root, "tests", "fixtures", "corpus", "04_images", "badge.png");
        using var image = SkiaSharp.SKImage.FromEncodedData(png);
        using var data = image.Encode(SkiaSharp.SKEncodedImageFormat.Jpeg, 92);
        using (var output = File.Create(Path.Combine(_temp, "badge.jpeg"))) data.SaveTo(output);
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Value == "maria.hernandez@example.com" && f.FileName == "badge.jpeg");
    }
    [Fact] public async Task SpreadsheetChecksEveryPlantedRow() {
        string source = Path.Combine(TestPaths.Root, "tests", "fixtures", "staff-register.xlsx");
        File.Copy(source, Path.Combine(_temp, "register.xlsx"));
        var result = await Scan(new(Ocr: false));
        Assert.Empty(result.Issues); Assert.False(result.Summary.Cancelled);
        var found = result.Findings.GroupBy(f => f.Type).ToDictionary(g => g.Key, g => g.Select(f => f.Value).ToHashSet());
        using var archive = ZipFile.OpenRead(source);
        using var stream = archive.GetEntry("xl/worksheets/sheet1.xml")!.Open();
        var document = System.Xml.Linq.XDocument.Load(stream);
        System.Xml.Linq.XNamespace ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        var rows = document.Descendants(ns + "row").Skip(1).ToArray();
        Assert.Equal(25000, rows.Length);
        var expectedEmails = new HashSet<string>(); var expectedNames = new HashSet<string>();
        foreach (var row in rows) {
            var values = row.Elements(ns + "c").Select(c => string.Concat(c.Descendants(ns + "t").Select(t => t.Value))).ToArray();
            Assert.True(found["Person"].Contains(values[1]), values[1]); Assert.True(found["Email"].Contains(values[2]), values[2]);
            Assert.True(found["Phone"].Contains(values[3]), values[3]); Assert.True(found["Social Security number"].Contains(values[4]), values[4]);
            Assert.True(found["Date of birth"].Contains("DOB: " + values[5]), values[5]);
            expectedNames.Add(values[1]); expectedEmails.Add(values[2]);
        }
        Assert.Equal(expectedEmails.Order(), found["Email"].Order());
        Assert.Equal(expectedNames.Order(), found["Person"].Order());
    }
    [Fact] public async Task CsvPreservesLabelsAndQuotedCommas() {
        File.WriteAllText(Path.Combine(_temp, "people.csv"), "name,dob,email,notes\n\"Priya Raghunathan\",1991-07-24,priya@example.net,\"Called Monday, send mail\"\n");
        var result = await Scan(new(Ocr: false));
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Type == "Person" && f.Value == "Priya Raghunathan");
        Assert.Contains(result.Findings, f => f.Type == "Date of birth" && f.Value == "DOB: 1991-07-24");
    }
    [Fact] public async Task LongUnbrokenDocumentTextMakesBoundedProgress() {
        string path = Path.Combine(_temp, "long.html");
        File.WriteAllText(path, "<html><body>" + new string('x', 100000) + " end@example.com</body></html>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        int segments = 0; bool found = false;
        await foreach (var part in client.ReadAsync(path, false, deadline.Token)) {
            Assert.True(++segments < 30, "Extractor repeatedly emitted overlapping chunks");
            found |= part.Text.Contains("end@example.com");
        }
        Assert.True(found);
    }
    [Fact] public async Task CorpusFindsPiiAcrossFormatsAndReportsBrokenFiles() {
        string corpus = Path.Combine(TestPaths.Root, "tests", "fixtures", "corpus");
        var findings = new ConcurrentBag<Finding>(); var issues = new ConcurrentBag<ScanIssue>();
        var hashes = Directory.GetFiles(corpus, "*", SearchOption.AllDirectories).ToDictionary(f => f, f => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(f))));
        var result = await new ScanEngine(TestPaths.Assets).ScanAsync(corpus, new(), new InlineProgress<ScanUpdate>(u => {
            foreach (var f in u.Findings ?? []) findings.Add(f); foreach (var i in u.Issues ?? []) issues.Add(i);
        }), default);
        Assert.Equal(hashes.Count, result.Files); Assert.Equal(hashes.Count, result.Completed); Assert.False(result.Cancelled);
        foreach (string file in new[] { "contacts.txt", "README.md", "staff-handbook.docx", "payroll.xlsx", "account-review.pptx", "lease-thread.eml", "invoice.pdf", "scanned-memo.pdf", "badge.png", "note.webp", "whiteboard-crooked.png", "thumbnail.png", "records.rar", "payroll.7z", "team-backup.zip", "nested-outer.zip", "logs.tar.gz" })
            Assert.Contains(findings, f => f.FileName == file && f.Type == "Email");
        foreach (string file in new[] { "corrupt.docx", "truncated.pdf", "Personal Notes.one", "Open Notebook.onetoc2", "photo.heic", "locked.zip", "broken.zip" })
            Assert.Contains(issues, i => Path.GetFileName(i.FilePath) == file);
        Assert.Contains(findings, f => f.FileName == "staff-handbook.docx" && f.Source.Contains("image1") && f.Type == "Phone");
        foreach (string control in new[] { "empty.txt", "release-notes.txt", "diagram.jpg" }) Assert.DoesNotContain(findings, f => f.FileName == control);
        foreach (var pair in hashes) Assert.Equal(pair.Value, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(pair.Key))));
    }
}
