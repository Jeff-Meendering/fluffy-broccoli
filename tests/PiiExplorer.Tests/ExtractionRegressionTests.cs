using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class ExtractionRegressionTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "PiiExtractionRegression", Guid.NewGuid().ToString("N"));
    public ExtractionRegressionTests(ITestOutputHelper output) { _output = output; Directory.CreateDirectory(_temp); }
    public void Dispose() => Directory.Delete(_temp, true);
    private static string Fixture(params string[] parts) => Path.Combine([TestPaths.Root, "tests", "fixtures", .. parts]);
    private sealed class Progress(Action<ScanUpdate> report) : IProgress<ScanUpdate>
    {
        public void Report(ScanUpdate value) => report(value);
    }
    private async Task<(ScanSummary Summary, Finding[] Findings, ScanIssue[] Issues)> Scan(ScanOptions? options = null)
    {
        var findings = new ConcurrentBag<Finding>();
        var issues = new ConcurrentBag<ScanIssue>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, options ?? new(Ocr: false, Names: false),
            new Progress(u => {
                foreach (var f in u.Findings ?? []) findings.Add(f);
                foreach (var i in u.Issues ?? []) issues.Add(i);
            }), timeout.Token);
        return (summary, findings.ToArray(), issues.ToArray());
    }
    private static byte[] Zip(params (string Name, byte[] Data)[] entries)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true))
            foreach (var entry in entries) {
                using var stream = zip.CreateEntry(entry.Name).Open();
                stream.Write(entry.Data);
            }
        return output.ToArray();
    }
    private static byte[] Text(string text) => Encoding.UTF8.GetBytes(text);

    [Fact]
    public async Task DocumentTableHeadersPreserveSensitiveColumnSemantics()
    {
        File.WriteAllText(Path.Combine(_temp, "table.html"),
            "<html><body><table><tr><th>ssn</th><th>passport_number</th><th>account_number</th><th>tax_id</th></tr>" +
            "<tr><td>123456789</td><td>AB1234567</td><td>12345678</td><td>12-3456789</td></tr></table></body></html>");
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Type == "Social Security number" && f.Value == "123456789");
        Assert.Contains(result.Findings, f => f.Value == "Passport number: AB1234567");
        Assert.Contains(result.Findings, f => f.Value == "Account number: 12345678");
        Assert.Contains(result.Findings, f => f.Value == "Tax ID: 12-3456789");
    }

    [Fact]
    public async Task EmbeddedImageScratchFilenamesAreNotSourceEvidence()
    {
        using var client = new ExtractionClient(TestPaths.Assets);
        var parts = new List<ExtractedPart>();
        await foreach (var part in client.ReadAsync(Fixture("corpus", "02_office", "textbox-only.docx"), false, default)) parts.Add(part);
        Assert.Contains(parts, p => p.Source.EndsWith("thumbnail.jpeg", StringComparison.Ordinal));
        Assert.DoesNotContain(parts, p => p.Location.StartsWith("metadata: File Name", StringComparison.Ordinal) &&
            p.Text.StartsWith("apache-tika-", StringComparison.Ordinal));
        Assert.Contains(parts, p => p.Location.StartsWith("document text", StringComparison.Ordinal) && p.Text.Contains('@'));
    }

    [Fact] public async Task BrokenNestedMemberDoesNotHideHealthySiblingsAndKeepsProvenance()
    {
        File.WriteAllBytes(Path.Combine(_temp, "outer.zip"), Zip(
            ("nested.zip", Zip(("broken.zip", Text("not an archive")), ("inside.txt", Text("inside@example.com")))),
            ("after.txt", Text("after@example.com"))));
        var result = await Scan();
        Assert.Contains(result.Issues, i => i.Source == "nested.zip > broken.zip");
        Assert.Contains(result.Findings, f => f.Value == "inside@example.com" && f.Source == "nested.zip > inside.txt");
        Assert.Contains(result.Findings, f => f.Value == "after@example.com" && f.Source == "after.txt");
        Assert.False(result.Summary.Cancelled);
    }

    [Theory]
    [InlineData("records.rar")]
    [InlineData("payroll.7z")]
    public async Task RarAndSevenZipInsideZipRetainMemberPaths(string name)
    {
        File.WriteAllBytes(Path.Combine(_temp, "outer.zip"), Zip((name, File.ReadAllBytes(Fixture("corpus", "09_archives", name)))));
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Type == "Email" && f.Source.StartsWith(name + " > "));
        Assert.All(result.Findings, f => Assert.Equal("outer.zip", f.FileName));
    }

    [Fact] public async Task ArchiveNamesAreCheckedEvenWhenContentIsEmpty()
    {
        File.WriteAllBytes(Path.Combine(_temp, "outer.zip"), Zip(("staff/member@example.com.txt", [])));
        var result = await Scan();
        Assert.Contains(result.Findings, f => f.Type == "Email" && f.Source == "staff/member@example.com.txt" && f.Location.Contains("name"));
    }

    [Fact] public async Task NameFindingDoesNotSuppressContentEvidence()
    {
        File.WriteAllText(Path.Combine(_temp, "contact@example.com.txt"), "contact@example.com.txt");
        var result = await Scan();
        Assert.Contains(result.Findings, f => f.Location.StartsWith("text") && f.Type == "Email");
        Assert.Contains(result.Findings, f => f.Location.Contains("name") && f.Type == "Email");
    }

    [Fact] public async Task LongUnbrokenPlainTextStillChecksTheTail()
    {
        File.WriteAllText(Path.Combine(_temp, "long.txt"), new string('x', 150_000) + " tail@example.net");
        var result = await Scan();
        Assert.Contains(result.Findings, f => f.Value == "tail@example.net");
        Assert.Empty(result.Issues);
    }

    [Fact] public async Task ArchiveSizeLimitIdentifiesMemberAndStopsExpansion()
    {
        File.WriteAllBytes(Path.Combine(_temp, "outer.zip"), Zip(("huge.txt", Text(new string(' ', 30_000))), ("after.txt", Text("unchecked@example.net"))));
        File.WriteAllText(Path.Combine(_temp, "other.txt"), "checked@example.net");
        var result = await Scan(new(Ocr: false, Names: false, MaxFileBytes: 10_000));
        Assert.Contains(result.Issues, i => i.Source == "huge.txt" && i.Message.Contains("expanded size"));
        Assert.Contains(result.Findings, f => f.Value == "checked@example.net");
        Assert.DoesNotContain(result.Findings, f => f.Value == "unchecked@example.net");
    }

    [Fact] public async Task NestedOneNotePreservesRealTextAndSource()
    {
        byte[] bytes = File.ReadAllBytes(Fixture("testOneNote2016.one"));
        const string original = "This is one note 2016";
        int changed = 0;
        foreach (var encoding in new[] { Encoding.Unicode, Encoding.UTF8 }) {
            byte[] search = encoding.GetBytes(original), replacement = encoding.GetBytes("one.test@example.com".PadRight(original.Length));
            for (int start = 0; start < bytes.Length;) {
                int index = bytes.AsSpan(start).IndexOf(search);
                if (index < 0) break;
                replacement.CopyTo(bytes, start + index); changed++; start += index + search.Length;
            }
        }
        Assert.True(changed > 0);
        File.WriteAllBytes(Path.Combine(_temp, "outer.zip"), Zip(("notes/contact.one", bytes)));
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Value == "one.test@example.com" && f.Source == "notes/contact.one");
    }

    [Fact] public async Task NotebookIndexExplicitlyReportsUncheckedSectionContent()
    {
        File.WriteAllText(Path.Combine(_temp, "notebook.onetoc2"), "index@example.com");
        var result = await Scan();
        Assert.Contains(result.Issues, i => i.Message.Contains("OneNote") && i.Message.Contains(".one"));
    }

    [Fact] public async Task AbandonedWorkerReadCannotLeakIntoNextRequest()
    {
        string first = Path.Combine(_temp, "first.html"), second = Path.Combine(_temp, "second.html");
        File.WriteAllText(first, "<html><body>" + string.Concat(Enumerable.Repeat("first@example.com ", 5000)) + "</body></html>");
        File.WriteAllText(second, "<html><body>second@example.net</body></html>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await foreach (var part in client.ReadAsync(first, false, deadline.Token)) break;
        var parts = new List<ExtractedPart>();
        await foreach (var part in client.ReadAsync(second, false, deadline.Token)) parts.Add(part);
        Assert.Contains(parts, p => p.Text.Contains("second@example.net"));
        Assert.DoesNotContain(parts, p => p.Text.Contains("first@example.com"));
    }

    [Fact] public async Task PreCancelledWorkerDoesNotStartMissingRuntime()
    {
        using var client = new ExtractionClient(new RuntimePaths(Path.Combine(_temp, "missing")));
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => {
            await foreach (var part in client.ReadAsync("missing.html", false, cancelled.Token)) { }
        });
    }

    [Fact] public async Task PreCancelledImageDoesNotOpenOrDecodeInput()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ImageReader.ReadAsync("missing.png", "archive/image.png", TestPaths.Assets, cancelled.Token));
    }

    [Fact] public async Task ImagePixelLimitStillAllowsMetadataExtraction()
    {
        byte[] original = File.ReadAllBytes(Fixture("corpus", "04_images", "badge.png"));
        static byte[] Chunk(string kind, byte[] data) {
            byte[] chunk = new byte[data.Length + 12];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(chunk, data.Length);
            Encoding.ASCII.GetBytes(kind).CopyTo(chunk, 4); data.CopyTo(chunk, 8);
            uint crc = uint.MaxValue;
            foreach (byte value in chunk.AsSpan(4, data.Length + 4)) {
                crc ^= value;
                for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0 : 0xedb88320);
            }
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(chunk.AsSpan(chunk.Length - 4), ~crc);
            return chunk;
        }
        byte[] header = original.AsSpan(16, 13).ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header, 8000);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4), 5000);
        File.WriteAllBytes(Path.Combine(_temp, "oversized.png"), [.. original.AsSpan(0, 8), .. Chunk("IHDR", header),
            .. Chunk("tEXt", Text("Comment\0metadata.only@example.net")), .. original.AsSpan(33)]);
        var result = await Scan(new(Ocr: true, Names: false));
        Assert.Contains(result.Issues, i => i.Message.Contains("32 megapixel"));
        Assert.Contains(result.Findings, f => f.Value == "metadata.only@example.net" && f.Location.StartsWith("metadata:"));
    }

    [Fact] public async Task XmlExternalEntitiesDoNotReadLocalFiles()
    {
        string secret = Path.Combine(_temp, "outside.bin");
        File.WriteAllText(secret, "external.secret@example.com");
        string xml = Path.Combine(_temp, "document.xml");
        File.WriteAllText(xml, $"<!DOCTYPE data [<!ENTITY secret SYSTEM '{new Uri(secret).AbsoluteUri}'>]><data>visible@example.net &secret;</data>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var parts = new List<ExtractedPart>();
        await foreach (var part in client.ReadAsync(xml, false, deadline.Token)) parts.Add(part);
        Assert.DoesNotContain(parts, p => p.Text.Contains("external.secret@example.com"));
    }

    [Theory]
    [InlineData("records.rar")]
    [InlineData("payroll.7z")]
    [InlineData("team-backup.zip")]
    public async Task RenamedArchivesUseTheBoundedArchivePipeline(string name)
    {
        File.WriteAllBytes(Path.Combine(_temp, "outer.bin"), Zip(("inner.dat", File.ReadAllBytes(Fixture("corpus", "09_archives", name)))));
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Type == "Email" && f.Source.StartsWith("inner.dat > "));
    }

    [Fact] public async Task TsvPreservesHeaderContextAndQuotedTabs()
    {
        File.WriteAllText(Path.Combine(_temp, "people.tsv"), "full_name\tdob\temail\tnotes\nPriya Raghunathan\t1991-07-24\tpriya@example.net\t\"Called\tMonday\"\n");
        var result = await Scan(new(Ocr: false));
        Assert.Empty(result.Issues);
        Assert.Contains(result.Findings, f => f.Type == "Person" && f.Value == "Priya Raghunathan" && f.Location.StartsWith("TSV rows"));
        Assert.Contains(result.Findings, f => f.Type == "Date of birth" && f.Value == "DOB: 1991-07-24");
        Assert.Contains(result.Findings, f => f.Value == "priya@example.net" && f.Context.Contains("Full name:"));
    }

    [Theory]
    [InlineData(0, 100, 10, 10)]
    [InlineData(1, 0, 10, 10)]
    [InlineData(1, -1, 10, 10)]
    [InlineData(1, 100, 0, 10)]
    [InlineData(1, 100, int.MaxValue, 10)]
    [InlineData(1, 100, 10, 0)]
    public async Task InvalidLimitsAreRejectedBeforeRuntimeStartup(int workers, long bytes, int seconds, int findings)
    {
        var engine = new ScanEngine(new RuntimePaths(Path.Combine(_temp, "missing")));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => engine.ScanAsync(_temp,
            new(Workers: workers, MaxFileBytes: bytes, FileTimeoutSeconds: seconds, MaxFindings: findings), new Progress(_ => { }), default));
    }

    [Fact] public async Task ActiveCancellationDiscardsBufferedWorkerOutputAndAllowsRestart()
    {
        string path = Path.Combine(_temp, "many.html");
        File.WriteAllText(path, "<html><body>" + string.Concat(Enumerable.Repeat("first@example.com ", 5000)) + "</body></html>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using (var parts = client.ReadAsync(path, false, deadline.Token).GetAsyncEnumerator()) {
            Assert.True(await parts.MoveNextAsync());
            deadline.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => parts.MoveNextAsync().AsTask());
        }
        File.WriteAllText(path, "<html><body>restarted@example.net</body></html>");
        using var restartDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var found = new List<string>();
        await foreach (var part in client.ReadAsync(path, false, restartDeadline.Token)) found.Add(part.Text);
        Assert.Contains(found, text => text.Contains("restarted@example.net"));
        Assert.DoesNotContain(found, text => text.Contains("first@example.com"));
    }

    [Fact] public async Task ConcurrentWorkerRequestIsRejectedWithoutCorruptingActiveResponse()
    {
        string path = Path.Combine(_temp, "many.html");
        File.WriteAllText(path, "<html><body>" + string.Concat(Enumerable.Repeat("first@example.com ", 5000)) + "</body></html>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var active = client.ReadAsync(path, false, deadline.Token).GetAsyncEnumerator();
        Assert.True(await active.MoveNextAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(async () => {
            await foreach (var part in client.ReadAsync(path, false, deadline.Token)) { }
        });
        int remaining = 0;
        while (await active.MoveNextAsync()) remaining++;
        Assert.True(remaining > 0);
    }

    [Fact] public async Task LogicalResourceNameReplacesStagingFilenameInMetadata()
    {
        string path = Path.Combine(_temp, "random-staging.html");
        File.WriteAllText(path, "<html><body>document@example.net</body></html>");
        using var client = new ExtractionClient(TestPaths.Assets);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var parts = new List<ExtractedPart>();
        await foreach (var part in client.ReadAsync(path, false, deadline.Token, "notes/original.html")) parts.Add(part);
        Assert.Contains(parts, p => p.Location.StartsWith("metadata: resourceName") && p.Text == "notes/original.html");
        Assert.DoesNotContain(parts, p => p.Text.Contains("random-staging"));
    }

    [Fact] public async Task DirectoryEntriesAlsoConsumeTheSharedArchiveMemberBudget()
    {
        var entries = Enumerable.Range(0, 2001).Select(i => ($"directory{i}/", Array.Empty<byte>())).ToList();
        entries.Add(("unchecked.txt", Text("unchecked@example.net")));
        File.WriteAllBytes(Path.Combine(_temp, "directories.zip"), Zip(entries.ToArray()));
        var result = await Scan();
        Assert.Contains(result.Issues, i => i.Message.Contains("member count limit"));
        Assert.DoesNotContain(result.Findings, f => f.Value == "unchecked@example.net");
    }

    [Fact] public async Task ParallelFindingLimitPublishesEveryReservedFindingOnce()
    {
        for (int i = 0; i < 8; i++)
            File.WriteAllText(Path.Combine(_temp, $"file{i}.txt"), string.Join(' ', Enumerable.Range(0, 100).Select(n => $"p{i}.{n}@example.net")));
        var result = await Scan(new(Ocr: false, Names: false, Workers: 4, MaxFindings: 25));
        Assert.True(result.Summary.Cancelled);
        Assert.Equal(25, result.Summary.Findings);
        Assert.Equal(25, result.Findings.Length);
        Assert.Single(result.Issues, i => i.Message.Contains("Finding limit"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidOrEncryptedZipEntryDoesNotHideIndependentSiblings(bool encrypted)
    {
        byte[] bytes = Zip(("bad.txt", Text("broken@example.com")), ("good.txt", Text("good@example.net")));
        // Alter only the first entry's flags/compression method in its local and central headers.
        // This keeps the directory valid while making that member unreadable.
        int central = bytes.AsSpan().IndexOf(new byte[] { 0x50, 0x4b, 0x01, 0x02 });
        Assert.True(central > 0);
        if (encrypted) { bytes[6] |= 1; bytes[central + 8] |= 1; }
        else { bytes[8] = 0xff; bytes[9] = 0xff; bytes[central + 10] = 0xff; bytes[central + 11] = 0xff; }
        File.WriteAllBytes(Path.Combine(_temp, "mixed.zip"), bytes);
        var result = await Scan();
        Assert.Contains(result.Issues, i => i.Source == "bad.txt");
        Assert.Contains(result.Findings, f => f.Value == "good@example.net" && f.Source == "good.txt");
    }

    [Fact] public async Task SolidSevenZipSequentialExtractionMatchesIndependentReadsAndFindsAllMembers()
    {
        // 48 synthetic text members in one solid LZMA2 block (about 2.7 MB expanded).
        // Embedded fixture keeps the test offline and independent of a 7-Zip installation.
        const string archiveData = "N3q8ryccAAQXNDzV4wQAAAAAAAAjAAAAAAAAAFct0HD/964CPV0AIJyIZqefnKuu6u/N38NlP58ZkVger7Sohcwo+u6zwJQ/jQ4I47eogJl3UFKh87wIFDlE1meJ/KcX7ODGqJG54MR1W8ouDeGX+1OuBMg+AsrPnqEAtLauzJg7V7ceNxtRtDL6VUIx5qdxM9zp3YkGLHOGLFb6/inXTMy3YC3pmVae9WCmhgSJe4xKcQGRuyDBkALwqxH04xkWco9SZXlHEZWgejc2uxdwS1gTLbDQNYVbi0emU1mNlxP0DGRpn4oaXhfQ/LNdrfppl0ff5SHH87FFbSdG+I45Sp1HP1wSfp01Z2RI00jcTiCQNlH1V18ZXFuxXULIfFLwZZN8wAFepwnKGu/OTVB6S2jswKSSsuQScnBjbl2dAEJzegxK9WfvfQCburpTeY95gSnojVP091i0qvttSq1KOEeGkFO5coOzBvNC+4+poa6OMwF6Ppgwt1NrWRAFvLDDPmfa5Y5jan12K/06Ibn7D3TKsAnPqea/gyP5HJoRNkzl/Z9lLZo5kuC+68qfARfBkS3hrmvMtOSlLafz1HpMS4cuF/LlsD+gItu1wbPqsPbnBwVejavc6lQoBo7A0NMZQ0hvfDRYcCUemc2N0tpeKQ0kPFao+EU8aIPZpqWXuKNhG62ZLEoDg6coTCO4vjC4AkVk0mUo5obhJiwvHw4T0gYSx4VgMuzQvJkHu63d9II1NZCspO+ndwHJTlu8Gdk6PabQeYmBGoetDDHLNYyj0/bbu46hbFOWTWQGGwe1vfLwSeQAicuQAIAA7JZdE93FfoCIQyVeWuBXAC2/siA5zZC1HhzUwz+z/qmV9IvWYq86tS+8tFTWHQE6XKSpDE6qw4alybdKwoYe2lGz1/bSlHiS0TObHebO/cWjTtYKHgwrMBoLYv5cmLbAhUmqJ5/XZKa2VJhg6YAtyT9ntNRe3GOKxaWJm8kIBAAAAACBMweuD9VHUefXJNP+s3AWsW1jb2Z9qMRjzCZeAbV7OjEmWtev4Rn7GyqjbQRgj7ke6VeBJAj1dWbBctoSKsQtsEHcLY48SgT48qoNNOuutJCIXxF4jgwcGP3VJwVcl7VzE6rBe5+J+4IU6uOrs4rjx5CqZ5xXGZmEi0nJb2z4zEgBCQuu+n55NO7nag1Zpe5I0IIGmy4Qd+mQH4+mFNZ5tY8EzjANbuCoTh3nD8O54puObWIpiXsLyeS/I6qzlKbjNoTMM1pXulpYxbK4ylpmg2ubDN82W7SF/cQRijG01aheQBUTwyI5TOMkvZB9PCySMt7D9vaxp6VQwrQs16x342xzrsd1mmK+3whAajyrdoTcHQqj9vWCI/FsPL9I2Cj6BN/agA3D2NfGEp6i1HVNahqdjZ46CCddRtvZ7xFoOYKAk7NPJJh9wQuX7ZZglPMZ4wUKU9sB2lSq20xS7V3wur24V3IfswgEFfrmEI/rpzsNlwgeNWij/91ZFyTjt5K9OUXpel72M/3f99FbJJtOqqXzIra2q/CevfWGEoa2YDD/bodJK498X0t85VcthVf+LeCG/ly1tOF+gMjopRDzgZFVQcjdMYoRuq8Gj1m1wzFrF0Y3Y981bEIb5+pGle96oxZ5uz6L142M3NQMcYcyuh/M4CnwQl3KpL+bCnjKB+zmZ8ci7555Z2LNVWbE+qrohNTZtQAXBoLLAQmCGAAHCwEAASMDAQEFXQAQAAAMiLIKAaHWP6oAAA==";
        string path = Path.Combine(_temp, "solid.7z");
        File.WriteAllBytes(path, Convert.FromBase64String(archiveData));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var before = new List<double>(); var after = new List<double>();
        async Task<long> Drain(Stream stream) {
            byte[] buffer = new byte[65536]; long bytes = 0; int read;
            while ((read = await stream.ReadAsync(buffer, deadline.Token)) > 0) bytes += read;
            return bytes;
        }
        for (int run = 0; run < 4; run++) {
            var watch = System.Diagnostics.Stopwatch.StartNew(); long oldBytes = 0, newBytes = 0;
            using (var archive = SharpCompress.Archives.ArchiveFactory.OpenArchive(path))
                foreach (var entry in archive.Entries) {
                    using var stream = entry.OpenEntryStream(); oldBytes += await Drain(stream);
                }
            if (run > 0) before.Add(watch.Elapsed.TotalMilliseconds);
            watch.Restart();
            await using (var archive = await SharpCompress.Archives.ArchiveFactory.OpenAsyncArchive(path, cancellationToken: deadline.Token)) {
                await using var reader = await archive.ExtractAllEntriesAsync();
                while (await reader.MoveToNextEntryAsync(deadline.Token)) {
                    await using var stream = await reader.OpenEntryStreamAsync(deadline.Token); newBytes += await Drain(stream);
                }
            }
            if (run > 0) after.Add(watch.Elapsed.TotalMilliseconds);
            Assert.Equal(oldBytes, newBytes); Assert.True(newBytes > 2_000_000);
        }
        _output.WriteLine($"Solid 7z decompression, median of 3 warm runs: independent entries {before.Order().ElementAt(1):F1} ms; sequential {after.Order().ElementAt(1):F1} ms");
        var result = await Scan();
        Assert.Empty(result.Issues);
        Assert.Equal(48, result.Findings.Count(f => f.Type == "Email" && f.Location.StartsWith("text")));
    }
}
