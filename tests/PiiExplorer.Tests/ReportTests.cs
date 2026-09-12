using System.Text;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class ReportTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "PiiReportTests", Guid.NewGuid().ToString("N"));
    public ReportTests() => Directory.CreateDirectory(Path.Combine(_temp, "source"));
    public void Dispose() => Directory.Delete(_temp, true);

    [Fact] public async Task PdfPreservesOccurrenceLocationsAndMarksSynthesizedContext()
    {
        var snapshot = Snapshot(context: true);
        var finding = snapshot.Findings[0] with
        {
            Evidence = new(new("root/archive:2", "table", EvidenceKind.Body, TextRepresentation.SynthesizedText), 120, 24, 110, 120, 24)
        };
        snapshot = snapshot with { Findings = [finding, finding with { Evidence = finding.Evidence with { Start = 220 } }] };
        string path = Path.Combine(_temp, "occurrences.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("root/archive:2 / table", text);
        Assert.Contains("UTF-16 offset 120", text);
        Assert.Contains("UTF-16 offset 220", text);
        Assert.Contains("Synthesized context", text);
    }

    private ReportSnapshot Snapshot(bool aliases = false, bool context = false)
    {
        string root = Path.Combine(_temp, "source");
        return new(root, [
            new(Path.Combine(root, "HR", "contacts.txt"), "", "text · character 0", "Email", "report.check@example.com", "Secret surrounding context", .99, "Pattern"),
            new(Path.Combine(root, "Finance", "contacts.txt"), "", "text", "Person", "José Muñoz", "Unshared context", .92, "Local model"),
            new(Path.Combine(root, "backup.rar"), "staff/contacts.txt", "text", "Email", "archive.check@example.com", "", .99, "Pattern")
        ], [new(Path.Combine(root, "locked.zip"), "inside.txt", "Cannot open C:\\Users\\ReportHostUser\\Documents\\locked.zip")],
            new(4, 4, 3, 1, TimeSpan.FromSeconds(10), false), new(), new(aliases, context));
    }

    [Fact] public async Task PdfHasNoIdentifyingMetadataAndPreservesSourcesAndUnicode()
    {
        var snapshot = Snapshot();
        string path = Path.Combine(_temp, "report.pdf");
        PdfReport.Save(path, snapshot);
        byte[] bytes = File.ReadAllBytes(path);
        string raw = Encoding.Latin1.GetString(bytes);
        Assert.StartsWith("%PDF-", raw);
        foreach (string key in new[] { "/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Metadata", "/EmbeddedFiles", "/JavaScript", "/ID " })
            Assert.DoesNotContain(key, raw);
        Assert.DoesNotContain("ReportHostUser", raw);
        string text = await Extract(path);
        Assert.Contains("report.check@example.com", text);
        Assert.Contains("archive.check@example.com", text);
        Assert.Contains("José Muñoz", text);
        Assert.Contains("HR/contacts.txt", text);
        Assert.Contains("Finance/contacts.txt", text);
        Assert.Contains("staff/contacts.txt", text);
        Assert.DoesNotContain("ReportHostUser", text);
        Assert.DoesNotContain(_temp, text);
        Assert.DoesNotContain("Secret surrounding context", text);
    }

    [Fact] public async Task AliasModeOmitsFilenamesAndKeepsDistinctTraceableIds()
    {
        var snapshot = Snapshot(aliases: true);
        string path = Path.Combine(_temp, "aliases.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        foreach (string value in new[] { "contacts.txt", "backup.rar", "locked.zip", "inside.txt", "ReportHostUser" })
            Assert.DoesNotContain(value, text);
        var labels = PdfReport.SourceLabels(snapshot);
        Assert.Equal(4, labels.Values.Distinct().Count());
        foreach (string label in labels.Values) Assert.Contains(label, text);
    }

    [Fact] public async Task ArbitraryUnixAndNestedAbsolutePathsAreOmitted()
    {
        var snapshot = Snapshot();
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with {
            Source = @"C:\Users\PrivateHost\one.zip > /srv/PrivateUser/secret.txt",
            Location = "metadata: /root-secret", Value = "report.check@example.com"
        }], Issues = [new(snapshot.Issues[0].FilePath, "//PrivateServer/Share/secret.txt", "Cannot read /opt/PrivateUser/hidden.txt")] };
        string path = Path.Combine(_temp, "paths.pdf"); PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        foreach (string secret in new[] { "PrivateHost", "PrivateUser", "PrivateServer", "root-secret", "hidden.txt" })
            Assert.DoesNotContain(secret, text);
        Assert.Contains("report.check@example.com", text);
    }

    [Fact] public async Task SlashPrefixedValuesSurviveWhileHostPathsStayOmitted()
    {
        var snapshot = Snapshot(context: true);
        const string value = "/O=Acme/CN=jane.doe@example.com";
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with {
            Value = value, Context = "cert=" + value + @" from C:\Users\PrivateHost\e.csv"
        }] };
        string path = Path.Combine(_temp, "slash-values.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("Value: " + value, text);
        Assert.Contains("cert=" + value + " from [absolute path omitted]", text);
        Assert.DoesNotContain("PrivateHost", text);
    }

    [Fact] public async Task PathsWithSpacesStayOmittedWithoutSwallowingTheirNeighbours()
    {
        var snapshot = Snapshot(context: true);
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with {
            Context = @"copied to C:\Users\PrivateHost\My Documents\salary.xlsx for jane.doe@example.com"
        }] };
        string path = Path.Combine(_temp, "spaced-paths.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        foreach (string secret in new[] { "PrivateHost", "My Documents", "salary.xlsx" })
            Assert.DoesNotContain(secret, text);
        Assert.Contains("for jane.doe@example.com", text);
    }

    [Fact] public async Task UrlAndConnectionStringCredentialsSurvive()
    {
        var snapshot = Snapshot();
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with { Value = "postgres://reader:s3cr3t@db.example.com:5432/app" },
            snapshot.Findings[1] with { Value = "https://vault.example.com/token?secret=8fa3" }] };
        string path = Path.Combine(_temp, "credentials.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("postgres://reader:s3cr3t@db.example.com:5432/app", text);
        Assert.Contains("https://vault.example.com/token?secret=8fa3", text);
    }

    [Fact] public async Task ValuesThatAreHostPathsStayRedacted()
    {
        var snapshot = Snapshot() with { Issues = [] };
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with { Value = @"\\PrivateServer\Share\token.txt" },
            snapshot.Findings[1] with { Value = @"D:\backups\credential.key" }] };
        string path = Path.Combine(_temp, "path-values.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        foreach (string secret in new[] { "PrivateServer", "token.txt", "credential.key" })
            Assert.DoesNotContain(secret, text);
        Assert.Equal(2, text.Split("[absolute path omitted]").Length - 1);
    }

    [Fact] public async Task ParserFailureReasonsSurvivePathRedaction()
    {
        var snapshot = Snapshot();
        snapshot = snapshot with { Issues = [
            new(snapshot.Issues[0].FilePath, "", "IOException: /tmp/tika-4711/private-input.tmp (No such file or directory)"),
            new(snapshot.Issues[0].FilePath, "inside.txt", "Extraction incomplete: WriteLimitReachedException: output exceeded /srv/PrivateUser/limit.txt")] };
        string path = Path.Combine(_temp, "reasons.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("IOException: [absolute path omitted] (No such file or directory)", text);
        Assert.Contains("Extraction incomplete", text);
        Assert.Contains("WriteLimitReachedException", text);
        foreach (string secret in new[] { "private-input.tmp", "PrivateUser", "limit.txt" })
            Assert.DoesNotContain(secret, text);
    }

    [Fact] public async Task AliasModeKeepsSlashValuesAndStillHidesNames()
    {
        var snapshot = Snapshot(aliases: true, context: true);
        const string value = "/CN=jane.doe@example.com";
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with { Value = value, Context = "owner " + value }] };
        string path = Path.Combine(_temp, "alias-values.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("Value: " + value, text);
        Assert.Contains("owner " + value, text);
        foreach (string secret in new[] { "contacts.txt", "backup.rar", "locked.zip", "ReportHostUser" })
            Assert.DoesNotContain(secret, text);
    }

    [Fact] public async Task BidiControlsInPreservedValuesAreEscapedNotHidden()
    {
        var snapshot = Snapshot();
        // A bidi override is a formatting control: the report shows it instead of letting it
        // silently reorder the value it reproduces.
        string value = "/CN=جين\u202E/email=jane.doe@example.com";
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with { Value = value }] };
        string path = Path.Combine(_temp, "bidi.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("[U+202E]", text);
        Assert.Contains("/email=jane.doe@example.com", text);
        Assert.DoesNotContain("جين", text);
        Assert.DoesNotContain('\u202E', text);
    }

    [Fact] public async Task LongSlashPrefixedValueRoundTripsAcrossWrappedLines()
    {
        var snapshot = Snapshot();
        string value = "/BEGIN-SLASH-VALUE/" + new string('k', 320) + "/END-SLASH-VALUE";
        snapshot = snapshot with { Findings = [snapshot.Findings[0] with { Value = value }] };
        string path = Path.Combine(_temp, "long-slash.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("/BEGIN-SLASH-VALUE/", text);
        Assert.Contains(new string('k', 60), text);
        Assert.Contains("/END-SLASH-VALUE", text);
    }

    [Fact] public async Task ReportKeepsReproducibilitySettingsAndAttentionReasons()
    {
        var snapshot = Snapshot();
        string path = Path.Combine(_temp, "settings.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        foreach (string setting in new[] { "Image reading: on", "People’s names: on", "File limit: 100 MiB", "Timeout: 180 seconds" })
            Assert.Contains(setting, text);
        Assert.Contains("Cannot open [absolute path omitted]", text);
    }

    [Fact] public void DestinationCreatedDuringRenderingIsNeverReplaced()
    {
        var snapshot = Snapshot();
        snapshot = snapshot with { Findings = Enumerable.Range(0, 260).Select(i => snapshot.Findings[0] with { Value = $"person{i}@example.com" }).ToArray() };
        string destination = Path.Combine(_temp, "appeared.pdf");
        Assert.Throws<IOException>(() => PdfReport.Save(destination, snapshot, default,
            new App.InlineProgress<int>(_ => File.WriteAllText(destination, "source appeared during export"))));
        Assert.Equal("source appeared during export", File.ReadAllText(destination));
        Assert.Empty(Directory.GetFiles(_temp, ".pii-export-*"));
    }

    [Fact] public async Task PartialAndEmptyReportsDoNotClaimCleanScan()
    {
        var snapshot = Snapshot() with { Findings = [], Issues = [], Summary = new(7, 2, 0, 0, TimeSpan.Zero, true) };
        string path = Path.Combine(_temp, "partial.pdf");
        PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("PARTIAL SCAN", text);
        Assert.Contains("2 / 7 files processed", text);
        Assert.Contains("may not have been checked", text);
    }

    [Fact] public void ExportCannotOverwriteSourceOrDamageExistingReportOnCancellation()
    {
        var snapshot = Snapshot();
        string source = Path.Combine(snapshot.Root, "clean.pdf");
        File.WriteAllText(source, "source even without findings");
        Assert.Throws<IOException>(() => PdfReport.Save(source, snapshot));
        Assert.Equal("source even without findings", File.ReadAllText(source));
        string destination = Path.Combine(_temp, "existing.pdf");
        File.WriteAllText(destination, "previous report");
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => PdfReport.Save(destination, snapshot, cancellation.Token));
        Assert.Equal("previous report", File.ReadAllText(destination));
        Assert.Empty(Directory.GetFiles(_temp, ".pii-export-*"));
    }

    [Fact] public void CancellationDuringRenderingPreservesExistingReportAndCleansStaging()
    {
        var snapshot = Snapshot();
        snapshot = snapshot with { Findings = Enumerable.Range(0, 300).Select(i => snapshot.Findings[0] with { Value = $"person{i}@example.com" }).ToArray() };
        string destination = Path.Combine(_temp, "existing.pdf"); File.WriteAllText(destination, "previous report");
        using var cancellation = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => PdfReport.Save(destination, snapshot, cancellation.Token,
            new App.InlineProgress<int>(_ => cancellation.Cancel())));
        Assert.Equal("previous report", File.ReadAllText(destination));
        Assert.Empty(Directory.GetFiles(_temp, ".pii-export-*"));
    }

    [Fact] public async Task MultipageLongValuesRemainCompleteAndCreateVisualQaSample()
    {
        var snapshot = Snapshot(context: true);
        var findings = Enumerable.Range(0, 18).Select(i => snapshot.Findings[i % 3] with {
            Value = i == 5 ? new string('W', 180) + "END-OF-LONG-VALUE" : i == 6 ? "李明" : snapshot.Findings[i % 3].Value
        }).ToArray();
        snapshot = snapshot with { Findings = findings, Summary = snapshot.Summary with { Findings = findings.Length } };
        string path = Path.Combine(_temp, "multipage.pdf"); PdfReport.Save(path, snapshot);
        string text = await Extract(path);
        Assert.Contains("END-OF-LONG-VALUE", text);
        Assert.Contains("[U+674E][U+660E]", text);
        Assert.Contains("Secret surrounding context", text);
        Assert.Contains("18.", text);
        string output = Path.Combine(TestPaths.Root, "test-results"); Directory.CreateDirectory(output);
        File.Copy(path, Path.Combine(output, "report-layout.pdf"), overwrite: true);
    }

    private static async Task<string> Extract(string path)
    {
        using var client = new ExtractionClient(TestPaths.Assets);
        var text = new StringBuilder();
        await foreach (var part in client.ReadAsync(path, false, default))
            if (part.Location.StartsWith("document text")) text.AppendLine(part.Text);
        return text.ToString();
    }
}
