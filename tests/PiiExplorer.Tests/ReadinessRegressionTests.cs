using System.Collections.Concurrent;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class ReadinessRegressionTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("PiiReadinessTests-").FullName;
    public void Dispose() => Directory.Delete(_temp, true);

    [Fact]
    public async Task AttentionItemsAreBoundedAndStopTheScanTransparently()
    {
        for (int i = 0; i < 20; i++) File.WriteAllText(Path.Combine(_temp, $"record-{i}.txt"), "oversized");
        var issues = new ConcurrentBag<ScanIssue>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp,
            new(Ocr: false, Names: false, MaxFileBytes: 1, MaxIssues: 2),
            new InlineProgress<ScanUpdate>(u => { foreach (var issue in u.Issues ?? []) issues.Add(issue); }), default);
        Assert.False(summary.Cancelled); Assert.Equal(ScanStopReason.IssueLimit, summary.StopReason);
        Assert.Equal(2, summary.Issues);
        Assert.Equal(2, issues.Count);
        Assert.Single(issues, i => i.Message.StartsWith("Attention item limit reached"));
    }

    [Fact]
    public async Task SourceChangesAreFlaggedEvenWhenFindingsWereAlreadyPublished()
    {
        string path = Path.Combine(_temp, "record.txt");
        File.WriteAllText(path, "first@example.com");
        var issues = new ConcurrentBag<ScanIssue>();
        int changed = 0;
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, new(Ocr: false, Names: false),
            new InlineProgress<ScanUpdate>(u => {
                // Timestamp changes work even while the text reader denies write sharing.
                if (u.Findings is { Count: > 0 } && Interlocked.Exchange(ref changed, 1) == 0)
                    File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(-10));
                foreach (var issue in u.Issues ?? []) issues.Add(issue);
            }), default);
        Assert.Equal(1, summary.Completed);
        Assert.Contains(issues, i => i.Reason == CoverageReason.SourceChanged);
        Assert.Contains(CoverageReason.SourceChanged, Assert.Single(summary.Outcomes).Reasons);
        Assert.Equal(CoverageStatus.Partial, summary.Status);
    }

    [Fact]
    public async Task DiscoveryIsBoundedAndCanStopBeforeEnumeratingTheWholeTree()
    {
        for (int i = 0; i < 1000; i++) File.WriteAllText(Path.Combine(_temp, $"record-{i}.txt"), "synthetic@example.com");
        using var cancellation = new CancellationTokenSource();
        var findings = new ConcurrentBag<Finding>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, new(Ocr: false, Names: false, Workers: 1),
            new InlineProgress<ScanUpdate>(u => {
                foreach (var finding in u.Findings ?? []) { findings.Add(finding); cancellation.Cancel(); }
            }), cancellation.Token).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(summary.Cancelled);
        Assert.Equal(ScanStopReason.UserCancellation, summary.StopReason);
        Assert.Equal(summary.Files, summary.Outcomes.Count);
        Assert.DoesNotContain(summary.Outcomes, o => o.Status == CoverageStatus.Success);
        Assert.InRange(summary.Files, 1, 259); // Active file + bounded queue + pending writer.
        Assert.Equal(1, summary.Completed);
        Assert.Equal(summary.Findings, findings.Count);
        Assert.Single(findings);
    }

    [Fact]
    public async Task CancellingOnPublishedPatternsDoesNotWaitForOrIncludeModelResults()
    {
        File.WriteAllText(Path.Combine(_temp, "record.txt"), "Maria Hernandez spoke with David Okonkwo. Contact synthetic@example.com.\n");
        using var cancellation = new CancellationTokenSource();
        var findings = new ConcurrentBag<Finding>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, new(Ocr: false, Workers: 1),
            new InlineProgress<ScanUpdate>(u => {
                foreach (var finding in u.Findings ?? []) findings.Add(finding);
                if (u.Findings?.Any(f => f.Type == "Email") == true) cancellation.Cancel();
            }), cancellation.Token).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(summary.Cancelled);
        Assert.Equal(ScanStopReason.UserCancellation, summary.StopReason);
        Assert.Equal(summary.Files, summary.Outcomes.Count);
        Assert.DoesNotContain(summary.Outcomes, o => o.Status == CoverageStatus.Success);
        Assert.Contains(findings, f => f.Value == "synthetic@example.com");
        Assert.DoesNotContain(findings, f => f.Location.StartsWith("text") && f.Method == "Local model");
        Assert.Equal(findings.Count, summary.Findings);
    }

    [Theory]
    [InlineData(".csv", ",")]
    [InlineData(".tsv", "\t")]
    public async Task MalformedRecordPreservesPreviouslyReadRows(string extension, string delimiter)
    {
        File.WriteAllText(Path.Combine(_temp, "records" + extension),
            $"name{delimiter}email\nSample Person{delimiter}before@example.com\n\"unterminated");
        var findings = new ConcurrentBag<Finding>(); var issues = new ConcurrentBag<ScanIssue>();
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, new(Ocr: false, Names: false),
            new InlineProgress<ScanUpdate>(u => {
                foreach (var finding in u.Findings ?? []) findings.Add(finding);
                foreach (var issue in u.Issues ?? []) issues.Add(issue);
            }), default);
        Assert.Contains(findings, f => f.Value == "before@example.com");
        Assert.Contains(issues, i => i.Message.Contains("Malformed") && i.Message.Contains("remaining content unchecked"));
        Assert.Equal(1, summary.Completed);
    }

    [Fact]
    public async Task OversizedFileStillChecksItsNameAndReportsUncheckedContent()
    {
        File.WriteAllText(Path.Combine(_temp, "ssn_123-45-6789.txt"), new string('x', 1000));
        var findings = new ConcurrentBag<Finding>(); var issues = new ConcurrentBag<ScanIssue>();
        await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, new(Ocr: false, Names: false, MaxFileBytes: 10),
            new InlineProgress<ScanUpdate>(u => {
                foreach (var finding in u.Findings ?? []) findings.Add(finding);
                foreach (var issue in u.Issues ?? []) issues.Add(issue);
            }), default);
        Assert.Contains(findings, f => f.Value == "123-45-6789" && f.Location.Contains("name"));
        Assert.Contains(issues, i => i.Message.Contains("File exceeds"));
    }

    [Fact]
    public void PatternsHonorCancellationBetweenFindings()
    {
        using var cancellation = new CancellationTokenSource();
        using var spans = new PatternDetector().Detect("first@example.com second@example.com", cancellation.Token).GetEnumerator();
        Assert.True(spans.MoveNext());
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => spans.MoveNext());
    }

    [Fact]
    public async Task CancelledInferenceDoesNotPoisonTheSharedSession()
    {
        using var names = new NameDetector(TestPaths.Assets);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        string longText = string.Concat(Enumerable.Repeat("Maria Hernandez spoke with David Okonkwo about the delivery. ", 20_000));
        var cancelled = Task.Run(() => names.Detect(longText, cancellation.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled.WaitAsync(TimeSpan.FromSeconds(10)));
        const string next = "Maria Hernandez spoke with David Okonkwo about the delivery.";
        Assert.Contains(names.Detect(next, default), span => next.Substring(span.Start, span.Length) == "Maria Hernandez");
    }
}
