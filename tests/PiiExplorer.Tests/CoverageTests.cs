using System.IO.Compression;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class CoverageTests : IDisposable
{
    private readonly string root = Directory.CreateTempSubdirectory("PiiCoverageTests-").FullName;
    public void Dispose() => Directory.Delete(root, true);
    private Task<ScanSummary> Scan(ScanOptions? options = null) => new ScanEngine(TestPaths.Assets)
        .ScanAsync(root, options ?? new(Ocr: false, Names: false), new InlineProgress<ScanUpdate>(_ => { }), default);

    [Fact] public async Task EmptyAndCleanFilesHaveDurableSuccessfulOutcomes()
    {
        File.WriteAllText(Path.Combine(root, "empty.txt"), "");
        File.WriteAllText(Path.Combine(root, "clean.txt"), "ordinary prose");
        var result = await Scan();
        Assert.Equal(2, result.Outcomes.Count);
        Assert.All(result.Outcomes, o => { Assert.Equal(CoverageStatus.Success, o.Status); Assert.Empty(o.Reasons); });
        Assert.Equal(2, result.SuccessfulFiles);
        Assert.Equal(CoverageStatus.Success, result.Status);
        Assert.Equal(new ScanConfiguration(false, false, true, "US,GB"), result.Configuration);
    }

    [Fact] public async Task ExcludedFolderIsRecordedWithoutClaimingItsContentsWereDiscovered()
    {
        Directory.CreateDirectory(Path.Combine(root, "node_modules"));
        File.WriteAllText(Path.Combine(root, "node_modules", "hidden.txt"), "example@example.com");
        var result = await Scan();
        Assert.Equal(0, result.Files);
        Assert.Equal(CoverageStatus.Excluded, Assert.Single(result.Outcomes).Status);
        Assert.Equal(CoverageStatus.Partial, result.Status);
    }

    [Fact] public async Task NestedFailureMakesEveryContainerPartialAndRetainsCleanSiblings()
    {
        using (var zip = ZipFile.Open(Path.Combine(root, "outer.zip"), ZipArchiveMode.Create)) {
            using (var stream = zip.CreateEntry("nested.zip").Open())
            using (var nested = new ZipArchive(stream, ZipArchiveMode.Create)) {
                using var bad = new StreamWriter(nested.CreateEntry("bad.csv").Open());
                bad.Write("header\n\"unterminated");
            }
            using var good = new StreamWriter(zip.CreateEntry("empty.txt").Open());
        }
        var result = await Scan();
        Assert.Equal(4, result.Outcomes.Count);
        Assert.Equal(CoverageStatus.Partial, result.Outcomes.Single(o => o.ResourceId == "root").Status);
        Assert.Equal(CoverageStatus.Partial, result.Outcomes.Single(o => o.Source == "nested.zip").Status);
        Assert.Equal(CoverageStatus.Success, result.Outcomes.Single(o => o.Source == "empty.txt").Status);
    }

    [Fact] public async Task SizeLimitIsTypedWithoutBeingUserCancellation()
    {
        File.WriteAllText(Path.Combine(root, "large.txt"), "large");
        var result = await Scan(new(Ocr: false, Names: false, MaxFileBytes: 1));
        Assert.Contains(CoverageReason.FileSizeLimit, Assert.Single(result.Outcomes).Reasons);
        Assert.False(result.Cancelled);
        Assert.Equal(ScanStopReason.None, result.StopReason);
        Assert.Equal(CoverageStatus.Partial, result.Status);
    }

    [Fact] public async Task UnsupportedContentIsNotCheckedClean()
    {
        File.WriteAllBytes(Path.Combine(root, "unknown.bin"), [0, 1, 2, 3, 4, 0, 255]);
        var result = await Scan();
        Assert.Contains(CoverageReason.Unsupported, Assert.Single(result.Outcomes).Reasons);
        Assert.Equal(CoverageStatus.Partial, result.Status);
    }

    [Fact] public async Task TimeoutHasAnOutcomeAndDoesNotMeanUserCancellation()
    {
        File.WriteAllText(Path.Combine(root, "record.txt"), "test@example.com");
        var result = await new ScanEngine(TestPaths.Assets).ScanAsync(root,
            new(Ocr: false, Names: false, FileTimeoutSeconds: 1),
            new InlineProgress<ScanUpdate>(u => { if (u.Findings?.Count > 0) Thread.Sleep(1200); }), default);
        Assert.Contains(CoverageReason.Timeout, Assert.Single(result.Outcomes).Reasons);
        Assert.False(result.Cancelled);
        Assert.Equal(CoverageStatus.Partial, result.Status);
    }

    [Fact] public async Task ArchiveDepthAndExpandedSizeLimitsAreTyped()
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes("payload");
        for (int i = 0; i < 5; i++) {
            using var output = new MemoryStream();
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) {
                using var entry = zip.CreateEntry(i == 0 ? "body.txt" : "nested.zip").Open();
                entry.Write(bytes);
            }
            bytes = output.ToArray();
        }
        File.WriteAllBytes(Path.Combine(root, "nested.zip"), bytes);
        var depth = await Scan();
        Assert.Contains(depth.Outcomes, o => o.Reasons.Contains(CoverageReason.ArchiveDepthLimit));
        Assert.Equal(CoverageStatus.Partial, depth.Status);
        File.Delete(Path.Combine(root, "nested.zip"));
        using (var zip = ZipFile.Open(Path.Combine(root, "expanded.zip"), ZipArchiveMode.Create)) {
            using var entry = zip.CreateEntry("large.txt").Open();
            entry.Write(new byte[20_000]);
        }
        var size = await Scan(new(Ocr: false, Names: false, MaxFileBytes: 1000));
        Assert.Contains(size.Outcomes, o => o.Reasons.Contains(CoverageReason.ArchiveSizeLimit));
        Assert.Equal(CoverageStatus.Partial, size.Status);
    }

    [Fact] public async Task CorruptArchiveIsFailedRatherThanSuccessfullyChecked()
    {
        File.WriteAllText(Path.Combine(root, "broken.zip"), "not a zip");
        var result = await Scan();
        Assert.Equal(CoverageStatus.Failed, Assert.Single(result.Outcomes).Status);
        Assert.Equal(CoverageStatus.Failed, result.Status);
        Assert.Equal(0, result.SuccessfulFiles);
    }

    [Fact] public async Task DisabledOcrIsRecordedForImageContent()
    {
        File.Copy(Path.Combine(TestPaths.Root, "tests", "fixtures", "corpus", "03_pdf", "invoice.pdf"),
            Path.Combine(root, "invoice.pdf"));
        var result = await Scan();
        Assert.False(result.Configuration!.Ocr);
        Assert.Contains(result.Outcomes, o => o.Reasons.Contains(CoverageReason.OcrDisabled));
        Assert.Equal(CoverageStatus.Partial, result.Status);
    }
}
