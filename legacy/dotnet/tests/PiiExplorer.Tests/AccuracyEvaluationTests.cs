using System.Text.Json;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class AccuracyEvaluationTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("PiiAccuracyTests-").FullName;
    public void Dispose() => Directory.Delete(_temp, true);
    private string Write(params EvaluationCase[] cases)
    {
        string path = Path.Combine(_temp, "labelled.jsonl");
        File.WriteAllLines(path, cases.Select(c => JsonSerializer.Serialize(c)));
        return path;
    }

    [Fact]
    public void ExactSpanAccountingPenalizesMissingExtraAndIncorrectBoundaries()
    {
        string path = Write(new("a@example.com b@example.com", [new("Email", 0, 13)]),
            new("nothing", [new("Person", 0, 7)]), new("c@example.com", [new("Email", 0, 12)]));
        var report = AccuracyEvaluation.Run(path, TestPaths.Assets, namesEnabled: false);
        Assert.Equal(3, report.Cases);
        Assert.Equal(new(1, 2, 2), report.Micro);
        Assert.Equal(new(1, 2, 1), report.ByType["Email"]);
        Assert.Equal(1.0 / 3, report.Micro.Precision);
        Assert.Equal(1.0 / 3, report.Micro.Recall);
        Assert.Equal(1.0 / 3, report.Micro.F1);
        Assert.Null(report.ByType["Person"].Precision);
        string json = JsonSerializer.Serialize(report);
        Assert.DoesNotContain("example.com", json);
        Assert.DoesNotContain(path, json);
        Assert.Equal(64, report.CorpusSha256.Length);
        Assert.Equal(report.CorpusSha256, AccuracyEvaluation.Run(path, TestPaths.Assets, false).CorpusSha256);
    }

    [Fact]
    public void CorrectNegativeControlsHaveUndefinedNotPerfectMetrics()
    {
        var report = AccuracyEvaluation.Run(Write(new EvaluationCase("nothing", [])), TestPaths.Assets, false);
        Assert.Null(report.Micro.Precision); Assert.Null(report.Micro.Recall); Assert.Null(report.Micro.F1);
        Assert.Null(report.Micro.FalseNegativeProportion);
        Assert.Equal(1, report.CleanDocuments);
        Assert.Equal(0, report.FalsePositivesPerCleanDocument);
    }

    [Fact]
    public void MissRateAndCleanDocumentFalsePositivesUseTheirOwnDenominators()
    {
        var report = AccuracyEvaluation.Run(Write(new EvaluationCase("a@example.com b@example.com", []),
            new("Tom", [new("Person", 0, 3)])), TestPaths.Assets, false);
        Assert.Equal(1, report.Micro.FalseNegativeProportion);
        Assert.Equal(1, report.CleanDocuments);
        Assert.Equal(2, report.FalsePositivesOnCleanDocuments);
        Assert.Equal(2, report.FalsePositivesPerCleanDocument);
    }

    [Theory]
    [InlineData(-1, 1)]
    [InlineData(0, 0)]
    [InlineData(0, int.MaxValue)]
    [InlineData(int.MaxValue, 1)]
    public void InvalidAnnotationsCannotProduceAnAccuracyReport(int start, int length) =>
        Assert.Throws<InvalidDataException>(() => AccuracyEvaluation.Run(
            Write(new EvaluationCase("a@example.com", [new("Email", start, length)])), TestPaths.Assets, false));

    [Fact]
    public void DuplicateAnnotationsAreRejected() => Assert.Throws<InvalidDataException>(() => AccuracyEvaluation.Run(
        Write(new EvaluationCase("a@example.com", [new("Email", 0, 13), new("Email", 0, 13)])), TestPaths.Assets, false));

    [Fact]
    public void MalformedAndOversizedRecordsAreBoundedAndDoNotEchoSourceText()
    {
        string path = Path.Combine(_temp, "bad.jsonl");
        File.WriteAllText(path, "{ secret@example.com }");
        var error = Assert.Throws<InvalidDataException>(() => AccuracyEvaluation.Run(path, TestPaths.Assets, false));
        Assert.DoesNotContain("secret@example.com", error.Message);
        File.WriteAllText(path, new string('x', 512_001));
        Assert.Throws<InvalidDataException>(() => AccuracyEvaluation.Run(path, TestPaths.Assets, false));
    }

    [Fact]
    public void ExportIsAtomicAndNeverOverwritesAnExistingFile()
    {
        var report = AccuracyEvaluation.Run(Write(new EvaluationCase("a@example.com", [new("Email", 0, 13)])), TestPaths.Assets, false);
        string output = Path.Combine(_temp, "result.json");
        AccuracyEvaluation.Save(output, report);
        byte[] original = File.ReadAllBytes(output);
        Assert.Throws<IOException>(() => AccuracyEvaluation.Save(output, report));
        Assert.Equal(original, File.ReadAllBytes(output));
        Assert.Empty(Directory.GetFiles(_temp, "*.tmp"));
        Assert.Throws<OperationCanceledException>(() => AccuracyEvaluation.Save(Path.Combine(_temp, "cancelled.json"), report, new(true)));
        Assert.False(File.Exists(Path.Combine(_temp, "cancelled.json")));
    }
}
