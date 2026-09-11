using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PiiExplorer.Core;

public sealed record ExpectedEntity(string Type, int Start, int Length);
public sealed record EvaluationCase(string Text, ExpectedEntity[] Entities);
public sealed record AccuracyCounts(long TruePositive, long FalsePositive, long FalseNegative)
{
    public double? Precision => TruePositive + FalsePositive == 0 ? null : (double)TruePositive / (TruePositive + FalsePositive);
    public double? Recall => TruePositive + FalseNegative == 0 ? null : (double)TruePositive / (TruePositive + FalseNegative);
    public double? F1 => 2 * TruePositive + FalsePositive + FalseNegative == 0 ? null :
        2.0 * TruePositive / (2 * TruePositive + FalsePositive + FalseNegative);
}
public sealed record AccuracyReport(int SchemaVersion, string CorpusSha256, string? ModelSha256, bool NamesEnabled,
    int Cases, long Characters, double Seconds, AccuracyCounts Micro, IReadOnlyDictionary<string, AccuracyCounts> ByType)
{
    public string EngineVersion => typeof(AccuracyEvaluation).Assembly.GetName().Version?.ToString() ?? "unknown";
    public string Matching => "Exact type and UTF-16 start/length; duplicate spans counted once. Text detector evaluation only; excludes file extraction and OCR.";
    public string Interpretation => "Scores describe this labelled corpus only. Negative controls and representative independent labels are required. Model scores are not calibrated probabilities.";
}

public static class AccuracyEvaluation
{
    private static readonly HashSet<string> Types = new(PiiTypes.All, StringComparer.Ordinal);
    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public static AccuracyReport Run(string corpus, RuntimePaths paths, bool namesEnabled = true, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        // Hold the input open without write sharing on Windows during hashing and evaluation.
        using var input = File.OpenRead(corpus);
        string fingerprint = Hash(input, token); input.Position = 0;
        using var reader = new StreamReader(input, new UTF8Encoding(false, true), true);
        using var names = namesEnabled ? new NameDetector(paths) : null;
        string? modelHash = null;
        if (namesEnabled) { using var model = File.OpenRead(paths.Model); modelHash = Hash(model, token); }
        var patterns = new PatternDetector(); var totals = new SortedDictionary<string, AccuracyCounts>(StringComparer.Ordinal);
        int cases = 0, lineNumber = 0; long characters = 0;
        var watch = Stopwatch.StartNew();
        while (ReadLine(reader, token) is string line)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            EvaluationCase item;
            try { item = JsonSerializer.Deserialize<EvaluationCase>(line, Json) ?? throw new JsonException(); }
            catch (JsonException) { throw new InvalidDataException($"Invalid evaluation JSON at line {lineNumber}. No source text was logged."); }
            if (item.Text is null || item.Entities is null || item.Text.Length > 100_000 || item.Entities.Length > 10_000)
                throw new InvalidDataException($"Invalid or oversized evaluation case at line {lineNumber}.");
            foreach (var e in item.Entities)
                if (e is null || e.Type is null || !Types.Contains(e.Type) || e.Start < 0 || e.Length <= 0 ||
                    e.Start > item.Text.Length || e.Length > item.Text.Length - e.Start)
                    throw new InvalidDataException($"Invalid entity label or UTF-16 span at line {lineNumber}.");
            var expected = item.Entities.ToHashSet();
            if (expected.Count != item.Entities.Length) throw new InvalidDataException($"Duplicate gold entity at line {lineNumber}.");
            var predicted = patterns.Detect(item.Text, token).Where(s => namesEnabled || s.Type != "Person")
                .Select(s => new ExpectedEntity(s.Type, s.Start, s.Length)).ToHashSet();
            if (names is not null) predicted.UnionWith(names.Detect(item.Text, token).Select(s => new ExpectedEntity(s.Type, s.Start, s.Length)));
            foreach (string type in expected.Select(e => e.Type).Concat(predicted.Select(e => e.Type)).Distinct())
            {
                long tp = predicted.Count(e => e.Type == type && expected.Contains(e));
                long fp = predicted.Count(e => e.Type == type) - tp, fn = expected.Count(e => e.Type == type) - tp;
                var previous = totals.GetValueOrDefault(type, new(0, 0, 0));
                totals[type] = new(previous.TruePositive + tp, previous.FalsePositive + fp, previous.FalseNegative + fn);
            }
            cases++; characters += item.Text.Length;
        }
        if (cases == 0) throw new InvalidDataException("Evaluation corpus contains no cases.");
        return new(1, fingerprint, modelHash, namesEnabled, cases, characters, watch.Elapsed.TotalSeconds,
            new(totals.Values.Sum(c => c.TruePositive), totals.Values.Sum(c => c.FalsePositive), totals.Values.Sum(c => c.FalseNegative)), totals);
    }

    public static void Save(string path, AccuracyReport report, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        path = Path.GetFullPath(path);
        string temp = Path.Combine(Path.GetDirectoryName(path)!, ".pii-evaluation-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None)) JsonSerializer.Serialize(stream, report, Json);
            token.ThrowIfCancellationRequested();
            File.Move(temp, path, overwrite: false);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    private static string Hash(Stream stream, CancellationToken token)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[65536];
        try { int read; while ((read = stream.Read(buffer)) > 0) { token.ThrowIfCancellationRequested(); hash.AppendData(buffer.AsSpan(0, read)); } }
        finally { Array.Clear(buffer); }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static string? ReadLine(StreamReader reader, CancellationToken token)
    {
        var buffer = new StringBuilder();
        int value;
        while ((value = reader.Read()) >= 0)
        {
            if ((buffer.Length & 4095) == 0) token.ThrowIfCancellationRequested();
            if (value == '\n') return buffer.ToString().TrimEnd('\r');
            if (buffer.Length >= 512_000) throw new InvalidDataException("Evaluation record exceeds 512,000 characters.");
            buffer.Append((char)value);
        }
        return buffer.Length == 0 ? null : buffer.ToString().TrimEnd('\r');
    }
}
