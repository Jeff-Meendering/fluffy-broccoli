using System.Diagnostics;
using System.Collections.Concurrent;
using System.Text.Json;
using PiiExplorer.Core;

if (args.FirstOrDefault() == "--accuracy-predict") return AccuracyPrediction.Run(args);

if (args.Length < 2) {
    Console.Error.WriteLine("Usage: PiiExplorer.Benchmarks <project root> <output.json> [repetitions=3] [--mixed-only] [--capture-fixture-findings]");
    return 1;
}
string root = Path.GetFullPath(args[0]);
int repetitions = args.Length > 2 ? int.Parse(args[2]) : 3;
if (repetitions is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(repetitions));
string temp = Path.Combine(Path.GetTempPath(), "PiiExplorerBenchmarks", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var samples = new List<object>();
try {
    string small = Directory.CreateDirectory(Path.Combine(temp, "small-text")).FullName;
    for (int i = 0; i < 2000; i++)
        File.WriteAllText(Path.Combine(small, $"record-{i:D5}.txt"), $"Contact: synthetic{i:D6}@example.com\n");
    string large = Directory.CreateDirectory(Path.Combine(temp, "large-text")).FullName;
    using (var writer = File.CreateText(Path.Combine(large, "contacts.txt")))
        for (int i = 0; i < 200_000; i++) writer.WriteLine($"Contact: synthetic{i:D6}@example.com");
    string sheet = Directory.CreateDirectory(Path.Combine(temp, "spreadsheet")).FullName;
    File.Copy(Path.Combine(root, "tests", "fixtures", "staff-register.xlsx"), Path.Combine(sheet, "register.xlsx"));
    var cases = new[] {
        (Name: "2000 small text files, patterns", Path: small, Options: new ScanOptions(Ocr: false, Names: false)),
        (Name: "200000 emails, patterns", Path: large, Options: new ScanOptions(Ocr: false, Names: false)),
        (Name: "25000 spreadsheet rows, names on", Path: sheet, Options: new ScanOptions(Ocr: false)),
        (Name: "mixed corpus, OCR and names on", Path: Path.Combine(root, "tests", "fixtures", "corpus"), Options: new ScanOptions())
    };
    foreach (var item in cases) {
        if (args.Contains("--mixed-only") && !item.Name.StartsWith("mixed")) continue;
        long bytes = Directory.EnumerateFiles(item.Path, "*", SearchOption.AllDirectories).Sum(p => new FileInfo(p).Length);
        for (int iteration = 1; iteration <= repetitions; iteration++) {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            long allocated = GC.GetTotalAllocatedBytes(true), firstTicks = -1;
            int published = 0;
            var captured = args.Contains("--capture-fixture-findings") && item.Name.StartsWith("mixed") ? new ConcurrentBag<Finding>() : null;
            var watch = Stopwatch.StartNew();
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var summary = await new ScanEngine(new(Path.Combine(root, "assets"))).ScanAsync(item.Path, item.Options,
                new Callback(update => {
                    if (update.Findings is not { Count: > 0 } findings) return;
                    Interlocked.Add(ref published, findings.Count);
                    if (captured is not null) foreach (var finding in findings) captured.Add(finding);
                    Interlocked.CompareExchange(ref firstTicks, watch.ElapsedTicks, -1);
                }), deadline.Token);
            if (summary.Cancelled || summary.Findings != published) throw new InvalidOperationException("Incomplete benchmark scan");
            var sample = new {
                workload = item.Name, iteration, bytes, summary.Files, summary.Completed, summary.Findings, summary.Issues,
                seconds = summary.Elapsed.TotalSeconds,
                firstFindingSeconds = firstTicks < 0 ? (double?)null : firstTicks / (double)Stopwatch.Frequency,
                managedAllocatedBytes = GC.GetTotalAllocatedBytes(true) - allocated
            };
            samples.Add(sample);
            Console.WriteLine(JsonSerializer.Serialize(sample));
            if (captured is not null) File.WriteAllText(Path.GetFullPath(args[1]) + $".{iteration}.findings.json",
                JsonSerializer.Serialize(captured.OrderBy(f => f.DisplaySource).ThenBy(f => f.Type).ThenBy(f => f.Value)));
        }
    }
    File.WriteAllText(Path.GetFullPath(args[1]), JsonSerializer.Serialize(new {
        createdUtc = DateTimeOffset.UtcNow, runtime = Environment.Version.ToString(),
        os = Environment.OSVersion.ToString(), logicalProcessors = Environment.ProcessorCount,
        note = "Fresh scanner per repetition; OS file cache may be warm. Allocations cover .NET only, not Java/OCR/native memory. UI and PDF export are excluded. Synthetic data only. Optional --capture-fixture-findings writes detailed mixed-fixture results for diagnosing repeatability and adds capture overhead.",
        samples
    }, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
} finally { Directory.Delete(temp, true); }

sealed class Callback(Action<ScanUpdate> report) : IProgress<ScanUpdate>
{
    public void Report(ScanUpdate value) => report(value);
}
