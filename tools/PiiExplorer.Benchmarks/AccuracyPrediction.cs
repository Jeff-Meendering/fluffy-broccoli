using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PiiExplorer.Core;

// Deliberately consumes text-only inputs. Gold labels never enter a recognizer process.
internal static class AccuracyPrediction
{
    public static int Run(string[] args)
    {
        if (args.Length != 4) throw new ArgumentException("--accuracy-predict <assets> <inputs.jsonl> <new-predictions.jsonl>");
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler stop = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += stop;
        string output = Path.GetFullPath(args[3]), temp = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var paths = new RuntimePaths(args[1]);
            using var names = new NameDetector(paths);
            var patterns = new PatternDetector();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            using (var writer = new StreamWriter(new FileStream(temp, FileMode.CreateNew), new UTF8Encoding(false)))
            {
                foreach (string line in File.ReadLines(args[2]))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    var input = JsonSerializer.Deserialize<Input>(line) ?? throw new InvalidDataException("Invalid prediction input.");
                    if (string.IsNullOrEmpty(input.Id) || input.Text is null || input.Text.Length > 100_000 || !ids.Add(input.Id))
                        throw new InvalidDataException("Invalid or duplicate prediction input.");
                    var watch = Stopwatch.StartNew();
                    var spans = patterns.Detect(input.Text, cancellation.Token).Concat(names.Detect(input.Text, cancellation.Token))
                        .Select(s => new ExpectedEntity(s.Type, s.Start, s.Length)).Distinct().OrderBy(s => s.Start).ThenBy(s => s.Type).ToArray();
                    writer.WriteLine(JsonSerializer.Serialize(new { input.Id,
                        TextSha256 = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input.Text))),
                        Entities = spans, Seconds = watch.Elapsed.TotalSeconds }));
                }
            }
            if (ids.Count == 0) throw new InvalidDataException("Empty prediction input.");
            cancellation.Token.ThrowIfCancellationRequested();
            File.Move(temp, output, overwrite: false);
            Console.WriteLine(JsonSerializer.Serialize(new { Engine = "PiiExplorer", Version = typeof(PatternDetector).Assembly.GetName().Version?.ToString(),
                Runtime = Environment.Version.ToString(), Names = true, PhoneRegions = "US,GB", Cases = ids.Count,
                CoreSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(typeof(PatternDetector).Assembly.Location))),
                PredictorSha256 = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(typeof(AccuracyPrediction).Assembly.Location))),
                Assets = Directory.GetFiles(Path.GetDirectoryName(paths.Model)!).Order().ToDictionary(p => Path.GetFileName(p),
                    p => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(p)))) }));
            return 0;
        }
        finally { Console.CancelKeyPress -= stop; if (File.Exists(temp)) File.Delete(temp); }
    }
    private sealed record Input(string Id, string Text);
}
