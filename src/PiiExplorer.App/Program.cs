using Avalonia;
using PiiExplorer.Core;
using System.Text.Json;

namespace PiiExplorer.App;

internal static class Program
{
    public static string? AssetsOverride { get; private set; }
    [STAThread]
    public static int Main(string[] args)
    {
        int index = Array.IndexOf(args, "--assets");
        if (index >= 0 && index + 1 < args.Length) AssetsOverride = Path.GetFullPath(args[index + 1]);
        if (args.Contains("--evaluate")) return Evaluate(args);
        if (args.Contains("--scan-test")) return ScanTest(args).GetAwaiter().GetResult();
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args); return 0;
    }
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().LogToTrace();
    private static int Evaluate(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler stop = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += stop;
        try
        {
            int index = Array.IndexOf(args, "--evaluate");
            if (index + 2 >= args.Length) throw new ArgumentException("Usage: PiiExplorer --evaluate <corpus.jsonl> <new-report.json> [--no-names] [--assets <folder>]");
            var report = AccuracyEvaluation.Run(args[index + 1], new(AssetsOverride), !args.Contains("--no-names"), cancellation.Token);
            AccuracyEvaluation.Save(args[index + 2], report, cancellation.Token);
            Console.WriteLine(JsonSerializer.Serialize(report)); return 0;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Evaluation stopped."); return 2; }
        catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
        finally { Console.CancelKeyPress -= stop; }
    }
    private static async Task<int> ScanTest(string[] args)
    {
        try {
            string folder = args[Array.IndexOf(args, "--scan-test") + 1];
            var updates = new InlineProgress<ScanUpdate>(update => {
                if (update.Findings is not null) foreach (var finding in update.Findings) Console.WriteLine(JsonSerializer.Serialize(new { kind = "finding", finding }));
                if (update.Issues is not null) foreach (var issue in update.Issues) Console.WriteLine(JsonSerializer.Serialize(new { kind = "issue", issue }));
            });
            var result = await new ScanEngine(new(AssetsOverride)).ScanAsync(folder,
                new(Ocr: !args.Contains("--no-ocr"), Names: !args.Contains("--no-names")), updates, CancellationToken.None);
            Console.WriteLine(JsonSerializer.Serialize(new { kind = "summary", result }));
            return result.StopReason != ScanStopReason.None ? 2 : result.Status == CoverageStatus.Failed ? 4 : result.Status == CoverageStatus.Partial ? 3 : 0;
        } catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}

public sealed class InlineProgress<T>(Action<T> action) : IProgress<T> { public void Report(T value) => action(value); }
