namespace PiiExplorer.Core;

public sealed record Finding(string FilePath, string Source, string Location, string Type,
    string Value, string Context, double Confidence, string Method)
{
    public string FileName => Path.GetFileName(FilePath);
    public string DisplaySource => string.IsNullOrEmpty(Source) ? FilePath : FilePath + " > " + Source.TrimStart('/');
    public string Score => Confidence.ToString("P0");
}

public sealed record ScanIssue(string FilePath, string Source, string Message)
{
    public string DisplaySource => string.IsNullOrEmpty(Source) ? FilePath : FilePath + " > " + Source.TrimStart('/');
}

/// <param name="Workers">Parallel file workers (1–8). Each may start its own document parser process.</param>
/// <param name="PhoneRegions">Comma-separated ISO regions for phone numbers written without a country code.</param>
public sealed record ScanOptions(bool Ocr = true, bool Names = true, int Workers = 2,
    long MaxFileBytes = 100L * 1024 * 1024, int FileTimeoutSeconds = 180, int MaxFindings = 500_000,
    int MaxIssues = 10_000, string PhoneRegions = "US,GB")
{
    public const int MaxWorkers = 8;
    /// <summary>A default worker count for this machine: parallel enough to use a workstation, small enough for a laptop.</summary>
    public static int DefaultWorkers => Math.Clamp(Environment.ProcessorCount / 4, 2, 4);
}

public sealed record ScanUpdate(string CurrentFile = "", int Discovered = 0, int Completed = 0,
    IReadOnlyList<Finding>? Findings = null, IReadOnlyList<ScanIssue>? Issues = null);

public sealed record ScanSummary(int Files, int Completed, int Findings, int Issues, TimeSpan Elapsed, bool Cancelled);
public sealed record EntitySpan(string Type, int Start, int Length, double Confidence, string Method);
public sealed record ExtractedPart(string Source, string Location, string Text, string ContentType, string? Issue = null);

public static class PiiTypes
{
    public static readonly string[] All = [
        "Person", "Email", "Phone", "Social Security number", "Payment card", "Street address", "Date of birth",
        "IP address", "MAC address", "UK National Insurance", "IBAN", "National ID", "Labelled identifier",
        "Credential", "Crypto wallet"];
}

public sealed class RuntimePaths
{
    public string Root { get; }
    public RuntimePaths(string? root = null) => Root = Path.GetFullPath(root ?? Path.Combine(AppContext.BaseDirectory, "assets"));
    public string Model => Path.Combine(Root, "models", "model_quantized.onnx");
    public string Vocab => Path.Combine(Root, "models", "vocab.txt");
    public string Worker => Path.Combine(Root, "worker");
    public string Java => Path.Combine(Root, "java", "bin", OperatingSystem.IsWindows() ? "java.exe" : "java");
    public string OcrDirectory => Path.Combine(Root, "ocr");
    public string OcrExecutable => Path.Combine(OcrDirectory, OperatingSystem.IsWindows() ? "tesseract.exe" : "tesseract");
    public IEnumerable<string> Missing(bool names, bool ocr)
    {
        foreach (var path in new[] { Java, Path.Combine(Worker, "tika-app.jar"), Path.Combine(Worker, "ExtractionWorker.class") })
            if (!File.Exists(path)) yield return path;
        if (names) foreach (var path in new[] { Model, Vocab }) if (!File.Exists(path)) yield return path;
        if (ocr && !File.Exists(OcrExecutable)) yield return OcrExecutable;
    }
}
