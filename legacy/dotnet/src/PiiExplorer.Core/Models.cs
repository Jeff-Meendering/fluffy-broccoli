namespace PiiExplorer.Core;

public sealed record Finding(string FilePath, string Source, string Location, string Type,
    string Value, string Context, double Confidence, string Method)
{
    public EvidenceLocation? Evidence { get; init; }
    public string FileName => Path.GetFileName(FilePath);
    public string DisplaySource => string.IsNullOrEmpty(Source) ? FilePath : FilePath + " > " + Source.TrimStart('/');
    public string Score => Confidence.ToString("P0");
    public string DisplayLocation => Evidence is null ? Location :
        $"{Location} · {Evidence.Origin.ResourceId} / {Evidence.Origin.StreamId} · {RepresentationLabel} · " +
        $"{(Evidence.Origin.Unit == OffsetUnit.Byte ? "byte" : "UTF-16")} offset {Evidence.Start}, length {Evidence.Length}";
    public string DisplayContext => Evidence?.Origin.Representation == TextRepresentation.SynthesizedText
        ? "[Synthesized context; may include generated labels, separators or name substitutions]\n" + Context : Context;
    private string RepresentationLabel => Evidence?.Origin.Representation switch
    {
        TextRepresentation.DecodedText => "decoded text",
        TextRepresentation.ExtractedText => "extracted text",
        TextRepresentation.SynthesizedText => "synthesized text",
        TextRepresentation.OcrText => "OCR text",
        TextRepresentation.BinaryText => "binary text",
        _ => "text"
    };
}

public enum EvidenceKind { Body, FileName, ArchiveMemberName, Metadata, Ocr, BinaryStrings }
public enum TextRepresentation { DecodedText, ExtractedText, SynthesizedText, OcrText, BinaryText }
public enum OffsetUnit { Utf16CodeUnit, Byte }

/// <summary>Identifies a text stream within a resource. Resource IDs use container entry ordinals,
/// not names or temporary paths. Start is zero based; offsets refer to this representation,
/// never to document bytes unless Unit is Byte. Stride maps binary text back to bytes.</summary>
public sealed record EvidenceOrigin(string ResourceId, string StreamId, EvidenceKind Kind,
    TextRepresentation Representation, long Start = 0, OffsetUnit Unit = OffsetUnit.Utf16CodeUnit, int Stride = 1);

/// <summary>An exact occurrence and its unmodified context within the identified stream.
/// DetectorStart/Length retain the UTF-16 span in the extraction chunk (before display trimming).</summary>
public sealed record EvidenceLocation(EvidenceOrigin Origin, long Start, long Length, long ContextStart,
    int DetectorStart, int DetectorLength);

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
public sealed record ExtractedPart(string Source, string Location, string Text, string ContentType, string? Issue = null)
{
    public EvidenceOrigin? Origin { get; init; }
}

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
