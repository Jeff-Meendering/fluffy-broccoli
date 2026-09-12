namespace PiiExplorer.Core;

/// <summary>Caller-owned, thread-safe recognizer. Return UTF-16 spans within the supplied text,
/// nonempty entity types/methods and confidence in [0,1]. Observe cancellation during enumeration.
/// Entity types are open strings: custom types need no central registration.</summary>
public interface IRecognizer
{
    string Id { get; }
    IEnumerable<EntitySpan> Detect(string text, CancellationToken cancellationToken);
}

public sealed record ExtractionRequest(string FilePath, string ResourceName, string Source,
    string ResourceId, ScanOptions Options);

/// <summary>Caller-owned, thread-safe parser. The first registered matching parser takes precedence
/// over built-in routing, including for archive members. Emit provenance on every successful part,
/// using the request resource ID (or descendant IDs), and observe cancellation. Emit issues for
/// incomplete representations; completion markers are reserved for the scanner.</summary>
public interface IExtractor
{
    bool CanExtract(ExtractionRequest request);
    IAsyncEnumerable<ExtractedPart> ExtractAsync(ExtractionRequest request, CancellationToken cancellationToken);
}
