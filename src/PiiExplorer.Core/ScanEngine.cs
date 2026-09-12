using System.Collections.Concurrent;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using SharpCompress.Archives;
using SharpCompress.Readers;

namespace PiiExplorer.Core;

public sealed class ScanEngine(RuntimePaths paths)
{
    // Native text reading keeps attribute values, link targets and code that document
    // parsers strip, and avoids the parser round trip on large machine-generated files.
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase) {
        ".txt", ".md", ".markdown", ".csv", ".tsv", ".log", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".sql", ".cs", ".py", ".js", ".ts", ".env",
        ".json", ".jsonl", ".ndjson", ".xml", ".svg", ".toml", ".properties", ".sh", ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
        ".java", ".go", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".rs", ".kt", ".swift", ".scala", ".pl", ".lua", ".r", ".vbs", ".jsx", ".tsx", ".vue",
        ".css", ".scss", ".less", ".vcf", ".ics", ".reg", ".inf", ".diff", ".patch", ".tex", ".rst", ".adoc", ".config", ".xaml", ".plist", ".csproj",
        ".props", ".targets", ".gradle", ".tf", ".hcl", ".srt", ".vtt" };
    // HTML is parsed for table semantics and readable text, then also read raw so that
    // mailto: links, data attributes and hidden fields are checked. Each representation has its own offsets.
    private static readonly HashSet<string> MarkupExtensions = new(StringComparer.OrdinalIgnoreCase) { ".html", ".htm", ".xhtml" };
    private static readonly HashSet<string> Archives = new(StringComparer.OrdinalIgnoreCase) {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".jar" };
    private static readonly HashSet<string> Excluded = new(StringComparer.OrdinalIgnoreCase) {
        ".git", ".venv", "venv", "node_modules", "__pycache__", "$RECYCLE.BIN", "System Volume Information" };
    private sealed class ArchiveBudget { public long Bytes; public int Members; public bool Exhausted; }

    public async Task<ScanSummary> ScanAsync(string root, ScanOptions options, IProgress<ScanUpdate> progress, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(progress);
        if (options.Workers <= 0) throw new ArgumentOutOfRangeException(nameof(options.Workers));
        if (options.MaxFileBytes <= 0) throw new ArgumentOutOfRangeException(nameof(options.MaxFileBytes));
        if (options.MaxFindings <= 0) throw new ArgumentOutOfRangeException(nameof(options.MaxFindings));
        if (options.MaxIssues <= 0) throw new ArgumentOutOfRangeException(nameof(options.MaxIssues));
        if (options.FileTimeoutSeconds <= 0 || options.FileTimeoutSeconds > uint.MaxValue / 1000)
            throw new ArgumentOutOfRangeException(nameof(options.FileTimeoutSeconds));
        root = Path.GetFullPath(root);
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        string[] missing = paths.Missing(options.Names, options.Ocr).ToArray();
        if (missing.Length > 0) throw new InvalidOperationException("The application package is incomplete. Missing: " + string.Join(", ", missing.Select(Path.GetFileName)));
        var watch = Stopwatch.StartNew();
        var coverage = new ConcurrentDictionary<string, ConcurrentDictionary<string, CoverageEntry>>();
        int stopReason = 0;
        CoverageEntry Entry(string file, string resource = "root", string source = "") => coverage.GetOrAdd(file, _ => new()).GetOrAdd(resource, _ => new(file, source, resource));
        int completed = 0, count = 0, issueCount = 0, discovered = 0;
        using var limitCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var cancellation = limitCancellation.Token;
        var files = Channel.CreateBounded<string>(new BoundedChannelOptions(256)
        {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
        void Issue(string file, string source, string message, CoverageReason reason = CoverageReason.ExtractionFailure, string resourceId = "root")
        {
            Entry(file, resourceId, source).Add(reason);
            if (resourceId != "root") {
                Entry(file).Add(CoverageReason.ChildIncomplete);
                int slash = resourceId.LastIndexOf('/');
                while (slash > 0) {
                    Entry(file, resourceId[..slash]).Add(CoverageReason.ChildIncomplete);
                    slash = resourceId.LastIndexOf('/', slash - 1);
                }
            }
            int reserved;
            do { reserved = Volatile.Read(ref issueCount); }
            while (reserved < options.MaxIssues && Interlocked.CompareExchange(ref issueCount, reserved + 1, reserved) != reserved);
            if (reserved >= options.MaxIssues) return;
            if (reserved == options.MaxIssues - 1)
            {
                message = "Attention item limit reached; scan stopped with remaining content unchecked. Scan smaller folders. Last issue: " + message;
                Interlocked.CompareExchange(ref stopReason, (int)ScanStopReason.IssueLimit, 0);
                limitCancellation.Cancel();
            }
            progress.Report(new(Issues: [new(file, source, message) { Reason = reason, ResourceId = resourceId }]));
        }
        int workerCount = Math.Clamp(options.Workers, 1, ScanOptions.MaxWorkers);
        // One inference session serves every worker; give it the cores the workers leave idle.
        int inferenceThreads = Math.Clamp(Environment.ProcessorCount / workerCount, 1, 4);
        using var names = options.Names ? await Task.Run(() => new NameDetector(paths, inferenceThreads), cancellation) : null;
        var discovery = Task.Run(async () =>
        {
            try
            {
                var pending = new Stack<string>(); pending.Push(Path.GetFullPath(root));
                while (pending.Count > 0)
                {
                    cancellation.ThrowIfCancellationRequested(); string folder = pending.Pop();
                    try
                    {
                        foreach (var entry in new DirectoryInfo(folder).EnumerateFileSystemInfos())
                        {
                            cancellation.ThrowIfCancellationRequested();
                            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) { Issue(entry.FullName, "", "Link not followed", CoverageReason.Excluded); continue; }
                            if (entry is DirectoryInfo)
                            {
                                if (Excluded.Contains(entry.Name)) Issue(entry.FullName, "", "Dependency or system folder excluded", CoverageReason.Excluded);
                                else pending.Push(entry.FullName);
                            }
                            else
                            {
                                Entry(entry.FullName);
                                Interlocked.Increment(ref discovered);
                                await files.Writer.WriteAsync(entry.FullName, cancellation);
                                if (discovered % 128 == 0) progress.Report(new(Discovered: Volatile.Read(ref discovered)));
                            }
                        }
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Issue(folder, "", "Cannot list folder: " + e.Message, CoverageReason.DiscoveryFailure); }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception) { limitCancellation.Cancel(); throw; }
            finally
            {
                files.Writer.TryComplete();
                progress.Report(new(Discovered: Volatile.Read(ref discovered)));
            }
        }, CancellationToken.None);
        var patterns = new PatternDetector(options.PhoneRegions);
        int findingLimitReported = 0;
        var workers = Enumerable.Range(0, workerCount).Select(_ => Task.Run(async () =>
        {
            using var extractor = new ExtractionClient(paths);
            try
            {
                await foreach (string file in files.Reader.ReadAllAsync(cancellation))
                {
                    if (cancellation.IsCancellationRequested) break;
                    progress.Report(new(file, Volatile.Read(ref discovered), Volatile.Read(ref completed)));
                    // A file and all its nested members are owned by one worker. Release its
                    // deduplication state immediately instead of retaining it for the whole scan.
                    var seen = new HashSet<(string Resource, string Stream, string Type, long Start, long Length)>();
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                    deadline.CancelAfter(TimeSpan.FromSeconds(options.FileTimeoutSeconds));
                    var ct = deadline.Token;
                    FileInfo? initialFile = null;
                    long initialLength = 0; DateTime initialWrite = default;
                    try
                    {
                        initialFile = new FileInfo(file);
                        initialLength = initialFile.Length; initialWrite = initialFile.LastWriteTimeUtc;
                        Detect(new("", "file / folder name", Path.GetRelativePath(root, file).Replace('_', ' '), "text/plain") { Origin = new("root", "name", EvidenceKind.FileName, TextRepresentation.SynthesizedText) });
                        if (initialLength > options.MaxFileBytes) { Issue(file, "", $"File exceeds {options.MaxFileBytes / 1024 / 1024} MiB limit", CoverageReason.FileSizeLimit); continue; }
                        await foreach (var part in ExtractAsync(file, "", options, extractor, new(), 0, ct))
                        {
                            ct.ThrowIfCancellationRequested();
                            string resource = part.Origin?.ResourceId ?? "root";
                            Entry(file, resource, part.Source);
                            if (part.CoverageComplete) { Entry(file, resource, part.Source).Finished = true; continue; }
                            if (part.Issue is not null) Issue(file, part.Source, part.Issue, part.Reason, resource);
                            else { Detect(part); if (part.Origin?.Kind is not (EvidenceKind.FileName or EvidenceKind.ArchiveMemberName)) Entry(file, resource, part.Source).Read = true; }
                        }
                        void Detect(ExtractedPart part)
                        {
                            ct.ThrowIfCancellationRequested();
                            // Publish patterns before potentially slow model inference. A timeout
                            // or regex failure must not discard findings already detected.
                            Publish(patterns.Detect(part.Text, ct).Where(s => options.Names || s.Type != "Person"));
                            ct.ThrowIfCancellationRequested();
                            if (names is not null && NamesPlausible(part.Location)) Publish(names.Detect(part.Text, ct));

                            void Publish(IEnumerable<EntitySpan> spans)
                            {
                                var batch = new List<Finding>();
                                var origin = part.Origin ?? throw new InvalidDataException("Extraction part has no evidence origin");
                                try
                                {
                                    foreach (var span in spans)
                                    {
                                        if (ct.IsCancellationRequested) break; // Publish already reserved findings before stopping.
                                        string value = part.Text.Substring(span.Start, span.Length).Trim();
                                        // Only the same span in the same representation is a duplicate.
                                        long start = origin.Start + (long)span.Start * origin.Stride;
                                        long length = (long)span.Length * origin.Stride;
                                        if (string.IsNullOrWhiteSpace(value) || !seen.Add((origin.ResourceId, origin.StreamId, span.Type, start, length))) continue;
                                        int reserved;
                                        do { reserved = Volatile.Read(ref count); }
                                        while (reserved < options.MaxFindings && Interlocked.CompareExchange(ref count, reserved + 1, reserved) != reserved);
                                        if (reserved >= options.MaxFindings)
                                        {
                                            if (Interlocked.Exchange(ref findingLimitReported, 1) == 0)
                                                Issue(file, part.Source, "Finding limit reached. Scan a smaller folder to see remaining content.", CoverageReason.FindingLimit, origin.ResourceId);
                                            Interlocked.CompareExchange(ref stopReason, (int)ScanStopReason.FindingLimit, 0);
                                            limitCancellation.Cancel(); break;
                                        }
                                        int lo = Math.Max(0, span.Start - 80), hi = Math.Min(part.Text.Length, span.Start + span.Length + 100);
                                        string context = part.Text[lo..hi];
                                        batch.Add(new(file, part.Source, part.Location, span.Type, value, context, span.Confidence, span.Method)
                                        {
                                            Evidence = new(origin, start, length, origin.Start + (long)lo * origin.Stride, span.Start, span.Length)
                                        });
                                        if (batch.Count == 256) { progress.Report(new(Findings: batch)); batch = []; }
                                    }
                                }
                                finally { if (batch.Count > 0) progress.Report(new(Findings: batch)); }
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        extractor.Stop(); if (!cancellation.IsCancellationRequested) Issue(file, "", $"File timeout after {options.FileTimeoutSeconds} seconds; remaining content unchecked", CoverageReason.Timeout);
                    }
                    catch (Exception e)
                    {
                        extractor.Stop(); Issue(file, "", "Could not fully check file: " + e.GetType().Name + ": " + e.Message);
                    }
                    finally
                    {
                        if (initialFile is not null)
                        {
                            try
                            {
                                initialFile.Refresh();
                                if (!initialFile.Exists || initialFile.Length != initialLength || initialFile.LastWriteTimeUtc != initialWrite)
                                    Issue(file, "", "Source changed during scanning; findings may not describe one consistent version. Rescan a stable copy.", CoverageReason.SourceChanged);
                            }
                            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                            { Issue(file, "", "Could not verify source stability after scanning.", CoverageReason.SourceChanged); }
                        }
                        foreach (var item in coverage[file].Values)
                        {
                            if (!item.Finished && cancellation.IsCancellationRequested) item.Add(token.IsCancellationRequested ? CoverageReason.UserCancellation :
                                (ScanStopReason)stopReason == ScanStopReason.FindingLimit ? CoverageReason.FindingLimit : CoverageReason.IssueLimit);
                            if (!item.Finished && Entry(file).Reasons.Contains(CoverageReason.Timeout)) item.Add(CoverageReason.Timeout);
                            item.Finished = true;
                        }
                        Interlocked.Increment(ref completed); progress.Report(new(file, Volatile.Read(ref discovered), Volatile.Read(ref completed)));
                    }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception) { limitCancellation.Cancel(); throw; }
        }, CancellationToken.None)).ToArray();
        await Task.WhenAll(workers.Append(discovery));
        var stop = token.IsCancellationRequested ? ScanStopReason.UserCancellation : (ScanStopReason)stopReason;
        foreach (var item in coverage.Values.SelectMany(e => e.Values).Where(e => !e.Finished && e.Reasons.Count == 0))
            item.Add(stop == ScanStopReason.UserCancellation ? CoverageReason.UserCancellation :
                stop == ScanStopReason.FindingLimit ? CoverageReason.FindingLimit : CoverageReason.IssueLimit);
        var outcomes = coverage.Values.SelectMany(e => e.Values).Select(e => e.Outcome()).OrderBy(e => e.FilePath, StringComparer.Ordinal)
            .ThenBy(e => e.ResourceId, StringComparer.Ordinal).ToArray();
        foreach (var outcome in outcomes) progress.Report(new(Outcomes: [outcome]));
        return new(discovered, completed, Math.Min(count, options.MaxFindings), issueCount, watch.Elapsed, token.IsCancellationRequested)
        { Outcomes = outcomes, StopReason = stop, Configuration = new(options.Ocr, options.Names, true, options.PhoneRegions) };
    }

    private async IAsyncEnumerable<ExtractedPart> ExtractAsync(string file, string source, ScanOptions options,
        ExtractionClient extractor, ArchiveBudget budget, int depth, [EnumeratorCancellation] CancellationToken token, string? resourceName = null, string resourceId = "root")
    {
        // Catch at the member boundary so a corrupt nested document cannot hide its siblings.
        await using var parts = ExtractCoreAsync(file, source, options, extractor, budget, depth, token,
            resourceName ?? Path.GetFileName(file), resourceId).GetAsyncEnumerator(token);
        while (true)
        {
            ExtractedPart? failed = null; bool moved = false;
            try { token.ThrowIfCancellationRequested(); moved = await parts.MoveNextAsync(); }
            catch (Exception e) when (e is not OperationCanceledException && !token.IsCancellationRequested)
            {
                extractor.Stop();
                failed = new(source, "", "", "", "Could not fully check file: " + e.GetType().Name + ": " + e.Message);
            }
            if (failed is not null) { yield return failed with { Origin = new(resourceId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) }; yield break; }
            if (!moved) {
                yield return new(source, "", "", "") { CoverageComplete = true,
                    Origin = new(resourceId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                break;
            }
            var current = parts.Current;
            if (current.Issue is null && current.Origin is null)
                throw new InvalidDataException("Extraction part has no evidence origin");
            yield return current.Origin is null ? current with { Origin = new(resourceId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) } : current;
        }
    }

    private async IAsyncEnumerable<ExtractedPart> ExtractCoreAsync(string file, string source, ScanOptions options,
        ExtractionClient extractor, ArchiveBudget budget, int depth, [EnumeratorCancellation] CancellationToken token, string resourceName, string resourceId)
    {
        token.ThrowIfCancellationRequested();
        string ext = await ArchiveExtensionAsync(file, token) ?? Path.GetExtension(resourceName);
        if (Archives.Contains(ext))
        {
            if (depth >= 4) { yield return new(source, "", "", "", "Archive nesting limit reached") { Reason = CoverageReason.ArchiveDepthLimit }; yield break; }
            string temp = Directory.CreateTempSubdirectory("PiiExplorer-").FullName;
            try
            {
                // Sequential extraction avoids repeatedly decoding solid 7z blocks. Own the input
                // stream explicitly: a failed factory probe must not leak a staged file handle.
                await using var input = File.OpenRead(file);
                await using var archive = new[] { ".7z", ".zip", ".jar", ".rar" }.Contains(ext.ToLowerInvariant())
                    ? await ArchiveFactory.OpenAsyncArchive(input, cancellationToken: token) : null;
                int memberOrdinal = 0;
                if (archive is not null && !await archive.IsSolidAsync())
                {
                    // Independent ZIP/non-solid RAR entries can recover from corrupt or encrypted
                    // payloads without decompressing them just to reach the next member.
                    await foreach (var entry in archive.EntriesAsync.WithCancellation(token))
                    {
                        token.ThrowIfCancellationRequested();
                        if (budget.Exhausted) yield break;
                        string key = string.IsNullOrEmpty(entry.Key) ? "member" : entry.Key;
                        string memberSource = JoinSource(source, key);
                        string memberId = resourceId + "/archive:" + ++memberOrdinal;
                        if (++budget.Members > 2000)
                        {
                            budget.Exhausted = true;
                            yield return new(memberSource, "", "", "", "Archive member count limit reached; remaining archive content unchecked") { Reason = CoverageReason.ArchiveMemberLimit, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                            yield break;
                        }
                        if (entry.IsDirectory) continue;
                        yield return new(memberSource, "archive member name", key.Replace('_', ' '), "text/plain")
                        { Origin = new(memberId, "name", EvidenceKind.ArchiveMemberName, TextRepresentation.SynthesizedText) };
                        if (entry.IsEncrypted || !string.IsNullOrEmpty(entry.LinkTarget))
                        {
                            yield return new(memberSource, "", "", "", entry.IsEncrypted ? "Password-protected archive member" : "Archive link not followed") { Reason = entry.IsEncrypted ? CoverageReason.Encrypted : CoverageReason.Excluded, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                            continue;
                        }
                        string? target = null; string? error = null;
                        try
                        {
                            await using var data = await entry.OpenEntryStreamAsync(token);
                            target = await StageAsync(data, temp, key, budget, options.MaxFileBytes, token);
                        }
                        catch (Exception e) when (e is not OperationCanceledException && !token.IsCancellationRequested)
                        {
                            error = e.Message + (budget.Exhausted ? "; remaining archive content unchecked" : "; member unchecked");
                        }
                        if (error is not null) { yield return new(memberSource, "", "", "", error) { Reason = budget.Exhausted ? CoverageReason.ArchiveSizeLimit : CoverageReason.ExtractionFailure, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) }; continue; }
                        try
                        {
                            await foreach (var part in ExtractAsync(target!, memberSource, options, extractor, budget, depth + 1, token, key, memberId)) yield return part;
                        }
                        finally { File.Delete(target!); }
                    }
                    yield break;
                }
                await using var reader = archive is null
                    ? await ReaderFactory.OpenAsyncReader(input, cancellationToken: token)
                    : await archive.ExtractAllEntriesAsync();
                using var registration = token.Register(reader.Cancel);
                while (!budget.Exhausted && await reader.MoveToNextEntryAsync(token))
                {
                    token.ThrowIfCancellationRequested();
                    string key = string.IsNullOrEmpty(reader.Entry.Key) ? Path.GetFileNameWithoutExtension(resourceName) : reader.Entry.Key;
                    if (string.IsNullOrEmpty(key)) key = "member";
                    string memberSource = JoinSource(source, key);
                    string memberId = resourceId + "/archive:" + ++memberOrdinal;
                    if (++budget.Members > 2000)
                    {
                        budget.Exhausted = true;
                        reader.Cancel();
                        yield return new(memberSource, "", "", "", "Archive member count limit reached; remaining archive content unchecked") { Reason = CoverageReason.ArchiveMemberLimit, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                        yield break;
                    }
                    if (reader.Entry.IsDirectory) continue;
                    yield return new(memberSource, "archive member name", key.Replace('_', ' '), "text/plain")
                        { Origin = new(memberId, "name", EvidenceKind.ArchiveMemberName, TextRepresentation.SynthesizedText) };
                    // Forward/solid readers cannot safely skip an encrypted or oversized stream.
                    if (reader.Entry.IsEncrypted || !string.IsNullOrEmpty(reader.Entry.LinkTarget))
                    {
                        reader.Cancel();
                        yield return new(memberSource, "", "", "", reader.Entry.IsEncrypted
                            ? "Password-protected archive member; remaining archive content unchecked"
                            : "Archive link not followed; remaining archive content unchecked") { Reason = reader.Entry.IsEncrypted ? CoverageReason.Encrypted : CoverageReason.Excluded, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                        yield break;
                    }
                    string? target = null; string? error = null;
                    try
                    {
                        await using var data = await reader.OpenEntryStreamAsync(token);
                        try { target = await StageAsync(data, temp, key, budget, options.MaxFileBytes, token); }
                        catch { reader.Cancel(); throw; } // Prevent EntryStream.Dispose from draining a bomb.
                    }
                    catch (Exception e) when (e is not OperationCanceledException && !token.IsCancellationRequested)
                    {
                        reader.Cancel(); error = e.Message + "; remaining archive content unchecked";
                    }
                    if (error is not null) { yield return new(memberSource, "", "", "", error) { Reason = budget.Exhausted ? CoverageReason.ArchiveSizeLimit : CoverageReason.ExtractionFailure, Origin = new(memberId, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) }; yield break; }
                    try
                    {
                        await foreach (var part in ExtractAsync(target!, memberSource, options, extractor, budget, depth + 1, token, key, memberId)) yield return part;
                    }
                    finally { File.Delete(target!); }
                }
            }
            finally { Directory.Delete(temp, recursive: true); }
        }
        else if (options.Ocr && new[] { ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif" }.Contains(ext.ToLowerInvariant()))
        {
            ExtractedPart[] imageParts;
            try { imageParts = await ImageReader.ReadAsync(file, source, paths, token); }
            catch (Exception e) when (e is not OperationCanceledException && !token.IsCancellationRequested)
            {
                imageParts = [new(source, "", "", "", "Image OCR incomplete: " + e.Message) { Reason = CoverageReason.OcrIncomplete }];
            }
            foreach (var part in imageParts) yield return WithSource(part with { Source = "" });
            await foreach (var part in extractor.ReadAsync(file, false, token, resourceName))
                if ((part.Issue is null && part.Location.StartsWith("metadata:")) || (part.Issue is not null &&
                    part.Reason != CoverageReason.OcrDisabled && part.Reason != CoverageReason.NoReadableText))
                    yield return WithSource(part);
        }
        else if ((ext.Equals(".csv", StringComparison.OrdinalIgnoreCase) || ext.Equals(".tsv", StringComparison.OrdinalIgnoreCase)) && await IsUnicodeTextAsync(file, token))
        {
            using var csv = new Microsoft.VisualBasic.FileIO.TextFieldParser(file, Encoding.UTF8, true) { HasFieldsEnclosedInQuotes = true };
            bool tsv = ext.Equals(".tsv", StringComparison.OrdinalIgnoreCase);
            csv.SetDelimiters(tsv ? "\t" : ",");
            string tableType = tsv ? "text/tab-separated-values" : "text/csv", tableName = tsv ? "TSV" : "CSV";
            string[] headers = csv.ReadFields() ?? [];
            string[] labels = headers.Select(TableContext.Label).ToArray();
            bool hasName = labels.Contains("Full name: ");
            var buffer = new StringBuilder(string.Join(" | ", headers) + "\n"); int row = 1, startRow = 1; long tableOffset = 0;
            while (!csv.EndOfData)
            {
                token.ThrowIfCancellationRequested();
                string[] fields = []; string? error = null;
                try { fields = csv.ReadFields() ?? []; }
                catch (Microsoft.VisualBasic.FileIO.MalformedLineException)
                {
                    error = $"Malformed {tableName} record at line {csv.ErrorLineNumber}; remaining content unchecked";
                }
                if (error is not null)
                {
                    if (buffer.Length > 0) yield return TablePart();
                    yield return new(source, "", "", "", error);
                    yield break;
                }
                row++;
                if (hasName) buffer.Append("[Table] ");
                for (int i = 0; i < fields.Length; i++)
                {
                    if (i < labels.Length) buffer.Append(labels[i]);
                    buffer.Append(fields[i].Replace('\n', ' ').Replace('\r', ' ')).Append(" | ");
                }
                buffer.AppendLine();
                if (buffer.Length >= 24000) { yield return TablePart(); tableOffset += buffer.Length; buffer.Clear(); startRow = row + 1; }
            }
            if (buffer.Length > 0) yield return TablePart();
            ExtractedPart TablePart() => new(source, $"{tableName} rows {startRow}-{row}", buffer.ToString(), tableType)
            { Origin = new(resourceId, "table", EvidenceKind.Body, TextRepresentation.SynthesizedText, tableOffset) };
        }
        else if ((TextExtensions.Contains(ext) || MarkupExtensions.Contains(ext)) && await IsUnicodeTextAsync(file, token))
        {
            if (MarkupExtensions.Contains(ext))
                await foreach (var part in extractor.ReadAsync(file, options.Ocr, token, resourceName))
                    yield return WithSource(part);
            using var reader = new StreamReader(file, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true);
            var buffer = ArrayPool<char>.Shared.Rent(24000);
            try
            {
                string overlap = "", pending = ""; long offset = 0;
                while (true)
                {
                    int read = await reader.ReadAsync(buffer.AsMemory(0, 24000), token);
                    pending += new string(buffer, 0, read);
                    if (pending.Length == 0) break;
                    int end = pending.Length;
                    if (read > 0)
                    {
                        while (end > 0 && !char.IsWhiteSpace(pending[end - 1])) end--;
                        if (end == 0 && pending.Length < 48000) continue;
                        if (end == 0) end = 24000;
                    }
                    string text = overlap + pending[..end];
                    yield return new(source, "text · character " + Math.Max(0, offset - overlap.Length), text, "text/plain")
                    { Origin = new(resourceId, "decoded-text", EvidenceKind.Body, TextRepresentation.DecodedText, Math.Max(0, offset - overlap.Length)) };
                    int start = Math.Max(0, text.Length - 256);
                    while (start > Math.Max(0, text.Length - 512) && !char.IsWhiteSpace(text[start - 1])) start--;
                    overlap = text[start..]; offset += end; pending = pending[end..];
                    if (read == 0) break;
                }
            }
            finally { ArrayPool<char>.Shared.Return(buffer, clearArray: true); }
        }
        else
        {
            bool unsupported = false;
            await foreach (var part in extractor.ReadAsync(file, options.Ocr, token, resourceName))
            {
                if (part.Issue is not null && part.Source.Length == 0 && part.Reason == CoverageReason.Unsupported)
                { unsupported = true; continue; }
                yield return WithSource(part);
            }
            // No parser understands this format: fall back to printable strings so captures,
            // dumps, databases and unknown binaries still surface embedded identifiers.
            if (unsupported)
            {
                yield return new(source, "", "", "", "Unrecognized format; only readable ASCII/UTF-16 strings were checked, so structured, compressed or encrypted content may hide PII") { Reason = CoverageReason.Unsupported };
                await foreach (var part in BinaryStrings.ReadAsync(file, "", 16_000_000, token)) yield return WithSource(part);
            }
        }
        ExtractedPart WithSource(ExtractedPart part) => part with
        {
            Source = JoinSource(source, part.Source),
            Origin = part.Origin is { } origin ? origin with
            { ResourceId = resourceId + (origin.ResourceId.Length == 0 ? "" : "/" + origin.ResourceId) } : null
        };
    }

    // Technical metadata (colour profiles, resource types, encodings) never names a person,
    // but the model reads single capitalized values there as names. Author-like keys keep
    // model inference; patterns still run on every field.
    private static readonly Regex PersonMetadataKey = new(@"(?i)creator|author|from|to\b|cc|owner|modif|artist|contributor|publisher|title|subject|comment|description|keyword|name|sender|recipient|initial|manager|company|organi|user",
        RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
    internal static bool NamesPlausible(string location) =>
        !location.StartsWith("metadata:", StringComparison.Ordinal) || PersonMetadataKey.IsMatch(location.AsSpan(9));

    private static string JoinSource(string parent, string child) => string.IsNullOrEmpty(parent) ? child :
        string.IsNullOrEmpty(child) ? parent : parent + " > " + child.TrimStart('/');

    private static async Task<string?> ArchiveExtensionAsync(string file, CancellationToken token)
    {
        using var input = File.OpenRead(file);
        byte[] header = new byte[512];
        int read = await input.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken: token);
        if (read >= 6 && header.AsSpan(0, 6).SequenceEqual(new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c })) return ".7z";
        if (read >= 7 && header.AsSpan(0, 7).SequenceEqual(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, header[6] }) && header[6] <= 1) return ".rar";
        if (read >= 2 && header[0] == 0x1f && header[1] == 0x8b) return ".gz";
        if (read >= 3 && header.AsSpan(0, 3).SequenceEqual("BZh"u8)) return ".bz2";
        if (read >= 6 && header.AsSpan(0, 6).SequenceEqual(new byte[] { 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0 })) return ".xz";
        if (read >= 262 && header.AsSpan(257, 5).SequenceEqual("ustar"u8)) return ".tar";
        // ZIP is also a document container. Leave recognized document formats to Tika.
        string ext = Path.GetExtension(file).ToLowerInvariant();
        if (read >= 4 && header[0] == 'P' && header[1] == 'K' &&
            ((header[2] == 3 && header[3] == 4) || (header[2] == 5 && header[3] == 6) || (header[2] == 7 && header[3] == 8)) &&
            ext is not (".docx" or ".docm" or ".dotx" or ".dotm" or ".xlsx" or ".xlsm" or ".xlsb" or ".xltx" or ".xltm" or
                ".pptx" or ".pptm" or ".potx" or ".potm" or ".ppsx" or ".ppsm" or ".odt" or ".ods" or ".odp" or ".epub")) return ".zip";
        return null;
    }

    private static async Task<bool> IsUnicodeTextAsync(string file, CancellationToken token)
    {
        // Validate before emitting anything, so legacy encoding fallback cannot leave partial duplicates.
        var buffer = ArrayPool<char>.Shared.Rent(32768);
        try
        {
            using var reader = new StreamReader(file, new UTF8Encoding(false, true), true);
            while (await reader.ReadAsync(buffer.AsMemory(), token) is int read && read > 0)
                if (Array.IndexOf(buffer, '\0', 0, read) >= 0) return false;
            return true;
        }
        catch (DecoderFallbackException) { return false; }
        finally { ArrayPool<char>.Shared.Return(buffer, clearArray: true); }
    }

    private static async Task<string> StageAsync(Stream stream, string temp, string name, ArchiveBudget budget, long memberLimit, CancellationToken token)
    {
        string suffix = Path.GetExtension(name); if (suffix.Length > 15 || suffix.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '.'))) suffix = ".bin";
        string path = Path.Combine(temp, Guid.NewGuid().ToString("N") + suffix);
        using var output = File.Create(path); byte[] buffer = new byte[65536]; long memberBytes = 0;
        while (true)
        {
            int read = await stream.ReadAsync(buffer, token); if (read == 0) break;
            memberBytes += read; budget.Bytes += read;
            if (memberBytes > memberLimit || budget.Bytes > 400L * 1024 * 1024)
            {
                budget.Exhausted = true;
                throw new IOException("Archive expanded size limit reached");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), token);
        }
        return path;
    }
}
