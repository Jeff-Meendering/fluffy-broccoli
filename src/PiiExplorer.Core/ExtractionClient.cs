using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace PiiExplorer.Core;

public sealed class ExtractionClient(RuntimePaths paths) : IDisposable
{
    private Process? _process;
    private DirectoryInfo? _tempDirectory;
    private int _reading;
    private int _terminated;
    private readonly char[] _buffer = new char[4096];
    private int _position, _length;

    public int? WorkerProcessId => _process?.Id;

    private void EnsureStarted()
    {
        // A killed process can still report HasExited == false while its termination is
        // pending, so a stopped worker is never handed another request.
        if (_process is { HasExited: false } && Volatile.Read(ref _terminated) == 0) return;
        Dispose();
        Volatile.Write(ref _terminated, 0);
        // CreateTempSubdirectory uses owner-only permissions on Unix. Isolate Tika and
        // its OCR children's scratch files as well as our own archive/image staging.
        _tempDirectory = Directory.CreateTempSubdirectory("PiiExplorer-");
        var start = new ProcessStartInfo(paths.Java)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = _tempDirectory.FullName,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string value in new[] { "-Xmx768m", "-XX:ActiveProcessorCount=2", "-Djava.awt.headless=true", "-Dfile.encoding=UTF-8",
            "-Djava.io.tmpdir=" + _tempDirectory.FullName,
            "-Djavax.xml.accessExternalDTD=", "-Djavax.xml.accessExternalSchema=", "-Djavax.xml.accessExternalStylesheet=", "-cp",
            paths.Worker + Path.PathSeparator + Path.Combine(paths.Worker, "tika-app.jar"), "ExtractionWorker" }) start.ArgumentList.Add(value);
        start.Environment["PATH"] = paths.OcrDirectory + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        start.Environment["TESSDATA_PREFIX"] = Path.Combine(paths.OcrDirectory, "tessdata");
        start.Environment["OMP_THREAD_LIMIT"] = "1";
        foreach (string variable in new[] { "TEMP", "TMP", "TMPDIR" }) start.Environment[variable] = _tempDirectory.FullName;
        if (OperatingSystem.IsLinux()) start.Environment["LD_LIBRARY_PATH"] = Path.Combine(paths.OcrDirectory, "lib") + ":" + Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
        _process = new Process { StartInfo = start };
        _process.Start();
        _position = _length = 0;
        _ = DrainErrorsAsync(_process.StandardError);
    }

    public async IAsyncEnumerable<ExtractedPart> ReadAsync(string file, bool ocr,
        [EnumeratorCancellation] CancellationToken cancellationToken, string? resourceName = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.CompareExchange(ref _reading, 1, 0) != 0)
            throw new InvalidOperationException("An extraction request is already active on this client");
        bool done = false;
        try
        {
            EnsureStarted();
            var process = _process!;
            using var registration = cancellationToken.Register(() => Terminate(process));
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new
            {
                path = Path.GetFullPath(file),
                ocr,
                resourceName = resourceName ?? Path.GetFileName(file)
            }).AsMemory(), cancellationToken);
            await process.StandardInput.FlushAsync(cancellationToken);
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = await ReadRecordAsync(process.StandardOutput, cancellationToken);
                if (line is null)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new IOException("Extraction worker stopped unexpectedly; file was not fully checked. " +
                        (process.HasExited ? "Exit code " + process.ExitCode : ""));
                }
                using var record = JsonDocument.Parse(line);
                var root = record.RootElement;
                string kind = root.GetProperty("kind").GetString()!;
                if (kind == "done") { cancellationToken.ThrowIfCancellationRequested(); done = true; break; }
                string source = root.TryGetProperty("source", out var s) ? s.GetString() ?? "" : "";
                if (kind == "issue") yield return new(source, "", "", "", root.GetProperty("message").GetString())
                { Reason = Enum.Parse<CoverageReason>(root.GetProperty("reason").GetString()!),
                  Origin = new(root.GetProperty("resourceId").GetString()!, "coverage", EvidenceKind.Body, TextRepresentation.ExtractedText) };
                else if (kind == "segment") yield return new(source, root.GetProperty("location").GetString() ?? "", root.GetProperty("text").GetString() ?? "",
                    root.GetProperty("contentType").GetString() ?? "") { Origin = ReadOrigin(root) };
                else throw new IOException("Unknown extraction worker record: " + kind);
            }
        }
        finally
        {
            // Breaking out of await foreach must discard the rest of this response, including
            // buffered records and any OCR child processes, before another request is allowed.
            if (!done) Dispose();
            Volatile.Write(ref _reading, 0);
        }
    }

    private static EvidenceOrigin ReadOrigin(JsonElement record)
    {
        if (!record.TryGetProperty("origin", out var origin))
            throw new IOException("Extraction worker has no evidence provenance; rebuild the worker");
        long start = origin.GetProperty("start").GetInt64();
        if (start < 0) throw new IOException("Invalid extraction offset");
        return new(origin.GetProperty("resourceId").GetString()!, origin.GetProperty("streamId").GetString()!,
            Enum.Parse<EvidenceKind>(origin.GetProperty("kind").GetString()!),
            Enum.Parse<TextRepresentation>(origin.GetProperty("representation").GetString()!), start);
    }

    private async Task<string?> ReadRecordAsync(StreamReader reader, CancellationToken token)
    {
        var record = new StringBuilder();
        while (true)
        {
            if (_position == _length)
            {
                _length = await reader.ReadAsync(_buffer.AsMemory(), token); _position = 0;
                if (_length == 0)
                {
                    if (record.Length != 0) throw new IOException("Truncated extraction worker record");
                    return null;
                }
            }
            int end = Array.IndexOf(_buffer, '\n', _position, _length - _position);
            int count = (end < 0 ? _length : end) - _position;
            if (record.Length + count > 256_000) throw new IOException("Extraction worker record size limit reached");
            record.Append(_buffer, _position, count); _position += count;
            if (end >= 0) { _position++; return record.ToString(); }
        }
    }

    private static async Task DrainErrorsAsync(StreamReader reader)
    {
        // Drain without retaining parser logs or allocating an unbounded stderr line.
        try { var buffer = new char[4096]; while (await reader.ReadAsync(buffer) > 0) { } }
        catch (Exception e) when (e is IOException or ObjectDisposedException) { }
    }

    private void Terminate(Process process)
    {
        Volatile.Write(ref _terminated, 1);
        if (process.HasExited) return;
        try
        {
            try { process.Kill(entireProcessTree: true); }
            catch (Exception e) when (e is InvalidOperationException or Win32Exception or NotSupportedException) { }
            // A failed tree walk must still stop the worker itself: a surviving worker
            // still holds the tail of the response it was producing.
            if (!process.HasExited) process.Kill();
        }
        catch (Exception e) when (e is InvalidOperationException or Win32Exception or NotSupportedException) { }
    }
    // Stopping discards the worker instead of leaving a pending kill for the next request
    // to discover: the following request must always start a usable process.
    public void Stop() { if (_process is null) return; Dispose(); }
    public void Dispose()
    {
        var process = _process;
        if (process is not null)
        {
            Terminate(process);
            try { process.WaitForExit(2000); }
            catch (InvalidOperationException) { } // A failed start has no process handle.
            process.Dispose(); _process = null;
        }
        if (_tempDirectory is not null)
        {
            try { _tempDirectory.Delete(recursive: true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            _tempDirectory = null;
        }
    }
}
