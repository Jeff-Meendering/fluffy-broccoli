using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SkiaSharp;

namespace PiiExplorer.Core;

public sealed record ReportOptions(bool HideFileNames = false, bool IncludeContext = false);
public sealed record ReportSnapshot(string Root, IReadOnlyList<Finding> Findings, IReadOnlyList<ScanIssue> Issues,
    ScanSummary Summary, ScanOptions ScanOptions, ReportOptions Options);

/// <summary>Creates a fresh PDF from findings only. Never imports source PDF objects or metadata.</summary>
public static class PdfReport
{
    public static Dictionary<(string, string), string> SourceLabels(ReportSnapshot report)
    {
        var text = new ReportText(report);
        return report.Findings.Select(f => (f.FilePath, f.Source)).Concat(report.Issues.Select(i => (i.FilePath, i.Source)))
            .Distinct().ToDictionary(s => s, s => text.Source(s.FilePath, s.Source));
    }

    public static void Save(string destination, ReportSnapshot report, CancellationToken token = default,
        IProgress<int>? progress = null)
    {
        string target = Path.GetFullPath(destination);
        // Never overwrite any existing file, including through junctions or links. The final
        // atomic non-overwriting move also protects a file created while rendering is underway.
        string staged = Path.Combine(Path.GetDirectoryName(target)!, ".pii-export-" + Guid.NewGuid().ToString("N") + ".tmp");
        try {
            token.ThrowIfCancellationRequested();
            using (var output = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                Write(output, report, token, progress);
                output.Flush(flushToDisk: true);
            }
            token.ThrowIfCancellationRequested();
            try { File.Move(staged, target, overwrite: false); }
            catch (IOException) when (File.Exists(target)) {
                throw new IOException("That filename already exists. Choose a new report filename; existing files are never overwritten.");
            }
        } finally { if (File.Exists(staged)) File.Delete(staged); }
    }

    private static bool IsWithin(string root, string path)
    {
        string relative = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
        return !Path.IsPathRooted(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar);
    }

    public static void Write(Stream output, ReportSnapshot report, CancellationToken token = default,
        IProgress<int>? progress = null)
    {
        token.ThrowIfCancellationRequested();
        var privacy = new ReportText(report);
        using var fontStream = typeof(PdfReport).Assembly.GetManifestResourceStream("PiiExplorer.Core.Fonts.NotoSans-Regular.ttf")
            ?? throw new InvalidOperationException("The report font is missing from this application.");
        using var typeface = SKTypeface.FromStream(fontStream);
        // Explicit empty strings (including Producer) suppress Skia defaults. Null dates suppress timestamps.
        // PDF/A is off: it would add XMP metadata and document/instance IDs.
        var metadata = new SKDocumentPdfMetadata {
            Title = "", Author = "", Subject = "", Keywords = "", Creator = "", Producer = "",
            Creation = null, Modified = null, PdfA = false, RasterDpi = 72, EncodingQuality = 101
        };
        using var stream = new SKManagedWStream(output, disposeManagedStream: false);
        using var document = SKDocument.CreatePdf(stream, metadata)
            ?? throw new IOException("Could not create a PDF report.");
        using var layout = new ReportLayout(document, typeface, token);
        layout.Heading("PII findings", 25);
        layout.Paragraph(report.Summary.Cancelled ? "PARTIAL SCAN - stopped before all content was checked" :
            report.Issues.Count > 0 ? "SCAN FINISHED - some content needs attention" : "SCAN FINISHED", 11, accent: true);
        layout.Paragraph($"{report.Findings.Count:N0} findings   |   {report.Summary.Completed:N0} / {report.Summary.Files:N0} files processed   |   {report.Issues.Count:N0} attention items");
        layout.Paragraph($"Image reading: {(report.ScanOptions.Ocr ? "on" : "off")}. People’s names: {(report.ScanOptions.Names ? "on" : "off")}. File limit: {report.ScanOptions.MaxFileBytes / 1024 / 1024:N0} MiB. Timeout: {report.ScanOptions.FileTimeoutSeconds} seconds.", 9);
        layout.Paragraph("Potential PII requires review. No findings does not prove that a file contains no PII. Files processed includes files that could not be fully read; see Needs attention.", 9);
        layout.Paragraph(report.Options.HideFileNames
            ? "Source labels use file and part IDs; their mapping stays in the app. Detected values can still reveal names."
            : "Sources are relative to the scanned folder. The folder’s absolute path is omitted.", 9);
        layout.Paragraph("The PDF contains no author, computer name, dates, source attachments or document IDs in its metadata. Visible findings still contain sensitive information. Unsupported font characters are written as [U+XXXX].", 9);
        layout.Paragraph(report.Options.IncludeContext ? "Surrounding context is included." : "Surrounding context is omitted.", 9);
        if (report.Findings.Count > 0) {
            layout.Heading("Finding types", 14);
            foreach (var group in report.Findings.GroupBy(f => f.Type).OrderBy(g => g.Key, StringComparer.Ordinal))
                layout.Paragraph($"{group.Key}: {group.Count():N0}", 10);
        }
        layout.Heading("Findings", 17);
        if (report.Findings.Count == 0) layout.Paragraph("No PII detected in the checked content.");
        int number = 0;
        foreach (var finding in report.Findings) {
            token.ThrowIfCancellationRequested();
            layout.Ensure(100);
            layout.Heading($"{++number:N0}. {finding.Type}", 12);
            layout.Paragraph("Source: " + privacy.Source(finding.FilePath, finding.Source), 9);
            layout.Paragraph("Location: " + privacy.Clean(finding.DisplayLocation), 9);
            layout.Paragraph("Value: " + privacy.Value(finding.Value), 11);
            layout.Paragraph("Detection: " + privacy.Clean(finding.Method) +
                (finding.Method == "Local model" ? $" (model score {finding.Confidence:P0}; not a calibrated probability)" : " (pattern / context match)"), 8);
            if (report.Options.IncludeContext) layout.Paragraph("Context: " + privacy.Clean(finding.DisplayContext, finding.Value), 9);
            layout.Rule();
            if (number % 250 == 0) progress?.Report(number);
        }
        layout.Ensure(130);
        layout.Heading("Needs attention", 17);
        if (report.Issues.Count == 0) layout.Paragraph(report.Summary.Cancelled
            ? "No individual file issues were recorded. The scan was stopped; some content may not have been checked."
            : "No extraction issues were reported. Detection is still not exhaustive.");
        foreach (var issue in report.Issues) {
            token.ThrowIfCancellationRequested();
            layout.Ensure(65);
            layout.Paragraph("Source: " + privacy.Source(issue.FilePath, issue.Source), 10, accent: true);
            // Error details can contain OS paths and filenames. Alias mode omits these free-form details.
            layout.Paragraph(report.Options.HideFileNames ? "Content could not be fully checked. Review this source’s attention item in the app."
                : privacy.Clean(issue.Message), 9);
            layout.Rule();
        }
        layout.Finish();
        document.Close();
        token.ThrowIfCancellationRequested();
        progress?.Report(number);
    }

    private sealed class ReportText
    {
        private const string Omitted = "[absolute path omitted]";
        // Unambiguous host paths: file URIs, drive letters and UNC shares. A drive letter must not
        // be the last letter of a scheme ("https://"), so URLs stay intact.
        private const string HostPathStart = @"(?:file:/+|(?<![\w])[a-z]:[\\/]|\\\\|(?<![\w:])//)";
        // A path ends after a separator and the space-free run that follows it, continuing over
        // spaces only while the next part also ends in a separator ("C:\a\My Documents\b.xlsx").
        // Bounding the token keeps the failure reason or the neighbour beside it on the same line.
        private const string HostPathBody =
            @"(?:[^<>|\r\n""]*?[\\/])?[^\s<>|""]*(?:[ \t]+[^\s<>|""\\/]*[\\/][^\s<>|""]*)*";
        // Detected values are the evidence a report exists to communicate: only an unambiguous
        // host path is removed from them, never a slash-initial value, URL or connection string.
        private static readonly Regex ValuePath = new(@"(?i)" + HostPathStart + HostPathBody,
            RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
        // Host-derived free text (locations, context, parser errors and member names) also hides a
        // bare slash-initial token, because an absolute path can start with "/" alone.
        private static readonly Regex TextPath = new(@"(?i)" + HostPathStart + HostPathBody +
            @"|(?<![\w:/])/(?=[^\s/])" + HostPathBody, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
        private readonly ReportSnapshot _report;
        private readonly Dictionary<string, string> _files;
        private readonly Dictionary<(string, string), string> _parts = [];
        private readonly string[] _privatePrefixes;

        public ReportText(ReportSnapshot report)
        {
            _report = report;
            var comparison = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
            _files = report.Findings.Select(f => f.FilePath).Concat(report.Issues.Select(i => i.FilePath))
                .Distinct(comparison).OrderBy(f => f, StringComparer.Ordinal).Select((f, i) => (f, id: $"File {i + 1:D5}"))
                .ToDictionary(p => p.f, p => p.id, comparison);
            _privatePrefixes = new[] { Path.GetFullPath(report.Root), Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar) }
                .Where(s => s.Length > 3).SelectMany(s => new[] { s, s.Replace('\\', '/') }).Distinct().OrderByDescending(s => s.Length).ToArray();
            foreach (var item in report.Findings.Select(f => (f.FilePath, f.Source)).Concat(report.Issues.Select(i => (i.FilePath, i.Source))))
                if (item.Source.Length > 0 && !_parts.ContainsKey(item)) _parts[item] = "Part " + (_parts.Count + 1).ToString("D5", CultureInfo.InvariantCulture);
        }

        public string Source(string file, string source)
        {
            string name = _report.Options.HideFileNames ? _files[file] : IsWithin(_report.Root, file)
                ? Path.GetRelativePath(_report.Root, file).Replace('\\', '/') : _files[file];
            if (source.Length > 0) name += " > " + (_report.Options.HideFileNames ? _parts[(file, source)] : Clean(source));
            return name;
        }

        /// <summary>Keeps a detected value intact apart from host paths, which are never evidence.</summary>
        public string Value(string value) => Private(ValuePath.Replace(value, Omitted));

        /// <summary>Redacts host paths in extracted metadata, parser errors and optional context as
        /// visible content too, while leaving any detected value inside them verbatim.</summary>
        public string Clean(string text, string? preserve = null)
        {
            var spans = Preserved(text, preserve);
            if (spans.Count == 0) return Private(TextPath.Replace(text, Omitted));
            // Clean around each value instead of inside it, so a path next to the value is still
            // redacted and the value is never swallowed by the path that follows it.
            var result = new StringBuilder();
            int at = 0;
            foreach (var (start, length) in spans) {
                result.Append(Private(TextPath.Replace(text[at..start], Omitted))).Append(text, start, length);
                at = start + length;
            }
            return result.Append(Private(TextPath.Replace(text[at..], Omitted))).ToString();
        }

        private List<(int Start, int Length)> Preserved(string text, string? preserve)
        {
            var spans = new List<(int Start, int Length)>();
            // A value that survives its own redaction is not a host path, so a neighbouring path
            // must not absorb it where it appears in the surrounding text.
            if (string.IsNullOrEmpty(preserve) || Value(preserve) != preserve) return spans;
            for (int i = text.IndexOf(preserve, StringComparison.Ordinal); i >= 0;
                 i = text.IndexOf(preserve, i + preserve.Length, StringComparison.Ordinal))
                spans.Add((i, preserve.Length));
            return spans;
        }

        private string Private(string text)
        {
            foreach (string prefix in _privatePrefixes) {
                var result = new StringBuilder();
                int at = 0;
                for (int i = text.IndexOf(prefix, StringComparison.OrdinalIgnoreCase); i >= 0;
                     i = text.IndexOf(prefix, at, StringComparison.OrdinalIgnoreCase)) {
                    result.Append(text, at, i - at).Append("[source root]");
                    at = i + prefix.Length;
                }
                text = result.Append(text, at, text.Length - at).ToString();
            }
            return text;
        }
    }

    private sealed class ReportLayout : IDisposable
    {
        private const float Width = 595, Height = 842, Margin = 44, Bottom = 785;
        private readonly SKDocument _document;
        private readonly SKFont _font;
        private readonly SKPaint _paint = new() { IsAntialias = true };
        private readonly CancellationToken _token;
        private SKCanvas _canvas = null!;
        private float _y;
        private int _page;

        public ReportLayout(SKDocument document, SKTypeface typeface, CancellationToken token)
        { _document = document; _font = new(typeface, 10); _token = token; NewPage(); }

        private void NewPage()
        {
            _token.ThrowIfCancellationRequested();
            if (_page > 0) _document.EndPage();
            _canvas = _document.BeginPage(Width, Height); _page++;
            _paint.Color = new SKColor(18, 45, 56); _canvas.DrawRect(0, 0, Width, 7, _paint);
            Draw("PII EXPLORER / FINDINGS REPORT", Margin, 29, 8, false);
            Draw("Sensitive findings - review before sharing", Margin, Height - 23, 8, false);
            Draw("Page " + _page.ToString(CultureInfo.InvariantCulture), Width - 85, Height - 23, 8, false);
            _y = 56;
        }

        public void Ensure(float height) { if (_y + height > Bottom) NewPage(); }
        public void Heading(string text, float size) { Ensure(size * 2 + 20); _y += 8; Paragraph(text, size, accent: true); }
        public void Paragraph(string text, float size = 10, bool accent = false)
        {
            _font.Size = size;
            var normalized = new StringBuilder();
            foreach (var rune in text.EnumerateRunes()) {
                // Do not let controls or missing glyphs silently alter a reported identifier.
                if (rune.Value is '\r' or '\n' or '\t') { normalized.Append(' '); continue; }
                string value = rune.ToString();
                normalized.Append(Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format || !_font.ContainsGlyphs(value)
                    ? $"[U+{rune.Value:X4}]" : value);
            }
            string remaining = normalized.ToString();
            while (remaining.Length > 0) {
                _token.ThrowIfCancellationRequested();
                _font.Size = size;
                // Measure at most one line's prefix. Binary search also bounds work for enormous tokens.
                int low = 1, high = Math.Min(remaining.Length, 256), count = 1;
                while (low <= high) {
                    int mid = (low + high) / 2;
                    if (_font.MeasureText(remaining[..mid]) <= Width - 2 * Margin) { count = mid; low = mid + 1; }
                    else high = mid - 1;
                }
                if (count < remaining.Length) {
                    int space = remaining.LastIndexOf(' ', count - 1, count);
                    if (space > count / 3) count = space + 1;
                    if (char.IsHighSurrogate(remaining[count - 1])) count--;
                }
                Ensure(size * 1.55f);
                Draw(remaining[..count].TrimEnd(), Margin, _y + size, size, accent);
                _y += size * 1.45f;
                remaining = remaining[count..];
            }
            _y += 4;
        }
        private void Draw(string text, float x, float y, float size, bool accent)
        {
            _font.Size = size; _paint.Color = accent ? new SKColor(17, 122, 115) : new SKColor(40, 59, 69);
            _canvas.DrawText(text, x, y, SKTextAlign.Left, _font, _paint);
        }
        public void Rule() { Ensure(12); _paint.Color = new SKColor(224, 231, 237); _canvas.DrawRect(Margin, _y + 3, Width - 2 * Margin, .6f, _paint); _y += 12; }
        public void Finish() => _document.EndPage();
        public void Dispose() { _font.Dispose(); _paint.Dispose(); }
    }
}
