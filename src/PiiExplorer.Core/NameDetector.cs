using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace PiiExplorer.Core;

public sealed class NameDetector : IDisposable
{
    private readonly InferenceSession _session;
    private readonly Dictionary<string, int> _vocabulary;
    private readonly ConcurrentDictionary<string, EntitySpan[]> _cache = new();
    private int _cachedCharacters;
    private static readonly Regex Words = new(@"\p{L}[\p{L}\p{M}\p{N}]*|\p{N}+|[^\s]", RegexOptions.Compiled,
        TimeSpan.FromSeconds(2));
    private static readonly Regex TableRows = new(@"(?m)^\[Table\] [^\r\n]*", RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex TableId = new(@"\A[A-Za-z]{1,3}[0-9]{2,}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly Regex PostalAddress = new(@"(?i)\A[0-9]{1,6}[^\r\n|:]{1,150},[ \t]*[\p{L} .'-]{1,80}[ \t]+(?:[0-9]{5}(?:-[0-9]{4})?|[A-Z][A-Z0-9]{1,3}[ \t]+[0-9][A-Z]{2})\z", RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static readonly PatternDetector Patterns = new();
    public readonly record struct Token(long Id, int Start, int End);
    private const int Packet = 254, Overlap = 24, Batch = 8;
    // Salutations, closings and field words the model sometimes labels as a person on their own.
    private static readonly HashSet<string> NotNames = new(StringComparer.OrdinalIgnoreCase) {
        "regards", "sincerely", "dear", "thanks", "thank", "cheers", "hello", "hi", "hey", "best", "yours", "faithfully", "truly",
        "greetings", "please", "note", "subject", "re", "fw", "fwd", "attn", "confidential", "draft", "copy", "page", "total", "invoice",
        "date", "name", "user", "admin", "administrator", "customer", "client", "patient", "guest", "member", "unknown", "none", "null",
        "test", "sample", "example", "error", "warning", "ok", "sir", "madam", "mr", "mrs", "ms", "dr", "team", "support", "sales", "info",
        "mon", "tue", "wed", "thu", "fri", "sat", "sun", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec", "cache",
        "memo", "display", "thumbnail", "summary", "report", "notice", "agenda", "minutes", "attachment", "untitled", "document", "sheet", "slide",
        "pattern", "findings", "source", "location", "value", "detection", "context", "page", "type", "score", "model", "local", "review" };
    // Uppercase tokens left untouched by truecasing: field labels, acronyms and function words
    // that would otherwise read as capitalized surnames (DOB, SSN) or join two names (AND).
    private static readonly HashSet<string> KeepUppercase = new(StringComparer.Ordinal) {
        "DOB", "SSN", "ID", "NAME", "TEL", "PHONE", "FAX", "EMAIL", "ADDRESS", "DATE", "REF", "NO", "PO", "ZIP", "USA", "UK", "EU", "US", "UN",
        "ISBN", "VAT", "TIN", "NI", "NHS", "IBAN", "BIC", "PIN", "DL", "MRN", "ACCT", "AMT", "TOTAL", "PAID", "DUE", "NOTE", "PAGE", "ATTN", "RE",
        "CC", "BCC", "FROM", "TO", "CV", "MM", "DD", "YYYY", "AM", "PM", "NA", "TBD", "TBA", "ASAP", "FYI", "URL", "HTTP", "HTTPS", "WWW", "COM",
        "PDF", "DOC", "XLS", "CSV", "IP", "MAC", "API", "KEY", "LOGIN", "USER", "PASSWORD", "OK", "YES", "AND", "OR", "THE", "OF", "IN", "AT",
        "BY", "FOR", "WITH", "ON", "IS", "ARE", "WAS", "AN", "IT", "AS", "BE", "THIS", "THAT", "NOT", "ALL", "ANY", "PER", "VIA", "ETC" };

    /// <param name="threads">Intra-operation threads for inference. One session is shared by every
    /// scan worker, so callers divide the machine's cores between workers.</param>
    public NameDetector(RuntimePaths paths, int threads = 1)
    {
        _vocabulary = File.ReadAllLines(paths.Vocab).Select((word, index) => (word, index)).ToDictionary(p => p.word, p => p.index);
        using var options = new SessionOptions { IntraOpNumThreads = Math.Clamp(threads, 1, 16), InterOpNumThreads = 1,
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL };
        _session = new InferenceSession(paths.Model, options);
    }

    public List<Token> Tokenize(string text) => Tokenize(text, default);

    private List<Token> Tokenize(string text, CancellationToken cancellationToken)
    {
        var result = new List<Token>();
        foreach (Match word in Words.Matches(text)) {
            cancellationToken.ThrowIfCancellationRequested();
            if (word.Length > 100) { result.Add(new(100, word.Index, word.Index + word.Length)); continue; }
            int initialCount = result.Count, start = 0;
            string wordText = word.Value;
            while (start < word.Length) {
                int end = word.Length, id = -1;
                while (end > start) {
                    string piece = (start == 0 ? "" : "##") + wordText[start..end];
                    if (_vocabulary.TryGetValue(piece, out id)) break;
                    id = -1; end--;
                }
                if (id < 0) {
                    result.RemoveRange(initialCount, result.Count - initialCount);
                    result.Add(new(100, word.Index, word.Index + word.Length)); break;
                }
                result.Add(new(id, word.Index + start, word.Index + end)); start = end;
            }
        }
        return result;
    }

    // The model is cased and was trained on ordinary prose. Forms and legal documents write
    // names in capitals, which it treats as unknown words. Title-casing fully uppercase words
    // keeps every offset while restoring the case pattern it expects; acronyms become
    // capitalized words, which the model does not read as people.
    public static string Truecase(string text)
    {
        char[]? result = null;
        var run = new List<(int Start, int End)>();
        int i = 0;
        while (i <= text.Length)
        {
            // Collect a run of uppercase words separated by single spaces or name punctuation.
            // A lone short token (EDT, USA, PDF) is an acronym and stays as written; a run of
            // two or more words, or any word of four letters or more, reads as a name or heading.
            int start = i; bool allUpper = true; int letters = 0;
            while (i < text.Length && (char.IsLetter(text[i]) || (text[i] is '\'' or '’' && i + 1 < text.Length && char.IsLetter(text[i + 1]))))
            {
                if (char.IsLetter(text[i])) { letters++; if (!char.IsUpper(text[i])) allUpper = false; }
                i++;
            }
            bool word = letters >= 2 && allUpper && !KeepUppercase.Contains(text[start..i]);
            if (word) run.Add((start, i));
            bool continues = word && i < text.Length && text[i] is ' ' or '\t' or '.' or ',' or '-' && i + 1 < text.Length && char.IsLetter(text[i + 1]);
            if (!continues)
            {
                if (run.Count >= 2 || (run.Count == 1 && run[0].End - run[0].Start >= 4))
                {
                    result ??= text.ToCharArray();
                    foreach (var (s, e) in run) for (int j = s + 1; j < e; j++) if (text[j - 1] is not ('\'' or '’')) result[j] = char.ToLowerInvariant(result[j]);
                }
                run.Clear();
            }
            i = Math.Max(i, start) + 1;
        }
        return result is null ? text : new string(result);
    }

    // True when anything between two tokens was blanked as machine noise. Compares the
    // truecased text, not the original, so case restoration alone is never read as a mask.
    private static bool MaskedBetween(string truecased, string cased, int from, int to)
    {
        for (int i = Math.Max(0, from); i < to && i < cased.Length; i++) if (cased[i] != truecased[i]) return true;
        return false;
    }

    // Machine-generated tokens — hashes, identifiers, base64 payloads, URLs, paths, code
    // symbols — cannot be a written name, but each one still costs word pieces and therefore
    // inference time, which dominates scanning of logs, dumps and event data. Blanking them
    // keeps every offset intact and leaves natural-language text untouched.
    internal static string MaskNoise(string text, CancellationToken cancellationToken)
    {
        char[]? result = null;
        int i = 0;
        while (i < text.Length)
        {
            if ((i & 4095) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (IsSeparator(text[i])) { i++; continue; }
            int start = i;
            while (i < text.Length && !IsSeparator(text[i])) i++;
            // Judged per run, never per whitespace token: JSON, CSV and code pack a name and a
            // machine value into one token, so masking the whole token would hide the name.
            for (int run = start; run < i;)
            {
                while (run < i && IsStructural(text[run])) run++;
                int runStart = run;
                int letters = 0, digits = 0, upper = 0, lower = 0, others = 0, longest = 0, current = 0;
                while (run < i && !IsStructural(text[run]))
                {
                    char t = text[run];
                    if (char.IsLetter(t)) { letters++; current++; longest = Math.Max(longest, current); if (char.IsUpper(t)) upper++; else lower++; }
                    else { current = 0; if (char.IsDigit(t)) digits++; else others++; }
                    run++;
                }
                int length = run - runStart;
                bool noise =
                    // Hashes, identifiers and keys: long, with digits mixed into the letters.
                    (length >= 12 && digits > 0 && letters > 0 && longest <= 4) ||
                    (length >= 16 && digits > 0 && upper > 0 && lower > 0) ||
                    // Hex or base64 runs with no word-shaped letter sequence at all.
                    (length >= 10 && letters == 0) ||
                    (length >= 20 && others >= 2 && longest <= 6);
                if (noise) Mask(text, ref result, runStart, length);
            }
        }
        return result is null ? text : new string(result);

        static bool IsSeparator(char c) => char.IsWhiteSpace(c);
        // Quotes, brackets and delimiters separate values; a name never spans one.
        static bool IsStructural(char c) => char.IsWhiteSpace(c) || c is '"' or '\'' or '`' or '{' or '}' or '[' or ']' or
            '(' or ')' or ',' or ';' or ':' or '|' or '=' or '<' or '>' or '&' or '?' or '#' or '*' or '\\' or '/' or '@';
        static void Mask(string text, ref char[]? result, int start, int length)
        {
            result ??= text.ToCharArray();
            result.AsSpan(start, length).Fill(' ');
        }
    }

    /// <summary>Diagnostic view of the model's per-token decision for a text: the word piece, its label index
    /// (1 B-PER, 2 I-PER) and the softmax score of that label. Not used by scanning.</summary>
    public List<(string Piece, int Label, double Score)> Inspect(string text)
    {
        string cased = Truecase(text);
        var tokens = Tokenize(cased, default);
        var output = new List<(string, int, double)>();
        int count = Math.Min(Packet, tokens.Count), length = count + 2;
        var ids = new DenseTensor<long>(new[] { 1, length }); var mask = new DenseTensor<long>(new[] { 1, length });
        ids[0, 0] = 101; ids[0, count + 1] = 102;
        for (int i = 0; i < length; i++) mask[0, i] = 1;
        for (int i = 0; i < count; i++) ids[0, i + 1] = tokens[i].Id;
        using var result = _session.Run([NamedOnnxValue.CreateFromTensor("input_ids", ids), NamedOnnxValue.CreateFromTensor("attention_mask", mask)]);
        var logits = result.First().AsTensor<float>();
        for (int i = 0; i < count; i++)
        {
            int best = 0; float max = logits[0, i + 1, 0];
            for (int label = 1; label < 9; label++) if (logits[0, i + 1, label] > max) { max = logits[0, i + 1, label]; best = label; }
            double total = 0; for (int label = 0; label < 9; label++) total += Math.Exp(logits[0, i + 1, label] - max);
            output.Add((cased[tokens[i].Start..tokens[i].End], best, 1 / total));
        }
        return output;
    }

    public EntitySpan[] Detect(string text, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // The cache owns its arrays; callers are free to modify returned results.
        string cacheKey = text;
        if (_cache.TryGetValue(cacheKey, out var cached)) return (EntitySpan[])cached.Clone();
        // Mask cells already handled by patterns, leaving notes and other free text visible.
        // Purely structured rows still take the no-letters fast path without model inference.
        if (text.Contains("[Table] ", StringComparison.Ordinal))
            text = TableRows.Replace(text, m => MaskTableRow(m.Value, cancellationToken));
        if (string.IsNullOrWhiteSpace(text) || !text.Any(char.IsLetter)) return [];
        cancellationToken.ThrowIfCancellationRequested();
        string truecased = Truecase(text);
        string cased = MaskNoise(truecased, cancellationToken);
        if (!cased.Any(char.IsLetter)) return [];
        var tokens = Tokenize(cased, cancellationToken);
        var found = new List<EntitySpan>();
        using var runOptions = new RunOptions();
        // Each call owns its cancellation state; cancelling one file must not stop another
        // worker sharing the inference session. Dispose the registration before its handle.
        using var registration = cancellationToken.Register(() => runOptions.Terminate = true);
        // The model is cased and only ever marks capitalized words, so a window without one
        // cannot produce a name. Skipping those windows removes most inference on logs, code
        // and machine data, where inference otherwise dominates the whole scan.
        var starts = new List<int>();
        for (int start = 0; start < tokens.Count; start += Packet - Overlap)
        {
            int count = Math.Min(Packet, tokens.Count - start);
            for (int i = 0; i < count; i++)
                if (char.IsUpper(cased[tokens[start + i].Start])) { starts.Add(start); break; }
            if (start + Packet >= tokens.Count) break;
        }
        for (int group = 0; group < starts.Count; group += Batch)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int rows = Math.Min(Batch, starts.Count - group), longest = 0;
            for (int r = 0; r < rows; r++) longest = Math.Max(longest, Math.Min(Packet, tokens.Count - starts[group + r]));
            int length = longest + 2;
            var ids = new DenseTensor<long>(new[] { rows, length });
            var mask = new DenseTensor<long>(new[] { rows, length });
            for (int r = 0; r < rows; r++)
            {
                int start = starts[group + r], count = Math.Min(Packet, tokens.Count - start);
                ids[r, 0] = 101; ids[r, count + 1] = 102;
                for (int i = 0; i <= count + 1; i++) mask[r, i] = 1;
                for (int i = 0; i < count; i++) ids[r, i + 1] = tokens[start + i].Id;
            }
            IDisposableReadOnlyCollection<DisposableNamedOnnxValue> result;
            try { result = _session.Run([NamedOnnxValue.CreateFromTensor("input_ids", ids), NamedOnnxValue.CreateFromTensor("attention_mask", mask)], _session.OutputNames, runOptions); }
            catch (OnnxRuntimeException) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException(cancellationToken); }
            using (result)
            {
                var logits = result.First().AsTensor<float>();
                for (int r = 0; r < rows; r++)
                {
                    int start = starts[group + r], count = Math.Min(Packet, tokens.Count - start);
                    int entityStart = -1, entityEnd = -1, entityTokens = 0; double confidence = 0;
                    void Flush() {
                        if (entityStart >= 0) TrimLowercaseTail(text, entityStart, ref entityEnd);
                        while (entityEnd > entityStart && entityStart >= 0 && !char.IsLetterOrDigit(text[entityEnd - 1])) entityEnd--;
                        if (entityStart >= 0 && entityEnd - entityStart >= 2 && entityTokens > 0 && confidence / entityTokens >= .60 &&
                            (entityStart == 0 || !char.IsLetterOrDigit(text[entityStart - 1])) &&
                            (entityEnd == text.Length || !char.IsLetterOrDigit(text[entityEnd])) &&
                            !NotNames.Contains(text[entityStart..entityEnd].TrimEnd('.', ',', ':')))
                            found.Add(new("Person", entityStart, entityEnd - entityStart, Math.Round(confidence / entityTokens, 4), "Local model"));
                        entityStart = entityEnd = -1; confidence = 0; entityTokens = 0;
                    }
                    for (int i = 0; i < count; i++) {
                        int best = 0; float max = logits[r, i + 1, 0];
                        for (int label = 1; label < 9; label++) if (logits[r, i + 1, label] > max) { max = logits[r, i + 1, label]; best = label; }
                        double total = 0; for (int label = 0; label < 9; label++) total += Math.Exp(logits[r, i + 1, label] - max);
                        double score = 1 / total;
                        var token = tokens[start + i];
                        // Masked content is a hard boundary: without this, a name before a masked
                        // value and one after it would be reported as a single span covering both.
                        if (entityStart >= 0 && MaskedBetween(truecased, cased, entityEnd, token.Start)) Flush();
                        if (!char.IsLetterOrDigit(text[token.Start])) {
                            // Punctuation never starts a name. Glued periods, apostrophes and hyphens
                            // (J. Robert, O'Brien, Jean-Luc) tentatively extend an open name; anything
                            // else ends it. Trailing punctuation is trimmed when the name is flushed.
                            bool glue = entityStart >= 0 && token.Start == entityEnd && token.End - token.Start == 1 && text[token.Start] is '.' or '\'' or '’' or '-';
                            if (glue) entityEnd = token.End; else Flush();
                            continue;
                        }
                        // A word piece that continues the entity's current word cannot begin a new name or
                        // end the current one mid-word: multi-piece names (Raghunathan, Nguyễn) keep their
                        // full span instead of being cut at a piece boundary and rejected.
                        bool glued = entityStart >= 0 && token.Start == entityEnd;
                        bool continuation = glued && char.IsLetterOrDigit(text[token.Start - 1]);
                        if (best is 1 or 2 || continuation) {
                            if (best == 1 && !glued) { Flush(); entityStart = token.Start; }
                            else if (entityStart < 0) entityStart = token.Start;
                            if (best is 1 or 2) { confidence += score; entityTokens++; }
                            entityEnd = token.End;
                        } else Flush();
                    }
                    Flush();
                }
            }
        }
        // With starts sorted, only the furthest preceding end is needed to test containment.
        // Adjacent spans joined by an apostrophe or hyphen (O'Brien, Jean-Luc) are one name.
        var spans = found.OrderBy(x => x.Start).ThenByDescending(x => x.Length).ThenByDescending(x => x.Confidence);
        var kept = new List<EntitySpan>();
        int furthestEnd = -1;
        foreach (var span in spans) {
            int end = span.Start + span.Length;
            if (end <= furthestEnd) continue;
            if (kept.Count > 0 && span.Start == furthestEnd + 1 && text[furthestEnd] is '\'' or '’' or '-') {
                var previous = kept[^1];
                kept[^1] = previous with { Length = end - previous.Start, Confidence = Math.Min(previous.Confidence, span.Confidence) };
            }
            else kept.Add(span);
            furthestEnd = end;
        }
        var output = kept.OrderByDescending(x => x.Length).ThenByDescending(x => x.Confidence).ToArray();
        cancellationToken.ThrowIfCancellationRequested();
        if (cacheKey.Length <= 32768 && _cache.Count < 2048) {
            int reserved = Interlocked.Add(ref _cachedCharacters, cacheKey.Length);
            if (reserved > 2_000_000 || !_cache.TryAdd(cacheKey, (EntitySpan[])output.Clone())) Interlocked.Add(ref _cachedCharacters, -cacheKey.Length);
        }
        return output;
    }

    // The cased model marks names by capitalization. Trailing all-lowercase words after a
    // name (an adjacent e-mail local part, a spilled common word) are model overreach, and an
    // entity with lowercase letters but no capital at all is not a written name. Scripts
    // without case (CJK, Arabic) have neither and are kept.
    private static void TrimLowercaseTail(string text, int start, ref int end)
    {
        while (end > start)
        {
            int wordEnd = end; while (wordEnd > start && !char.IsLetterOrDigit(text[wordEnd - 1])) wordEnd--;
            int wordStart = wordEnd; while (wordStart > start && (char.IsLetterOrDigit(text[wordStart - 1]) || text[wordStart - 1] is '.' or '\'' or '’' or '-')) wordStart--;
            string word = text[wordStart..wordEnd];
            bool lower = false, upper = false;
            foreach (char c in word) { lower |= char.IsLower(c); upper |= char.IsUpper(c); }
            // Also drop a trailing field label the model swallowed into the name
            // ("MARIA HERNANDEZ DOB"), which uppercase forms make easy to mistake for a surname.
            if ((lower && !upper) || (wordStart > start && (KeepUppercase.Contains(word) || NotNames.Contains(word)))) end = wordStart;
            else return;
        }
    }

    private static string MaskTableRow(string row, CancellationToken cancellationToken)
    {
        var masked = row.ToCharArray();
        masked.AsSpan(0, 8).Fill(' '); // [Table] marker, not document content.
        foreach (var range in row.AsSpan(8).Split('|')) {
            cancellationToken.ThrowIfCancellationRequested();
            var (start, length) = range.GetOffsetAndLength(row.Length - 8);
            string cell = row.AsSpan(start + 8, length).Trim().ToString();
            if (IsStructuredCell(cell)) masked.AsSpan(start + 8, length).Fill(' ');
        }
        return new string(masked);
    }

    private static readonly Regex OnlyLabel = new(@"\A\s*(?:[\p{L}][\p{L} .'’/-]{0,30}:)?\s*\z", RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static bool IsStructuredCell(string cell)
    {
        if (!cell.Any(char.IsLetter) || TableId.IsMatch(cell)) return true;
        var name = PatternDetector.LabelledName.Match(cell);
        if (name.Success && name.Index == 0 && name.Length == cell.Length) return true;
        char[]? remaining = null;
        foreach (var span in Patterns.Detect(cell)) {
            if (span.Start == 0 && span.Length == cell.Length) return true;
            // A street followed by a city and postal code is still one structured address.
            // Require the postal suffix to avoid masking prose following a street name.
            if (span.Start == 0 && span.Type == "Street address" && PostalAddress.IsMatch(cell)) return true;
            remaining ??= cell.ToCharArray();
            remaining.AsSpan(span.Start, span.Length).Fill(' ');
        }
        // "SSN: 123-45-6789" is a label plus a detected value: nothing is left for the model.
        return remaining is not null && OnlyLabel.IsMatch(new string(remaining));
    }
    public void Dispose() => _session.Dispose();
}
