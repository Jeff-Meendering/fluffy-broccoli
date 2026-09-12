using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text;

namespace PiiExplorer.Core;

// Printable-string extraction for formats no parser understands (captures, memory dumps,
// databases, unknown binaries). ASCII and UTF-16LE runs are checked; other encodings and
// compressed or encrypted content remain unreadable and are reported as such.
internal static class BinaryStrings
{
    private const int MinimumRun = 6, SegmentChars = 24_000, Overlap = 512;

    public static async IAsyncEnumerable<ExtractedPart> ReadAsync(string file, string source, long maxChars,
        [EnumeratorCancellation] CancellationToken token)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxChars);
        token.ThrowIfCancellationRequested();
        await using var input = File.OpenRead(file);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        var pending = new Queue<ExtractedPart>();
        var narrow = new Run(source, "ASCII", 1, pending);
        var wide = new Run(source, "UTF-16LE", 2, pending);
        long position = 0, emitted = 0;
        bool expectHigh = false; char pendingWide = '\0';
        try
        {
            int read;
            while ((read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), token)) > 0)
            {
                for (int i = 0; i < read; i++)
                {
                    if ((i & 0xfff) == 0) token.ThrowIfCancellationRequested();
                    byte b = buffer[i]; long at = position + i;
                    bool printable = b is >= 0x20 and <= 0x7e || b == '\t';
                    if (printable) narrow.Append((char)b, at);
                    else narrow.Flush();
                    if (expectHigh)
                    {
                        if (b == 0) wide.Append(pendingWide, at - 1);
                        else wide.Flush();
                    }
                    else if (!printable) wide.Flush();
                    expectHigh = printable;
                    if (printable) pendingWide = (char)b;
                    while (pending.TryDequeue(out var part))
                    {
                        int length = (int)Math.Min(part.Text.Length, maxChars - emitted);
                        yield return part with { Text = part.Text[..length] };
                        emitted += length;
                        if (emitted >= maxChars) { yield return Limit(); yield break; }
                    }
                }
                position += read;
            }
            narrow.Flush(); wide.Flush();
            while (pending.TryDequeue(out var part))
            {
                int length = (int)Math.Min(part.Text.Length, maxChars - emitted);
                yield return part with { Text = part.Text[..length] };
                emitted += length;
                if (emitted >= maxChars) { yield return Limit(); yield break; }
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }

        ExtractedPart Limit() => new(source, "", "", "", "Binary string extraction limit reached; remaining content unchecked") { Reason = CoverageReason.TextLimit };
    }

    // Keep each contiguous run separate: combining unrelated byte ranges invents
    // context and makes the reported byte offset misleading. Long runs overlap so
    // ordinary identifiers crossing a chunk boundary can still be found.
    private sealed class Run(string source, string encoding, int stride, Queue<ExtractedPart> pending)
    {
        private readonly StringBuilder _text = new();
        private long _start;
        private int _fresh;

        public void Append(char c, long offset)
        {
            if (_text.Length == 0) _start = offset;
            _text.Append(c); _fresh++;
            if (_text.Length < SegmentChars) return;
            // Prefer a nearby word boundary; a hard cut through .com can invent
            // a separate, valid-looking .co email even when the next chunk overlaps.
            int end = SegmentChars;
            while (end > SegmentChars - Overlap && !char.IsWhiteSpace(_text[end - 1])) end--;
            if (end == SegmentChars - Overlap) end = SegmentChars;
            Emit(end);
            _text.Remove(0, end - Overlap);
            _start += (end - Overlap) * stride;
        }

        public void Flush()
        {
            if (_text.Length >= MinimumRun && _fresh > 0) Emit(_text.Length);
            _text.Clear(); _fresh = 0;
        }

        private void Emit(int length)
        {
            pending.Enqueue(new(source, $"binary strings · byte {_start} ({encoding})", _text.ToString(0, length), "application/octet-stream")
            { Origin = new("", "binary:" + encoding, EvidenceKind.BinaryStrings, TextRepresentation.BinaryText, _start, OffsetUnit.Byte, stride) });
            _fresh = Math.Min(_fresh, _text.Length - length);
        }
    }
}
