using System.Globalization;

namespace PiiExplorer.Core;

// A narrow detection view, never a replacement for the evidence. Keep UTF-16 source
// offsets through removed format characters. Do not guess OCR letters or homoglyphs.
internal sealed class DetectionText(string original, string text, int[]? offsets)
{
    public string Text => text;

    public EntitySpan OriginalSpan(EntitySpan span)
    {
        if (offsets is null) return span;
        int start = offsets[span.Start], end = offsets[span.Start + span.Length - 1] + 1;
        bool changed = !original.AsSpan(start, end - start).SequenceEqual(text.AsSpan(span.Start, span.Length));
        return span with { Start = start, Length = end - start,
            Method = changed ? span.Method + " (Unicode normalized)" : span.Method };
    }

    public static DetectionText Create(string original, CancellationToken token)
    {
        // ASCII is by far the common case: no text copy or offset array needed.
        if (original.AsSpan().IndexOfAnyInRange('\u0080', '\uffff') < 0) return new(original, original, null);
        char[]? chars = null; int[]? offsets = null; int length = 0;
        for (int i = 0; i < original.Length; i++)
        {
            if ((i & 4095) == 0) token.ThrowIfCancellationRequested();
            char c = original[i];
            char? mapped = c switch
            {
                '\u00ad' or '\u200b' or '\u200c' or '\u200d' or '\u200e' or '\u200f' or
                '\u2060' or '\ufeff' or >= '\u202a' and <= '\u202e' or >= '\u2066' and <= '\u2069' => null,
                >= '\uff01' and <= '\uff5e' => (char)(c - 0xfee0),
                >= '\u2010' and <= '\u2015' or '\u2212' => '-',
                _ when c > 127 && char.GetUnicodeCategory(c) == UnicodeCategory.SpaceSeparator => ' ',
                _ when c > 127 && char.GetUnicodeCategory(c) == UnicodeCategory.DecimalDigitNumber => (char)('0' + (int)char.GetNumericValue(c)),
                _ => c
            };
            if (chars is null && mapped != c)
            {
                chars = new char[original.Length]; offsets = new int[original.Length];
                original.AsSpan(0, i).CopyTo(chars);
                for (int j = 0; j < i; j++) offsets[j] = j;
                length = i;
            }
            if (chars is not null && mapped is char value) { chars[length] = value; offsets![length++] = i; }
        }
        return chars is null ? new(original, original, null) : new(original, new string(chars, 0, length), offsets);
    }
}
