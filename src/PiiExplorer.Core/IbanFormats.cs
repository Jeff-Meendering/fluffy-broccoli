using System.Globalization;

namespace PiiExplorer.Core;

internal static class IbanFormats
{
    // Country/length facts cross-checked against Apache Commons Validator on
    // 2026-09-10. SWIFT is the registration authority. Keep this snapshot explicit:
    // https://commons.apache.org/proper/commons-validator/xref/org/apache/commons/validator/routines/IBANValidator.html
    // This is length + MOD-97 validation, not national BBAN/account validation.
    private const string Registry = "AD24 AE23 AL28 AT20 AZ28 BA20 BE16 BG22 BH22 BI27 BR29 BY28 CH21 CR22 CY28 CZ24 " +
        "DE22 DJ27 DK18 DO28 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GB22 GE22 GI23 GL18 GR27 GT28 HN28 HR21 HU28 " +
        "IE22 IL23 IQ23 IS26 IT27 JO30 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 LV21 LY25 MC27 MD24 ME22 MK19 MN20 " +
        "MR27 MT31 MU30 NI28 NL18 NO15 OM23 PK24 PL28 PS29 PT25 QA29 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 " +
        "SK24 SM27 SO23 ST25 SV28 TL23 TN24 TR26 UA29 VA22 VG24 XK20 YE30 " +
        "AX18 GF27 GP27 MQ27 RE27 PF27 TF27 YT27 NC27 BL27 MF27 PM27 WF27 IM22 JE22 GG22";

    internal static readonly IReadOnlyDictionary<string, int> Lengths = Registry.Split(' ')
        .ToDictionary(s => s[..2], s => int.Parse(s.AsSpan(2), CultureInfo.InvariantCulture), StringComparer.OrdinalIgnoreCase);

    internal const string Pattern = @"(?<![\w])[A-Za-z]{2}[0-9]{2}";

    // Scan the short prefix once, then use a bounded country-length check. A large
    // case-insensitive alternation rescans ordinary lowercase email-heavy text.
    internal static int CandidateLength(string text, int start)
    {
        if (!Lengths.TryGetValue(text.Substring(start, 2), out int expected)) return 0;
        int end = start + 4;
        for (int count = 4; count < expected; count++)
        {
            if (end < text.Length && text[end] is ' ' or '\t') end++;
            if (end >= text.Length || !char.IsAsciiLetterOrDigit(text[end])) return 0;
            end++;
        }
        if (end < text.Length && (char.IsLetterOrDigit(text[end]) ||
            char.GetUnicodeCategory(text[end]) is UnicodeCategory.NonSpacingMark or UnicodeCategory.ConnectorPunctuation)) return 0;
        return end - start;
    }
}
