namespace PiiExplorer.Core;

// Check-digit validation for national identifiers. A verified checksum is evidence that
// a number fits this format, not that it was issued or belongs to a person.
internal static class NationalIds
{
    private static int[] Digits(string value, int expected)
    {
        var digits = new int[expected]; int n = 0;
        foreach (char c in value) if (char.IsAsciiDigit(c)) { if (n == expected) return []; digits[n++] = c - '0'; }
        return n == expected ? digits : [];
    }

    private static bool AllSame(int[] d) => d.All(x => x == d[0]);

    private static bool ValidDate(int year, int month, int day) =>
        year is >= 1 and <= 9999 && month is >= 1 and <= 12 && day >= 1 && day <= DateTime.DaysInMonth(year, month);

    private static bool LabelNearby(string text, int start, params string[] labels)
    {
        var before = text.AsSpan(Math.Max(0, start - 40), Math.Min(start, 40));
        foreach (string label in labels) if (before.Contains(label, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // A single check digit still admits roughly one in ten numbers of the right shape, so a
    // bare digit run is reported only as a weak lead unless its own name appears beside it.
    private static double Labelled(string text, int start, double labelled, double bare, params string[] labels) =>
        LabelNearby(text, start, labels) ? labelled : bare;

    public static double Cpf(string text, int start, string value)
    {
        var d = Digits(value, 11); if (d.Length == 0 || AllSame(d)) return 0;
        for (int check = 9; check <= 10; check++)
        {
            int sum = 0; for (int i = 0; i < check; i++) sum += d[i] * (check + 1 - i);
            int r = sum * 10 % 11; if (r == 10) r = 0;
            if (r != d[check]) return 0;
        }
        return .9;
    }

    private static readonly int[,] VerhoeffD = {
        {0,1,2,3,4,5,6,7,8,9},{1,2,3,4,0,6,7,8,9,5},{2,3,4,0,1,7,8,9,5,6},{3,4,0,1,2,8,9,5,6,7},{4,0,1,2,3,9,5,6,7,8},
        {5,9,8,7,6,0,4,3,2,1},{6,5,9,8,7,1,0,4,3,2},{7,6,5,9,8,2,1,0,4,3},{8,7,6,5,9,3,2,1,0,4},{9,8,7,6,5,4,3,2,1,0}};
    private static readonly int[,] VerhoeffP = {
        {0,1,2,3,4,5,6,7,8,9},{1,5,7,6,2,8,3,0,9,4},{5,8,0,3,7,9,6,1,4,2},{8,9,1,6,0,4,3,5,2,7},
        {9,4,5,3,1,2,6,8,7,0},{4,2,8,6,5,7,3,9,0,1},{2,7,9,3,8,0,6,4,1,5},{7,0,4,6,9,1,3,2,5,8}};

    public static double Aadhaar(string text, int start, string value)
    {
        var d = Digits(value, 12); if (d.Length == 0 || AllSame(d)) return 0;
        int c = 0;
        for (int i = 0; i < 12; i++) c = VerhoeffD[c, VerhoeffP[i % 8, d[11 - i]]];
        return c == 0 ? Labelled(text, start, .85, .6, "aadhaar", "uidai", "आधार") : 0;
    }

    public static double Nhs(string text, int start, string value)
    {
        var d = Digits(value, 10); if (d.Length == 0 || AllSame(d)) return 0;
        int sum = 0; for (int i = 0; i < 9; i++) sum += d[i] * (10 - i);
        int check = 11 - sum % 11; if (check == 11) check = 0;
        return check != 10 && check == d[9] ? .85 : 0;
    }

    public static double Sin(string text, int start, string value)
    {
        var d = Digits(value, 9); if (d.Length == 0 || d[0] == 0 || d[0] == 8 || !PatternDetector.Luhn(value)) return 0;
        return Labelled(text, start, .9, .45, "sin", "social insurance", "assurance sociale");
    }

    public static double Dni(string text, int start, string value)
    {
        const string Letters = "TRWAGMYFPDXBNJZSQVHLCKE";
        string s = value.Replace("-", "").Replace(" ", "");
        int number = s[0] switch { 'X' => 0, 'Y' => 1, 'Z' => 2, _ => s[0] - '0' };
        for (int i = 1; i < s.Length - 1; i++) number = number * 10 + s[i] - '0';
        return Letters[number % 23] == s[^1] ? .85 : 0;
    }

    private static readonly int[] OddValues = { 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23 };

    public static double CodiceFiscale(string text, int start, string value)
    {
        int sum = 0;
        for (int i = 0; i < 15; i++)
        {
            int index = char.IsAsciiDigit(value[i]) ? value[i] - '0' : value[i] - 'A' + 10;
            sum += (i + 1) % 2 == 1 ? OddValues[index] : char.IsAsciiDigit(value[i]) ? value[i] - '0' : value[i] - 'A';
        }
        return (char)('A' + sum % 26) == value[15] ? .9 : 0;
    }

    public static double Pesel(string text, int start, string value)
    {
        var d = Digits(value, 11); if (d.Length == 0 || AllSame(d)) return 0;
        int[] weights = { 1, 3, 7, 9, 1, 3, 7, 9, 1, 3 };
        int sum = 0; for (int i = 0; i < 10; i++) sum += d[i] * weights[i];
        if ((10 - sum % 10) % 10 != d[10]) return 0;
        int month = d[2] * 10 + d[3], century = month / 20;
        int year = new[] { 1900, 2000, 2100, 2200, 1800 }[century] + d[0] * 10 + d[1];
        return ValidDate(year, month - century * 20, d[4] * 10 + d[5]) ? Labelled(text, start, .8, .45, "pesel") : 0;
    }

    public static double Nir(string text, int start, string value)
    {
        string s = value.Replace(" ", "").ToUpperInvariant();
        if (s.Length != 15) return 0;
        string body = s[..13].Replace("2A", "19").Replace("2B", "18");
        if (!long.TryParse(body, out long number) || !int.TryParse(s[13..], out int key)) return 0;
        return 97 - number % 97 == key ? .9 : 0;
    }

    public static double Personnummer(string text, int start, string value)
    {
        var d = Digits(value, value.Count(char.IsAsciiDigit)); if (d.Length is not (10 or 12)) return 0;
        int offset = d.Length - 10;
        int year = (offset == 2 ? d[0] * 1000 + d[1] * 100 : 1900) + d[offset] * 10 + d[offset + 1];
        int day = d[offset + 4] * 10 + d[offset + 5]; if (day > 60) day -= 60; // Coordination numbers add 60.
        if (!ValidDate(year, d[offset + 2] * 10 + d[offset + 3], day)) return 0;
        string last10 = string.Concat(d.Skip(offset));
        return PatternDetector.Luhn(last10) ? .8 : 0;
    }

    public static double Bsn(string text, int start, string value)
    {
        var d = Digits(value, 9); if (d.Length == 0 || AllSame(d)) return 0;
        int sum = 0; for (int i = 0; i < 8; i++) sum += d[i] * (9 - i);
        return (sum - d[8]) % 11 == 0 ? .85 : 0;
    }

    public static double Tfn(string text, int start, string value)
    {
        int count = value.Count(char.IsAsciiDigit);
        var d = Digits(value, count); if (d.Length is not (8 or 9) || AllSame(d)) return 0;
        int[] weights = d.Length == 9 ? [1, 4, 3, 7, 5, 8, 6, 9, 10] : [10, 7, 8, 4, 6, 3, 5, 1];
        int sum = 0; for (int i = 0; i < d.Length; i++) sum += d[i] * weights[i];
        return sum % 11 == 0 ? .85 : 0;
    }

    public static double SouthAfrica(string text, int start, string value)
    {
        var d = Digits(value, 13); if (d.Length == 0 || AllSame(d) || d[10] > 1) return 0;
        int yy = d[0] * 10 + d[1];
        if (!ValidDate(yy > DateTime.UtcNow.Year % 100 ? 1900 + yy : 2000 + yy, d[2] * 10 + d[3], d[4] * 10 + d[5])) return 0;
        return PatternDetector.Luhn(value) ? Labelled(text, start, .8, .45, "id number", "identity", "id no", "rsa id", "sa id") : 0;
    }

    public static double Rrn(string text, int start, string value)
    {
        var d = Digits(value, 13); if (d.Length == 0) return 0;
        int century = d[6] switch { 1 or 2 or 5 or 6 => 1900, 3 or 4 or 7 or 8 => 2000, _ => 1800 };
        if (!ValidDate(century + d[0] * 10 + d[1], d[2] * 10 + d[3], d[4] * 10 + d[5])) return 0;
        int[] weights = { 2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5 };
        int sum = 0; for (int i = 0; i < 12; i++) sum += d[i] * weights[i];
        return (11 - sum % 11) % 10 == d[12] ? .85 : 0;
    }

    public static double ChinaId(string text, int start, string value)
    {
        if (!int.TryParse(value.AsSpan(6, 4), out int year) || !ValidDate(year, int.Parse(value.AsSpan(10, 2)), int.Parse(value.AsSpan(12, 2))) || year < 1900) return 0;
        int[] weights = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2 };
        int sum = 0; for (int i = 0; i < 17; i++) sum += (value[i] - '0') * weights[i];
        return "10X98765432"[sum % 11] == value[17] ? .85 : 0;
    }
}
