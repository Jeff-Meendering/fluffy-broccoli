using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using PhoneNumbers;

namespace PiiExplorer.Core;

public sealed class PatternDetector
{
    // A validator returns the finding's confidence; zero or less rejects the candidate.
    private delegate double Validator(string text, int start, string value);
    private sealed record Rule(string Type, Regex Pattern, double Score, Validator? Validate = null,
        bool ValueOnly = false, Func<string, int, bool>? When = null, string Method = "Pattern");
    private static Regex Rx(string pattern) => new(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));
    private static bool Has(string text, string value) => text.Contains(value, StringComparison.OrdinalIgnoreCase);

    internal static readonly Regex LabelledName = Rx(@"(?im)\bFull[ \t]+name[ \t]*:[ \t]*(?<value>[\p{L}][\p{L}\p{M}.'’ \t-]{0,100}?)(?=[ \t]*(?:\||\r?$))");
    // Explicit person labels with at least two capitalized words. Bare "name:" is excluded
    // because file, product and field names use the same label.
    private static readonly Regex LabelledPersonName = Rx(@"(?im)(?:^[ \t]*name|\b(?:full|first|last|contact|patient|employee|customer|applicant|member|legal|your|my)[ \t]+name|\b(?:surname|family[ \t]+name|given[ \t]+name|attn|attention|employee|customer|patient|applicant|cardholder|account[ \t]+holder|beneficiary|borrower|insured|tenant|claimant|signed|prepared[ \t]+by))[ \t]*:[ \t]*(?<value>[\p{Lu}][\p{L}\p{M}'’.-]*(?:[ \t]+[\p{Lu}][\p{L}\p{M}'’.-]*){1,4})(?=[ \t]*(?:[|<(,]|\r?$))");
    private static readonly Regex EmailAssignment = Rx(@"(?i)\A(?:email|e-mail|mail|user|username|value|contact)=");
    private const string Months = @"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";
    private const string StreetSuffix = @"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|place|pl|way|terrace|ter|circle|cir|parkway|pkwy|highway|hwy|square|sq|trail|trl|loop|alley|crescent|cres|close|gardens|grove|row|walk|plaza|path|pike|turnpike|route|rte|broadway|expressway|expy|freeway|fwy)";

    private static readonly Rule[] Rules = [
        new("Person", LabelledName, .85, ValueOnly: true, When: (t, _) => Has(t, "full")),
        new("Person", LabelledPersonName, .70, ValueOnly: true, When: (t, _) => Has(t, "name") || Has(t, "attn") || Has(t, "attention") || Has(t, "employee") || Has(t, "customer") || Has(t, "patient") || Has(t, "applicant") || Has(t, "holder") || Has(t, "beneficiary") || Has(t, "borrower") || Has(t, "insured") || Has(t, "tenant") || Has(t, "claimant") || Has(t, "signed") || Has(t, "prepared")),
        // Consume the whole candidate before validating: never report a valid-looking prefix
        // of a malformed address. Atomic groups and matching left boundaries avoid retries
        // at every character of long local-part punctuation runs. The last label must be
        // alphabetic or IDNA-encoded so package versions such as lodash@4.17.21 are not addresses.
        new("Email", Rx(@"(?<![\w.!#$%&'*+/=?^`{|}~@-])(?>[\w.!#$%&'*+/=?^`{|}~-]+)@(?>(?:[\p{L}\p{M}0-9_-]+\.)+(?:(?i:xn--)[A-Za-z0-9-]{1,59}|[\p{L}\p{M}]{2,63}))(?![\w@-]|\.[\w.-])"), .99, Email, When: (t, _) => t.Contains('@')),
        // Structurally invalid SSNs (area 000/666/9xx, group 00, serial 0000) stay visible at
        // low confidence: test data and redactions are still worth review, not silent discards.
        new("Social Security number", Rx(@"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])"), .8, SsnDashed, When: (_, d) => d >= 9),
        new("Social Security number", Rx(@"(?i)\b(?:ssn|social[ _\t]+security)(?:[ _\t]+(?:number|no\.?))?(?=[ \t:=#])[ \t]*(?:[:=#][ \t]*)?(?<value>\d{3}[ -]?\d{2}[ -]?\d{4})(?![\w-])"), .9, SsnLabelled, ValueOnly: true, When: (t, d) => d >= 9 && (Has(t, "ssn") || Has(t, "social"))),
        new("Social Security number", Rx(@"(?<![\w-])\d{3} \d{2} \d{4}(?![\w-])"), .55, SsnSpaced, When: (_, d) => d >= 9),
        new("Payment card", Rx(@"(?<!\d)(?:[0-9][   -]?){12,18}[0-9](?!\d)"), .90, Card, When: (_, d) => d >= 13),
        // Consume IPv6 before IPv4 so mapped addresses yield one span. TryParse validates
        // compression/group counts offline; numeric scope IDs do not require interface lookup.
        new("IP address", Rx(@"(?<![\w:.%])(?>[A-Fa-f0-9]*:[A-Fa-f0-9:]+(?:(?:\.[0-9]+){3})?(?:%[0-9]+)?)(?![\w:%]|\.[\w.])|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), .8, Ip, When: (t, d) => d >= 4 || t.Contains(':')),
        new("Date of birth", Rx(@"(?i)\b(?:d\.?o\.?b\.?|date[_\s]+of[_\s]+birth|birth[_\s]*date|birthday|born(?:[_\s]+on)?)(?![\p{L}\d])[_\s]*[:=\-]?\s*(?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|\d{1,2}(?:st|nd|rd|th)?[-/ .]*" + Months + @"\.?,?[-/ .]*\d{2,4}|" + Months + @"\.?[ .]*\d{1,2}(?:st|nd|rd|th)?,?[ .]*\d{2,4})(?!\d)"), .9, When: (t, d) => d >= 4 && (Has(t, "birth") || Has(t, "dob") || Has(t, "born") || Has(t, "d.o.b"))),
        // The first street word must be capitalized or numbered: prose such as "a 2 hour drive"
        // otherwise matches, while written addresses are almost always capitalized.
        new("Street address", Rx(@"(?i)\b\d{1,6}[a-z]?\s+(?-i:[\p{Lu}\d])[\p{L}\d.'’-]*\s+(?:[\p{L}\d][\p{L}\d.'’-]*\s+){0,4}" + StreetSuffix + @"(?![\p{L}\d])\.?(?:,?\s+(?:n|s|e|w|ne|nw|se|sw|north|south|east|west)(?![\p{L}\d])\.?)?(?:,?\s+(?:apt|apartment|suite|ste|unit|floor|fl|bldg|building|#)\.?\s*#?\s*[\w-]{1,8}(?![\w-]))?"), .8, When: (_, d) => d >= 1),
        new("Street address", Rx(@"(?i)\b(?:p\.?\s?o\.?\s+box|post\s+office\s+box|pob)\s*#?\s*\d{1,6}(?![\p{L}\d])"), .8, When: (t, d) => d >= 1 && (Has(t, "box") || Has(t, "pob"))),
        new("Street address", Rx(@"(?i)\b\d{1,4}(?:\s?(?:bis|ter))?,?\s+(?:rue|avenue|boulevard|bd|place|chemin|allée|allee|impasse|quai|cours|passage)\s+(?:[\p{L}][\p{L}'’-]*(?:\s+|(?=[,.;\r\n]|$))){1,6}?(?=[,.;\r\n]|\s*\d|$)"), .7, When: (_, d) => d >= 1),
        new("Street address", Rx(@"(?i)\b[\p{L}][\p{L}-]{2,}(?:straße|strasse|str\.|weg|platz|allee|gasse|damm|ufer|laan|straat|gatan|vägen|vej|gade)\s+\d{1,4}\s?[a-z]?(?![\p{L}\d])"), .65, When: (_, d) => d >= 1),
        new("Street address", Rx(@"\b(?:Calle|Avenida|Avda\.?|Paseo|Plaza|Carrer|Via|Viale|Piazza|Corso|Rua|Praça)\s+(?:[\p{Lu}][\p{L}'’-]*\s+){1,5}?(?:n[º°.]?\s*)?\d{1,4}(?![\p{L}\d])"), .65, When: (_, d) => d >= 1),
        new("UK National Insurance", Rx(@"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"), .8, When: (_, d) => d >= 6),
        new("IBAN", Rx(IbanFormats.Pattern), .95, (_, _, v) => Iban(v) ? .95 : 0, When: (_, d) => d >= 2),
        new("Labelled identifier", Rx(@"(?i)\b(?:(?:passport|driver['’]?s?[ \t]+licen[cs]e|driving[ \t]+licen[cs]e)(?:[ \t]+(?:number|no\.?))?|account[ \t]+(?:number|no\.?)|routing[ \t]+(?:number|no\.?)|tax[ \t]+id|national[ \t]+id(?:[ \t]+(?:number|no\.?))?|id[ \t]+number|medical[ \t]+record[ \t]+(?:number|no\.?)|mrn|patient[ \t]+(?:id|number)|member[ \t]+(?:id|number)|policy[ \t]+(?:number|no\.?))[ \t]*[:=#][ \t]*(?>[A-Z0-9](?:[A-Z0-9-]|[ \t](?=[0-9])){3,24}[A-Z0-9])(?![\w-])"), .65, (_, _, v) => v.Any(char.IsAsciiDigit) ? .65 : 0, When: (t, d) => d >= 1 && (Has(t, "passport") || Has(t, "licen") || Has(t, "account") || Has(t, "routing") || Has(t, "tax") || Has(t, "id") || Has(t, "mrn") || Has(t, "medical") || Has(t, "patient") || Has(t, "member") || Has(t, "policy"))),
        new("MAC address", Rx(@"(?<![0-9A-Fa-f:.-])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f:.-])"), .7, Mac, When: (t, _) => t.Contains(':') || t.Contains('-') || t.Contains('.')),
        // Credentials: fixed-prefix tokens have near-zero collision rates. Labelled secrets are
        // the exception and are filtered against placeholders and prose.
        new("Credential", Rx(@"(?<![A-Za-z0-9/+])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9/+])"), .9, When: (t, _) => t.Contains("AKIA") || t.Contains("ASIA"), Method: "Pattern (AWS access key)"),
        new("Credential", Rx(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), .95, When: (t, _) => t.Contains("gh") , Method: "Pattern (GitHub token)"),
        new("Credential", Rx(@"\bxox[abpors]-[A-Za-z0-9-]{10,250}"), .9, When: (t, _) => t.Contains("xox"), Method: "Pattern (Slack token)"),
        new("Credential", Rx(@"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), .9, When: (t, _) => t.Contains("AIza"), Method: "Pattern (Google API key)"),
        new("Credential", Rx(@"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,99}\b"), .9, When: (t, _) => t.Contains("k_live") || t.Contains("k_test"), Method: "Pattern (Stripe key)"),
        new("Credential", Rx(@"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"), .95, When: (t, _) => t.Contains("PRIVATE KEY"), Method: "Pattern (private key)"),
        new("Credential", Rx(@"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])"), .85, When: (t, _) => t.Contains("eyJ"), Method: "Pattern (JSON Web Token)"),
        // The label may carry a prefix (db_password, X-Api-Key), so an underscore or hyphen
        // before it still counts as a boundary.
        new("Credential", Rx(@"(?i)(?<![\p{L}\d])[\w.-]{0,20}?(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)(?![\p{L}\d])[ \t]*[:=][ \t]*[""']?(?<value>[^\s""'<>,;]{8,128})"), .6, Secret, ValueOnly: true, When: (t, _) => Has(t, "pass") || Has(t, "secret") || Has(t, "key") || Has(t, "token"), Method: "Pattern (labelled secret)"),
        new("Crypto wallet", Rx(@"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])"), .95, CryptoWallets.Bitcoin, Method: "Pattern (Bitcoin address)"),
        new("Crypto wallet", Rx(@"(?i)(?<![A-Za-z0-9])(?:bc|tb)1[ac-hj-np-z02-9]{11,87}(?![A-Za-z0-9])"), .95, CryptoWallets.Bech32, When: (t, _) => Has(t, "bc1") || Has(t, "tb1"), Method: "Pattern (Bitcoin address)"),
        new("Crypto wallet", Rx(@"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])"), .95, CryptoWallets.Ethereum, When: (t, _) => t.Contains("0x"), Method: "Pattern (Ethereum address)"),
        // National identifiers are only reported when their check digits verify. Nine-digit
        // formats that collide with other numbers additionally require an explicit label.
        new("National ID", Rx(@"(?<![\w.-])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\w-])"), .9, NationalIds.Cpf, When: (_, d) => d >= 11, Method: "Pattern (Brazil CPF)"),
        new("National ID", Rx(@"(?<![\w-])[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![\w-])"), .85, NationalIds.Aadhaar, When: (_, d) => d >= 12, Method: "Pattern (India Aadhaar)"),
        new("National ID", Rx(@"(?i)\bNHS(?:[ \t]+(?:number|no\.?))?[ \t]*[:#=]?[ \t]*(?<value>\d{3}[ -]?\d{3}[ -]?\d{4})(?![\w-])"), .85, NationalIds.Nhs, ValueOnly: true, When: (t, d) => d >= 10 && Has(t, "nhs"), Method: "Pattern (UK NHS number)"),
        new("National ID", Rx(@"(?<![\w-])\d{3}[ -]\d{3}[ -]\d{3}(?![\w-])"), .6, NationalIds.Sin, When: (_, d) => d >= 9, Method: "Pattern (Canada SIN)"),
        new("National ID", Rx(@"(?<![\w-])(?:\d{8}|[XYZ]\d{7})[- ]?[A-Z](?![\w-])"), .85, NationalIds.Dni, When: (_, d) => d >= 7, Method: "Pattern (Spain DNI/NIE)"),
        new("National ID", Rx(@"(?<![\w-])[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z](?![\w-])"), .9, NationalIds.CodiceFiscale, When: (_, d) => d >= 7, Method: "Pattern (Italy codice fiscale)"),
        new("National ID", Rx(@"(?<![\w-])\d{11}(?![\w-])"), .7, NationalIds.Pesel, When: (_, d) => d >= 11, Method: "Pattern (Poland PESEL)"),
        new("National ID", Rx(@"(?<![\w-])[12] ?\d{2} ?(?:0[1-9]|1[0-2]) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}(?![\w-])"), .9, NationalIds.Nir, When: (_, d) => d >= 13, Method: "Pattern (France NIR)"),
        new("National ID", Rx(@"(?<![\w-])(?:\d{2})?\d{6}[-+]\d{4}(?![\w-])"), .8, NationalIds.Personnummer, When: (_, d) => d >= 10, Method: "Pattern (Sweden personnummer)"),
        new("National ID", Rx(@"(?i)\bBSN(?:[ \t]+(?:number|nummer))?[ \t]*[:#=]?[ \t]*(?<value>\d{9})(?![\w-])"), .85, NationalIds.Bsn, ValueOnly: true, When: (t, d) => d >= 9 && Has(t, "bsn"), Method: "Pattern (Netherlands BSN)"),
        new("National ID", Rx(@"(?i)\bTFN(?:[ \t]+(?:number|no\.?))?[ \t]*[:#=]?[ \t]*(?<value>\d{3}[ -]?\d{3}[ -]?\d{2,3})(?![\w-])"), .85, NationalIds.Tfn, ValueOnly: true, When: (t, d) => d >= 8 && Has(t, "tfn"), Method: "Pattern (Australia TFN)"),
        new("National ID", Rx(@"(?<![\w-])\d{13}(?![\w-])"), .65, NationalIds.SouthAfrica, When: (_, d) => d >= 13, Method: "Pattern (South Africa ID)"),
        new("National ID", Rx(@"(?<![\w-])\d{6}-[1-8]\d{6}(?![\w-])"), .85, NationalIds.Rrn, When: (_, d) => d >= 13, Method: "Pattern (Korea RRN)"),
        new("National ID", Rx(@"(?<![\w-])\d{17}[\dX](?![\w-])"), .85, NationalIds.ChinaId, When: (_, d) => d >= 17, Method: "Pattern (China resident ID)")
    ];

    private static readonly PhoneNumberUtil PhoneUtil = PhoneNumberUtil.GetInstance();
    private readonly string[] _phoneRegions;

    /// <param name="phoneRegions">Comma-separated ISO region codes used to interpret phone numbers
    /// written without a country code. International numbers with a + prefix are recognized regardless.</param>
    public PatternDetector(string? phoneRegions = null)
    {
        var supported = PhoneUtil.GetSupportedRegions();
        _phoneRegions = (phoneRegions ?? "US,GB").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(r => r.ToUpperInvariant()).Where(supported.Contains).Distinct().DefaultIfEmpty("US").ToArray();
    }

    public IReadOnlyList<string> PhoneRegions => _phoneRegions;

    /// <summary>Require domestic numbers to be grouped the way their country writes them. This rejects
    /// dates and reference numbers that happen to have a valid digit count; international + numbers are unaffected.</summary>
    public bool StrictPhoneGrouping { get; init; } = true;

    public IEnumerable<EntitySpan> Detect(string text, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        cancellationToken.ThrowIfCancellationRequested();
        var view = DetectionText.Create(text, cancellationToken);
        foreach (var span in Resolve(DetectCore(view.Text, cancellationToken), cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return view.OriginalSpan(span);
        }
    }

    // Identical spans keep their best rule; a span nested inside a stronger finding of
    // another type (a card inside a labelled account number) is not reported separately.
    internal static IEnumerable<EntitySpan> Resolve(IEnumerable<EntitySpan> spans, CancellationToken cancellationToken = default)
    {
        var collected = new List<EntitySpan>();
        System.Runtime.ExceptionServices.ExceptionDispatchInfo? failure = null;
        using (var iterator = spans.GetEnumerator())
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool moved;
                try { moved = iterator.MoveNext(); }
                catch (RegexMatchTimeoutException error)
                {
                    failure = System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error);
                    break;
                }
                if (!moved) break;
                collected.Add(iterator.Current);
            }
        }
        var ordered = collected.OrderBy(s => s.Start).ThenByDescending(s => s.Length).ThenByDescending(s => s.Confidence);
        var active = new List<EntitySpan>();
        foreach (var span in ordered)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Start order does not imply end order: an expired short span can sit
            // between this candidate and an earlier, still-containing long span.
            active.RemoveAll(s => s.Start + s.Length <= span.Start);
            bool covered = false;
            for (int i = active.Count - 1; i >= 0; i--)
            {
                var other = active[i];
                if (other.Start == span.Start && other.Length == span.Length && other.Type == span.Type) { covered = true; break; }
                if (other.Start <= span.Start && other.Start + other.Length >= span.Start + span.Length &&
                    other.Type != span.Type && other.Confidence >= span.Confidence && !(other.Start == span.Start && other.Length == span.Length)) { covered = true; break; }
            }
            if (!covered) { active.Add(span); yield return span; }
        }
        // Preserve earlier evidence, then let the scanner report the incomplete part.
        failure?.Throw();
    }

    private IEnumerable<EntitySpan> DetectCore(string text, CancellationToken cancellationToken)
    {
        int digits = 0;
        foreach (char c in text) if (char.IsAsciiDigit(c)) digits++;
        foreach (var rule in Rules) {
            cancellationToken.ThrowIfCancellationRequested();
            if (rule.When is not null && !rule.When(text, digits)) continue;
            foreach (Match match in rule.Pattern.Matches(text)) {
                cancellationToken.ThrowIfCancellationRequested();
                Group value = rule.ValueOnly ? match.Groups["value"] : match;
                int start = value.Index, length = value.Length;
                string candidate = rule.Validate is not null || rule.Type is "IBAN" or "Email" ? value.Value : "";
                if (rule.Type == "IBAN") {
                    length = IbanFormats.CandidateLength(text, start);
                    if (length == 0) continue;
                    candidate = text.Substring(start, length);
                }
                // Tika image metadata and config/log text often expose key=email@example.com.
                // '=' is legal in an email local part: strip only familiar assignment labels.
                if (rule.Type == "Email") {
                    var assignment = EmailAssignment.Match(candidate);
                    if (assignment.Success) { start += assignment.Length; length -= assignment.Length; candidate = candidate[assignment.Length..]; }
                }
                double confidence = rule.Validate is null ? rule.Score : rule.Validate(text, start, candidate);
                if (confidence > 0) yield return new(rule.Type, start, length, Math.Min(confidence, .99), rule.Method);
            }
        }
        if (digits >= 7) foreach (var span in Phones(text, cancellationToken)) yield return span;
    }

    private static readonly Regex PhoneCandidate = Rx(@"(?<![\p{L}\d+])\+?\(?\d[\d ().-]{5,28}\d(?:\s*(?:ext\.?|extension|x|#)\s*\d{1,6})?(?![\p{L}\d])");
    private static readonly Regex DottedQuad = Rx(@"\A\d{1,3}(?:\.\d{1,3}){3}\z"), IsoDate = Rx(@"\A\d{4}-\d{2}-\d{2}\z");
    private static readonly Regex NonPhoneLabel = Rx(@"(?i)\b(?:nhs[ \t]+(?:number|no\.?)|bsn(?:[ \t]+(?:number|nummer))?|tfn(?:[ \t]+(?:number|no\.?))?|ssn|social[ \t]+security(?:[ \t]+number)?)[ \t]*[:=#]?[ \t]*$");

    private IEnumerable<EntitySpan> Phones(string text, CancellationToken cancellationToken)
    {
        // libphonenumber validates length, prefix and grouping rules per country, which rejects
        // most identifiers that merely look like a phone number. Candidates are located here
        // first so that paths, IP addresses, dates and money are never parsed and so each
        // region pass only costs one parse per remaining candidate.
        var leniency = StrictPhoneGrouping ? PhoneNumberUtil.Leniency.STRICT_GROUPING : PhoneNumberUtil.Leniency.VALID;
        foreach (Match candidate in PhoneCandidate.Matches(text))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string value = candidate.Value;
            int digits = value.Count(char.IsAsciiDigit);
            if (digits is < 7 or > 17 || DottedQuad.IsMatch(value) || IsoDate.IsMatch(value)) continue;
            if (candidate.Index > 0 && text[candidate.Index - 1] is '/' or '#' or '$' or '£' or '€' or '\\') continue;
            // Explicit ID labels are stronger evidence than an incidental phone prefix.
            // Anchor to the candidate so "NHS helpline: ..." still permits a phone.
            if (NonPhoneLabel.IsMatch(text.AsSpan(Math.Max(0, candidate.Index - 60), Math.Min(60, candidate.Index)))) continue;
            foreach (string region in _phoneRegions)
            {
                bool any = false;
                foreach (var match in PhoneUtil.FindNumbers(value, region, leniency, long.MaxValue))
                {
                    any = true;
                    bool bare = match.RawString.All(char.IsAsciiDigit);
                    yield return new("Phone", candidate.Index + match.Start, match.Length, bare ? .55 : .85, "Pattern");
                }
                if (any || value[0] == '+') break;
            }
        }
    }

    /// <summary>Per-rule timing for a text, for benchmarking and tuning. Not used by scanning.</summary>
    public IEnumerable<(string Rule, double Milliseconds, int Matches)> Profile(string text)
    {
        var view = DetectionText.Create(text, default);
        int digits = view.Text.Count(char.IsAsciiDigit);
        foreach (var rule in Rules)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew(); int matches = 0;
            if (rule.When is null || rule.When(view.Text, digits)) matches = rule.Pattern.Matches(view.Text).Count;
            yield return (rule.Type + " " + rule.Method, watch.Elapsed.TotalMilliseconds, matches);
        }
        var phones = System.Diagnostics.Stopwatch.StartNew(); int found = Phones(view.Text, default).Count();
        yield return ("Phone", phones.Elapsed.TotalMilliseconds, found);
    }

    private static double Email(string text, int start, string value)
    {
        int at = value.IndexOf('@');
        var local = value.AsSpan(0, at);
        var domain = value.AsSpan(at + 1);
        if (local.Length > 64 || local[0] == '.' || local[^1] == '.' || local.Contains("..", StringComparison.Ordinal) ||
            domain.Length > 253) return 0;
        foreach (var range in domain.Split('.')) {
            var label = domain[range];
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' || label.Contains('_')) return 0;
        }
        return .99;
    }

    private static double SsnDashed(string text, int start, string value) => SsnConfidence(text, start, value, .8, .35);
    private static double SsnLabelled(string text, int start, string value) => SsnConfidence(text, start, value, .9, .5);
    private static double SsnSpaced(string text, int start, string value) => SsnStructureValid(value) ? SsnConfidence(text, start, value, .55, 0) : 0;

    private static double SsnConfidence(string text, int start, string value, double valid, double invalid)
    {
        double confidence = SsnStructureValid(value) ? valid : invalid;
        // "#123-45-6789" reads as a ticket or order reference.
        int i = start - 1; while (i >= 0 && text[i] == ' ') i--;
        if (i >= 0 && text[i] == '#') confidence *= .5;
        return confidence;
    }

    public static bool SsnStructureValid(string value)
    {
        Span<char> d = stackalloc char[9]; int n = 0;
        foreach (char c in value) if (char.IsAsciiDigit(c)) { if (n == 9) return false; d[n++] = c; }
        if (n != 9) return false;
        int area = (d[0] - '0') * 100 + (d[1] - '0') * 10 + d[2] - '0';
        int group = (d[3] - '0') * 10 + d[4] - '0';
        int serial = (d[5] - '0') * 1000 + (d[6] - '0') * 100 + (d[7] - '0') * 10 + d[8] - '0';
        if (area is 0 or 666 or >= 900 || group == 0 || serial == 0) return false;
        if (area == 78 && group == 5 && serial == 1120) return false; // Advertised specimen card number.
        if (area == 219 && group == 9 && serial == 9999) return false;
        return true;
    }

    private static readonly Regex DigitGroupBefore = Rx(@"\d{3,}[   -]\z"), DigitGroupAfter = Rx(@"\A[   -]\d{3,}");

    private static double Card(string text, int start, string value)
    {
        if (!Luhn(value)) return 0;
        // A valid-looking window inside a longer digit sequence is a different identifier.
        // An expiry such as "12/26" after the number is not a continuation.
        if (DigitGroupBefore.IsMatch(text.AsSpan(Math.Max(0, start - 24), Math.Min(start, 24))) ||
            DigitGroupAfter.IsMatch(text.AsSpan(start + value.Length, Math.Min(24, text.Length - start - value.Length)))) return 0;
        Span<char> d = stackalloc char[19]; int n = 0;
        foreach (char c in value) if (char.IsAsciiDigit(c)) { if (n == 19) return 0; d[n++] = c; }
        int p2 = (d[0] - '0') * 10 + d[1] - '0', p3 = p2 * 10 + d[2] - '0', p4 = p3 * 10 + d[3] - '0';
        // Issuer ranges and lengths: Luhn alone accepts about one random digit string in ten,
        // including IMEIs and many account numbers.
        if (d[0] == '4') return n is 13 or 16 or 19 ? .9 : 0;
        if (p2 is >= 51 and <= 55 || p4 is >= 2221 and <= 2720) return n == 16 ? .9 : 0;
        if (p2 is 34 or 37) return n == 15 ? .9 : 0;
        if (p2 is 36 or 38 or 39 || p3 is >= 300 and <= 305 || p4 == 3095) return n is >= 14 and <= 19 ? .85 : 0;
        if (p4 is >= 3528 and <= 3589) return n is >= 16 and <= 19 ? .85 : 0;
        if (p4 == 6011 || p3 is >= 644 and <= 649 || p2 is 65 or 62) return n is >= 16 and <= 19 ? .85 : 0;
        if (p2 is 50 or 56 or 57 or 58 or 63 or 67) return n is >= 12 and <= 19 ? .6 : 0;
        return 0;
    }

    private static double Ip(string text, int start, string value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return 0;
        int i = start - 1; while (i >= 0 && text[i] is ' ' or '\t') i--;
        int end = i + 1; while (i >= 0 && char.IsAsciiLetter(text[i])) i--;
        bool versionLike = text.AsSpan(i + 1, end - i - 1).ToString().ToLowerInvariant() is "v" or "ver" or "version" or "build" or "release" or "rev";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            uint bits = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            bool special = b[0] is 0 or 127 or >= 224 || (b[0] == 169 && b[1] == 254) || (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2) ||
                (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113) || (~bits & (~bits + 1)) == 0;
            if (special) return .3;
            bool @private = b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] is >= 64 and <= 127);
            return versionLike ? .3 : @private ? .6 : .8;
        }
        var v6 = ip.GetAddressBytes();
        if (ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6Loopback) || ip.IsIPv6Multicast || ip.IsIPv6LinkLocal ||
            (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8)) return .3;
        return (v6[0] & 0xfe) == 0xfc || ip.IsIPv6SiteLocal ? .6 : .8;
    }

    private static double Mac(string text, int start, string value)
    {
        string hex = value.Replace(":", "").Replace("-", "").Replace(".", "").ToLowerInvariant();
        if (hex.All(c => c == '0') || hex.All(c => c == 'f')) return .3;
        return hex.Any(char.IsAsciiLetter) || value.Contains(':') ? .7 : .4;
    }

    private static readonly HashSet<string> Placeholders = new(StringComparer.OrdinalIgnoreCase)
    { "null", "none", "true", "false", "changeme", "password", "redacted", "example", "secret", "required", "optional", "undefined", "<redacted>", "********" };

    private static double Secret(string text, int start, string value)
    {
        // A sentence ending the line ("password: required.") is prose, not a secret.
        value = value.TrimEnd('.', '!', '?', ')', ']', '}');
        if (value.Length < 8 || Placeholders.Contains(value) || value.All(c => c is '*' or 'x' or 'X' or '•' or '#')) return 0;
        if (value[0] is '$' or '%' or '{' or '<' or '@' or '[' or '(') return 0; // Variable references and markup.
        bool digit = value.Any(char.IsAsciiDigit), symbol = value.Any(c => !char.IsLetterOrDigit(c));
        bool mixed = value.Any(char.IsUpper) && value.Any(char.IsLower);
        if (!digit && !symbol && !(mixed && value.Length >= 12)) return 0;
        return digit && symbol ? .75 : .6;
    }

    public static bool Luhn(string text)
    {
        int count = 0, sum = 0, first = -1;
        bool different = false;
        for (int i = text.Length - 1; i >= 0; i--) {
            char c = text[i];
            if (c is ' ' or '-' or ' ' or ' ' or '.') continue;
            if (!char.IsAsciiDigit(c) || ++count > 19) return false;
            int digit = c - '0';
            if (first < 0) first = digit;
            else different |= digit != first;
            if (count % 2 == 0) { digit *= 2; if (digit > 9) digit -= 9; }
            sum += digit;
        }
        return count >= 8 && different && sum % 10 == 0;
    }

    public static bool Iban(string text)
    {
        string value = text.Replace(" ", "").Replace("\t", "").Replace(" ", "").Replace(" ", "").ToUpperInvariant();
        if (value.Length is < 15 or > 34 || !IbanFormats.Lengths.TryGetValue(value[..2], out int length) ||
            value.Length != length || !char.IsAsciiDigit(value[2]) || !char.IsAsciiDigit(value[3])) return false;
        value = value[4..] + value[..4]; int remainder = 0;
        foreach (char c in value) {
            if (char.IsAsciiDigit(c)) remainder = (remainder * 10 + c - '0') % 97;
            else if (c is >= 'A' and <= 'Z') remainder = (remainder * 100 + c - 'A' + 10) % 97;
            else return false;
        }
        return remainder == 1;
    }
}
