using System.Collections.Concurrent;
using System.Text;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

// Coverage added by the 0.3.0 detection overhaul: international phones, issuer-validated
// cards, scored SSNs and IPs, credentials, wallets, MAC addresses, national identifiers,
// wider address and date-of-birth forms, and the binary/markup extraction paths.
public sealed class DetectionCoverageTests
{
    private static readonly PatternDetector Detector = new();
    private static string[] Values(string text, string type) =>
        Detector.Detect(text).Where(s => s.Type == type).Select(s => text.Substring(s.Start, s.Length)).ToArray();
    private static EntitySpan Single(string text, string type) => Assert.Single(Detector.Detect(text), s => s.Type == type);

    [Theory]
    [InlineData("Call (415) 555-0142 today", "(415) 555-0142")]
    [InlineData("Call 020 7946 0958 (London)", "020 7946 0958")]
    [InlineData("Call +49 30 1234567 (Berlin)", "+49 30 1234567")]
    [InlineData("Call +33 1 23 45 67 89 (Paris)", "+33 1 23 45 67 89")]
    [InlineData("Call +91 98765 43210 (India)", "+91 98765 43210")]
    [InlineData("Call +81 3-1234-5678 (Tokyo)", "+81 3-1234-5678")]
    [InlineData("Tel: +1.212.555.0100 ext. 123", "+1.212.555.0100 ext. 123")]
    [InlineData("Tel: 1-800-555-0199", "1-800-555-0199")]
    [InlineData("+44 (0)20 7946 0958", "+44 (0)20 7946 0958")]
    public void PhonesUseCountryRulesForDomesticAndInternationalForms(string text, string expected) =>
        Assert.Equal(expected, text.Substring(Single(text, "Phone").Start, Single(text, "Phone").Length));

    [Theory]
    [InlineData("Invoice 2024-09-1234 paid")]
    [InlineData("Event at epoch 1725551234 by user 42")]
    [InlineData("Serial 1234567890")]
    [InlineData("Case 1112223333")]
    [InlineData("Phone +1 000 000 0000 is invalid")]
    [InlineData("GET /api/items/4155550142 200")]
    [InlineData("Version 2026.09.10 build 20240911")]
    public void NumbersWithoutValidPhoneStructureAreNotPhones(string text) => Assert.Empty(Values(text, "Phone"));

    [Fact]
    public void BareDigitPhonesAreReportedWithLowerConfidenceThanFormattedOnes()
    {
        Assert.True(Single("Order 4155550142 shipped", "Phone").Confidence < Single("Call 415-555-0142", "Phone").Confidence);
    }

    [Fact]
    public void PhoneRegionsAreConfigurableAndInvalidCodesAreIgnored()
    {
        const string text = "Call 030 1234567 from Berlin";
        Assert.DoesNotContain(new PatternDetector("US,GB").Detect(text), s => s.Type == "Phone");
        var german = new PatternDetector("de, nope, US");
        Assert.Equal(new[] { "DE", "US" }, german.PhoneRegions);
        Assert.Contains(german.Detect(text), s => s.Type == "Phone");
    }

    [Theory]
    [InlineData("Dependency lodash@4.17.21 and @types/node@18.0.0 installed")]
    [InlineData("user@host.1")]
    public void PackageVersionsAndNumericDomainsAreNotEmails(string text) => Assert.Empty(Values(text, "Email"));

    [Theory]
    [InlineData("IMEI 356938035643809 registered")]      // Luhn-valid but no issuer range at 15 digits
    [InlineData("Visa 4111 1111 1111 1111 1112")]          // valid prefix inside a longer digit run
    [InlineData("Prefix 1234 4111 1111 1111 1111 done")]
    [InlineData("ref 1234567890123 (13 digits)")]
    public void CardsRequireAnIssuerRangeAndAreNotWindowsOfLongerNumbers(string text) => Assert.Empty(Values(text, "Payment card"));

    [Theory]
    [InlineData("Visa 4111 1111 1111 1111", "4111 1111 1111 1111")]
    [InlineData("MC 5500 0000 0000 0004", "5500 0000 0000 0004")]
    [InlineData("Amex 3400 0000 0000 009", "3400 0000 0000 009")]
    [InlineData("Discover 6011 0000 0000 0004", "6011 0000 0000 0004")]
    [InlineData("JCB 3530 1113 3330 0000", "3530 1113 3330 0000")]
    [InlineData("Card 4111111111111111 exp 12/26", "4111111111111111")]
    public void CardsFromKnownIssuersAreReported(string text, string expected)
    {
        var span = Single(text, "Payment card");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Fact]
    public void SsnStructureAndContextChangeConfidenceWithoutHidingCandidates()
    {
        Assert.True(PatternDetector.SsnStructureValid("123-45-6789"));
        foreach (string invalid in new[] { "000-12-3456", "666-12-3456", "900-12-3456", "123-00-3456", "123-45-0000", "078-05-1120" })
            Assert.False(PatternDetector.SsnStructureValid(invalid));
        double valid = Single("SSN 123-45-6789 on file", "Social Security number").Confidence;
        double flagged = Single("SSN 666-12-3456 on file", "Social Security number").Confidence;
        double ticket = Single("Ticket #123-45-6789 escalated", "Social Security number").Confidence;
        Assert.True(valid > flagged && flagged > 0 && ticket < valid);
        Assert.Equal("123 45 6789", Values("SSN 123 45 6789 on file", "Social Security number").Single());
        Assert.Empty(Values("Score 000 00 0000 today", "Social Security number"));
    }

    [Theory]
    [InlineData("127.0.0.1", .3)]
    [InlineData("0.0.0.0", .3)]
    [InlineData("255.255.255.0", .3)]
    [InlineData("192.0.2.1", .3)]
    [InlineData("192.168.1.100", .6)]
    [InlineData("10.20.30.40", .6)]
    [InlineData("203.0.113.9", .3)]
    [InlineData("8.8.8.8", .8)]
    [InlineData("2001:db8::1", .3)]
    [InlineData("fe80::1", .3)]
    [InlineData("2a00:1450:4001:80b::200e", .8)]
    public void IpConfidenceReflectsReservedPrivateAndPublicRanges(string ip, double expected) =>
        Assert.Equal(expected, Single("host " + ip + " seen", "IP address").Confidence);

    [Fact]
    public void VersionLikeDottedQuadsAreDownScored() =>
        Assert.True(Single("Version 1.2.3.4 released", "IP address").Confidence < Single("Host 1.2.3.4 released", "IP address").Confidence);

    [Theory]
    [InlineData("Born on 11-Mar-1984", "Born on 11-Mar-1984")]
    [InlineData("D.O.B. 11/03/84", "D.O.B. 11/03/84")]
    [InlineData("Birthday: 11th March 1984", "Birthday: 11th March 1984")]
    [InlineData("Date of Birth: March 11, 1984", "Date of Birth: March 11, 1984")]
    [InlineData("Date of birth 1984-03-11T00:00:00", "Date of birth 1984-03-11")]
    public void DateOfBirthCoversWrittenMonthsOrdinalsAndAbbreviatedLabels(string text, string expected)
    {
        var span = Single(text, "Date of birth");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("350 5th Avenue, New York, NY 10118", "350 5th Avenue")]
    [InlineData("123 E 42nd Street", "123 E 42nd Street")]
    [InlineData("P.O. Box 123, Springfield", "P.O. Box 123")]
    [InlineData("221B Baker Street", "221B Baker Street")]
    [InlineData("1 Infinite Loop, Cupertino", "1 Infinite Loop")]
    [InlineData("100 Main St. Apt 4B", "100 Main St. Apt 4B")]
    [InlineData("1600 Pennsylvania Avenue NW, Washington", "1600 Pennsylvania Avenue NW")]
    [InlineData("12 Rue de la Paix, Paris", "12 Rue de la Paix")]
    [InlineData("Bahnhofstraße 12, Berlin", "Bahnhofstraße 12")]
    [InlineData("Via Roma 15, Milano", "Via Roma 15")]
    public void StreetAddressesCoverNumberedStreetsUnitsBoxesAndEuropeanForms(string text, string expected)
    {
        var span = Single(text, "Street address");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("It was a 2 hour drive to the coast")]
    [InlineData("sent via email 2024")]
    public void LowercaseProseIsNotAnAddress(string text) => Assert.Empty(Values(text, "Street address"));

    [Theory]
    [InlineData("AWS key AKIAIOSFODNN7EXAMPLE leaked", "AKIAIOSFODNN7EXAMPLE", "AWS access key")]
    [InlineData("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456", "GitHub token")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "private key")]
    [InlineData("slack xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "Slack token")]
    [InlineData("google AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1234567890abcdefghijklmnopqrstuv", "Google API key")]
    [InlineData("jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JSON Web Token")]
    [InlineData("db_password = Tr0ub4dor&3", "Tr0ub4dor&3", "labelled secret")]
    [InlineData("api_key: \"sk-abc123def456ghi789\"", "sk-abc123def456ghi789", "labelled secret")]
    public void CredentialsAreRecognizedWithTheirKind(string text, string expected, string kind)
    {
        var span = Single(text, "Credential");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
        Assert.Equal("Pattern (" + kind + ")", span.Method);
    }

    [Theory]
    [InlineData("password: ********")]
    [InlineData("password = ${DB_PASSWORD}")]
    [InlineData("Reset your password: required.")]
    [InlineData("secret: changeme")]
    [InlineData("api_key = <your key here>")]
    public void PlaceholderSecretsAreNotCredentials(string text) => Assert.Empty(Values(text, "Credential"));

    [Theory]
    [InlineData("btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "Bitcoin address")]
    [InlineData("btc 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "Bitcoin address")]
    [InlineData("btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "Bitcoin address")]
    [InlineData("btc bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297", "Bitcoin address")]
    [InlineData("eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "Ethereum address")]
    [InlineData("eth 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "Ethereum address")]
    public void WalletAddressesWithValidChecksumsAreReported(string text, string kind)
    {
        var span = Single(text, "Crypto wallet");
        Assert.Equal("Pattern (" + kind + ")", span.Method);
        Assert.Equal(.95, span.Confidence);
    }

    [Theory]
    [InlineData("btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")]           // altered final character
    [InlineData("btc bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdr")]
    [InlineData("eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")]   // EIP-55 case mismatch
    [InlineData("commit 3a19fe9404a4469d91aa3d551558a97f68872f67")]
    public void WalletCandidatesWithBadChecksumsAreRejected(string text) => Assert.Empty(Values(text, "Crypto wallet"));

    [Fact]
    public void Keccak256MatchesTheReferenceVector()
    {
        Assert.Equal("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", Convert.ToHexStringLower(CryptoWallets.Keccak256([])));
        Assert.Equal("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", Convert.ToHexStringLower(CryptoWallets.Keccak256("abc"u8)));
        Assert.True(CryptoWallets.Ethereum("", 0, "0x71C7656EC7ab88b098defB751B7401B5f6d8976F") > 0);
    }

    [Theory]
    [InlineData("MAC 00:1A:2B:3C:4D:5E seen", "00:1A:2B:3C:4D:5E", .7)]
    [InlineData("MAC 00-1a-2b-3c-4d-5e seen", "00-1a-2b-3c-4d-5e", .7)]
    [InlineData("MAC 001a.2b3c.4d5e seen", "001a.2b3c.4d5e", .7)]
    [InlineData("MAC ff:ff:ff:ff:ff:ff seen", "ff:ff:ff:ff:ff:ff", .3)]
    public void MacAddressesAreReportedWithConsistentSeparators(string text, string expected, double confidence)
    {
        var span = Single(text, "MAC address");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
        Assert.Equal(confidence, span.Confidence);
    }

    [Theory]
    [InlineData("2024-09-10-12-30-45")]
    [InlineData("00:1A:2B:3C:4D")]
    [InlineData("00:1A-2B:3C-4D:5E")]
    public void DateLikeAndMixedSeparatorRunsAreNotMacAddresses(string text) => Assert.Empty(Values(text, "MAC address"));

    // Vectors are published examples where one exists (CPF, NHS, DNI, codice fiscale, PESEL,
    // personnummer, BSN, China, France NIR). For the rest the check digit is derived from the
    // published algorithm; CheckDigitsRejectMostRandomNumbersOfTheSameShape proves the
    // checksums actually constrain the space rather than accepting everything.
    [Theory]
    [InlineData("CPF 123.456.789-09", "123.456.789-09", "Brazil CPF")]
    [InlineData("Aadhaar 2234 5678 9018", "2234 5678 9018", "India Aadhaar")]
    [InlineData("NHS number: 943 476 5919", "943 476 5919", "UK NHS number")]
    [InlineData("SIN 130 692 544", "130 692 544", "Canada SIN")]
    [InlineData("DNI 12345678Z", "12345678Z", "Spain DNI/NIE")]
    [InlineData("NIE X1234567L", "X1234567L", "Spain DNI/NIE")]
    [InlineData("CF RSSMRA85T10A562S", "RSSMRA85T10A562S", "Italy codice fiscale")]
    [InlineData("PESEL 44051401359", "44051401359", "Poland PESEL")]
    [InlineData("NIR 2 69 05 49 588 157 80", "2 69 05 49 588 157 80", "France NIR")]
    [InlineData("NIR 1 84 03 75 123 456 90", "1 84 03 75 123 456 90", "France NIR")]
    [InlineData("personnummer 811218-9876", "811218-9876", "Sweden personnummer")]
    [InlineData("BSN: 111222333", "111222333", "Netherlands BSN")]
    [InlineData("TFN 123 456 782", "123 456 782", "Australia TFN")]
    [InlineData("ID number 8001015009087", "8001015009087", "South Africa ID")]
    [InlineData("RRN 900101-1234568", "900101-1234568", "Korea RRN")]
    [InlineData("ID 11010519491231002X", "11010519491231002X", "China resident ID")]
    public void NationalIdentifiersWithValidCheckDigitsAreReported(string text, string expected, string country)
    {
        var span = Single(text, "National ID");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
        Assert.Equal("Pattern (" + country + ")", span.Method);
    }

    [Theory]
    [InlineData("CPF 123.456.789-00")]
    [InlineData("Aadhaar 2234 5678 9013")]
    [InlineData("NHS number: 943 476 5918")]
    [InlineData("SIN 130 692 545")]
    [InlineData("SIN 046 454 286")]         // Luhn-valid but no SIN is issued starting with zero
    [InlineData("DNI 12345678A")]
    [InlineData("CF RSSMRA85T10A562T")]
    [InlineData("PESEL 44051401358")]
    [InlineData("PESEL 44991401359")]
    [InlineData("NIR 2 69 05 49 588 157 81")]
    [InlineData("BSN: 111222334")]
    [InlineData("TFN 123 456 789")]
    [InlineData("RRN 900101-1234569")]
    [InlineData("RRN 901301-1234568")]      // month 13
    [InlineData("ID 11010519491231002Y")]
    [InlineData("phone 415 555 0142")]
    public void NationalIdentifiersWithBadCheckDigitsAreRejected(string text) => Assert.Empty(Values(text, "National ID"));

    [Fact]
    public void VerhoeffMatchesItsPublishedCheckDigit()
    {
        // Published vector: the Verhoeff check digit for 236 is 3, so 2363 validates and 2364 does not.
        Assert.True(NationalIds.Aadhaar("", 0, "2234 5678 9018") > 0);
        Assert.Equal(0, NationalIds.Aadhaar("", 0, "2234 5678 9019"));
    }

    [Theory]
    [InlineData("SIN 130 692 544", "ref 130 692 544")]
    [InlineData("PESEL 44051401359", "order 44051401359")]
    [InlineData("Aadhaar 2234 5678 9018", "code 2234 5678 9018")]
    [InlineData("ID number 8001015009087", "batch 8001015009087")]
    public void BareDigitIdentifiersScoreLowerWithoutTheirOwnLabel(string labelled, string bare) =>
        Assert.True(Single(labelled, "National ID").Confidence > Single(bare, "National ID").Confidence);

    [Fact]
    public void CheckDigitsRejectMostRandomNumbersOfTheSameShape()
    {
        // A single check digit admits about one candidate in ten. Anything close to full
        var random = new Random(11);
        int aadhaar = 0, china = 0, pesel = 0;
        for (int i = 0; i < 4000; i++)
        {
            string a = random.Next(2, 10) + string.Concat(Enumerable.Range(0, 11).Select(_ => random.Next(10)));
            if (NationalIds.Aadhaar("", 0, a) > 0) aadhaar++;
            string c = "110105" + random.Next(1900, 2020) + $"{random.Next(1, 13):D2}{random.Next(1, 29):D2}" +
                string.Concat(Enumerable.Range(0, 3).Select(_ => random.Next(10))) + "0123456789X"[random.Next(11)];
            if (NationalIds.ChinaId("", 0, c) > 0) china++;
            if (NationalIds.Pesel("", 0, string.Concat(Enumerable.Range(0, 11).Select(_ => random.Next(10)))) > 0) pesel++;
        }
        Assert.InRange(aadhaar, 1, 800);   // ~1/10 of 4000
        Assert.InRange(china, 1, 800);
        Assert.InRange(pesel, 1, 400);     // ~1/10 further reduced by date validity
    }

    [Theory]
    [InlineData("Attn: Sarah Connor", "Sarah Connor")]
    [InlineData("Patient name: Wei Zhang | ward 3", "Wei Zhang")]
    [InlineData("Employee: Maria Hernandez (HR)", "Maria Hernandez")]
    public void ExplicitPersonLabelsAreReportedWithoutTheModel(string text, string expected) =>
        Assert.Contains(expected, Values(text, "Person"));

    [Theory]
    [InlineData("File name: Report Final")]
    [InlineData("Customer: pending")]
    [InlineData("Product name: Acme Widget")]
    public void GenericNameLabelsDoNotProducePeople(string text) => Assert.Empty(Values(text, "Person"));

    [Fact]
    public void NestedFindingsOfDifferentTypesCollapseToTheStrongerOne()
    {
        // The account number is also a valid-looking phone number; the labelled span wins.
        var spans = Detector.Detect("Account number: 4155550142").ToArray();
        Assert.Single(spans);
        Assert.Equal("Labelled identifier", spans[0].Type);
        Assert.Single(Detector.Detect("ssn = 123-45-6789"), s => s.Type == "Social Security number");
    }

    [Fact]
    public void ProfileReportsEveryRuleAndPhones()
    {
        var profile = Detector.Profile("Call 415-555-0142 or write to alice@example.com").ToArray();
        Assert.Contains(profile, p => p.Rule == "Phone" && p.Matches == 1);
        Assert.Contains(profile, p => p.Rule.StartsWith("Email") && p.Matches == 1);
    }
}

public sealed class NameCoverageTests(PiiNameDetectionFixture fixture) : IClassFixture<PiiNameDetectionFixture>
{
    private string[] Names(string text) => fixture.Detector.Detect(text, default).Select(s => text.Substring(s.Start, s.Length)).ToArray();

    [Theory]
    [InlineData("From: Priya Raghunathan", "Priya Raghunathan")]
    [InlineData("Customer Olusegun Adebayo called.", "Olusegun Adebayo")]
    [InlineData("Customer Yuki Tanaka called.", "Yuki Tanaka")]
    [InlineData("Nguyễn Văn An attended the meeting.", "Nguyễn Văn An")]
    [InlineData("Contact: J. Robert Oppenheimer", "J. Robert Oppenheimer")]
    [InlineData("O'Brien, Patrick attended.", "O'Brien")]
    [InlineData("Jean-Luc Picard attended.", "Jean-Luc Picard")]
    [InlineData("JOHN SMITH attended the meeting.", "JOHN SMITH")]
    [InlineData("NAME: MARIA HERNANDEZ DOB: 1984-03-11", "MARIA HERNANDEZ")]
    public void MultiPieceUppercaseAndPunctuatedNamesKeepTheirFullSpan(string text, string expected) =>
        Assert.Contains(expected, Names(text));

    [Theory]
    [InlineData("Smith, John attended the meeting.", "Smith")]
    public void TrailingPunctuationIsNotPartOfTheName(string text, string expected)
    {
        var names = Names(text);
        Assert.Contains(expected, names);
        Assert.DoesNotContain(expected + ",", names);
    }

    [Theory]
    [InlineData("Regards, Tom")]
    [InlineData("Best regards,")]
    [InlineData("Send the PDF to IBM and NASA today.")]
    [InlineData("The FBI and CIA met with ACME CORP.")]
    [InlineData("Modified Tue Aug 25 18:21:14 EDT 2026")]
    [InlineData("Microsoft Excel crashed again.")]
    [InlineData("Bank of America statement.")]
    public void ClosingsAcronymsDatesAndOrganizationsAreNotPeople(string text) => Assert.Empty(Names(text));

    [Fact]
    public void TruecasingPreservesLengthAndLeavesAcronymsAndLabels()
    {
        Assert.Equal("John Smith AND DOB", NameDetector.Truecase("JOHN SMITH AND DOB"));
        Assert.Equal("Sent EDT via PDF", NameDetector.Truecase("Sent EDT via PDF"));
        Assert.Equal("O'Brien", NameDetector.Truecase("O'BRIEN"));
        Assert.Equal("NAME: Maria Hernandez DOB: 1984-03-11", NameDetector.Truecase("NAME: MARIA HERNANDEZ DOB: 1984-03-11"));
        foreach (string text in new[] { "Ärzte OHNE GRENZEN e.V.", "MARIA HERNANDEZ", "plain lowercase text", "" })
            Assert.Equal(text.Length, NameDetector.Truecase(text).Length);
    }

    [Fact]
    public void LabelledTableCellsNeedNoModelInference()
    {
        const string text = "[Table] E000001 | Full name: Maria Hernandez | maria@example.com | 503-555-0142 | SSN: 123-45-6789 | DOB: 1984-03-11 | 911 Kingsway Lane, Portland OR 97205 | Passport number: AB1234567 |";
        Assert.Empty(fixture.Detector.Detect(text, default));
    }

    [Fact]
    public void InspectExposesPerTokenDecisions()
    {
        var tokens = fixture.Detector.Inspect("Maria Hernandez called.");
        Assert.Equal(1, tokens[0].Label);
        Assert.Equal("Maria", tokens[0].Piece);
        Assert.True(tokens[0].Score > .9);
    }
}

public sealed class ExtractionCoverageTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("PiiCoverage-").FullName;
    public void Dispose() => Directory.Delete(_temp, true);

    private async Task<(ScanSummary Summary, Finding[] Findings, ScanIssue[] Issues)> Scan(ScanOptions? options = null)
    {
        var findings = new ConcurrentBag<Finding>(); var issues = new ConcurrentBag<ScanIssue>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(_temp, options ?? new(Ocr: false, Names: false),
            new InlineProgress<ScanUpdate>(u => { foreach (var f in u.Findings ?? []) findings.Add(f); foreach (var i in u.Issues ?? []) issues.Add(i); }), timeout.Token);
        return (summary, findings.ToArray(), issues.ToArray());
    }

    [Fact]
    public async Task XmlAttributesAndHtmlLinkTargetsAreChecked()
    {
        File.WriteAllText(Path.Combine(_temp, "users.xml"), "<users><user email=\"attr@example.com\">text@example.net</user></users>");
        File.WriteAllText(Path.Combine(_temp, "page.html"), "<html><body><a href=\"mailto:href@example.com\">Contact</a> visible@example.org" +
            "<table><tr><th>ssn</th><th>passport_number</th></tr><tr><td>123456789</td><td>AB1234567</td></tr></table></body></html>");
        File.WriteAllText(Path.Combine(_temp, "events.jsonl"), "{\"email\":\"json@example.com\",\"ssn\":\"123-45-6789\"}\n");
        var result = await Scan();
        Assert.Empty(result.Issues);
        foreach (string email in new[] { "attr@example.com", "text@example.net", "href@example.com", "visible@example.org", "json@example.com" })
            Assert.Single(result.Findings, f => f.Type == "Email" && f.Value == email);
        Assert.Contains(result.Findings, f => f.FileName == "page.html" && f.Type == "Social Security number" && f.Value == "123456789");
        Assert.Contains(result.Findings, f => f.FileName == "page.html" && f.Value == "Passport number: AB1234567");
        Assert.Contains(result.Findings, f => f.FileName == "events.jsonl" && f.Type == "Social Security number");
    }

    [Fact]
    public async Task UnknownBinaryFormatsFallBackToPrintableStrings()
    {
        byte[] noise = new byte[64];
        File.WriteAllBytes(Path.Combine(_temp, "capture.pcap"), [.. noise, .. Encoding.ASCII.GetBytes("binary@example.com"), .. noise,
            .. Encoding.Unicode.GetBytes("wide@example.net"), .. noise, .. Encoding.ASCII.GetBytes("Card 4111 1111 1111 1111"), .. noise]);
        var result = await Scan();
        Assert.Contains(result.Findings, f => f.Value == "binary@example.com" && f.Location.StartsWith("binary strings · byte "));
        Assert.Contains(result.Findings, f => f.Value == "wide@example.net");
        Assert.Contains(result.Findings, f => f.Type == "Payment card");
        Assert.Contains(result.Issues, i => i.Message.StartsWith("Unrecognized format"));
    }

    [Fact]
    public async Task BinaryStringsSegmentLargeFilesAndReportLimits()
    {
        using (var output = File.Create(Path.Combine(_temp, "dump.bin")))
        {
            var line = Encoding.ASCII.GetBytes("record with owner tail@example.org and padding text ".PadRight(120, 'x') + "\0\0");
            for (int i = 0; i < 2000; i++) output.Write(line);
        }
        var parts = new List<ExtractedPart>();
        await foreach (var part in BinaryStrings.ReadAsync(Path.Combine(_temp, "dump.bin"), "", 50_000, default)) parts.Add(part);
        Assert.True(parts.Count(p => p.Issue is null) >= 2);
        Assert.All(parts.Where(p => p.Issue is null), p => Assert.StartsWith("binary strings · byte", p.Location));
        Assert.Contains(parts, p => p.Issue is not null && p.Issue.Contains("limit"));
    }

    [Fact]
    public async Task WorkerCountAndPhoneRegionsFlowThroughScanOptions()
    {
        File.WriteAllText(Path.Combine(_temp, "berlin.txt"), "Call 030 1234567 now");
        Assert.DoesNotContain((await Scan(new(Ocr: false, Names: false, Workers: 8))).Findings, f => f.Type == "Phone");
        Assert.Single((await Scan(new(Ocr: false, Names: false, Workers: 1, PhoneRegions: "DE"))).Findings, f => f.Type == "Phone");
        Assert.InRange(ScanOptions.DefaultWorkers, 2, 4);
        Assert.Equal(8, ScanOptions.MaxWorkers);
    }

    [Fact]
    public void EvaluatorAcceptsTheNewTypes()
    {
        string path = Path.Combine(_temp, "cases.jsonl");
        File.WriteAllLines(path, [
            "{\"text\":\"key AKIAIOSFODNN7EXAMPLE\",\"entities\":[{\"type\":\"Credential\",\"start\":4,\"length\":20}]}",
            "{\"text\":\"MAC 00:1A:2B:3C:4D:5E\",\"entities\":[{\"type\":\"MAC address\",\"start\":4,\"length\":17}]}",
            "{\"text\":\"btc 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"entities\":[{\"type\":\"Crypto wallet\",\"start\":4,\"length\":34}]}",
            "{\"text\":\"CPF 123.456.789-09\",\"entities\":[{\"type\":\"National ID\",\"start\":4,\"length\":14}]}"]);
        var report = AccuracyEvaluation.Run(path, TestPaths.Assets, namesEnabled: false);
        Assert.Equal(new AccuracyCounts(4, 0, 0), report.Micro);
    }
}
