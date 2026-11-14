using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class PiiPatternDetectionTests
{
    [Theory]
    [InlineData("IP: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    [InlineData("IP: 2001:db8::1.", "2001:db8::1")]
    [InlineData("https://[2001:DB8::1]:443/path", "2001:DB8::1")]
    [InlineData("IP: ::1", "::1")]
    [InlineData("IP: ::", "::")]
    [InlineData("IP: ::ffff:192.0.2.128", "::ffff:192.0.2.128")]
    [InlineData("IP: fe80::1%12", "fe80::1%12")]
    [InlineData("Subnet: 2001:db8::/32", "2001:db8::")]
    [InlineData("IP: 192.0.2.1", "192.0.2.1")]
    public void IpAddressFormsHaveOneExactSpan(string text, string expected)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "IP address");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
        Assert.Equal(text.IndexOf(expected, StringComparison.Ordinal), span.Start);
    }

    [Theory]
    [InlineData("2001:db8:::1")]
    [InlineData("2001:db8::1::2")]
    [InlineData("2001:db8:1:2:3:4:5:6:7")]
    [InlineData("2001:db8::12345")]
    [InlineData("2001:db8::xyz")]
    [InlineData("fe80::1%invalid")]
    [InlineData("::ffff:999.0.2.1")]
    [InlineData("12:34:56")]
    [InlineData("aa:bb:cc:dd:ee:ff")]
    public void InvalidIpTokensDoNotProduceFragments(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "IP address");

    [Theory]
    [InlineData("SSN: 123456789", "123456789")]
    [InlineData("ssn = 000000000", "000000000")]
    [InlineData("SSN # 666123456", "666123456")]
    [InlineData("Social Security number: 900123456", "900123456")]
    [InlineData("social_security_number=123456789", "123456789")]
    [InlineData("Social Security No. 123456789", "123456789")]
    [InlineData("unissued: 000-00-0000", "000-00-0000")]
    [InlineData("synthetic: 666-12-3456", "666-12-3456")]
    [InlineData("synthetic: 900-12-3456", "900-12-3456")]
    public void ContextualSsnAndBroadFormattedCandidatesArePreserved(string text, string expected)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Social Security number");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("Order: 123456789")]
    [InlineData("SSN: 1234567890")]
    [InlineData("SSN: 123456789A")]
    [InlineData("SSN:\r\nOrder 123456789")]
    [InlineData("SSN: 12345678")]
    public void UndashedSsnRequiresLabelAndExactlyNineDigits(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "Social Security number");

    [Theory]
    [InlineData("Passport number: AB1234567 expires tomorrow", "Passport number: AB1234567")]
    [InlineData("Passport No. = AB1234567 | other", "Passport No. = AB1234567")]
    [InlineData("Driver’s license number: D123-456-789, CA", "Driver’s license number: D123-456-789")]
    [InlineData("drivers license: D1234567\r\nNext row", "drivers license: D1234567")]
    [InlineData("Driving licence no.: AB 1234567 |", "Driving licence no.: AB 1234567")]
    [InlineData("Passport: AB1234567", "Passport: AB1234567")]
    [InlineData("Account number: 123456789 |", "Account number: 123456789")]
    [InlineData("Tax ID: 12-3456789", "Tax ID: 12-3456789")]
    public void CommonIdentifierLabelsStopAtTheValue(string text, string expected)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Labelled identifier");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("Passport number: pending")]
    [InlineData("Driver's license: expired")]
    [InlineData("Passport number:\r\nOrder 1234567")]
    [InlineData("Passport number: AB123456789012345678901234567890")]
    public void IdentifierLabelsDoNotConsumeStatusProseOrOversizedTokens(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "Labelled identifier");

    [Theory]
    [InlineData("prefix\r\nFull name: Maria Hernandez\r\nnext", "Maria Hernandez")]
    [InlineData("[Table] FULL  NAME :\tAnne-Marie O’Neill   | other", "Anne-Marie O’Neill")]
    [InlineData("Full name: 李", "李")]
    public void LabelledNamesPreserveExactOffsets(string text, string expected)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Person");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
        Assert.Equal(text.IndexOf(expected, StringComparison.Ordinal), span.Start);
    }

    [Theory]
    [InlineData("Full name:\r\nMaria Hernandez")]
    [InlineData("Full name: | Maria Hernandez")]
    public void EmptyNameFieldsDoNotConsumeTheNextLineOrCell(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "Person");

    [Theory]
    [InlineData("a..b@example.com")]
    [InlineData(".alice@example.com")]
    [InlineData("alice.@example.com")]
    [InlineData("alice@example.com_bad")]
    [InlineData("alice@example.com-bad-")]
    [InlineData("alice@example.com..invalid")]
    [InlineData("alice@-example.com")]
    public void MalformedEmailsDoNotYieldValidSubstrings(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "Email");

    [Theory]
    [InlineData("Contact <o'neill+work@example.co.uk>.", "o'neill+work@example.co.uk")]
    [InlineData("Email: alice@example.com. Next sentence.", "alice@example.com")]
    [InlineData("Email: josé@exämple.org", "josé@exämple.org")]
    [InlineData("email=alice@example.com", "alice@example.com")]
    [InlineData("keyword=Comment, value=metadata.only@example.net", "metadata.only@example.net")]
    [InlineData("Contact a=b@example.com", "a=b@example.com")]
    public void EmailsRetainUsefulFormatsAndExcludePunctuation(string text, string expected)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Email");
        Assert.Equal(expected, text.Substring(span.Start, span.Length));
    }

    [Fact]
    public void OversizedEmailComponentsAreRejected()
    {
        foreach (string text in new[] { new string('a', 65) + "@example.com", "a@" + new string('b', 64) + ".com" })
            Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "Email");
    }

    [Theory]
    [InlineData("4111111111111111", true)]
    [InlineData("4111 1111 1111 1111", true)]
    [InlineData("4111-1111-1111-1111", true)]
    [InlineData("4111\u00a01111\u00a01111\u00a01111", true)]
    [InlineData("4111\u202f1111\u202f1111\u202f1111", true)]
    [InlineData("4111x1111x1111x1111", false)]
    [InlineData("4111\n1111\n1111\n1111", false)]
    [InlineData("0000000000000000", false)]
    [InlineData("4111111111111112", false)]
    public void CardValidationDoesNotDiscardArbitraryCharacters(string text, bool valid) =>
        Assert.Equal(valid, PatternDetector.Luhn(text));

    [Fact]
    public void NonbreakingSpacesInCardsPreserveOffsets()
    {
        const string card = "4111\u00a01111\u00a01111\u00a01111";
        const string text = "Card: " + card + ".";
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Payment card");
        Assert.Equal(card, text.Substring(span.Start, span.Length));
    }

    [Fact]
    public void LongNonEmailTokensDoNotHideLaterFindings()
    {
        // Each rule has a two-second timeout: this previously caused quadratic email backtracking.
        string text = new string('!', 100_000) + " end@example.com";
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "Email");
        Assert.Equal("end@example.com", text.Substring(span.Start, span.Length));
    }
}

public sealed class PiiNameDetectionFixture : IDisposable
{
    public NameDetector Detector { get; } = new(TestPaths.Assets);
    public void Dispose() => Detector.Dispose();
}

public sealed class PiiNameDetectionTests(PiiNameDetectionFixture fixture) : IClassFixture<PiiNameDetectionFixture>
{
    [Theory]
    [InlineData("[Table] Full name: Maria Hernandez | notes: David Okonkwo called.")]
    [InlineData("[Table] Full name: Maria Hernandez | David Okonkwo called.")]
    public void TableNotesRetainNamesAtOriginalOffsets(string text)
    {
        var spans = fixture.Detector.Detect(text, default);
        Assert.Contains(spans, s => s.Start == text.IndexOf("David", StringComparison.Ordinal) && s.Length == "David Okonkwo".Length);
        Assert.DoesNotContain(spans, s => text.Substring(s.Start, s.Length) == "Maria Hernandez");
    }

    [Fact]
    public void PurelyStructuredTableRowsNeedNoModelDetections()
    {
        const string text = "[Table] E000001 | Full name: Maria Hernandez | maria@example.com | 415-555-0142 | 123-45-6789 | DOB: 1984-03-11 | 911 Kingsway Lane, Portland OR 97205 |";
        Assert.Empty(fixture.Detector.Detect(text, default));
    }

    [Theory]
    [InlineData("[Table] Maria Hernandez spoke with David Okonkwo about the delivery.\r\n")]
    [InlineData("[Table] Full name: (Dr) Maria Hernandez | David Okonkwo\r\n")]
    public void TableRowsWithoutAUsableNameLabelStillUseTheModel(string text)
    {
        var values = fixture.Detector.Detect(text, default).Select(s => text.Substring(s.Start, s.Length));
        Assert.Contains("Maria Hernandez", values);
        Assert.Contains("David Okonkwo", values);
    }

    [Fact]
    public void MaskedTableRowsPreserveFollowingProseOffsets()
    {
        const string text = "[Table] Full name: Other Person |\r\nMaria Hernandez spoke with David Okonkwo about the delivery.";
        var spans = fixture.Detector.Detect(text, default);
        Assert.Contains(spans, s => s.Start == text.IndexOf("Maria", StringComparison.Ordinal) && s.Length == "Maria Hernandez".Length);
        Assert.DoesNotContain(spans, s => s.Start < text.IndexOf("Maria", StringComparison.Ordinal));
    }

    [Fact]
    public void FailedWordPiecesRollBackToOneUnknownToken()
    {
        string word = new string('a', 99) + "\u08a0";
        string text = "Maria " + word + " David";
        var tokens = fixture.Detector.Tokenize(text);
        var unknown = Assert.Single(tokens, t => t.Start >= 6 && t.Start < 6 + word.Length);
        Assert.Equal(100, unknown.Id);
        Assert.Equal(6, unknown.Start);
        Assert.Equal(6 + word.Length, unknown.End);
        Assert.Contains(tokens, t => t.Start == text.IndexOf("David", StringComparison.Ordinal));
    }

    [Fact]
    public void OverlongWordsDoNotSpendTimeTryingEveryWordPiece()
    {
        string text = new string('a', 100_000);
        var token = Assert.Single(fixture.Detector.Tokenize(text));
        Assert.Equal(100, token.Id);
        Assert.Equal(0, token.Start);
        Assert.Equal(text.Length, token.End);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("12345")]
    [InlineData("[Table] Full name: Maria Hernandez |")]
    public void CancellationIsHonoredBeforeFastPaths(string text) =>
        Assert.Throws<OperationCanceledException>(() => fixture.Detector.Detect(text, new CancellationToken(true)));

    [Fact]
    public void CallersCannotCorruptCachedDetections()
    {
        const string text = "Maria Hernandez spoke with David Okonkwo about the delivery.";
        var first = fixture.Detector.Detect(text, default);
        Assert.NotEmpty(first);
        var expected = first.ToArray();
        first[0] = new("Person", 0, 1, 0, "Changed by caller");
        var second = fixture.Detector.Detect(text, default);
        Assert.Equal(expected, second);
        second[0] = first[0];
        Assert.Equal(expected, fixture.Detector.Detect(text, default));
    }

    [Fact]
    public void OverlappingPacketsKeepRepeatedNamesAtDistinctOffsets()
    {
        const string sentence = "Maria Hernandez spoke with David Okonkwo about the delivery. ";
        string text = string.Concat(Enumerable.Repeat(sentence, 60));
        var spans = fixture.Detector.Detect(text, default);
        Assert.Equal(spans.Length, spans.Select(s => (s.Start, s.Length)).Distinct().Count());
        for (int i = 0; i < 60; i++) {
            int offset = i * sentence.Length;
            Assert.Contains(spans, s => s.Start == offset && text.Substring(s.Start, s.Length) == "Maria Hernandez");
            Assert.Contains(spans, s => s.Start == offset + sentence.IndexOf("David", StringComparison.Ordinal) &&
                text.Substring(s.Start, s.Length) == "David Okonkwo");
        }
    }
}
