using System.Collections.Concurrent;
using PiiExplorer.App;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class DetectionRobustnessTests
{
    [Theory]
    [InlineData("Transfer GB82 WEST 1234 5698 7654 32 REF approved", "GB82 WEST 1234 5698 7654 32")]
    [InlineData("Transfer gb82 west 1234 5698 7654 32 today", "gb82 west 1234 5698 7654 32")]
    [InlineData("DE89 3704 0044 0532 0130 00 TOTAL", "DE89 3704 0044 0532 0130 00")]
    [InlineData("IBAN: GB82\u00a0WEST\u202f1234 5698 7654 32", "GB82\u00a0WEST\u202f1234 5698 7654 32")]
    public void CountrySpecificIbanEndsDoNotSwallowFollowingWords(string text, string value)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == "IBAN");
        Assert.Equal(value, text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("ZZ82370400440532013000")]
    [InlineData("GB82WEST123456987654321")]
    [InlineData("GB82 WEST 1234 5698 7654 33")]
    [InlineData("GBXXWEST12345698765432")]
    public void InvalidIbanCandidatesAreRejected(string text)
    {
        Assert.False(PatternDetector.Iban(text));
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "IBAN");
    }

    [Theory]
    [InlineData("Ｅｍａｉｌ： ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ", "Email")]
    [InlineData("Send to ali\u200bce@example.com now", "ali\u200bce@example.com", "Email")]
    [InlineData("Contact ali\u2060ce@exam\u00adple.com", "ali\u2060ce@exam\u00adple.com", "Email")]
    [InlineData("SSN: ١٢٣٤٥٦٧٨٩", "١٢٣٤٥٦٧٨٩", "Social Security number")]
    [InlineData("SSN: １２３－４５－６７８９", "１２３－４５－６７８９", "Social Security number")]
    [InlineData("SSN: 123\u201145\u20116789", "123\u201145\u20116789", "Social Security number")]
    [InlineData("Card: ４１１１ １１１１ １１１１ １１１１", "４１１１ １１１１ １１１１ １１１１", "Payment card")]
    [InlineData("emoji 😀 alice\u200b@example.com", "alice\u200b@example.com", "Email")]
    public void NormalizedDetectionRetainsExactOriginalEvidence(string text, string value, string type)
    {
        var span = Assert.Single(new PatternDetector().Detect(text), s => s.Type == type);
        Assert.Equal(value, text.Substring(span.Start, span.Length));
        Assert.Equal(text.IndexOf(value, StringComparison.Ordinal), span.Start);
        Assert.Contains("Unicode normalized", span.Method);
    }

    [Fact]
    public void UnchangedEvidenceDoesNotClaimNormalization()
    {
        const string text = "Note\u200b: alice@example.com";
        var span = Assert.Single(new PatternDetector().Detect(text));
        Assert.Equal("Pattern", span.Method);
        Assert.Equal("alice@example.com", text.Substring(span.Start, span.Length));
    }

    [Theory]
    [InlineData("\u200b\u2060\u00ad")]
    [InlineData("Order: １２３４５６７８９")]
    [InlineData("Card: ４１１１ １１１１ １１１１ １１１２")]
    public void NormalizationDoesNotPromoteNegativeControls(string text) => Assert.Empty(new PatternDetector().Detect(text));

    [Theory]
    [InlineData("csv", ",")]
    [InlineData("tsv", "\t")]
    public async Task TableHeadersPreserveSensitiveSemanticsAndMultipleNameColumns(string extension, string separator)
    {
        string temp = Directory.CreateTempSubdirectory("PiiTableContext-").FullName;
        try
        {
            string[] headers = ["ssn", "passport_number", "account_number", "tax_id", "name", "full_name", "order_id"];
            string[] row = ["123456789", "AB1234567", "12345678", "12-3456789", "Maria Hernandez", "David Okonkwo", "987654321"];
            File.WriteAllText(Path.Combine(temp, "table." + extension), string.Join(separator, headers) + "\n" + string.Join(separator, row));
            var findings = new ConcurrentBag<Finding>();
            var summary = await new ScanEngine(TestPaths.Assets).ScanAsync(temp, new(Ocr: false),
                new InlineProgress<ScanUpdate>(u => { foreach (var f in u.Findings ?? []) findings.Add(f); }), default);
            Assert.Equal(0, summary.Issues);
            Assert.Contains(findings, f => f.Type == "Social Security number" && f.Value == "123456789");
            Assert.Contains(findings, f => f.Value == "Passport number: AB1234567");
            Assert.Contains(findings, f => f.Value == "Account number: 12345678");
            Assert.Contains(findings, f => f.Value == "Tax ID: 12-3456789");
            Assert.Contains(findings, f => f.Type == "Person" && f.Value == "Maria Hernandez");
            Assert.Contains(findings, f => f.Type == "Person" && f.Value == "David Okonkwo");
            Assert.DoesNotContain(findings, f => f.Value == "987654321");
        }
        finally { Directory.Delete(temp, true); }
    }
}
