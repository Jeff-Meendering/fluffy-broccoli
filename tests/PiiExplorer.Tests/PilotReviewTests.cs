using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using PiiExplorer.Core;
using Xunit;

namespace PiiExplorer.Tests;

public sealed class PilotReviewTests : IDisposable
{
    private readonly string _temp = Directory.CreateTempSubdirectory("PiiPilotReview-").FullName;
    public void Dispose() => Directory.Delete(_temp, true);

    [Theory]
    [InlineData("host abcd:efab:abcd:efab:abcd:efab:abcd:efab", "IP address")]
    [InlineData("POB 123", "Street address")]
    [InlineData("patient number: 123456", "Labelled identifier")]
    [InlineData("member number: 123456", "Labelled identifier")]
    [InlineData("medical record number: 123456", "Labelled identifier")]
    [InlineData("GB82 WEST 1234 5698 7654 32", "IBAN")]
    [InlineData("alice@example.xn--p1ai", "Email")]
    [InlineData("alice@example.XN--P1AI", "Email")]
    public void FastGatesDoNotExcludeSupportedForms(string text, string type) =>
        Assert.Contains(new PatternDetector().Detect(text), s => s.Type == type);

    [Fact]
    public void AlphanumericIbanNeedsOnlyItsCheckDigitsToPassTheFastGate()
    {
        // Synthetic Qatar IBAN: four bank letters and 21 alphanumeric account
        // characters. A real account's existence is outside offline validation.
        string iban = Enumerable.Range(2, 97).Select(n => $"QA{n:D2}" + new string('A', 25)).Single(PatternDetector.Iban);
        Assert.Single(new PatternDetector().Detect(iban), s => s.Type == "IBAN");
    }

    [Theory]
    [InlineData("110105000001010020")]
    [InlineData("00000101-1234")]
    public void InvalidYearsCannotAbortDetectionOfOtherEvidence(string value)
    {
        var spans = new PatternDetector().Detect(value + " contact alice@example.com").ToArray();
        Assert.Contains(spans, s => s.Type == "Email");
        Assert.DoesNotContain(spans, s => s.Type == "National ID");
    }

    [Theory]
    [InlineData("NHS 000 000 0000")]
    [InlineData("TFN 000 000 000")]
    public void ZeroFilledNationalIdentifiersAreNotValidated(string text) =>
        Assert.DoesNotContain(new PatternDetector().Detect(text), s => s.Type == "National ID");

    [Theory]
    [InlineData("NHS number: 943 476 5919", false)]
    [InlineData("NHS helpline: 943 476 5919", true)]
    public void AnExplicitIdLabelPreventsAnIncidentalPhoneMatch(string text, bool phone) =>
        Assert.Equal(phone, new PatternDetector().Detect(text).Any(s => s.Type == "Phone"));

    [Fact]
    public void EverySmokeAnnotationMatchesThePatternEvidence()
    {
        var detector = new PatternDetector();
        foreach (string line in File.ReadLines(Path.Combine(TestPaths.Root, "tests/fixtures/accuracy-smoke.jsonl")))
        {
            var item = JsonSerializer.Deserialize<EvaluationCase>(line, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
            var actual = detector.Detect(item.Text).Select(s => new ExpectedEntity(s.Type, s.Start, s.Length)).ToHashSet();
            Assert.True(actual.SetEquals(item.Entities), $"Synthetic smoke annotations differ for: {item.Text}");
        }
    }

    [Fact]
    public void OverlapResolutionHandlesNonMonotonicEndPositions()
    {
        EntitySpan[] candidates = [new("Labelled identifier", 0, 100, .8, "Pattern"),
            new("Labelled identifier", 10, 5, .9, "Pattern"), new("Phone", 20, 10, .5, "Pattern")];
        Assert.DoesNotContain(PatternDetector.Resolve(candidates), s => s.Type == "Phone");
    }

    [Fact]
    public void EarlierEvidenceSurvivesALaterRegexTimeout()
    {
        using var iterator = PatternDetector.Resolve(Partial()).GetEnumerator();
        Assert.True(iterator.MoveNext());
        Assert.Equal("Email", iterator.Current.Type);
        Assert.Throws<RegexMatchTimeoutException>(() => iterator.MoveNext());
        static IEnumerable<EntitySpan> Partial()
        {
            yield return new("Email", 0, 17, .99, "Pattern");
            throw new RegexMatchTimeoutException();
        }
    }

    // BIP-350 official v0-v16 examples, including a short future-version address.
    // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    [Theory]
    [InlineData("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")]
    [InlineData("BC1SW50QGDZ25J")]
    public void SegwitAddressesRequireMoreThanAGenericChecksum(string value) =>
        Assert.Contains(new PatternDetector().Detect(value), s => s.Type == "Crypto wallet");

    [Theory]
    [InlineData("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh")] // v0 with Bech32m
    [InlineData("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7k8e76x7")] // v1 with Bech32
    [InlineData("bc1gmk9yu")] // empty data
    public void SegwitWrongEncodingsAreRejected(string value) =>
        Assert.Equal(0, CryptoWallets.Bech32("", 0, value));

    [Fact]
    public async Task BinaryRunsKeepTheirEncodingAndExactByteStart()
    {
        byte[] ascii = Encoding.ASCII.GetBytes("alice@example.com");
        byte[] wide = Encoding.Unicode.GetBytes("bob@example.net");
        var parts = await Read([0, 0, 0, .. ascii, 0, 0, .. wide, 0, 0]);
        var first = Assert.Single(parts, p => p.Text == "alice@example.com");
        var second = Assert.Single(parts, p => p.Text == "bob@example.net");
        Assert.Equal("binary strings · byte 3 (ASCII)", first.Location);
        Assert.Equal($"binary strings · byte {3 + ascii.Length + 2} (UTF-16LE)", second.Location);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BinaryLimitIsStrictIncludingTheFinalRun(bool wide)
    {
        string text = new('x', 100_000);
        var parts = await Read((wide ? Encoding.Unicode : Encoding.ASCII).GetBytes(text), 50_000);
        Assert.Equal(50_000, parts.Sum(p => p.Text.Length));
        Assert.Single(parts, p => p.Issue is not null);
        Assert.All(parts, p => Assert.InRange(p.Text.Length, 0, 24_000));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BinaryOverlapRetainsAnIdentifierAcrossAChunkBoundary(bool wide)
    {
        string text = new string('x', 23_989) + " alice@example.com tail";
        var parts = await Read((wide ? Encoding.Unicode : Encoding.ASCII).GetBytes(text));
        Assert.Contains(parts, p => p.Text.Contains("alice@example.com"));
        Assert.DoesNotContain(parts, p => p.Issue is not null);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BinaryChunksDoNotInventAValidLookingEmailPrefix(bool wide)
    {
        string text = new string('x', 23_983) + " alice@example.com tail";
        var parts = await Read((wide ? Encoding.Unicode : Encoding.ASCII).GetBytes(text));
        var detector = new PatternDetector();
        var emails = parts.SelectMany(p => detector.Detect(p.Text).Where(s => s.Type == "Email")
            .Select(s => p.Text.Substring(s.Start, s.Length))).Distinct().ToArray();
        Assert.Equal(new[] { "alice@example.com" }, emails);
    }

    [Fact]
    public async Task BinaryRunsDoNotInventLabelContextAcrossGaps()
    {
        var parts = await Read([.. Encoding.ASCII.GetBytes("patient number:"), 0, 1, 0,
            .. Encoding.ASCII.GetBytes("123456")]);
        Assert.Equal(2, parts.Count);
        Assert.DoesNotContain(parts.SelectMany(p => new PatternDetector().Detect(p.Text)), s => s.Type == "Labelled identifier");
    }

    private async Task<List<ExtractedPart>> Read(byte[] bytes, long limit = 200_000)
    {
        string path = Path.Combine(_temp, Guid.NewGuid() + ".bin");
        await File.WriteAllBytesAsync(path, bytes);
        var parts = new List<ExtractedPart>();
        await foreach (var part in BinaryStrings.ReadAsync(path, "", limit, default)) parts.Add(part);
        return parts;
    }
}
