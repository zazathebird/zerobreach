using System.Globalization;
using System.Text;
using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

/// <summary>
/// Same bytes, same output, whatever the host looks like. InvariantGlobalization is on
/// package-wide (Directory.Build.props), so a named real culture either throws or behaves
/// invariantly and would prove nothing — the hostile cultures here are clones of the invariant
/// culture with their separators and signs mutated, which bites regardless (the Q1 handoff
/// records why; anyone copying this technique should read that entry).
/// </summary>
public class DeterminismTests
{
    private static CultureInfo Hostile(string decimalSeparator, string negativeSign, string groupSeparator)
    {
        var culture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
        culture.NumberFormat.NumberDecimalSeparator = decimalSeparator;
        culture.NumberFormat.NegativeSign = negativeSign;
        culture.NumberFormat.NumberGroupSeparator = groupSeparator;
        culture.DateTimeFormat.TimeSeparator = "·";
        return culture;
    }

    private static readonly Func<CultureInfo>[] HostileCultures =
    [
        () => (CultureInfo)CultureInfo.InvariantCulture.Clone(),
        () => Hostile(",", "⊖", "."),
        () => Hostile("٫", "−", " "),
    ];

    private static string RunUnder(CultureInfo culture, Func<string> dump)
    {
        var previous = CultureInfo.CurrentCulture;
        var previousUi = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
            return dump();
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }

    // Everything observable about a result, rendered with explicit invariant formatting in the
    // test so that any culture leak inside the library shows up as a byte difference here.
    private static string Dump(TextResult<DetectionResult> result)
    {
        var sb = new StringBuilder();
        sb.Append(result.State).Append('|').Append(result.Reason).Append('|');
        var v = result.Value!;
        sb.Append(v.Encoding).Append('|').Append(v.Confidence).Append('|')
            .Append(v.MarkLength.ToString(CultureInfo.InvariantCulture)).Append('|')
            .Append(v.HintOutcome).Append('|')
            .Append(v.NulByteCount.ToString(CultureInfo.InvariantCulture)).Append('|')
            .Append(v.ControlByteCount.ToString(CultureInfo.InvariantCulture)).Append('|');
        foreach (var c in v.SingleByteCandidates)
        {
            sb.Append(c.Encoding).Append('=')
                .Append(c.Score.ToString(CultureInfo.InvariantCulture)).Append('/')
                .Append(c.ScorePerNonAsciiByte.ToString("R", CultureInfo.InvariantCulture)).Append(';');
        }

        foreach (var r in v.SampledRanges)
        {
            sb.Append(r.Offset.ToString(CultureInfo.InvariantCulture)).Append('+')
                .Append(r.Length.ToString(CultureInfo.InvariantCulture)).Append(';');
        }

        return sb.ToString();
    }

    private static string Dump(TextResult<DecodedText> result)
    {
        var sb = new StringBuilder();
        sb.Append(result.State).Append('|').Append(result.Reason).Append('|')
            .Append(result.Position?.ToString(CultureInfo.InvariantCulture)).Append('|');
        var v = result.Value!;
        sb.Append(v.Text).Append('|').Append(v.Encoding).Append('|')
            .Append(v.MarkLength.ToString(CultureInfo.InvariantCulture)).Append('|')
            .Append(v.SourceReplacementCharacterCount.ToString(CultureInfo.InvariantCulture)).Append('|');
        foreach (var r in v.UndecodableRuns)
        {
            sb.Append(r.ByteOffset).Append(',').Append(r.ByteLength).Append(',')
                .Append(r.CharIndex).Append(',').Append(r.CharLength).Append(';');
        }

        foreach (var s in v.UnpairedSurrogates)
        {
            sb.Append(s.ByteOffset).Append(',').Append(s.CharIndex).Append(',')
                .Append(((int)s.Value).ToString(CultureInfo.InvariantCulture)).Append(';');
        }

        return sb.ToString();
    }

    private static readonly (string Name, byte[] Bytes)[] DetectionCorpus =
    [
        ("utf8-marked", TextFixtures.Concat(TextFixtures.Utf8Mark, TextFixtures.Utf8("héllo — ω"))),
        ("utf8-markless", TextFixtures.Utf8("naïve café")),
        ("ascii", TextFixtures.Ascii("plain text")),
        ("utf16le", TextFixtures.Utf16("null bytes on one side", bigEndian: false, withMark: false)),
        ("cp1252", TextFixtures.PageEncode("l’exception — « détails »", TextEncodingKind.Windows1252)),
        ("cp1251", TextFixtures.PageEncode("ђакон и ѓерѓеф", TextEncodingKind.Windows1251)),
        ("tie", TextFixtures.PageEncode("réserve développée", TextEncodingKind.Windows1252)),
        ("hostile", TextFixtures.EveryPageScoresBadly(4096)),
    ];

    [Fact]
    public void DetectionIsByteIdenticalUnderHostileCultures()
    {
        foreach (var (name, bytes) in DetectionCorpus)
        {
            var baseline = RunUnder(CultureInfo.InvariantCulture, () => Dump(TextDetector.Detect(bytes)));
            foreach (var makeCulture in HostileCultures)
            {
                var under = RunUnder(makeCulture(), () => Dump(TextDetector.Detect(bytes)));
                Assert.True(baseline == under, $"{name}: detection changed under a hostile culture");
            }
        }
    }

    [Fact]
    public void DecodingIsByteIdenticalUnderHostileCultures()
    {
        var corpus = new (TextEncodingKind Kind, byte[] Bytes)[]
        {
            (TextEncodingKind.Utf8, TextFixtures.Concat(TextFixtures.Utf8("ok"), [0xFF, 0xFE], TextFixtures.Utf8("go"))),
            (TextEncodingKind.Utf16LittleEndian, TextFixtures.Concat(TextFixtures.Utf16("pair\U0001F600", false, true), [0x41])),
            (TextEncodingKind.Windows1250, TextFixtures.PageEncode("žluťoučký", TextEncodingKind.Windows1250)),
            (TextEncodingKind.Cp437, [0x81, 0x9B, 0xE0, 0xB0]),
        };

        foreach (var (kind, bytes) in corpus)
        {
            var baseline = RunUnder(CultureInfo.InvariantCulture, () => Dump(TextDecoder.DecodeReporting(bytes, kind)));
            foreach (var makeCulture in HostileCultures)
            {
                var under = RunUnder(makeCulture(), () => Dump(TextDecoder.DecodeReporting(bytes, kind)));
                Assert.True(baseline == under, $"{kind}: decoding changed under a hostile culture");
            }

            var strictBaseline = RunUnder(CultureInfo.InvariantCulture, () => Dump(TextDecoder.DecodeStrict(bytes, kind)));
            foreach (var makeCulture in HostileCultures)
            {
                var under = RunUnder(makeCulture(), () => Dump(TextDecoder.DecodeStrict(bytes, kind)));
                Assert.True(strictBaseline == under, $"{kind}: strict decoding changed under a hostile culture");
            }
        }
    }

    // The negative control: prove the hostile cultures are not inert, so the equalities above
    // are evidence rather than a vacuous pass. An unguarded negative-number format changes.
    [Fact]
    public void TheHostileCulturesWouldActuallyChangeAnUnguardedFormat()
    {
        var invariant = RunUnder(CultureInfo.InvariantCulture, () => (-42).ToString());
        var hostile = RunUnder(Hostile(",", "⊖", "."), () => (-42).ToString());

        Assert.NotEqual(invariant, hostile);
        Assert.Equal("⊖42", hostile);
    }

    // The assertion that catches a tie broken by enumeration order: score with the candidate
    // list reversed and the ranking must not move. Reverted form: sort by score alone (drop the
    // canonical-index tie-break in CodePageScorer) and the tied buffer's ranking follows the
    // evaluation order, failing here.
    [Fact]
    public void ScoringWithTheCandidateListReversedPicksTheSameWinnerAndRanking()
    {
        var buffers = new[]
        {
            TextFixtures.PageEncode("réserve développée", TextEncodingKind.Windows1252), // full tie
            TextFixtures.PageEncode("ђакон и ѓерѓеф", TextEncodingKind.Windows1251),     // clear winner
        };

        foreach (var bytes in buffers)
        {
            var ranges = new[] { new SampledRange(0, bytes.Length) };
            var forward = CodePageScorer.Score(bytes, ranges, null, CodePage.CanonicalOrder);
            var reversed = CodePageScorer.Score(bytes, ranges, null, CodePage.CanonicalOrder.Reverse().ToArray());

            Assert.Equal(
                forward.Ranked.Select(c => (c.Encoding, c.Score)),
                reversed.Ranked.Select(c => (c.Encoding, c.Score)));
        }
    }

    [Fact]
    public void TheSameInputTwiceProducesByteIdenticalResults()
    {
        foreach (var (name, bytes) in DetectionCorpus)
        {
            Assert.True(
                Dump(TextDetector.Detect(bytes)) == Dump(TextDetector.Detect(bytes)),
                $"{name}: two detections of the same bytes disagreed");
        }

        var decodeBytes = TextFixtures.Concat(TextFixtures.Utf8("same"), [0xC0], TextFixtures.Utf8("twice"));
        Assert.Equal(
            Dump(TextDecoder.DecodeReporting(decodeBytes, TextEncodingKind.Utf8)),
            Dump(TextDecoder.DecodeReporting(decodeBytes, TextEncodingKind.Utf8)));
    }
}
