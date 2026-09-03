using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

public class MalformedAndBudgetTests
{
    private static ScanBudget SmallBudget(long maxInputBytes) => ScanBudget.Default with
    {
        MaxInputBytes = maxInputBytes,
    };

    // The budget canary pair: input past MaxInputBytes is refused with the budget named, and
    // input at the limit still works — the guard is shown to be quiet as well as loud.
    // Reverted form: drop the MaxInputBytes check and the first assertion sees Ok.
    [Fact]
    public void InputOverMaxInputBytesIsIncompleteWithTheBudgetNamed()
    {
        var bytes = TextFixtures.Ascii(new string('a', 1025));

        var detection = TextDetector.Detect(bytes, budget: SmallBudget(1024));
        Assert.Equal(TextResultState.Incomplete, detection.State);
        Assert.Contains("MaxInputBytes", detection.Reason);
        Assert.Same(bytes, detection.Value!.OriginalBytes);

        var decode = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Ascii, SmallBudget(1024));
        Assert.Equal(TextResultState.Incomplete, decode.State);
        Assert.Contains("MaxInputBytes", decode.Reason);
    }

    // A hint on a buffer detection never examined must not be reported as contradicted — nothing
    // was learned about it. Reverted form: report ContradictedByStructure on the over-budget path
    // and the outcome assertion fails.
    [Fact]
    public void AHintOnABufferOverBudgetIsReportedAsNotEvaluated()
    {
        var bytes = TextFixtures.Ascii(new string('a', 1025));

        var detection = TextDetector.Detect(bytes, new DetectionHint(TextEncodingKind.Utf8), SmallBudget(1024));

        Assert.Equal(TextResultState.Incomplete, detection.State);
        Assert.Equal(HintOutcome.NotEvaluated, detection.Value!.HintOutcome);
        Assert.Equal(TextEncodingKind.Utf8, detection.Value.Hint);
        Assert.Equal(TextEncodingKind.Unknown, detection.Value.Encoding);
    }

    [Fact]
    public void InputExactlyAtMaxInputBytesStillRuns()
    {
        var bytes = TextFixtures.Ascii(new string('a', 1024));

        var detection = TextDetector.Detect(bytes, budget: SmallBudget(1024));
        Assert.Equal(TextResultState.Ok, detection.State);
        Assert.Equal(TextEncodingKind.Ascii, detection.Value!.Encoding);

        var decode = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Ascii, SmallBudget(1024));
        Assert.Equal(TextResultState.Ok, decode.State);
    }

    [Fact]
    public void TheDefaultBudgetRefusesABufferOverSixtyFourMebibytes()
    {
        var bytes = new byte[ScanBudget.DefaultMaxInputBytes + 1];

        var detection = TextDetector.Detect(bytes);

        Assert.Equal(TextResultState.Incomplete, detection.State);
        Assert.Contains("MaxInputBytes", detection.Reason);
    }

    [Fact]
    public void MegabytesOfBytesThatFitNoPageComeBackLowConfidencePromptly()
    {
        // 4 MiB constructed so every candidate page scores firmly negative — see the fixture
        // builder's comment for why each family loses. Promptness is structural: scoring reads
        // the bounded sampled extents, asserted below, not the whole buffer.
        var bytes = TextFixtures.EveryPageScoresBadly(4 * 1024 * 1024);

        var detection = TextDetector.Detect(bytes);

        Assert.Equal(TextResultState.Ok, detection.State);
        Assert.Equal(DetectionConfidence.Low, detection.Value!.Confidence);
        Assert.All(detection.Value.SingleByteCandidates, c => Assert.True(c.Score < 0));

        var sampled = detection.Value.SampledRanges.Sum(r => (long)r.Length);
        Assert.True(sampled <= 96 * 1024, $"scoring read {sampled} bytes; the sample must stay bounded");
        Assert.True(detection.Value.SampledRanges.Count > 0);
    }

    // The MaxMatches canary. Reverted form: drop the ceiling in Decoder.Undecodable and this
    // runs to a million entries and reports Ok — the run list must stop at the budget with the
    // runs gathered so far, and say so.
    [Fact]
    public void AMillionUndecodableRunsStopAtMaxMatchesWithTheRunsGatheredSoFar()
    {
        var bytes = new byte[2_000_000];
        for (var i = 0; i < bytes.Length; i += 2)
        {
            bytes[i] = 0xFF; // never valid in UTF-8
            bytes[i + 1] = 0x41; // 'A' separates the runs so they cannot coalesce
        }

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Incomplete, result.State);
        Assert.Contains("MaxMatches", result.Reason);
        Assert.Equal(ScanBudget.DefaultMaxMatches, result.Value!.UndecodableRuns.Count);
        Assert.Equal(ScanBudget.DefaultMaxMatches, result.Value.Text.Count(c => c == '�'));
    }

    [Fact]
    public void ABufferThatIsASingleLeadByteIsOneRunNotACrash()
    {
        byte[] bytes = [0xE2];

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Ok, result.State);
        var run = Assert.Single(result.Value!.UndecodableRuns);
        Assert.Equal(0, run.ByteOffset);
        Assert.Equal(1, run.ByteLength);
        Assert.Equal("�", result.Value.Text);

        var strict = TextDecoder.DecodeStrict(bytes, TextEncodingKind.Utf8);
        Assert.Equal(TextResultState.Incomplete, strict.State);
    }

    [Fact]
    public void ATruncatedFourByteMarkFallsBackToTheTwoByteMarkItBeginsWith()
    {
        // FF FE 00 is three bytes of the UTF-32 LE mark. Only FF FE is actually present in
        // full, so the honest reading of the bytes on hand is UTF-16 LE with a dangling byte.
        byte[] bytes = [0xFF, 0xFE, 0x00];

        var detection = TextDetector.Detect(bytes);
        Assert.Equal(TextResultState.Ok, detection.State);
        Assert.Equal(TextEncodingKind.Utf16LittleEndian, detection.Value!.Encoding);
        Assert.Equal(2, detection.Value.MarkLength);

        var decode = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf16LittleEndian);
        Assert.Equal(TextResultState.Ok, decode.State);
        var run = Assert.Single(decode.Value!.UndecodableRuns);
        Assert.Equal(2, run.ByteOffset);
        Assert.Equal(1, run.ByteLength);
    }

    [Fact]
    public void AnOddTrailingByteInUtf16IsARunInReportingAndARefusalInStrict()
    {
        var bytes = TextFixtures.Concat(TextFixtures.Utf16("ok", bigEndian: false, withMark: false), [0x41]);

        var reporting = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf16LittleEndian);
        Assert.Equal(TextResultState.Ok, reporting.State);
        var run = Assert.Single(reporting.Value!.UndecodableRuns);
        Assert.Equal(4, run.ByteOffset);
        Assert.Equal(1, run.ByteLength);

        var strict = TextDecoder.DecodeStrict(bytes, TextEncodingKind.Utf16LittleEndian);
        Assert.Equal(TextResultState.Incomplete, strict.State);
        Assert.Equal(4, strict.Position);
    }

    [Fact]
    public void AnIllFormedUtf32UnitIsARunOfFourBytes()
    {
        // 0x00110000 is above U+10FFFF; a surrogate code point is not a scalar value either.
        var bytes = TextFixtures.Utf32([0x41, 0x110000, 0xD800, 0x42], bigEndian: false, withMark: false);

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf32LittleEndian);

        Assert.Equal(TextResultState.Ok, result.State);
        // The two bad units are adjacent, so they coalesce into one eight-byte run.
        var run = Assert.Single(result.Value!.UndecodableRuns);
        Assert.Equal(4, run.ByteOffset);
        Assert.Equal(8, run.ByteLength);
        Assert.Equal("A�B", result.Value.Text);
    }

    [Fact]
    public void AnUnrecognisedEncodingKindIsFailedNotAThrow()
    {
        var result = TextDecoder.DecodeReporting([0x41], (TextEncodingKind)9999);

        Assert.Equal(TextResultState.Failed, result.State);
        Assert.Contains("unrecognised", result.Reason);
    }
}
