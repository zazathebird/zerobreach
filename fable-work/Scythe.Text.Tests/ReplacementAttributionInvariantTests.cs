using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

/// <summary>
/// The invariant the whole design exists to provide, with the test named after it: every U+FFFD
/// in the decoded text whose character index is not covered by an UndecodableRuns entry was
/// present in the source. Reverted form: stop recording runs (substitute without listing) and
/// the attribution assertions here fail — a tool-inserted replacement becomes indistinguishable
/// from a file-original one, which is exactly the bare-GetString failure mode.
/// </summary>
public class ReplacementAttributionInvariantTests
{
    private static void AssertInvariant(DecodedText decoded)
    {
        var covered = decoded.UndecodableRuns
            .SelectMany(r => Enumerable.Range(r.CharIndex, r.CharLength))
            .ToHashSet();

        var uncoveredReplacements = 0;
        for (var i = 0; i < decoded.Text.Length; i++)
        {
            if (decoded.Text[i] == '�' && !covered.Contains(i))
            {
                uncoveredReplacements++;
            }
        }

        Assert.Equal(decoded.SourceReplacementCharacterCount, uncoveredReplacements);
    }

    [Fact]
    public void EveryReplacementNotCoveredByARunWasPresentInTheSource()
    {
        // One genuine U+FFFD (EF BF BD, well-formed) and one damaged byte (FF), in one buffer.
        var bytes = TextFixtures.Concat(
            TextFixtures.Ascii("A"), [0xEF, 0xBF, 0xBD], TextFixtures.Ascii("B"), [0xFF], TextFixtures.Ascii("C"));

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Ok, result.State);
        var decoded = result.Value!;
        Assert.Equal("A�B�C", decoded.Text);

        var run = Assert.Single(decoded.UndecodableRuns);
        Assert.Equal(5, run.ByteOffset);
        Assert.Equal(1, run.ByteLength);
        Assert.Equal(3, run.CharIndex);

        Assert.Equal(1, decoded.SourceReplacementCharacterCount);
        AssertInvariant(decoded);
    }

    [Fact]
    public void TheInvariantHoldsInUtf16Too()
    {
        // U+FFFD as a code unit, plus a dangling odd byte at the end.
        var bytes = TextFixtures.Concat(
            TextFixtures.Utf16("x�y", bigEndian: false, withMark: false), [0x00]);

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf16LittleEndian);

        Assert.Equal(TextResultState.Ok, result.State);
        Assert.Equal("x�y�", result.Value!.Text);
        Assert.Equal(1, result.Value.SourceReplacementCharacterCount);
        AssertInvariant(result.Value);
    }

    [Fact]
    public void ACleanBufferHasNoUncoveredReplacementsAndSaysSo()
    {
        var result = TextDecoder.DecodeReporting(TextFixtures.Utf8("nothing wrong here"), TextEncodingKind.Utf8);

        Assert.Equal(0, result.Value!.SourceReplacementCharacterCount);
        Assert.Empty(result.Value.UndecodableRuns);
        AssertInvariant(result.Value);
    }

    // Negative control for the helper itself: hand it a result whose bookkeeping is wrong the
    // way the reverted decoder would produce, and it must fail. Proves AssertInvariant can go
    // red, so its green above is evidence rather than a claim.
    [Fact]
    public void TheInvariantCheckItselfCatchesUnattributedReplacements()
    {
        var forged = new DecodedText(
            "A�B",
            TextEncodingKind.Utf8,
            0,
            [], // the run that should cover index 1 is missing
            [],
            0, // and the source count does not claim it either
            [0x41, 0xFF, 0x42]);

        Assert.ThrowsAny<Xunit.Sdk.XunitException>(() => AssertInvariant(forged));
    }

    [Fact]
    public void RunCoordinatesAgreeInBothCoordinateSystems()
    {
        // Multi-byte characters before the damage shift the two coordinate systems apart; the
        // run must carry both, correctly, without the caller re-decoding.
        var bytes = TextFixtures.Concat(
            TextFixtures.Utf8("héllo€"), // é is 2 bytes, € is 3: 9 bytes, 6 chars
            [0xF5, 0x91],               // 2 undecodable bytes
            TextFixtures.Utf8("末"));    // 3 bytes, 1 char

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        var run = Assert.Single(result.Value!.UndecodableRuns);
        Assert.Equal(9, run.ByteOffset);
        Assert.Equal(2, run.ByteLength);
        Assert.Equal(6, run.CharIndex);
        Assert.Equal("héllo€�末", result.Value.Text);
        AssertInvariant(result.Value);
    }
}
