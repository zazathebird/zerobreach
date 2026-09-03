using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

/// <summary>
/// One fixture per rejection class in the reference table's bolded second-byte ranges, plus the
/// invalid leads. All are asserted rejected rather than replaced: exactly one undecodable run,
/// at the right byte offset, of the right length. Reverted form for the lot: validate with
/// "lead says N continuations, check they are 80–BF" and the over-long forms, surrogate halves
/// and out-of-range sequences all decode to code points they must not.
/// </summary>
public class Utf8RejectionTests
{
    public static TheoryData<string, byte[], int, int> Rejections => new()
    {
        // name, bad bytes (placed between 'A' and 'B'), expected run offset, expected run length
        { "over-long two-byte lead C0", [0xC0, 0xAF], 1, 2 },
        { "over-long two-byte lead C1", [0xC1, 0x81], 1, 2 },
        { "over-long three-byte form E0 80", [0xE0, 0x80, 0x80], 1, 3 },
        { "over-long three-byte form E0 9F", [0xE0, 0x9F, 0xBF], 1, 3 },
        { "encoded high surrogate ED A0", [0xED, 0xA0, 0x80], 1, 3 },
        { "encoded low surrogate ED BF", [0xED, 0xBF, 0xBF], 1, 3 },
        { "over-long four-byte form F0 8F", [0xF0, 0x8F, 0xBF, 0xBF], 1, 4 },
        { "code point above the maximum F4 90", [0xF4, 0x90, 0x80, 0x80], 1, 4 },
        { "invalid lead F5", [0xF5, 0x80], 1, 2 },
        { "invalid lead FF", [0xFF], 1, 1 },
        { "continuation with no lead", [0x80], 1, 1 },
    };

    [Theory]
    [MemberData(nameof(Rejections))]
    public void EachIllFormedSequenceProducesExactlyOneRunAtTheRightOffset(
        string name, byte[] bad, int runOffset, int runLength)
    {
        var bytes = TextFixtures.Concat([0x41], bad, [0x42]); // A <bad> B

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Ok, result.State);
        var run = Assert.Single(result.Value!.UndecodableRuns);
        Assert.Equal(runOffset, run.ByteOffset);
        Assert.Equal(runLength, run.ByteLength);
        Assert.Equal(1, run.CharIndex);
        Assert.Equal(1, run.CharLength);
        Assert.Equal("A�B", result.Value.Text);
        Assert.Equal(0, result.Value.SourceReplacementCharacterCount);
        _ = name;
    }

    [Theory]
    [MemberData(nameof(Rejections))]
    public void EachIllFormedSequenceIsRefusedByTheStrictDecode(
        string name, byte[] bad, int runOffset, int runLength)
    {
        var bytes = TextFixtures.Concat([0x41], bad, [0x42]);

        var result = TextDecoder.DecodeStrict(bytes, TextEncodingKind.Utf8);

        // Reverted form: replace the strict decode with a substituting one and this state
        // assertion fails with Ok — the strict-mode fixture the brief names.
        Assert.Equal(TextResultState.Incomplete, result.State);
        Assert.Equal(string.Empty, result.Value!.Text);
        Assert.Equal(runOffset, result.Position);
        Assert.NotNull(result.Reason);
        _ = (name, runLength);
    }

    [Fact]
    public void ALeadByteWithATruncatedTailAtEndOfBufferIsOneRun()
    {
        var bytes = TextFixtures.Concat(TextFixtures.Ascii("AB"), [0xE2, 0x82]); // € missing its last byte

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Ok, result.State);
        var run = Assert.Single(result.Value!.UndecodableRuns);
        Assert.Equal(2, run.ByteOffset);
        Assert.Equal(2, run.ByteLength);
        Assert.Equal("AB�", result.Value.Text);

        var strict = TextDecoder.DecodeStrict(bytes, TextEncodingKind.Utf8);
        Assert.Equal(TextResultState.Incomplete, strict.State);
    }

    [Theory]
    [MemberData(nameof(Rejections))]
    public void ABufferHoldingAnIllFormedSequenceIsNotDetectedAsUtf8(
        string name, byte[] bad, int runOffset, int runLength)
    {
        var bytes = TextFixtures.Concat(TextFixtures.Ascii("padding "), bad, TextFixtures.Ascii(" padding"));

        var detection = TextDetector.Detect(bytes);

        Assert.Equal(TextResultState.Ok, detection.State);
        Assert.NotEqual(TextEncodingKind.Utf8, detection.Value!.Encoding);
        Assert.NotEqual(TextEncodingKind.Ascii, detection.Value.Encoding);
        _ = (name, runOffset, runLength);
    }
}
