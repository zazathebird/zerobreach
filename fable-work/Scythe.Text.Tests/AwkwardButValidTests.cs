using Scythe.Text.Tests.Fixtures;
using Xunit;

namespace Scythe.Text.Tests;

public class AwkwardButValidTests
{
    private static DetectionResult Detect(byte[] bytes, DetectionHint? hint = null)
    {
        var result = TextDetector.Detect(bytes, hint);
        Assert.Equal(TextResultState.Ok, result.State);
        return result.Value!;
    }

    // THE pinning test for mark ordering. Reverted form: test the two-byte marks before the
    // four-byte ones (swap the UTF-32 LE and UTF-16 LE rows in ByteOrderMark.Marks) and this
    // buffer is detected as UTF-16 LE — every UTF-32 file then decodes as alternating real
    // characters and nulls, which reads as text at a glance.
    [Fact]
    public void AUtf32LittleEndianBufferIsNotDetectedAsUtf16()
    {
        var bytes = TextFixtures.Utf32([0x41, 0x42, 0x43], bigEndian: false, withMark: true);

        var detected = Detect(bytes);

        Assert.Equal(TextEncodingKind.Utf32LittleEndian, detected.Encoding);
        Assert.Equal(4, detected.MarkLength);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
    }

    [Fact]
    public void AUtf32BigEndianMarkAlsoWinsOverItsEmbeddedUtf16Mark()
    {
        // 00 00 FE FF contains FE FF at offset 2, but at offset 0 the four-byte mark decides.
        var bytes = TextFixtures.Utf32([0x1F600], bigEndian: true, withMark: true);

        var detected = Detect(bytes);

        Assert.Equal(TextEncodingKind.Utf32BigEndian, detected.Encoding);
        Assert.Equal(4, detected.MarkLength);
    }

    [Fact]
    public void AllAsciiIsAsciiNotUtf8()
    {
        // A caller deciding whether a re-encode is a no-op needs the distinction.
        var detected = Detect(TextFixtures.Ascii("no multi-byte sequence anywhere"));

        Assert.Equal(TextEncodingKind.Ascii, detected.Encoding);
        Assert.NotEqual(TextEncodingKind.Utf8, detected.Encoding);
    }

    [Fact]
    public void MarklessNonLatinUtf16YieldsLowConfidenceRatherThanAConfidentWrongAnswer()
    {
        // Cyrillic UTF-16LE: the high half of each unit is 0x04, not 0x00, so the null
        // distribution the heuristic needs is produced only by the spaces. Degrading to Low is
        // the correct behaviour and is easy to "fix" into a guess — this asserts it stays.
        var bytes = TextFixtures.Utf16("привет как дела сегодня вечером", bigEndian: false, withMark: false);

        var detected = Detect(bytes);

        Assert.NotEqual(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.NotEqual(TextEncodingKind.Utf16BigEndian, detected.Encoding);
        Assert.Equal(DetectionConfidence.Low, detected.Confidence);
    }

    [Fact]
    public void ACallerHintRescuesMarklessNonLatinUtf16AtMediumConfidence()
    {
        var bytes = TextFixtures.Utf16("привет как дела сегодня вечером", bigEndian: false, withMark: false);

        var detected = Detect(bytes, new DetectionHint(TextEncodingKind.Utf16LittleEndian));

        Assert.Equal(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.Equal(DetectionConfidence.Medium, detected.Confidence);
        Assert.Equal(HintOutcome.FollowedForUtf16, detected.HintOutcome);
    }

    [Fact]
    public void AnOddLengthBufferThatOtherwiseLooksLikeUtf16IsDisqualified()
    {
        var even = TextFixtures.Utf16("null bytes everywhere", bigEndian: false, withMark: false);
        var odd = even[..^1]; // drop one byte: same distribution, odd length

        Assert.Equal(TextEncodingKind.Utf16LittleEndian, Detect(even).Encoding);

        var detected = Detect(odd);
        Assert.NotEqual(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.NotEqual(TextEncodingKind.Utf16BigEndian, detected.Encoding);
    }

    // Below 16 bytes the null distribution carries no information (reference §11.2). Reverted
    // form: drop the minimum length and this ten-byte buffer is UTF-16 LE at High confidence.
    [Fact]
    public void AMarklessBufferShorterThanSixteenBytesIsNotJudgedByItsNullDistribution()
    {
        var bytes = TextFixtures.Utf16("short", bigEndian: false, withMark: false); // 10 bytes

        var detected = Detect(bytes);

        Assert.NotEqual(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.NotEqual(TextEncodingKind.Utf16BigEndian, detected.Encoding);
        Assert.Equal(DetectionConfidence.Low, detected.Confidence);
    }

    // An array of small little-endian 32-bit integers puts a null at every odd offset — the
    // UTF-16 LE signature — but also at half the even ones, which UTF-16 Latin text never does.
    // Reverted form: drop the opposite-side ceiling and this is UTF-16 LE at High confidence.
    [Fact]
    public void NullsOnBothSidesDisqualifyUtf16EvenWhenTheDominantSideIsSaturated()
    {
        var bytes = new byte[64];
        for (var i = 0; i < bytes.Length; i += 4)
        {
            bytes[i] = (byte)(0x10 + i); // 10 00 00 00, 14 00 00 00, ...
        }

        var detected = Detect(bytes);

        Assert.True(detected.NulByteCount * 2 > bytes.Length, "the fixture must be null-heavy on both sides");
        Assert.NotEqual(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.NotEqual(TextEncodingKind.Utf16BigEndian, detected.Encoding);
        Assert.Equal(DetectionConfidence.Low, detected.Confidence);
    }

    [Fact]
    public void AnOddLengthBufferDefeatsEvenAUtf16Hint()
    {
        var odd = TextFixtures.Utf16("null bytes everywhere", bigEndian: false, withMark: false)[..^1];

        var detected = Detect(odd, new DetectionHint(TextEncodingKind.Utf16LittleEndian));

        Assert.NotEqual(TextEncodingKind.Utf16LittleEndian, detected.Encoding);
        Assert.NotEqual(HintOutcome.FollowedForUtf16, detected.HintOutcome);
    }

    // The 0x80–0x9F range is the single most discriminating region: printable in the Windows
    // pages, C1 controls in the ISO pages. Reverted form: score C1 entries at 0 instead of -50
    // and the ISO page ties the Windows one here, handing the ISO family half the wins.
    [Fact]
    public void BytesIn80To9FDiscriminateTheWindowsFamilyFromTheIsoFamily()
    {
        var bytes = TextFixtures.PageEncode("l’exception — « détails »", TextEncodingKind.Windows1252);

        var detected = Detect(bytes);

        var windows = detected.SingleByteCandidates.Single(c => c.Encoding == TextEncodingKind.Windows1252);
        var iso = detected.SingleByteCandidates.Single(c => c.Encoding == TextEncodingKind.Iso8859Part1);
        Assert.True(windows.Score > iso.Score,
            $"windows-1252 ({windows.Score}) must outscore iso-8859-1 ({iso.Score}) on curly punctuation");
        Assert.True(iso.Score < 0, "the C1 hits must push the ISO page negative here");
        // The overall winner is deliberately not asserted: cp850 maps all of 0x80–0x9F to
        // letters, so under the reference's letter-favouring weights the OEM pages legitimately
        // outrank windows-1252 on text whose curly punctuation sits inside words. The fixture's
        // job is the Windows/ISO family split, and that is what the score comparison pins.
    }

    // A characterisation test, not an endorsement. Under reference §11.2's weights, a letter in
    // the primary script scores +3 plus +2 beside each ASCII letter, while a prose symbol scores
    // +1 — so any page that maps the curly-apostrophe byte (0x92) to a *letter* out-scores the
    // page that maps it to the apostrophe. cp850 maps 0x92 to Æ and 0xE9 to Ú, and wins this
    // very ordinary French sentence at High confidence. The weights are the reference's and
    // were implemented exactly; this test exists so the consequence is visible in the suite
    // rather than only in HANDOFF.md, and so that whoever retunes the weights sees it move.
    [Fact]
    public void KnownLimitation_TheReferenceWeightsRankCp850AboveWindows1252OnCurlyApostropheFrench()
    {
        var bytes = TextFixtures.PageEncode("c’est l’été", TextEncodingKind.Windows1252);

        var detected = Detect(bytes);

        var cp850 = detected.SingleByteCandidates.Single(c => c.Encoding == TextEncodingKind.Cp850);
        var windows = detected.SingleByteCandidates.Single(c => c.Encoding == TextEncodingKind.Windows1252);
        Assert.True(cp850.Score > windows.Score,
            $"if cp850 ({cp850.Score}) no longer outscores windows-1252 ({windows.Score}), the weights changed: update HANDOFF.md Q2 and retire this test");
        Assert.Equal(TextEncodingKind.Cp850, detected.Encoding);
        Assert.Equal(DetectionConfidence.High, detected.Confidence);
    }

    // Reverted form: drop the -100 undefined-entry penalty and windows-1252's five holes stop
    // costing it anything, so it out-scores windows-1251 on this Cyrillic text via its extra
    // prose-symbol points — the discrimination fixture then picks the wrong page.
    [Fact]
    public void UndefinedEntriesDiscriminateBetweenPagesThatBothAssignLetters()
    {
        // ђ (0x90) and ѓ (0x83) are letters in windows-1251 but undefined in windows-1252.
        var bytes = TextFixtures.PageEncode("ђакон и ѓерѓеф", TextEncodingKind.Windows1251);

        var detected = Detect(bytes);

        Assert.Equal(TextEncodingKind.Windows1251, detected.Encoding);
        var wrong = detected.SingleByteCandidates.Single(c => c.Encoding == TextEncodingKind.Windows1252);
        Assert.True(wrong.Score < 0, "the undefined entries must push windows-1252 negative here");
    }

    [Fact]
    public void AGenuinelyAmbiguousBufferReportsTheTie()
    {
        // é and è map identically in windows-1252, windows-1250, iso-8859-1, iso-8859-2 and
        // cp850 — nothing in the bytes can separate them.
        var bytes = TextFixtures.PageEncode("réserve développée", TextEncodingKind.Windows1252);

        var detected = Detect(bytes);

        Assert.Equal(DetectionConfidence.Ambiguous, detected.Confidence);
        var top = detected.SingleByteCandidates[0];
        var second = detected.SingleByteCandidates[1];
        Assert.True(top.Score - second.Score <= top.Score * 0.05 + 1,
            "the top two candidates must be visibly close");
        // The winner is the canonical-order tie-break, and the runner-up is reported beside it.
        Assert.Equal(TextEncodingKind.Windows1252, top.Encoding);
    }

    [Fact]
    public void AGenuineSourceReplacementCharacterSurvivesWithTheRunsEmpty()
    {
        // EF BF BD is U+FFFD encoded in well-formed UTF-8: content, not damage.
        var bytes = TextFixtures.Concat(TextFixtures.Ascii("before "), [0xEF, 0xBF, 0xBD], TextFixtures.Ascii(" after"));

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf8);

        Assert.Equal(TextResultState.Ok, result.State);
        Assert.Equal("before � after", result.Value!.Text);
        Assert.Empty(result.Value.UndecodableRuns);
        Assert.Equal(1, result.Value.SourceReplacementCharacterCount);
    }

    [Fact]
    public void AHintContradictingAMarkLosesToTheMarkAndTheContradictionIsReported()
    {
        var bytes = TextFixtures.Concat(TextFixtures.Utf8Mark, TextFixtures.Utf8("marked"));

        var detected = Detect(bytes, new DetectionHint(TextEncodingKind.Windows1252));

        Assert.Equal(TextEncodingKind.Utf8, detected.Encoding);
        Assert.Equal(DetectionConfidence.FromMark, detected.Confidence);
        Assert.Equal(HintOutcome.ContradictedByMark, detected.HintOutcome);
        Assert.Equal(TextEncodingKind.Windows1252, detected.Hint);
    }

    [Fact]
    public void ASingleBytePageHintBiasesATieWithoutBypassingScoring()
    {
        // Unhinted, this ties across the Latin pages and the canonical order picks 1252.
        var bytes = TextFixtures.PageEncode("réserve développée", TextEncodingKind.Iso8859Part1);

        var unhinted = Detect(bytes);
        Assert.Equal(TextEncodingKind.Windows1252, unhinted.Encoding);

        var hinted = Detect(bytes, new DetectionHint(TextEncodingKind.Iso8859Part1));
        Assert.Equal(TextEncodingKind.Iso8859Part1, hinted.Encoding);
        Assert.Equal(HintOutcome.BiasApplied, hinted.HintOutcome);
    }

    [Fact]
    public void AHintCannotOverrideCleanMultiByteUtf8()
    {
        var bytes = TextFixtures.Utf8("structural — evidence");

        var detected = Detect(bytes, new DetectionHint(TextEncodingKind.Windows1251));

        Assert.Equal(TextEncodingKind.Utf8, detected.Encoding);
        Assert.Equal(HintOutcome.ContradictedByStructure, detected.HintOutcome);
    }

    [Fact]
    public void AUtf8HintOnAllAsciiBytesAgreesRatherThanContradicts()
    {
        // ASCII is a subset of UTF-8: a caller told "this is UTF-8" was not wrong. The answer is
        // still ASCII, because that is what the bytes are and what a re-encode decision needs.
        var detected = Detect(TextFixtures.Ascii("seven-bit"), new DetectionHint(TextEncodingKind.Utf8));

        Assert.Equal(TextEncodingKind.Ascii, detected.Encoding);
        Assert.Equal(HintOutcome.AgreedWithEvidence, detected.HintOutcome);

        // Whereas an ASCII hint on multi-byte UTF-8 is genuinely contradicted.
        var contradicted = Detect(TextFixtures.Utf8("naïve"), new DetectionHint(TextEncodingKind.Ascii));
        Assert.Equal(TextEncodingKind.Utf8, contradicted.Encoding);
        Assert.Equal(HintOutcome.ContradictedByStructure, contradicted.HintOutcome);
    }

    [Fact]
    public void AnUnpairedSurrogateIsReportedNotReplaced()
    {
        // A lone high surrogate is legal in a .NET string; a caller may need it intact.
        var bytes = TextFixtures.Utf16("a\uD801b", bigEndian: false, withMark: true);

        var result = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Utf16LittleEndian);

        Assert.Equal(TextResultState.Ok, result.State);
        Assert.Equal("a\uD801b", result.Value!.Text);
        var surrogate = Assert.Single(result.Value.UnpairedSurrogates);
        Assert.Equal('\uD801', surrogate.Value);
        Assert.Equal(1, surrogate.CharIndex);
        Assert.Equal(4, surrogate.ByteOffset); // mark(2) + 'a'(2)
        Assert.Empty(result.Value.UndecodableRuns);
    }

    [Fact]
    public void AnUndefinedSingleByteEntryIsAHoleNotAPlausibleCharacter()
    {
        // 0x81 has no meaning in windows-1252. Reverted form: fill the hole with a
        // plausible-looking character and both modes decode it silently — the strongest
        // scoring signal in the format disappears along with the caller's ability to see it.
        byte[] bytes = [0x41, 0x81, 0x42];

        var reporting = TextDecoder.DecodeReporting(bytes, TextEncodingKind.Windows1252);
        Assert.Equal(TextResultState.Ok, reporting.State);
        Assert.Equal("A�B", reporting.Value!.Text);
        var run = Assert.Single(reporting.Value.UndecodableRuns);
        Assert.Equal(1, run.ByteOffset);
        Assert.Equal(1, run.ByteLength);

        var strict = TextDecoder.DecodeStrict(bytes, TextEncodingKind.Windows1252);
        Assert.Equal(TextResultState.Incomplete, strict.State);
        Assert.Contains("undefined", strict.Reason);
        Assert.Equal(1, strict.Position);
    }

    [Fact]
    public void ControlByteDensityCapsASingleByteAnswerAtLowConfidence()
    {
        // Greek UTF-16LE read byte-wise is letter-byte then 0x03, over and over. The bytes are
        // not valid UTF-8 and carry no nulls, so scoring runs — and some Cyrillic page happily
        // assigns letters to the odd bytes. The C0 controls between them are what says "this is
        // not single-byte prose"; without the cap this is a confident wrong answer.
        var bytes = TextFixtures.Utf16("αβγδεζηθικλμνξο", bigEndian: false, withMark: false);

        var detected = Detect(bytes);
        Assert.Equal(DetectionConfidence.Low, detected.Confidence);
        Assert.True(detected.ControlByteCount > 0);

        var hinted = Detect(bytes, new DetectionHint(TextEncodingKind.Utf16LittleEndian));
        Assert.Equal(TextEncodingKind.Utf16LittleEndian, hinted.Encoding);
        Assert.Equal(HintOutcome.FollowedForUtf16, hinted.HintOutcome);
    }

    [Fact]
    public void CjkLookingAsciiBytesWithAUtf16HintFollowTheHint()
    {
        // U+4141 etc.: every byte is below 0x80 and there are no nulls, so the bytes read as
        // ASCII — but an even-length buffer of such bytes is also what CJK UTF-16 looks like.
        var bytes = TextFixtures.Utf16("䅁䅂䅃䅄䅅䅆䅇䅈", bigEndian: false, withMark: false);

        var unhinted = Detect(bytes);
        Assert.Equal(TextEncodingKind.Ascii, unhinted.Encoding);

        var hinted = Detect(bytes, new DetectionHint(TextEncodingKind.Utf16LittleEndian));
        Assert.Equal(TextEncodingKind.Utf16LittleEndian, hinted.Encoding);
        Assert.Equal(DetectionConfidence.Medium, hinted.Confidence);
        Assert.Equal(HintOutcome.FollowedForUtf16, hinted.HintOutcome);
    }
}
