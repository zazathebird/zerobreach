namespace Scythe.Text;

/// <summary>
/// One maximal run of adjacent bytes the reporting decode could not decode, carried in both
/// coordinate systems. Both, because deriving one from the other requires re-decoding, and every
/// caller that has tried has got it wrong once (Q2 brief).
/// </summary>
/// <param name="ByteOffset">First undecodable byte, in the original buffer, mark included.</param>
/// <param name="ByteLength">Length of the run in the original buffer.</param>
/// <param name="CharIndex">Index in the decoded string of the replacement stand-in.</param>
/// <param name="CharLength">
/// Always 1 today — one U+FFFD per run, because a run is one decoding event. Carried as a member
/// so the granularity is data rather than an assumption baked into every caller.
/// </param>
public sealed record UndecodableRun(int ByteOffset, int ByteLength, int CharIndex, int CharLength);

/// <summary>
/// A surrogate code unit with no partner, found while decoding UTF-16. Reported, not replaced:
/// it is legal in a .NET string and a caller may need it intact.
/// </summary>
public sealed record UnpairedSurrogate(int ByteOffset, int CharIndex, char Value);

/// <summary>
/// The outcome of one decode.
/// </summary>
/// <remarks>
/// The invariant the whole design exists to provide: every U+FFFD in <see cref="Text"/> whose
/// character index is not covered by an <see cref="UndecodableRuns"/> entry was present in the
/// source, and <see cref="SourceReplacementCharacterCount"/> counts exactly those. Together they
/// make a tool-inserted replacement and a file-original one distinguishable, which no bare
/// <c>GetString</c> can offer.
/// </remarks>
/// <param name="Text">The decoded text. The mark, when present, is not part of it.</param>
/// <param name="Encoding">The encoding that was decoded.</param>
/// <param name="MarkLength">Byte length of the mark that was skipped, zero when none.</param>
/// <param name="UndecodableRuns">Byte-offset order. Empty on a strict decode (it refuses instead).</param>
/// <param name="UnpairedSurrogates">Unpaired surrogate code units, kept in the text and listed here.</param>
/// <param name="SourceReplacementCharacterCount">U+FFFD characters genuinely in the source, not inserted by the tool.</param>
/// <param name="OriginalBytes">The buffer exactly as received, mark included, nothing normalised.</param>
public sealed record DecodedText(
    string Text,
    TextEncodingKind Encoding,
    int MarkLength,
    IReadOnlyList<UndecodableRun> UndecodableRuns,
    IReadOnlyList<UnpairedSurrogate> UnpairedSurrogates,
    int SourceReplacementCharacterCount,
    byte[] OriginalBytes);
