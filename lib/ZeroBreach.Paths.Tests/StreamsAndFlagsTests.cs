using Xunit;

namespace ZeroBreach.Paths.Tests;

/// <summary>
/// Alternate data streams (split out, never dropped) and the evidence flags: reserved device
/// names, 8.3-style short names, and Unicode look-alikes — all flagged and left alone, because
/// resolving needs the file system and folding destroys a detection signal.
/// </summary>
public sealed class StreamsAndFlagsTests
{
    private static NormalizedPath Ok(string path)
    {
        NormalizedPath result = PathNormalizer.Normalize(path);
        Assert.Equal(OperationState.Ok, result.State);
        return result;
    }

    // ------------------------------------------------------------------ alternate data streams

    [Fact]
    public void Stream_IsSplitFromTheFinalComponent()
    {
        NormalizedPath p = Ok(@"C:\dir\file.txt:secret");
        Assert.Equal(@"c:\dir\file.txt", p.Canonical);
        Assert.Equal("secret", p.StreamName);
        Assert.Null(p.StreamType);
        Assert.Equal("secret:$data", p.CanonicalStream);
        Assert.True(p.Flags.HasFlag(PathFlags.AlternateDataStream));
        Assert.Contains(p.Transformations, t => t.Kind == TransformationKind.AlternateDataStreamSplit);
    }

    [Fact]
    public void Stream_WithExplicitDataType()
    {
        NormalizedPath p = Ok(@"C:\dir\file.txt:secret:$DATA");
        Assert.Equal("secret", p.StreamName);
        Assert.Equal("$DATA", p.StreamType);
        Assert.Equal("secret:$data", p.CanonicalStream);
    }

    [Fact]
    public void StreamIdentity_AgreesWithAndWithoutDefaultType()
    {
        // "f:s" and "f:s:$DATA" are the same stream; the canonical identity must agree.
        Assert.Equal(Ok(@"C:\f:s").CanonicalStream, Ok(@"C:\f:s:$DATA").CanonicalStream);
        Assert.Equal(Ok(@"C:\f:s").CanonicalFull, Ok(@"C:\f:s:$DATA").CanonicalFull);
    }

    [Fact]
    public void DefaultDataStreamSuffix_IsTheFileItself()
    {
        // "file.txt::$DATA" is a classic filter bypass for the file's own content: it must
        // normalise to the same identity as the plain path, and be flagged.
        NormalizedPath p = Ok(@"C:\dir\file.txt::$DATA");
        Assert.Equal(@"c:\dir\file.txt", p.Canonical);
        Assert.Null(p.CanonicalStream);
        Assert.Equal(@"c:\dir\file.txt", p.CanonicalFull);
        Assert.True(p.Flags.HasFlag(PathFlags.DefaultDataStream));
        Assert.True(p.Flags.HasFlag(PathFlags.AlternateDataStream));
        Assert.Equal(Ok(@"C:\dir\file.txt").CanonicalFull, p.CanonicalFull);
    }

    [Fact]
    public void Stream_OnADirectoryStylePath()
    {
        // Streams attach to directories too ("dir:evil" hides data on the folder).
        NormalizedPath p = Ok(@"C:\Windows\Tasks:payload");
        Assert.Equal(@"c:\windows\tasks", p.Canonical);
        Assert.Equal("payload", p.StreamName);
    }

    [Fact]
    public void DirectoryIndexStream_TypeIsPreserved()
    {
        NormalizedPath p = Ok(@"C:\dir:$I30:$INDEX_ALLOCATION");
        Assert.Equal("$I30", p.StreamName);
        Assert.Equal("$INDEX_ALLOCATION", p.StreamType);
        Assert.Equal("$i30:$index_allocation", p.CanonicalStream);
    }

    [Fact]
    public void StreamCase_IsFoldedForIdentity_PreservedForDisplay()
    {
        NormalizedPath p = Ok(@"C:\f:Secret");
        Assert.Equal("Secret", p.StreamName);
        Assert.Equal("secret:$data", p.CanonicalStream);
        Assert.EndsWith(":Secret", p.NormalizedDisplay);
    }

    [Fact]
    public void PathEndTrim_RunsBeforeStreamSplit()
    {
        // GetFullPathName trims the path end textually before NTFS ever sees a stream name:
        // "file:stream..." opens stream "stream".
        NormalizedPath p = Ok(@"C:\file:stream...");
        Assert.Equal("stream", p.StreamName);
    }

    // ------------------------------------------------------------------ reserved device names

    [Theory]
    [InlineData(@"C:\CON")]
    [InlineData(@"C:\dir\prn")]
    [InlineData(@"C:\AUX.txt")]
    [InlineData(@"C:\NUL.tar.gz")]
    [InlineData(@"C:\COM1")]
    [InlineData(@"C:\lpt9.log")]
    [InlineData(@"C:\CONIN$")]
    [InlineData("C:\\COM\u00B9")] // COM¹ — superscript digit, reserved on modern Windows
    public void ReservedDeviceNames_AreFlagged(string path)
    {
        Assert.True(Ok(path).Flags.HasFlag(PathFlags.ReservedDeviceName));
    }

    [Theory]
    [InlineData(@"C:\COM0")]     // classic Windows does not reserve COM0/LPT0
    [InlineData(@"C:\CONSOLE")]
    [InlineData(@"C:\NULABLE")]
    [InlineData(@"C:\xCON")]
    public void NonReservedNames_AreNotFlagged(string path)
    {
        Assert.False(Ok(path).Flags.HasFlag(PathFlags.ReservedDeviceName));
    }

    [Fact]
    public void ReservedName_InAMiddleComponent_IsAlsoFlagged()
    {
        Assert.True(Ok(@"C:\CON\file.txt").Flags.HasFlag(PathFlags.ReservedDeviceName));
    }

    [Fact]
    public void ReservedName_IsFlaggedNotRewritten()
    {
        NormalizedPath p = Ok(@"C:\NUL.txt");
        Assert.Equal(@"c:\nul.txt", p.Canonical); // left alone: evidence, not an error
    }

    // ------------------------------------------------------------------ 8.3 short names

    [Theory]
    [InlineData(@"C:\PROGRA~1\Vendor")]
    [InlineData(@"C:\Users\RUNNER~1\AppData")]
    [InlineData(@"C:\LONGFI~1.TXT")]
    [InlineData(@"C:\DOCUM~10\x")]   // NTFS goes past ~9 for many collisions
    public void ShortNameShapes_AreFlagged(string path)
    {
        Assert.True(Ok(path).Flags.HasFlag(PathFlags.ShortNameComponent));
    }

    [Theory]
    [InlineData(@"C:\foo~bar\x")]        // suffix after ~ is not digits
    [InlineData(@"C:\~1\x")]             // tilde at position 0
    [InlineData(@"C:\backup~\x")]        // no digits after ~
    [InlineData(@"C:\notshort~1.html")]  // base name longer than 8
    [InlineData(@"C:\a~1.longext")]      // extension longer than 3
    public void NonShortNameShapes_AreNotFlagged(string path)
    {
        Assert.False(Ok(path).Flags.HasFlag(PathFlags.ShortNameComponent));
    }

    [Fact]
    public void ShortName_IsFlaggedNotResolved()
    {
        // Resolving PROGRA~1 to "Program Files" needs the file system; the library must not guess.
        Assert.Equal(@"c:\progra~1\x", Ok(@"C:\PROGRA~1\x").Canonical);
    }

    // ------------------------------------------------------------------ homoglyphs / look-alikes

    [Theory]
    [InlineData("C:\\Wind\u043Ews")]       // Cyrillic о for o
    [InlineData("C:\\\u0430dmin")]          // Cyrillic а
    [InlineData("C:\\W\uFF49ndows")]        // fullwidth ｉ
    [InlineData("C:\\Win\u200Bdows")]       // zero-width space
    [InlineData("C:\\Program\u00A0Files")]  // no-break space
    [InlineData("C:\\file\u2024txt")]       // one-dot leader imitating '.'
    [InlineData("C:\\dir\\\u202Egpj.exe")]  // RTL override — classic extension spoof
    public void LookAlikeCharacters_AreFlagged(string path)
    {
        Assert.True(Ok(path).Flags.HasFlag(PathFlags.HomoglyphCharacters));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32")]
    [InlineData("C:\\Caf\u00E9\\menu")]     // é: legitimately non-ASCII, not a look-alike
    [InlineData("C:\\\u6587\u6863\\x")]     // CJK: legitimate non-Latin path
    public void OrdinaryText_IsNotFlagged(string path)
    {
        Assert.False(Ok(path).Flags.HasFlag(PathFlags.HomoglyphCharacters));
    }

    [Fact]
    public void Homoglyph_IsFlaggedNeverFolded()
    {
        // Folding Cyrillic о into Latin o would make the spoof invisible — the flag plus the
        // preserved original IS the detection signal.
        NormalizedPath p = Ok("C:\\Wind\u043Ews\\x");
        Assert.Contains('\u043E', p.Canonical!);
        Assert.NotEqual(@"c:\windows\x", p.Canonical);
        Assert.True(p.Flags.HasFlag(PathFlags.HomoglyphCharacters));
    }

    [Fact]
    public void HomoglyphInUncServer_IsFlagged()
    {
        Assert.True(Ok("\\\\fileserv\u0435r\\share\\x").Flags.HasFlag(PathFlags.HomoglyphCharacters));
    }

    [Fact]
    public void HomoglyphInStreamName_IsFlagged()
    {
        Assert.True(Ok("C:\\f:s\u043Ename").Flags.HasFlag(PathFlags.HomoglyphCharacters));
    }
}
