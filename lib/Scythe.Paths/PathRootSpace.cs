namespace Scythe.Paths;

/// <summary>
/// The namespace a normalised path resolves into. Where <see cref="PathKind"/> reports the
/// syntactic form of the input, this reports the space the comparison logic works in:
/// <c>\\?\C:\x</c> is kind <see cref="PathKind.Extended"/> but lives in <see cref="Drive"/>
/// space, which is exactly why it compares equal to <c>C:\x</c>.
/// </summary>
public enum PathRootSpace
{
    /// <summary>Normalisation failed; the path resolves nowhere.</summary>
    None,

    /// <summary>A drive-letter volume: root <c>x:\</c>.</summary>
    Drive,

    /// <summary>A UNC server/share: root <c>\\server\share</c>.</summary>
    Unc,

    /// <summary>The device namespace: root <c>\\.\devicename</c>.</summary>
    Device,

    /// <summary>The object-manager namespace: root <c>\\.\globalroot</c>.</summary>
    GlobalRoot,

    /// <summary>Rooted on the (unknown) current drive: <c>\foo</c>.</summary>
    CurrentDrive,

    /// <summary>A named drive's (unknown) current directory: <c>C:foo</c>.</summary>
    DriveCurrentDirectory,

    /// <summary>No root at all: resolves against an unknown current directory.</summary>
    Relative,
}
