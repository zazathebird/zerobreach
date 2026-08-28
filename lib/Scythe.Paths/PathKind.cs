namespace Scythe.Paths;

/// <summary>
/// The syntactic form the input path arrived in. This reports what the caller wrote,
/// not where the path points: <c>\\?\C:\Windows</c> has kind <see cref="Extended"/> even
/// though its comparison form is the same as plain <c>C:\Windows</c>. Use
/// <see cref="NormalizedPath.RootSpace"/> for the namespace the path resolves into.
/// </summary>
public enum PathKind
{
    /// <summary>No drive and no leading separator: <c>foo\bar</c>. Resolves against an unknown current directory.</summary>
    Relative,

    /// <summary>Rooted on the current drive: <c>\foo\bar</c>. The drive is unknown to pure string logic.</summary>
    RootRelative,

    /// <summary>Drive-qualified but relative to that drive's current directory: <c>C:foo</c>.</summary>
    DriveRelative,

    /// <summary>Fully qualified drive path: <c>C:\foo</c>.</summary>
    DriveAbsolute,

    /// <summary>Plain UNC: <c>\\server\share\...</c>.</summary>
    Unc,

    /// <summary>Device namespace: <c>\\.\...</c> (for example <c>\\.\PhysicalDrive0</c> or <c>\\.\C:\x</c>).</summary>
    Device,

    /// <summary>Extended-length / verbatim prefix: <c>\\?\...</c> (for example <c>\\?\C:\x</c>).</summary>
    Extended,

    /// <summary>Extended UNC: <c>\\?\UNC\server\share\...</c> (also used for <c>\\.\UNC\...</c>).</summary>
    ExtendedUnc,

    /// <summary>Object-manager root: <c>\\?\GLOBALROOT\...</c> or <c>\\.\GLOBALROOT\...</c>.</summary>
    GlobalRoot,
}
