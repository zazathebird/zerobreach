namespace Scythe.Paths;

/// <summary>Named limits (BLUEPRINT §3: bounds are explicit, not literals scattered through code).</summary>
public static class PathLimits
{
    /// <summary>
    /// Maximum accepted path length in UTF-16 code units, matching the NT kernel's extended
    /// path ceiling. Input longer than this — including after environment expansion — fails.
    /// Every algorithm in this library is a single linear pass bounded by this value, which is
    /// why normalisation needs no separate time budget.
    /// </summary>
    public const int MaxPathLength = 32767;

    /// <summary>The NTFS default data stream type: <c>file.txt::$DATA</c> is the file itself.</summary>
    public const string DefaultStreamType = "$DATA";
}
