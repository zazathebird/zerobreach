namespace Scythe.Core.Scanning;

/// <summary>One detection category (spec §3), run as a numbered phase.</summary>
public interface IScanner
{
    /// <summary>Phase number — determines run order and the console banner.</summary>
    int Phase { get; }

    /// <summary>Human-readable phase name for the banner.</summary>
    string Name { get; }

    /// <summary>Category label stamped on findings (spec §5 "group").</summary>
    string Group { get; }

    /// <summary>Minimum depth at which this phase runs at all. Individual checks inside a
    /// scanner may additionally gate on ctx.Depth (e.g. deep-only hive walks).</summary>
    ScanDepth MinDepth { get; }

    /// <summary>Run all checks. Must not throw for expected failure modes — report
    /// Inconclusive instead. Must never write to the machine.</summary>
    void Run(ScanContext ctx, IFindingSink sink);
}
