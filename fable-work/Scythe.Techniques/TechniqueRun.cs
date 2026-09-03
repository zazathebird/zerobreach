namespace Scythe.Techniques;

/// <summary>The outcome of one resolution run: every finding's resolution, and the rollup over them.</summary>
public sealed class TechniqueRun
{
    internal TechniqueRun(IReadOnlyList<FindingResolution> resolutions, TechniqueRollup rollup)
    {
        Resolutions = resolutions;
        Rollup = rollup;
    }

    /// <summary>One resolution per finding processed, in the order the findings were supplied.</summary>
    public IReadOnlyList<FindingResolution> Resolutions { get; }

    public TechniqueRollup Rollup { get; }
}
