namespace ZeroBreach.Core.Scanning;

/// <summary>Wall-clock record of one executed phase (spec §7) — recorded for every phase
/// that actually ran, including one that crashed or was cancelled mid-way (time was spent
/// and partial findings may exist); never for skipped/excluded phases (they did not run).</summary>
public sealed record PhaseTiming(int Phase, string Name, TimeSpan Elapsed, int FindingCount);
