namespace ZeroBreach.Formats.Containers;

/// <summary>
/// Accumulates expanded (decompressed) byte counts across every read that shares it, and
/// enforces a total cap. A decompression bomb split across many entries — or across nesting
/// levels — is only visible in the aggregate, which is why the guard is an object handed
/// through the whole walk rather than a per-call check.
/// </summary>
public sealed class ExpansionGuard
{
    /// <summary>The cap this guard enforces.</summary>
    public long MaxTotalExpandedBytes { get; }

    /// <summary>Expanded bytes committed so far by completed reads.</summary>
    public long TotalExpandedBytes { get; private set; }

    public ExpansionGuard(long maxTotalExpandedBytes = ContainerLimits.MaxTotalExpandedBytes)
    {
        if (maxTotalExpandedBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxTotalExpandedBytes), "cap must be positive");
        }
        MaxTotalExpandedBytes = maxTotalExpandedBytes;
    }

    /// <summary>True when committed bytes plus <paramref name="pendingBytes"/> would exceed the cap.</summary>
    internal bool WouldExceed(long pendingBytes) => TotalExpandedBytes + pendingBytes > MaxTotalExpandedBytes;

    /// <summary>Commits the output of a completed read into the running total.</summary>
    internal void Commit(long producedBytes) => TotalExpandedBytes += producedBytes;
}
