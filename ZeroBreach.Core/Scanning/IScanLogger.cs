namespace ZeroBreach.Core.Scanning;

/// <summary>Console/progress output abstraction. STEALTH mode swaps in the null logger —
/// scanners never write to the console directly.</summary>
public interface IScanLogger
{
    void PhaseBanner(int phase, string name);
    void PhaseDone(int phase, string name, TimeSpan elapsed, int findings);
    void Info(string message);
    void Warn(string message);
}

public sealed class NullScanLogger : IScanLogger
{
    public static readonly NullScanLogger Instance = new();
    public void PhaseBanner(int phase, string name) { }
    public void PhaseDone(int phase, string name, TimeSpan elapsed, int findings) { }
    public void Info(string message) { }
    public void Warn(string message) { }
}
