namespace Scythe.Core.Scanning;

/// <summary>Scan depth per spec §2. STEALTH is not a depth — it is an output mode
/// (silent console + single compressed JSON blob) combined with FULL or DEEP depth.</summary>
public enum ScanDepth
{
    Quick = 0,
    Full = 1,
    Deep = 2,
}
