namespace Scythe.Core.Model;

/// <summary>Finding severity per spec §5. Order matters: comparisons like
/// <c>severity &gt;= Severity.High</c> implement the §6 auto-select gate.</summary>
public enum Severity
{
    Info = 0,
    Possible = 1,
    High = 2,
    Critical = 3,
}
