namespace Scythe.Remediation;

/// <summary>Spec §6.9: a batch applies only after the operator types the literal word.
/// Deliberate friction — exact, case-sensitive, no default, no -y bypass anywhere.</summary>
public static class ConfirmationGate
{
    public const string RequiredWord = "CONFIRM";

    public static bool IsConfirmed(string? typed) =>
        string.Equals(typed?.Trim(), RequiredWord, StringComparison.Ordinal);
}
