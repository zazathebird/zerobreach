using System.Globalization;

namespace Scythe.TestKit;

public enum PropertyOutcome
{
    /// <summary>Every planned case passed.</summary>
    Holds,

    /// <summary>A case failed; the report carries the original input, the minimised counterexample and how to reproduce it.</summary>
    Falsified,

    /// <summary>The run stopped before finishing its cases — deadline or case ceiling — or was vacuous. Not a pass.</summary>
    Exhausted,
}

/// <summary>
/// What one property run found. <see cref="Message"/> is the line a failing test prints: the
/// property, the seed, the case index and the counterexample in hex, so the failure can be
/// reproduced with <c>Gen.Case(seed, index, maxLength)</c> and nothing else.
/// </summary>
public sealed class PropertyReport
{
    internal PropertyReport(
        string property,
        ulong seed,
        int maxLength,
        int casesPlanned,
        int casesRun,
        PropertyOutcome outcome,
        string? detail,
        int? failingCaseIndex,
        byte[]? originalFailure,
        byte[]? counterexample,
        int shrinkSteps,
        int shrinkEvaluations,
        bool shrinkCapped)
    {
        Property = property;
        Seed = seed;
        MaxLength = maxLength;
        CasesPlanned = casesPlanned;
        CasesRun = casesRun;
        Outcome = outcome;
        Detail = detail;
        FailingCaseIndex = failingCaseIndex;
        OriginalFailure = originalFailure;
        Counterexample = counterexample;
        ShrinkSteps = shrinkSteps;
        ShrinkEvaluations = shrinkEvaluations;
        ShrinkCapped = shrinkCapped;
    }

    public string Property { get; }

    public ulong Seed { get; }

    public int MaxLength { get; }

    public int CasesPlanned { get; }

    public int CasesRun { get; }

    public PropertyOutcome Outcome { get; }

    public bool Holds => Outcome == PropertyOutcome.Holds;

    /// <summary>For Falsified: why the case failed. For Exhausted: why the run stopped.</summary>
    public string? Detail { get; }

    public int? FailingCaseIndex { get; }

    /// <summary>The generated input that first failed, before shrinking.</summary>
    public byte[]? OriginalFailure { get; }

    /// <summary>The minimised input that still fails.</summary>
    public byte[]? Counterexample { get; }

    public int ShrinkSteps { get; }

    public int ShrinkEvaluations { get; }

    /// <summary>True when shrinking stopped at the evaluation ceiling rather than at a fixed point.</summary>
    public bool ShrinkCapped { get; }

    public string Message
    {
        get
        {
            string head = $"property '{Property}' (seed {Seed}, maxLength {MaxLength}, {CasesRun}/{CasesPlanned} cases)";
            return Outcome switch
            {
                PropertyOutcome.Holds => head + ": holds",
                PropertyOutcome.Exhausted => head + ": EXHAUSTED — " + Detail,
                _ => head + $": FALSIFIED at case {FailingCaseIndex} — {Detail}; counterexample ({Counterexample!.Length} bytes, shrunk from {OriginalFailure!.Length} in {ShrinkSteps} steps{(ShrinkCapped ? ", shrink capped" : string.Empty)}): {HexDump(Counterexample)}; reproduce the original with Gen.Case({Seed}, {FailingCaseIndex}, {MaxLength})",
            };
        }
    }

    public override string ToString() => Message;

    /// <summary>Up to 64 bytes as hex, then an ellipsis with the remaining count.</summary>
    public static string HexDump(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        const int Shown = 64;
        var text = new System.Text.StringBuilder();
        for (int i = 0; i < Math.Min(Shown, bytes.Length); i++)
        {
            if (i > 0)
            {
                text.Append(' ');
            }

            text.Append(bytes[i].ToString("X2", CultureInfo.InvariantCulture));
        }

        if (bytes.Length > Shown)
        {
            text.Append(CultureInfo.InvariantCulture, $" ... (+{bytes.Length - Shown})");
        }

        return bytes.Length == 0 ? "(empty)" : text.ToString();
    }
}
