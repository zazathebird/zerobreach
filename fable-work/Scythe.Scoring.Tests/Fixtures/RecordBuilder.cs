using System.Text;
using System.Text.Json;

namespace Scythe.Scoring.Tests.Fixtures;

/// <summary>
/// Builds the scoring projection of a run record programmatically, so the awkward and malformed
/// variants are one mutation away from the ordinary one rather than a second checked-in blob.
/// </summary>
/// <remarks>
/// The builder deliberately does <b>not</b> validate: a duplicate id, an orphan finding, a null
/// entry and an undefined enum value are all constructible here, because those are exactly the
/// records the library has to refuse. Expected scores in the tests are worked by hand from the
/// weights in the brief's terms, not read back from <c>ScoreWeights</c>, wherever the arithmetic
/// is the thing under test.
/// </remarks>
internal sealed class RecordBuilder
{
    private readonly List<CheckInput> _checks = new();
    private readonly List<FindingInput> _findings = new();

    internal RecordBuilder Check(string id, CheckStatus status = CheckStatus.Completed, string? reason = null, string? title = null)
    {
        _checks.Add(new CheckInput(id, title ?? $"Title of {id}", status, reason));
        return this;
    }

    internal RecordBuilder Completed(params string[] ids)
    {
        foreach (var id in ids)
        {
            Check(id);
        }

        return this;
    }

    internal RecordBuilder Inconclusive(string id, string? reason = "needed elevation") =>
        Check(id, CheckStatus.Inconclusive, reason);

    internal RecordBuilder Skipped(string id, string? reason = "not in this mode") =>
        Check(id, CheckStatus.Skipped, reason);

    internal RecordBuilder Finding(string id, Severity severity, string checkId)
    {
        _findings.Add(new FindingInput(id, severity, checkId));
        return this;
    }

    /// <summary>Adds <paramref name="count"/> findings at one severity, ids <c>prefix-0000…</c>.</summary>
    internal RecordBuilder Findings(int count, Severity severity, string checkId, string prefix = "f")
    {
        for (int i = 0; i < count; i++)
        {
            _findings.Add(new FindingInput($"{prefix}-{severity}-{i:D6}", severity, checkId));
        }

        return this;
    }

    internal RecordBuilder RawCheck(CheckInput? check)
    {
        _checks.Add(check!);
        return this;
    }

    internal RecordBuilder RawFinding(FindingInput? finding)
    {
        _findings.Add(finding!);
        return this;
    }

    internal RollupInput Build() => new(_checks.ToArray(), _findings.ToArray());

    /// <summary>The same record with both lists in a seeded pseudo-random order.</summary>
    internal RollupInput BuildShuffled(int seed)
    {
        var random = new Random(seed);
        return new RollupInput(Shuffle(_checks, random), Shuffle(_findings, random));
    }

    private static T[] Shuffle<T>(List<T> items, Random random)
    {
        var copy = items.ToArray();
        for (int i = copy.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (copy[i], copy[j]) = (copy[j], copy[i]);
        }

        return copy;
    }

    // ------------------------------------------------------------------ canned records

    /// <summary>Six checks, all completed, no findings: the clean end of the range.</summary>
    internal static RecordBuilder Clean(int checks = 6)
    {
        var builder = new RecordBuilder();
        for (int i = 0; i < checks; i++)
        {
            builder.Check($"check-{i:D2}");
        }

        return builder;
    }

    /// <summary>
    /// The ordinary record used across the suite: five checks (one inconclusive, one skipped),
    /// five findings across three severities. Worked score, from the brief's weights
    /// (Informational 1, Low 2, Medium 5, High 15, Critical 40):
    /// 100 − (1×15 + 2×5 + 1×2 + 1×1) = 72 after findings; 3 of 4 attempted completed →
    /// floor(72 × 3 / 4) = 54.
    /// </summary>
    internal static RecordBuilder Ordinary() =>
        new RecordBuilder()
            .Completed("autoruns", "services", "tasks")
            .Inconclusive("hives", "needed elevation")
            .Skipped("mft", "not in quick mode")
            .Finding("f-1", Severity.High, "autoruns")
            .Finding("f-2", Severity.Medium, "autoruns")
            .Finding("f-3", Severity.Medium, "services")
            .Finding("f-4", Severity.Low, "tasks")
            .Finding("f-5", Severity.Informational, "hives");

    // ------------------------------------------------------------------ serialisation

    private static readonly JsonSerializerOptions SerialiserOptions = new() { WriteIndented = false };

    /// <summary>The whole rollup as UTF-8 JSON, for byte-identical comparison.</summary>
    internal static byte[] Serialise(RunRollup rollup) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(rollup, SerialiserOptions));

    internal static byte[] Serialise(ScoringResult<RunRollup> result) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
            new { result.State, result.Reason, result.Position, result.Value }, SerialiserOptions));
}
