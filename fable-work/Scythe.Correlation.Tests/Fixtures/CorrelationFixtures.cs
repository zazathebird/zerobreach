using Xunit;

namespace Scythe.Correlation.Tests.Fixtures;

/// <summary>
/// Builds the findings of one run programmatically. Every fixture in the suite is authored here
/// so a malformed or awkward variant is one changed argument away from the ordinary one.
/// </summary>
internal static class CorrelationFixtures
{
    /// <summary>The run's one timestamp: every finding in a real record carries this same value.</summary>
    public static readonly DateTimeOffset RunTime = new(2026, 9, 2, 10, 15, 0, TimeSpan.Zero);

    public static FindingReference Finding(string id, string description, EntityReference? target = null, DateTimeOffset? anchor = null) =>
        new(id, description, target, anchor ?? RunTime);

    public static FindingReference PathFinding(string id, string path, string description = "") =>
        Finding(id, description, EntityReference.Path(path));

    /// <summary>
    /// <paramref name="count"/> findings whose descriptions all mention <paramref name="entityText"/>
    /// and nothing else, ids F000..F(count-1).
    /// </summary>
    public static List<FindingReference> AllMentioning(int count, string entityText, string idPrefix = "F")
    {
        var list = new List<FindingReference>(count);
        for (var i = 0; i < count; i++)
        {
            list.Add(Finding($"{idPrefix}{i:D3}", $"check {i} observed {entityText} during the run"));
        }

        return list;
    }

    /// <summary>Findings sharing nothing: each names a path unique to itself.</summary>
    public static List<FindingReference> AllDistinct(int count, DateTimeOffset? anchor = null)
    {
        var list = new List<FindingReference>(count);
        for (var i = 0; i < count; i++)
        {
            list.Add(Finding($"D{i:D3}", $"observed C:\\Unique\\item{i}.exe", EntityReference.Path($"C:\\Unique\\target{i}.dll"), anchor));
        }

        return list;
    }

    public static CorrelationOutput Build(IReadOnlyList<FindingReference> findings, ScanBudget? budget = null)
    {
        var result = ChainBuilder.Build(findings, budget);
        Assert.Equal(CorrelationResultState.Ok, result.State);
        return result.Value!;
    }

    public static Entity Unwrap(CorrelationResult<Entity> result)
    {
        Assert.True(result.IsOk, result.Reason);
        return result.Value!;
    }

    /// <summary>A deterministic permutation: Fisher–Yates with a seeded generator.</summary>
    public static List<T> Shuffled<T>(IReadOnlyList<T> items, int seed)
    {
        var random = new Random(seed);
        var copy = items.ToList();
        for (var i = copy.Count - 1; i > 0; i--)
        {
            var j = random.Next(i + 1);
            (copy[i], copy[j]) = (copy[j], copy[i]);
        }

        return copy;
    }
}
