using System.Text.RegularExpressions;

namespace Scythe.Rules.Linting;

/// <summary>
/// Measures a compiled pattern against bait input under the per-pattern budget
/// (BLUEPRINT §9: "a pattern that backtracks catastrophically, measured against bait
/// input under the budget"). Rules run against attacker-authored content, so the bait is
/// what an attacker would feed a backtracker: long homogeneous runs with a poisoned tail
/// that forces the engine to try every split before failing.
/// </summary>
public static class BacktrackingProbe
{
    /// <summary>Length of each bait body. Long enough that an exponential or quadratic
    /// pattern blows the 150 ms budget by orders of magnitude; short enough that a
    /// healthy pattern crosses all baits in microseconds.</summary>
    public const int BaitLength = 2048;

    /// <summary>The bait battery, built once. Public so the tests can assert the battery
    /// itself stays varied — a shrunken battery is a silently weakened check.</summary>
    public static IReadOnlyList<string> Baits { get; } = BuildBaits();

    private static IReadOnlyList<string> BuildBaits()
    {
        // Each bait pairs a long homogeneous body (maximal ambiguity for nested
        // quantifiers over that character class) with a tail character the body cannot
        // contain, so overall matching fails and a backtracker must exhaust every split.
        var repeatedWord = string.Concat(Enumerable.Repeat("ab", BaitLength / 2));
        var pathBody = string.Concat(Enumerable.Repeat(@"\aaaaaaaa", BaitLength / 9 + 1));
        return new[]
        {
            new string('a', BaitLength) + "!",           // lower-case run, poisoned
            new string('a', BaitLength),                 // lower-case run, clean (greedy sweep)
            new string('1', BaitLength) + "x",           // digit run, letter tail
            new string('1', BaitLength) + "!",           // digit run, symbol tail
                                                         // (two tails: no single tail
                                                         // character poisons every
                                                         // digit-hungry pattern)
            repeatedWord + "!",                          // two-character word run, poisoned
            new string(' ', BaitLength) + ".",           // whitespace run, poisoned
            "C:" + pathBody + "\0",                      // Windows-path shape, poisoned
        };
    }

    /// <summary>
    /// Runs <paramref name="pattern"/> (already compiled with a match timeout) across the
    /// battery. Returns the description of the first bait that blew the budget, or null
    /// when the pattern stayed inside it everywhere.
    /// </summary>
    public static string? FindBudgetBlowingBait(Regex pattern)
    {
        for (int i = 0; i < Baits.Count; i++)
        {
            try
            {
                // The verdict is irrelevant; only staying inside the budget matters.
                _ = pattern.IsMatch(Baits[i]);
            }
            catch (RegexMatchTimeoutException)
            {
                return DescribeBait(i);
            }
        }
        return null;
    }

    private static string DescribeBait(int index) => index switch
    {
        0 => $"a run of {BaitLength} 'a' characters with a non-matching tail",
        1 => $"a run of {BaitLength} 'a' characters",
        2 => $"a run of {BaitLength} digits with a letter tail",
        3 => $"a run of {BaitLength} digits with a symbol tail",
        4 => $"{BaitLength} characters of repeated \"ab\" with a non-matching tail",
        5 => $"a run of {BaitLength} spaces with a non-matching tail",
        _ => $"a {BaitLength}-character Windows-path shape with a non-matching tail",
    };
}
