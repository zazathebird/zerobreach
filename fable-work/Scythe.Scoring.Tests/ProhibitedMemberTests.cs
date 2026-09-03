using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace Scythe.Scoring.Tests;

/// <summary>
/// The brief's named reflection test. Fails the moment a member appears on the public surface
/// whose name suggests a single pass-rate, percentage or health figure.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this list exists.</b> Coverage has three totals — completed, inconclusive, skipped.
/// The moment a member exists that collapses them into one number, it is the shortest thing to
/// render, so it lands at the top of the report; and whatever definition it was given, a reader
/// interprets "94%" as "94% fine". A run with a third of its checks inconclusive has genuinely
/// not examined a third of the host, and a single figure lets that vanish. There is no careful
/// definition of such a figure that survives being read at a client's desk, so the rule is not
/// "define it carefully" but "make it unavailable" (reference/07.2_scoring.md).
/// </para>
/// <para>
/// The overall <see cref="CleanlinessScore"/> is permitted and expected: it summarises what was
/// <i>found</i>. Only a <i>coverage</i> figure can lie by omission, so the word "Score" is
/// allowed only on the score-side types listed in <see cref="ScoreWordAllowedOn"/>.
/// </para>
/// <para>
/// If this test has just failed on you: read the paragraph above, then either rename the member
/// to say what it counts (a count, not a rate), or make a deliberate written case in HANDOFF.md
/// for why this particular figure cannot be misread. "It is convenient for the renderer" is the
/// exact argument this test exists to refuse.
/// </para>
/// </remarks>
public sealed class ProhibitedMemberTests
{
    /// <summary>
    /// Whole PascalCase words that may not appear in any public type or member name in the
    /// assembly. Matched as words, not substrings, so "Separate" does not trip "Rate" but
    /// "PassRate", "CompletionRate" and "HealthIndex" all do.
    /// </summary>
    private static readonly string[] ForbiddenWords =
    {
        "Pass", "Passed", "Passing", "PassRate",
        "Rate", "Rates",
        "Percent", "Percentage", "Percentile", "Pct",
        "Ratio", "Ratios",
        "Fraction", "Proportion", "Share", "Quotient",
        "Health", "Healthy", "Healthiness",
        "Grade", "Graded", "Grading",
        "Index",
    };

    /// <summary>"Score" and its forms are forbidden everywhere except these type names and this one member.</summary>
    private static readonly string[] ScoreWords = { "Score", "Scores", "Scored" };

    private static readonly string[] ScoreWordAllowedOn =
    {
        nameof(CleanlinessScore),
        nameof(ScoreContribution),
        nameof(ScoreWeights),
        $"{nameof(RunRollup)}.{nameof(RunRollup.Score)}",
    };

    private static readonly Regex WordSplitter = new("[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", RegexOptions.CultureInvariant);

    private static IEnumerable<Type> PublicTypes() =>
        typeof(RunRollup).Assembly.GetTypes().Where(t => t.IsPublic || t.IsNestedPublic);

    private static IEnumerable<(string Owner, string Name)> PublicNames()
    {
        foreach (var type in PublicTypes())
        {
            var typeName = type.Name.Contains('`') ? type.Name[..type.Name.IndexOf('`')] : type.Name;
            yield return (typeName, typeName);

            const BindingFlags flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
            foreach (var member in type.GetMembers(flags))
            {
                // Compiler-generated record plumbing and object overrides are not surface.
                if (member.Name.StartsWith('<') || member.Name.StartsWith("op_", StringComparison.Ordinal)
                    || member.Name.StartsWith("get_", StringComparison.Ordinal) || member.Name.StartsWith("set_", StringComparison.Ordinal)
                    || member.Name is "Equals" or "GetHashCode" or "ToString" or "Deconstruct" or "PrintMembers" or "EqualityContract" or "value__")
                {
                    continue;
                }

                yield return (typeName, member.Name);
            }
        }
    }

    private static string[] Words(string identifier) =>
        WordSplitter.Matches(identifier).Select(m => m.Value).ToArray();

    [Fact]
    public void ThePublicSurfaceCarriesNoMemberNamedLikeAPassRateOrPercentage()
    {
        var offenders = new List<string>();
        foreach (var (owner, name) in PublicNames())
        {
            var hit = Words(name).FirstOrDefault(w => ForbiddenWords.Contains(w, StringComparer.Ordinal));
            if (hit is not null)
            {
                offenders.Add($"{owner}.{name} (word '{hit}')");
            }
        }

        Assert.True(offenders.Count == 0, Explain(offenders));
    }

    [Fact]
    public void TheWordScoreAppearsOnlyOnTheScoreSideOfTheResult()
    {
        var offenders = new List<string>();
        foreach (var (owner, name) in PublicNames())
        {
            if (!Words(name).Any(w => ScoreWords.Contains(w, StringComparer.Ordinal)))
            {
                continue;
            }

            bool allowed = ScoreWordAllowedOn.Contains(owner, StringComparer.Ordinal)
                || ScoreWordAllowedOn.Contains($"{owner}.{name}", StringComparer.Ordinal);
            if (!allowed)
            {
                offenders.Add($"{owner}.{name}");
            }
        }

        Assert.True(offenders.Count == 0, Explain(offenders));
    }

    /// <summary>
    /// The unnamed near-miss: a fractional member is a percentage waiting to be multiplied by
    /// 100. Every public number in this library is an integer count or an integer number of points.
    /// </summary>
    [Fact]
    public void NoPublicMemberReturnsAFloatingPointOrDecimalValue()
    {
        var fractional = new[] { typeof(float), typeof(double), typeof(decimal), typeof(Half) };
        var offenders = new List<string>();

        foreach (var type in PublicTypes())
        {
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (fractional.Contains(Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType))
                {
                    offenders.Add($"{type.Name}.{property.Name} : {property.PropertyType.Name}");
                }
            }

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                if (fractional.Contains(Nullable.GetUnderlyingType(field.FieldType) ?? field.FieldType))
                {
                    offenders.Add($"{type.Name}.{field.Name} : {field.FieldType.Name}");
                }
            }
        }

        Assert.True(offenders.Count == 0, Explain(offenders));
    }

    /// <summary>
    /// Negative control: the word splitter and the list actually catch the names the brief
    /// names. Without this the two tests above could pass because the matcher is broken.
    /// </summary>
    [Theory]
    [InlineData("PassRate", "Pass")]
    [InlineData("CompletionRate", "Rate")]
    [InlineData("InconclusivePercent", "Percent")]
    [InlineData("Percentage", "Percentage")]
    [InlineData("CoverageRatio", "Ratio")]
    [InlineData("HealthIndex", "Health")]
    [InlineData("Grade", "Grade")]
    [InlineData("CompletedFraction", "Fraction")]
    [InlineData("CompletedShare", "Share")]
    public void TheForbiddenListCatchesTheObviousNames(string identifier, string expectedWord)
    {
        var hit = Words(identifier).FirstOrDefault(w => ForbiddenWords.Contains(w, StringComparer.Ordinal));

        Assert.Equal(expectedWord, hit);
    }

    [Theory]
    [InlineData("Separate")]
    [InlineData("Generated")]
    [InlineData("CompletedCount")]
    [InlineData("InconclusiveReasons")]
    [InlineData("Operate")]
    public void TheForbiddenListDoesNotTripOnInnocentSubstrings(string identifier)
    {
        Assert.DoesNotContain(Words(identifier), w => ForbiddenWords.Contains(w, StringComparer.Ordinal));
    }

    [Fact]
    public void TheScoreWordCheckWouldCatchAScoreOnTheCoverageType()
    {
        var words = Words("Score");
        Assert.Contains("Score", words);
        Assert.DoesNotContain(nameof(CoverageStatement), ScoreWordAllowedOn);
    }

    [Fact]
    public void TheSurfaceScanActuallySeesTheResultTypes()
    {
        var names = PublicNames().Select(n => $"{n.Owner}.{n.Name}").ToHashSet(StringComparer.Ordinal);

        Assert.Contains("CoverageStatement.CompletedCount", names);
        Assert.Contains("CoverageStatement.InconclusiveCount", names);
        Assert.Contains("RunRollup.Score", names);
        Assert.Contains("CleanlinessScore.Value", names);
        Assert.Contains("CleanlinessScore.Maximum", names);
    }

    private static string Explain(List<string> offenders) =>
        "The public result surface exposes a member whose name suggests a single pass-rate, percentage or health figure:\n  "
        + string.Join("\n  ", offenders)
        + "\n\nSuch a member collapses completed, inconclusive and skipped into one number, becomes the shortest thing to render, "
        + "lands at the top of the report, and is read as 'N% fine' whatever its definition says. A run that could not examine a "
        + "third of the host must never present that way. Rename the member to say what it counts, or argue the case in "
        + "HANDOFF.md — see the remarks on ProhibitedMemberTests and reference/07.2_scoring.md.";
}
