using Scythe.Time.Tests.Fixtures;
using Xunit;

namespace Scythe.Time.Tests;

/// <summary>
/// Canaries for the one budget member that binds in this project.
/// </summary>
/// <remarks>
/// Only <see cref="ScanBudget.MaxInputBytes"/> has anything to constrain here: every other entry
/// point takes a fixed-width scalar the caller has already read, so there is no loop to bound, no
/// container to recurse into and no output to expand. The decimal-string form is the exception —
/// its size is a property of the artifact rather than of the caller — and these tests exist so
/// that if the guard on it is ever refactored into a no-op, the suite says so instead of
/// continuing to assert a safety that is not there.
/// </remarks>
public sealed class BudgetCanaryTests
{
    private static ScanBudget Tiny => ScanBudget.Default with { MaxInputBytes = 8 };

    [Fact]
    public void DefaultBudgetHasTheValuesTheSharedContractStates()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), ScanBudget.Default.Deadline);
        Assert.Equal(64L * 1024 * 1024, ScanBudget.Default.MaxInputBytes);
        Assert.Equal(10_000, ScanBudget.Default.MaxMatches);
        Assert.Equal(16, ScanBudget.Default.MaxNestingDepth);
    }

    [Fact]
    public void AnInputPastTheByteBudgetIsIncompleteWithTheBudgetNamed()
    {
        var result = TimeDecoder.DecodeDecimalStringCounter1601(new string('9', 400), Tiny);

        // Incomplete, not Failed: the reader stopped because the caller told it to, which is a
        // different fact about the run from "this field is corrupt".
        Assert.Equal(TimeResultState.Incomplete, result.State);
        Assert.Null(result.Value);
        Assert.Contains("budget allows 8", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void TheSameInputUnderTheDefaultBudgetIsFailedOnItsLengthInstead()
    {
        // The canary's negative control. The two guards report different states for the same
        // bytes, and collapsing either into the other would lose the distinction a caller needs.
        var result = TimeDecoder.DecodeDecimalStringCounter1601(new string('9', 400));

        Assert.Equal(TimeResultState.Failed, result.State);
    }

    [Fact]
    public void AnInputInsideTheByteBudgetStillDecodesNormally()
    {
        // Proves the canary can be quiet as well as loud: a guard that refused everything would
        // pass the test above while being useless.
        var count = TimeFixtures.Counter1601(TimeFixtures.Ordinary);
        var digits = count.ToString(System.Globalization.CultureInfo.InvariantCulture);

        var budget = ScanBudget.Default with { MaxInputBytes = digits.Length };

        var decoded = TimeFixtures.Unwrap(TimeDecoder.DecodeDecimalStringCounter1601(digits, budget));

        Assert.Equal(TimeFixtures.Ordinary, decoded.Value);
    }

    [Fact]
    public void ABudgetOfZeroRefusesEveryNonEmptyInput()
    {
        var budget = ScanBudget.Default with { MaxInputBytes = 0 };

        Assert.Equal(
            TimeResultState.Incomplete,
            TimeDecoder.DecodeDecimalStringCounter1601("1", budget).State);
    }

    [Fact]
    public void OmittingTheBudgetUsesTheDefaultRatherThanNoLimit()
    {
        var withDefault = TimeDecoder.DecodeDecimalStringCounter1601(new string('9', 400));
        var withExplicitDefault = TimeDecoder.DecodeDecimalStringCounter1601(new string('9', 400), ScanBudget.Default);

        Assert.Equal(withExplicitDefault.State, withDefault.State);
        Assert.Equal(withExplicitDefault.Reason, withDefault.Reason);
    }
}
