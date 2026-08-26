namespace ZeroBreach.Baseline.Tests;

/// <summary>Every comparison operator, both directions, including the ordinal corner:
/// at-least must pass a machine that is stricter than the floor.</summary>
public sealed class ComparisonTests
{
    private static ComplianceStatus Evaluate(BaselineCheck check, SettingValue observed) =>
        TestData.EvaluateOne(check, TestData.Observed(
            (check.SettingKey, SettingObservation.Present(observed)))).Status;

    // ---- equals ----

    [Fact]
    public void Equals_Integer_PassesOnSameValue() =>
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(
            TestData.IntegerCheck(comparison: CheckComparison.EqualTo(SettingValue.OfInteger(5))),
            SettingValue.OfInteger(5)));

    [Fact]
    public void Equals_Integer_FailsOnDifferentValue() =>
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(
            TestData.IntegerCheck(comparison: CheckComparison.EqualTo(SettingValue.OfInteger(5))),
            SettingValue.OfInteger(6)));

    [Fact]
    public void Equals_Boolean_BothDirections()
    {
        var check = TestData.BooleanCheck(comparison: CheckComparison.EqualTo(SettingValue.OfBoolean(true)));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(check, SettingValue.OfBoolean(true)));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(check, SettingValue.OfBoolean(false)));
    }

    // ---- not-equals ----

    [Fact]
    public void NotEquals_PassesOnDifferentValue_FailsOnMatch()
    {
        var check = TestData.IntegerCheck(comparison: CheckComparison.NotEqualTo(SettingValue.OfInteger(0)));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(check, SettingValue.OfInteger(1)));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(check, SettingValue.OfInteger(0)));
    }

    // ---- at-least ----

    [Fact]
    public void AtLeast_PassesOnExactFloor() =>
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(
            TestData.IntegerCheck(comparison: CheckComparison.AtLeast(5)),
            SettingValue.OfInteger(5)));

    [Fact]
    public void AtLeast_PassesOnStricterValueThanExpected()
    {
        // The ordinal corner from the brief: a value of 6 is stricter than a floor of 5 and
        // must pass. A check compiled down to equality would wrongly fail it.
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(
            TestData.IntegerCheck(comparison: CheckComparison.AtLeast(5)),
            SettingValue.OfInteger(6)));
    }

    [Fact]
    public void AtLeast_FailsBelowFloor() =>
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(
            TestData.IntegerCheck(comparison: CheckComparison.AtLeast(5)),
            SettingValue.OfInteger(4)));

    // ---- one-of ----

    [Fact]
    public void OneOf_PassesOnMember_FailsOnNonMember()
    {
        var check = TestData.IntegerCheck(comparison: CheckComparison.OneOf(
            SettingValue.OfInteger(1), SettingValue.OfInteger(3)));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(check, SettingValue.OfInteger(3)));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(check, SettingValue.OfInteger(2)));
    }

    // ---- none-of ----

    [Fact]
    public void NoneOf_FailsOnMember_PassesOnNonMember()
    {
        var check = TestData.IntegerCheck(comparison: CheckComparison.NoneOf(
            SettingValue.OfInteger(0), SettingValue.OfInteger(255)));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(check, SettingValue.OfInteger(255)));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(check, SettingValue.OfInteger(1)));
    }

    // ---- string case sensitivity ----

    [Fact]
    public void CaseSensitiveAndInsensitiveChecks_DisagreeOnTheSameInput()
    {
        // The same observed value against the same expected value: only the declared case
        // sensitivity separates a pass from a failure. Comparison is ordinal in both modes.
        var expected = CheckComparison.EqualTo(SettingValue.OfString("NTLMv2"));
        var observed = SettingValue.OfString("ntlmv2");

        var sensitive = TestData.StringCheck(StringCase.Sensitive, comparison: expected);
        var insensitive = TestData.StringCheck(StringCase.Insensitive, comparison: expected);

        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(sensitive, observed));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(insensitive, observed));
    }

    [Fact]
    public void CaseSensitivity_AppliesInsideOneOfAndNoneOf()
    {
        var values = new[] { SettingValue.OfString("Alpha"), SettingValue.OfString("Beta") };
        var observed = SettingValue.OfString("alpha");

        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(
            TestData.StringCheck(StringCase.Sensitive, comparison: CheckComparison.OneOf(values)), observed));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(
            TestData.StringCheck(StringCase.Insensitive, comparison: CheckComparison.OneOf(values)), observed));

        // none-of flips: the insensitive check treats "alpha" as a forbidden value.
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(
            TestData.StringCheck(StringCase.Sensitive, comparison: CheckComparison.NoneOf(values)), observed));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(
            TestData.StringCheck(StringCase.Insensitive, comparison: CheckComparison.NoneOf(values)), observed));
    }

    [Fact]
    public void StringComparison_IsOrdinal_NotCultureSensitive()
    {
        // Ordinal comparison must not fold culture-specific casing: the Turkish dotless i
        // corner. OrdinalIgnoreCase maps 'i' <-> 'I' only; 'ı' (U+0131) stays distinct.
        var check = TestData.StringCheck(StringCase.Insensitive,
            comparison: CheckComparison.EqualTo(SettingValue.OfString("file")));
        Assert.Equal(ComplianceStatus.NonCompliant, Evaluate(check, SettingValue.OfString("fıle")));
        Assert.Equal(ComplianceStatus.Compliant, Evaluate(check, SettingValue.OfString("FILE")));
    }
}
