namespace Scythe.Baseline.Tests;

/// <summary>Check-table validation: every defect the brief names must reject the table rather
/// than let it evaluate, because a check that cannot be evaluated must never count as compliant.</summary>
public sealed class ValidatorTests
{
    private static void AssertRejected(BaselineCheck check, string messageFragment)
    {
        var errors = CheckTableValidator.Validate(TestData.Table(check));
        Assert.Contains(errors, e =>
            e.Message.Contains(messageFragment, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidTable_ProducesNoErrors()
    {
        var errors = CheckTableValidator.Validate(TestData.Table(
            TestData.IntegerCheck(),
            TestData.BooleanCheck(),
            TestData.StringCheck(StringCase.Sensitive),
            TestData.MultiIntegerCheck()));
        Assert.Empty(errors);
    }

    [Fact]
    public void DuplicateCheckIds_AreRejected()
    {
        var errors = CheckTableValidator.Validate(TestData.Table(
            TestData.IntegerCheck(id: "DUP-1"),
            TestData.BooleanCheck(id: "DUP-1")));
        var error = Assert.Single(errors);
        Assert.Equal("DUP-1", error.CheckId);
        Assert.Contains("duplicate check id", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyId_IsRejected_AndAttributedByTablePosition()
    {
        var errors = CheckTableValidator.Validate(TestData.Table(
            TestData.IntegerCheck(),
            TestData.BooleanCheck(id: "   ")));
        var error = Assert.Single(errors);
        Assert.Null(error.CheckId);
        Assert.Contains("checks[1]", error.Message, StringComparison.Ordinal);
        Assert.Contains("id is empty", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyTitle_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { Title = "" }, "title is empty");

    [Fact]
    public void EmptySettingKey_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { SettingKey = " " }, "setting key is empty");

    [Fact]
    public void EmptyRemediation_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { Remediation = "" }, "remediation text is empty");

    [Fact]
    public void SeverityOutsideThePermittedSet_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(severity: (Severity)99), "severity 99 is outside");

    [Fact]
    public void UndeclaredValueKind_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { ExpectedKind = (SettingValueKind)7 },
            "outside the permitted set");

    // ---- comparison / declared type agreement ----

    [Fact]
    public void AtLeast_OnAStringCheck_IsRejected() =>
        AssertRejected(TestData.StringCheck(StringCase.Sensitive, comparison: CheckComparison.AtLeast(3)),
            "at-least is a numeric floor and cannot apply to a string");

    [Fact]
    public void AtLeast_OnABooleanCheck_IsRejected() =>
        AssertRejected(TestData.BooleanCheck(comparison: CheckComparison.AtLeast(1)),
            "cannot apply to a boolean");

    [Fact]
    public void EqualsExpectedValue_OfTheWrongKind_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(comparison: CheckComparison.EqualTo(SettingValue.OfString("5"))),
            "expected value is string but the check declares integer");

    [Fact]
    public void NotEqualsExpectedValue_OfTheWrongKind_IsRejected() =>
        AssertRejected(TestData.BooleanCheck(comparison: CheckComparison.NotEqualTo(SettingValue.OfInteger(0))),
            "expected value is integer but the check declares boolean");

    [Fact]
    public void OneOf_WithAnEmptyValueList_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(comparison: CheckComparison.OneOf()),
            "one-of has an empty value list");

    [Fact]
    public void NoneOf_WithAnEmptyValueList_IsRejected()
    {
        // An empty none-of is vacuously always compliant — a check that can never fail is a
        // silently disabled check.
        AssertRejected(TestData.IntegerCheck(comparison: CheckComparison.NoneOf()),
            "none-of has an empty value list");
    }

    [Fact]
    public void ValueList_WithAMistypedMember_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(comparison: CheckComparison.OneOf(
                SettingValue.OfInteger(1), SettingValue.OfBoolean(true))),
            "expected value is boolean but the check declares integer");

    [Fact]
    public void MissingComparison_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { Comparison = null! }, "comparison is missing");

    // ---- absence ----

    [Fact]
    public void MissingAbsenceRule_IsRejected()
    {
        // Required-by-construction, but the table is data and null! is one typo away in a
        // loader; the "no global fallback" rule holds at validation too.
        AssertRejected(TestData.IntegerCheck() with { Absence = null! }, "absence rule is missing");
    }

    [Fact]
    public void AbsenceDefault_OfTheWrongKind_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(absence: AbsenceRule.MeansDefault(SettingValue.OfString("3"))),
            "absence default is string but the check declares integer");

    [Fact]
    public void AbsenceDefault_WithANullValue_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(absence: new AbsenceMeansDefault(null!)),
            "absence-means-default has no default value");

    // ---- string case sensitivity ----

    [Fact]
    public void StringCheck_WithoutDeclaredCaseSensitivity_IsRejected() =>
        AssertRejected(TestData.StringCheck(StringCase.Sensitive) with { CaseSensitivity = null },
            "must declare case sensitivity");

    [Fact]
    public void CaseSensitivity_OutsideThePermittedSet_IsRejected() =>
        AssertRejected(TestData.StringCheck((StringCase)9), "case sensitivity 9 is outside");

    [Fact]
    public void IntegerCheck_WithoutCaseSensitivity_IsFine()
    {
        var errors = CheckTableValidator.Validate(TestData.Table(TestData.IntegerCheck()));
        Assert.Empty(errors);
    }

    // ---- instancing ----

    [Fact]
    public void MultiInstanceCheck_WithoutAnEmptyInstancesRule_IsRejected() =>
        AssertRejected(TestData.MultiIntegerCheck() with { EmptyInstances = null },
            "must declare what an empty instance collection means");

    [Fact]
    public void EmptyInstancesRule_OutsideThePermittedSet_IsRejected() =>
        AssertRejected(TestData.MultiIntegerCheck(emptyInstances: (EmptyInstancesRule)42),
            "empty-instances rule 42 is outside");

    [Fact]
    public void Instancing_OutsideThePermittedSet_IsRejected() =>
        AssertRejected(TestData.IntegerCheck() with { Instancing = (CheckInstancing)3 },
            "instancing 3 is outside");

    // ---- applicability ----

    [Fact]
    public void ApplicabilityCondition_WithAnEmptyContextKey_IsRejected() =>
        AssertRejected(TestData.IntegerCheck(
                appliesWhen: new ApplicabilityCondition("", new[] { "Server" })),
            "empty context key");

    [Fact]
    public void ApplicabilityCondition_WithAnEmptyValueList_IsRejected()
    {
        // A predicate with no candidate values would silently never apply — a disabled check.
        AssertRejected(TestData.IntegerCheck(
                appliesWhen: new ApplicabilityCondition("Role", Array.Empty<string>())),
            "empty value list");
    }

    // ---- a bad table never evaluates ----

    [Fact]
    public void BadTable_EvaluatesNothing_FailedStateEmptyResultsNullRollup()
    {
        var table = TestData.Table(
            TestData.IntegerCheck(id: "GOOD-1"),
            TestData.IntegerCheck(id: "BAD-1") with { Remediation = "" });
        var observations = TestData.Observed(
            ("Policy\\SomeInteger", SettingObservation.Present(SettingValue.OfInteger(1))));

        var evaluation = BaselineEvaluator.Evaluate(table, observations, MachineContext.Empty);

        // Even the good check is not evaluated: partial evaluation would let a defective
        // check disappear from the output while the rest reads as a clean run.
        Assert.Equal(EvaluationState.Failed, evaluation.State);
        Assert.Empty(evaluation.Results);
        Assert.Null(evaluation.Rollup);
        var error = Assert.Single(evaluation.TableErrors);
        Assert.Equal("BAD-1", error.CheckId);
    }

    [Fact]
    public void EveryDefect_IsReported_NotJustTheFirst()
    {
        var errors = CheckTableValidator.Validate(TestData.Table(
            TestData.IntegerCheck(id: "B1") with { Title = "" },
            TestData.BooleanCheck(id: "B2") with { Remediation = "" }));
        Assert.Equal(2, errors.Count);
        Assert.Equal(new[] { "B1", "B2" }, errors.Select(e => e.CheckId));
    }
}
